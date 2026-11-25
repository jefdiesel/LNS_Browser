// Zero-dependency Logos Storage reader and v1 site manifest parser for `lns-gateway`.
// Uses only Node built-ins, `./derive.mjs`, and package-free `basecamp/qml/logic.mjs`.

import { extname } from "node:path";
import { tryParseManifestJson } from "../basecamp/qml/logic.mjs";
import { isValidCid, normalizeSitePath, sha256Hex } from "./derive.mjs";

export const MANIFEST_KIND = "lns-site-manifest";
export const MANIFEST_MIME = "application/vnd.logos.site-manifest+json";
export const STANDIN_SEED_PEER_ID = "16Uiu2HAmLocalLogosStorageSeed";
export const MAX_FETCH_BYTES = 100 * 1024 * 1024;

const MIME_BY_EXT = {
  ".html": "text/html; charset=utf-8",
  ".htm": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".wasm": "application/wasm",
  ".lgx": "application/octet-stream",
  ".mp3": "audio/mpeg",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
};

const EXT_BY_MIME = {
  "text/html": ".html",
  "text/css": ".css",
  "text/plain": ".txt",
  "text/markdown": ".md",
  "application/json": ".json",
  "image/svg+xml": ".svg",
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/gif": ".gif",
  "image/webp": ".webp",
  "image/x-icon": ".ico",
  "font/woff": ".woff",
  "font/woff2": ".woff2",
  "font/ttf": ".ttf",
  "application/wasm": ".wasm",
  "audio/mpeg": ".mp3",
  "video/mp4": ".mp4",
  "video/webm": ".webm",
};

export function bareMimeType(contentType = "application/octet-stream") {
  const bare = String(contentType || "").split(";")[0].trim().toLowerCase();
  return bare || "application/octet-stream";
}

export function extensionForMime(contentType = "application/octet-stream") {
  return EXT_BY_MIME[bareMimeType(contentType)] || ".bin";
}

export function mimeForPath(filePath) {
  return MIME_BY_EXT[extname(filePath).toLowerCase()] || "application/octet-stream";
}

export function sniffContentType(bytes, fallback = "application/octet-stream") {
  const head = new TextDecoder("utf-8", { fatal: false }).decode(bytes.subarray(0, 512)).trimStart();
  if (/^<!doctype html|^<html|^<head|^<body/i.test(head)) return "text/html; charset=utf-8";
  if (/^<svg[\s>]/i.test(head)) return "image/svg+xml";
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
    return "image/png";
  }
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return "image/jpeg";
  }
  return fallback;
}

/**
 * Parses and validates an LNS v1 `lns-site-manifest` JSON blob.
 * Returns the validated manifest or `null` if the bytes are not a v1 manifest.
 */
export function tryParseManifest(bytes) {
  if (!bytes || bytes.length === 0 || bytes.length > 2 * 1024 * 1024) return null;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
  const parsed = tryParseManifestJson(text);
  if (!parsed || parsed.version !== 1) return null;

  const files = {};
  for (const [rawPath, entry] of Object.entries(parsed.files)) {
    const cleanPath = normalizeSitePath(rawPath);
    if (!entry || typeof entry !== "object" || !isValidCid(entry.cid)) {
      throw new Error(`manifest entry ${rawPath} has an invalid CID`);
    }
    files[cleanPath] = {
      cid: entry.cid,
      sha256:
        typeof entry.sha256 === "string" && /^[0-9a-f]{64}$/i.test(entry.sha256)
          ? entry.sha256.toLowerCase()
          : null,
      size: Number.isInteger(entry.size) && entry.size >= 0 ? entry.size : null,
      contentType: typeof entry.contentType === "string" ? entry.contentType : mimeForPath(cleanPath),
    };
  }

  const index = typeof parsed.index === "string" ? normalizeSitePath(parsed.index) : "/index.html";
  return {
    kind: MANIFEST_KIND,
    version: 1,
    title: typeof parsed.title === "string" ? parsed.title : null,
    index,
    files,
  };
}

export class StorageClient {
  constructor(baseUrl = "", { fetchImpl = fetch, timeoutMs = 30_000, allowStandin = false } = {}) {
    this.baseUrl = String(baseUrl || "").trim().replace(/\/+$/, "");
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.allowStandin = Boolean(allowStandin);
    this._verifiedRealNode = false;
  }

  get configured() {
    return this.baseUrl.length > 0;
  }

  async info() {
    if (!this.configured) {
      throw new Error("No Logos Storage node is configured. Set LOGOS_STORAGE_API or pass --storage URL.");
    }
    let res;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/debug/info`, {
        redirect: "error",
        signal: AbortSignal.timeout(Math.min(this.timeoutMs, 10_000)),
      });
    } catch (err) {
      throw new Error(`Cannot reach Logos Storage node at ${this.baseUrl}: ${err.message}`);
    }
    if (!res.ok) {
      const hint = /:8080(\/|$)/.test(this.baseUrl)
        ? " (port 8080 is used by the Logos Blockchain node, not Logos Storage)"
        : "";
      throw new Error(`No Logos Storage node at ${this.baseUrl} (HTTP ${res.status})${hint}`);
    }
    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error(`${this.baseUrl} did not return valid Logos Storage JSON`);
    }
    if (!data || typeof data.id !== "string" || !data.id) {
      throw new Error(`${this.baseUrl} did not return a Logos Storage peer ID`);
    }
    return data;
  }

  async assertRealStorageNode() {
    if (this._verifiedRealNode) return;
    const info = await this.info();
    const isStandin = Boolean(info.mock) || info.id === STANDIN_SEED_PEER_ID;
    if (isStandin && !this.allowStandin) {
      throw new Error(
        "Refused to publish to a stand-in mock storage stub (nobody else can open its CIDs). Connect a real Logos Storage node.",
      );
    }
    this._verifiedRealNode = true;
    return info;
  }

  /**
   * Uploads bytes to Logos Storage using a bare MIME type (no `; charset=...` parameters).
   * If the real node rejects a MIME type (HTTP 422 / 415), falls back to `application/octet-stream`.
   */
  async upload(bytes, { filename = "blob", contentType = "application/octet-stream" } = {}) {
    await this.assertRealStorageNode();
    const buf = bytes instanceof Uint8Array ? bytes : Buffer.from(bytes);
    const safeName = String(filename || "blob").replace(/[^\x20-\x7e]|["/\\]/g, "_") || "blob";
    const initialMime = bareMimeType(contentType);

    const tryUpload = async (mime) => {
      const res = await this.fetchImpl(`${this.baseUrl}/data`, {
        method: "POST",
        redirect: "error",
        headers: {
          "Content-Type": mime,
          "Content-Disposition": `attachment; filename="${safeName}"`,
        },
        body: buf,
        signal: AbortSignal.timeout(Math.max(this.timeoutMs, 120_000)),
      });
      return res;
    };

    let usedMime = initialMime;
    let res = await tryUpload(usedMime);
    if ((res.status === 422 || res.status === 415) && usedMime !== "application/octet-stream") {
      usedMime = "application/octet-stream";
      res = await tryUpload(usedMime);
    }
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Storage upload failed (HTTP ${res.status}): ${text.slice(0, 200)}`);
    }
    const cid = (await res.text()).trim();
    if (!isValidCid(cid)) {
      throw new Error(`Storage returned an unexpected CID: ${JSON.stringify(cid)}`);
    }
    return {
      cid,
      sha256: sha256Hex(buf),
      size: buf.length,
      contentType: usedMime,
    };
  }

  async download(cid, { expectedSha256 = null, expectedSize = null, maxBytes = MAX_FETCH_BYTES } = {}) {
    if (!this.configured) {
      throw new Error("No Logos Storage node is configured. Set LOGOS_STORAGE_API or pass --storage URL.");
    }
    if (!isValidCid(cid)) throw new Error(`invalid CID: ${cid}`);

    const endpoints = [
      `${this.baseUrl}/data/${cid}/network/stream`,
      `${this.baseUrl}/data/${cid}`,
    ];

    let sawNotFound = false;
    let lastErr = null;
    for (const url of endpoints) {
      try {
        const res = await this.fetchImpl(url, {
          redirect: "error",
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (res.status === 404) {
          sawNotFound = true;
          continue;
        }
        if (!res.ok) {
          lastErr = new Error(`Storage node returned HTTP ${res.status} for CID ${cid}`);
          continue;
        }
        const contentType = res.headers.get("content-type") || "application/octet-stream";
        const contentLenHeader = res.headers.get("content-length");
        if (contentLenHeader !== null) {
          const declaredLen = Number(contentLenHeader);
          if (Number.isFinite(declaredLen) && declaredLen > maxBytes) {
            if (res.body && typeof res.body.cancel === "function") {
              await res.body.cancel().catch(() => {});
            }
            throw new Error(`CID ${cid} exceeds limit of ${maxBytes} bytes (${declaredLen} bytes)`);
          }
        }
        let buf;
        if (res.body && typeof res.body.getReader === "function") {
          const reader = res.body.getReader();
          const chunks = [];
          let received = 0;
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (!value || value.byteLength === 0) continue;
              received += value.byteLength;
              if (received > maxBytes) {
                await reader.cancel().catch(() => {});
                throw new Error(`CID ${cid} exceeds limit of ${maxBytes} bytes`);
              }
              chunks.push(value);
            }
          } finally {
            reader.releaseLock();
          }
          buf = new Uint8Array(received);
          let offset = 0;
          for (const c of chunks) {
            buf.set(c, offset);
            offset += c.byteLength;
          }
        } else {
          buf = new Uint8Array(await res.arrayBuffer());
          if (buf.length > maxBytes) {
            throw new Error(`CID ${cid} exceeds limit of ${maxBytes} bytes (${buf.length} bytes)`);
          }
        }
        const actualSha256 = sha256Hex(buf);
        if (expectedSize !== null && buf.length !== expectedSize) {
          throw new Error(
            `integrity mismatch for ${cid}: expected ${expectedSize} bytes, got ${buf.length}`,
          );
        }
        if (expectedSha256 && actualSha256 !== expectedSha256.toLowerCase()) {
          throw new Error(
            `SHA-256 mismatch for ${cid}: on-chain expected ${expectedSha256.toLowerCase()}, got ${actualSha256}`,
          );
        }
        return {
          cid,
          bytes: buf,
          size: buf.length,
          sha256: actualSha256,
          contentType,
          verified: Boolean(expectedSha256),
        };
      } catch (err) {
        if (
          err.message.includes("SHA-256 mismatch") ||
          err.message.includes("integrity mismatch") ||
          err.message.includes("exceeds limit")
        ) {
          throw err;
        }
        lastErr = new Error(`Cannot reach Logos Storage node at ${this.baseUrl}: ${err.message}`);
      }
    }
    if (sawNotFound) {
      throw new Error(`CID ${cid} was not found on the configured Logos Storage node.`);
    }
    throw lastErr ?? new Error(`Cannot reach any Logos Storage node for CID ${cid}`);
  }
}
