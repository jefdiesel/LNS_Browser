// Logos Storage REST client (API v0.5.3: /api/storage/v1/data) with SHA-256 verification.
// Matches the contract in lez-program-registry/sdk/rust/src/storage.rs.

import { createHash } from "node:crypto";
import { isValidCid } from "./lns.js";

// Never default to port 8080 (used by the Logos Blockchain node, not Logos Storage).
export const DEFAULT_STORAGE_API = "";
export const STANDIN_SEED_PEER_ID = "16Uiu2HAmLocalLogosStorageSeed";
export const MAX_FETCH_BYTES = 25 * 1024 * 1024; // 25 MiB per asset

export function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export class StorageClient {
  constructor(baseUrl = DEFAULT_STORAGE_API, { fetchImpl = fetch, timeoutMs = 30_000, allowStandin = false } = {}) {
    this.baseUrl = String(baseUrl || "").trim().replace(/\/+$/, "");
    this.fetchImpl = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.allowStandin = Boolean(allowStandin);
  }

  get configured() {
    return this.baseUrl.length > 0;
  }

  _requireConfigured() {
    if (!this.configured) {
      throw new Error(
        "No Logos Storage node is configured. Pick your real Logos Storage API URL in Settings (or pass --storage URL). Note: port 8080 is used by the Logos Blockchain node, not Storage.",
      );
    }
  }

  /** Checks node health via GET /debug/info. */
  async info() {
    this._requireConfigured();
    let res;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/debug/info`, {
        signal: AbortSignal.timeout(5_000),
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

  /** Refuses publishing to stand-in local-only mocks so published CIDs are actually reachable by other peers. */
  async assertRealStorageNode() {
    const info = await this.info();
    const isStandin = Boolean(info.mock) || info.id === STANDIN_SEED_PEER_ID;
    if (isStandin && !this.allowStandin) {
      throw new Error(
        "Refused to publish to the stand-in local-storage.js stub (nobody else can open its CIDs). Connect a real Logos Storage node or publish through Basecamp's built-in Storage module.",
      );
    }
    return info;
  }

  /**
   * Uploads raw bytes to Logos Storage and returns `{ cid, sha256, size }`.
   */
  async upload(bytes, { filename = "index.html", contentType = "application/octet-stream" } = {}) {
    await this.assertRealStorageNode();
    const buf = bytes instanceof Uint8Array ? bytes : Buffer.from(bytes);
    const safeName = filename.replace(/["\r\n/\\]/g, "_") || "blob";
    const res = await this.fetchImpl(`${this.baseUrl}/data`, {
      method: "POST",
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": `attachment; filename="${safeName}"`,
      },
      body: buf,
      signal: AbortSignal.timeout(120_000),
    });
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
    };
  }

  /**
   * Downloads a CID from the user's Logos Storage node and optionally verifies
   * its SHA-256 and byte size against the on-chain / manifest commitment.
   */
  async download(cid, { expectedSha256 = null, expectedSize = null, maxBytes = MAX_FETCH_BYTES } = {}) {
    this._requireConfigured();
    if (!isValidCid(cid)) throw new Error(`invalid CID: ${cid}`);

    // Try network stream first, then local cache (standard Logos Storage endpoints).
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
        const buf = new Uint8Array(await res.arrayBuffer());
        if (buf.length > maxBytes) {
          throw new Error(`CID ${cid} exceeds limit of ${maxBytes} bytes (${buf.length} bytes)`);
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
      throw new Error(
        `CID ${cid} is not on any Logos Storage node this browser can reach. It may only exist on a private local node, or no peer is currently seeding it.`,
      );
    }
    throw lastErr ?? new Error(`Cannot reach any Logos Storage node for CID ${cid}`);
  }
}
