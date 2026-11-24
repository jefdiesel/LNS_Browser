// Multi-file site manifest + single-file HTML support for LNS + Logos Storage CID sites.
//
// A root CID pointed to by an LNS name's `cid` record can be EITHER:
//   1. A JSON site manifest (`version: 1`, `kind: "lns-site-manifest"`, `files: { "/index.html": { cid, sha256, size, contentType }, ... }`)
//   2. A raw single-file HTML document (or image/text/JSON asset)

import { readdir, readFile, stat } from "node:fs/promises";
import { extname, join, posix } from "node:path";
import { isValidCid, normalizeSitePath } from "./lns.js";

export const MANIFEST_KIND = "lns-site-manifest";
export const MANIFEST_MIME = "application/vnd.logos.site-manifest+json";

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
  ".mp3": "audio/mpeg",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
};

export function mimeForPath(filePath) {
  return MIME_BY_EXT[extname(filePath).toLowerCase()] || "application/octet-stream";
}

/**
 * Attempts to parse bytes as an LNS v1 site manifest.
 * Returns the validated manifest object, or `null` if the bytes are not a site manifest.
 */
export function tryParseManifest(bytes) {
  if (!bytes || bytes.length === 0 || bytes.length > 2 * 1024 * 1024) return null;
  // Quick leading-byte check for JSON object
  let first = 0;
  while (first < bytes.length && (bytes[first] === 0x20 || bytes[first] === 0x09 || bytes[first] === 0x0a || bytes[first] === 0x0d)) {
    first += 1;
  }
  if (bytes[first] !== 0x7b /* '{' */) return null;

  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;
  if (parsed.kind !== MANIFEST_KIND || parsed.version !== 1) return null;
  if (!parsed.files || typeof parsed.files !== "object") return null;

  const files = {};
  for (const [rawPath, entry] of Object.entries(parsed.files)) {
    const cleanPath = normalizeSitePath(rawPath);
    if (!entry || typeof entry !== "object" || !isValidCid(entry.cid)) {
      throw new Error(`manifest entry ${rawPath} has an invalid CID`);
    }
    files[cleanPath] = {
      cid: entry.cid,
      sha256: typeof entry.sha256 === "string" && /^[0-9a-f]{64}$/i.test(entry.sha256)
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

/** Resolves a requested site path against a manifest (handling `/` and directory `/foo` → `/foo/index.html`). */
export function resolveManifestEntry(manifest, rawPath) {
  const clean = normalizeSitePath(rawPath);
  if (clean === "/") {
    return manifest.files[manifest.index] ?? manifest.files["/index.html"] ?? null;
  }
  if (manifest.files[clean]) return manifest.files[clean];
  const withIndex = clean.endsWith("/") ? `${clean}index.html` : `${clean}/index.html`;
  if (manifest.files[withIndex]) return manifest.files[withIndex];
  return null;
}

/** Sniffs content type when a single-file CID is served directly (no manifest). */
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
 * Publishes either a single file or an entire directory to Logos Storage.
 * - Single file: uploads directly and returns `{ mode: "single", rootCid, sha256, size, contentType, files }`.
 * - Directory: uploads every file, builds a v1 site manifest, uploads the manifest, and returns
 *   `{ mode: "manifest", rootCid, sha256, size, manifest, files }`.
 */
export async function publishPath(storageClient, targetPath, { title = null, index = "/index.html" } = {}) {
  const info = await stat(targetPath);
  if (info.isFile()) {
    const bytes = await readFile(targetPath);
    const contentType = mimeForPath(targetPath);
    const filename = targetPath.split(/[\\/]/).pop() || "index.html";
    const uploaded = await storageClient.upload(bytes, { filename, contentType });
    return {
      mode: "single",
      rootCid: uploaded.cid,
      sha256: uploaded.sha256,
      size: uploaded.size,
      contentType,
      files: [{ path: `/${filename}`, cid: uploaded.cid, sha256: uploaded.sha256, size: uploaded.size, contentType }],
    };
  }

  if (!info.isDirectory()) {
    throw new Error(`target is neither a file nor a directory: ${targetPath}`);
  }

  const collected = [];
  await walkDir(targetPath, "", collected);
  if (collected.length === 0) throw new Error(`directory is empty: ${targetPath}`);

  const filesMap = {};
  const fileList = [];
  for (const relPath of collected.sort()) {
    const absPath = join(targetPath, relPath);
    const bytes = await readFile(absPath);
    const sitePath = normalizeSitePath("/" + relPath);
    const contentType = mimeForPath(sitePath);
    const filename = posix.basename(sitePath);
    const uploaded = await storageClient.upload(bytes, { filename, contentType });
    filesMap[sitePath] = {
      cid: uploaded.cid,
      sha256: uploaded.sha256,
      size: uploaded.size,
      contentType,
    };
    fileList.push({ path: sitePath, ...filesMap[sitePath] });
  }

  const resolvedIndex = filesMap[normalizeSitePath(index)]
    ? normalizeSitePath(index)
    : filesMap["/index.html"]
      ? "/index.html"
      : fileList[0].path;

  const manifest = {
    kind: MANIFEST_KIND,
    version: 1,
    ...(title ? { title } : {}),
    index: resolvedIndex,
    files: filesMap,
  };

  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf-8");
  const rootUploaded = await storageClient.upload(manifestBytes, {
    filename: "lns-site-manifest.json",
    contentType: MANIFEST_MIME,
  });

  return {
    mode: "manifest",
    rootCid: rootUploaded.cid,
    sha256: rootUploaded.sha256,
    size: rootUploaded.size,
    contentType: MANIFEST_MIME,
    manifest,
    files: fileList,
  };
}

/**
 * Publishes an in-memory map of `{ "/index.html": Buffer|string, ... }` (used by the browser UI's Publish drawer).
 */
export async function publishFiles(storageClient, entries, { title = null, index = "/index.html" } = {}) {
  const keys = Object.keys(entries);
  if (keys.length === 0) throw new Error("no files provided");

  if (keys.length === 1 && !title) {
    const sitePath = normalizeSitePath(keys[0]);
    const raw = entries[keys[0]];
    const bytes = typeof raw === "string" ? Buffer.from(raw, "utf-8") : Buffer.from(raw);
    const contentType = mimeForPath(sitePath);
    const uploaded = await storageClient.upload(bytes, {
      filename: posix.basename(sitePath) || "index.html",
      contentType,
    });
    return {
      mode: "single",
      rootCid: uploaded.cid,
      sha256: uploaded.sha256,
      size: uploaded.size,
      contentType,
      files: [{ path: sitePath, cid: uploaded.cid, sha256: uploaded.sha256, size: uploaded.size, contentType }],
    };
  }

  const filesMap = {};
  const fileList = [];
  for (const key of keys.sort()) {
    const sitePath = normalizeSitePath(key);
    const raw = entries[key];
    const bytes = typeof raw === "string" ? Buffer.from(raw, "utf-8") : Buffer.from(raw);
    const contentType = mimeForPath(sitePath);
    const uploaded = await storageClient.upload(bytes, {
      filename: posix.basename(sitePath) || "blob",
      contentType,
    });
    filesMap[sitePath] = {
      cid: uploaded.cid,
      sha256: uploaded.sha256,
      size: uploaded.size,
      contentType,
    };
    fileList.push({ path: sitePath, ...filesMap[sitePath] });
  }

  const resolvedIndex = filesMap[normalizeSitePath(index)]
    ? normalizeSitePath(index)
    : filesMap["/index.html"]
      ? "/index.html"
      : fileList[0].path;

  const manifest = {
    kind: MANIFEST_KIND,
    version: 1,
    ...(title ? { title } : {}),
    index: resolvedIndex,
    files: filesMap,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf-8");
  const rootUploaded = await storageClient.upload(manifestBytes, {
    filename: "lns-site-manifest.json",
    contentType: MANIFEST_MIME,
  });

  return {
    mode: "manifest",
    rootCid: rootUploaded.cid,
    sha256: rootUploaded.sha256,
    size: rootUploaded.size,
    contentType: MANIFEST_MIME,
    manifest,
    files: fileList,
  };
}

async function walkDir(rootDir, relPrefix, out) {
  const entries = await readdir(join(rootDir, relPrefix), { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".")) continue;
    const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      await walkDir(rootDir, rel, out);
    } else if (entry.isFile()) {
      out.push(rel);
    }
  }
}

/**
 * Injects a tiny navigation bridge into served HTML so clicking `lns://...`, `cid://...`,
 * or `https://...` links inside the sandboxed iframe notifies the parent browser shell via `postMessage`.
 * External `https://` links are never opened silently; the shell displays a click-to-confirm bar.
 */
export function injectLnsBridge(htmlBytes) {
  const html = new TextDecoder("utf-8", { fatal: false }).decode(htmlBytes);
  const bridge = `<script>(function(){document.addEventListener("click",function(e){var a=e.target&&e.target.closest?e.target.closest("a[href]"):null;if(!a)return;var h=a.getAttribute("href")||"";if(/^(lns|cid):\\/\\//i.test(h)){e.preventDefault();window.parent.postMessage({type:"lns-navigate",url:h},"*");}else if(/^https:\\/\\//i.test(h)){e.preventDefault();window.parent.postMessage({type:"lns-external-link",url:a.href||h},"*");}},true);})();</script>`;
  const closeBody = html.lastIndexOf("</body>");
  if (closeBody !== -1) {
    return Buffer.from(html.slice(0, closeBody) + bridge + html.slice(closeBody), "utf-8");
  }
  return Buffer.from(html + bridge, "utf-8");
}

/** Builds a `basecamp://intent/names.publish_site?p=<base64url>` deep link for Names. */
export function buildPublishDeepLink({ name = "", cid = "", sha256 = "", siteType = "", html = "", returnApp = "" } = {}) {
  const payload = {};
  const cleanName = String(name || "")
    .trim()
    .toLowerCase()
    .replace(/^lns:\/\//, "")
    .replace(/^@/, "")
    .split("/")[0]
    .replace(/\.lez$/, "");
  if (cleanName) payload.name = cleanName;
  if (cid) payload.cid = String(cid).trim();
  if (sha256) payload.sha256 = String(sha256).trim().toLowerCase();
  if (siteType) payload.site_type = String(siteType).trim();
  if (html) payload.html = String(html);
  if (returnApp) payload.return_app = String(returnApp).trim();
  const encoded = Buffer.from(JSON.stringify(payload), "utf-8").toString("base64url");
  return `basecamp://intent/names.publish_site?p=${encoded}`;
}

/** Builds the exact `names profile` CLI command to bind a published CID on-chain to an LNS name. */
export function buildNamesProfileCommand(name, { rootCid, sha256, mode }) {
  const cleanName = name || "<your-name>";
  const parts = ["names", "profile", cleanName, "--cid", rootCid];
  if (sha256) parts.push("--set", `cid.sha256=${sha256}`);
  if (mode) parts.push("--set", `cid.type=${mode}`);
  return parts.join(" ");
}
