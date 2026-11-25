#!/usr/bin/env node
// Static snapshot builder for LNS name websites.
// Reads names.json, resolves each LNS name on LEZ 0.4, fetches its on-chain page or
// Logos Storage CID bundle, verifies every SHA-256, sanitizes and rewrites HTML/CSS/SVG,
// and writes out/lns/<name>/... plus out/lns/index.json only when content changed.

import { mkdir, readdir, readFile, rm, rmdir, writeFile } from "node:fs/promises";
import { dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { isValidName, normalizeName } from "../basecamp/qml/logic.mjs";
import {
  assertSupportedNode,
  checkNodeVersion,
  DEFAULT_CONFIG,
  MIN_NODE_MAJOR,
  normalizeSitePath,
  resolveName,
  resolveOnChainPage,
  sha256Hex,
} from "./derive.mjs";
import {
  isLinksContentType,
  isLinksListText,
  MAX_ONCHAIN_LINKS_BYTES,
  parseLinksList,
  walkLinksTree,
} from "./links.mjs";
import {
  extensionForMime,
  mimeForPath,
  sniffContentType,
  StorageClient,
  tryParseManifest,
} from "./storage.mjs";
import {
  buildNotFoundHtml,
  escapeHtml,
  extractCidReferences,
  sanitizeCss,
  sanitizeHtml,
  sanitizeSvg,
} from "./sanitize.mjs";

export { assertSupportedNode, checkNodeVersion, MIN_NODE_MAJOR };

const __dirname = dirname(fileURLToPath(import.meta.url));
export const DEFAULT_NAMES_FILE = join(__dirname, "names.json");
export const DEFAULT_OUT_DIR = join(__dirname, "out");
export const DEFAULT_MAX_SITE_FILES = 2000;
export const DEFAULT_MAX_SITE_BYTES = 200 * 1024 * 1024;
export const MAX_SITE_FILES = DEFAULT_MAX_SITE_FILES;
export const MAX_SITE_BYTES = DEFAULT_MAX_SITE_BYTES;
export const MAX_ONCHAIN_PAGE_BYTES = 80 * 1024;

export function parseNamesList(raw) {
  const list = Array.isArray(raw) ? raw : Array.isArray(raw?.names) ? raw.names : null;
  if (!list) {
    throw new Error("names.json must be a JSON array of bare LNS names (or { names: [...] })");
  }
  const seen = new Set();
  const names = [];
  for (const item of list) {
    if (typeof item !== "string") {
      throw new Error(`invalid LNS name in list: ${JSON.stringify(item)}`);
    }
    const stripped = item.trim().replace(/^lns:\/\//i, "").replace(/^lns:/i, "").replace(/^@/, "");
    if (!stripped || /[/?#\s]/.test(stripped)) {
      throw new Error(`invalid LNS name in list: ${JSON.stringify(item)}`);
    }
    const clean = normalizeName(item);
    if (!isValidName(clean)) {
      throw new Error(`invalid LNS name in list: ${JSON.stringify(item)}`);
    }
    if (!seen.has(clean)) {
      seen.add(clean);
      names.push(clean);
    }
  }
  return names;
}

function parsePositiveInt(val, fallback) {
  if (val === undefined || val === null || val === "") return fallback;
  const n = Number.parseInt(String(val), 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

const REFUSED_ACTIVE_EXTENSIONS = new Set([
  ".xhtml",
  ".xht",
  ".xml",
  ".xsl",
  ".xslt",
  ".shtml",
  ".svgz",
  ".mhtml",
  ".mht",
]);

const REFUSED_ACTIVE_MIMES = new Set([
  "application/xhtml+xml",
  "application/xml",
  "text/xml",
  "application/xslt+xml",
  "text/xsl",
]);

function assertAllowedAsset(name, sitePath, contentType) {
  const ext = extname(String(sitePath || "")).toLowerCase();
  const bareCt = String(contentType || "").split(";")[0].trim().toLowerCase();
  if (REFUSED_ACTIVE_EXTENSIONS.has(ext) || REFUSED_ACTIVE_MIMES.has(bareCt)) {
    throw new Error(
      `Refused "${name}": active XML/compressed-SVG asset "${sitePath}" (${bareCt || ext}) is not allowed on the static gateway`,
    );
  }
}

function assetKind(contentType, sitePath) {
  const ct = String(contentType || "").toLowerCase();
  if (ct.startsWith("text/html") || /\.html?$/i.test(sitePath)) return "html";
  if (ct.startsWith("text/css") || /\.css$/i.test(sitePath)) return "css";
  if (ct.startsWith("image/svg+xml") || /\.svg$/i.test(sitePath)) return "svg";
  return "binary";
}

function safeExtFromHint(hintFilename, sniffedMime) {
  const rawExt = hintFilename ? extname(String(hintFilename).trim()).toLowerCase() : "";
  if (/^\.[a-z0-9]{1,10}$/.test(rawExt) && !REFUSED_ACTIVE_EXTENSIONS.has(rawExt)) return rawExt;
  return extensionForMime(sniffedMime);
}

function processAssetBytes(bytes, contentType, sitePath, meta) {
  assertAllowedAsset(meta.name, sitePath, contentType);
  const kind = assetKind(contentType, sitePath);
  if (kind === "html") {
    const html = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return Buffer.from(sanitizeHtml(html, { ...meta, sitePath }), "utf-8");
  }
  if (kind === "css") {
    const css = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return Buffer.from(
      sanitizeCss(css, meta.name, { resolveCidUrl: meta.resolveCidUrl, sitePath }),
      "utf-8",
    );
  }
  if (kind === "svg") {
    const svg = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return Buffer.from(
      sanitizeSvg(svg, meta.name, { resolveCidUrl: meta.resolveCidUrl, sitePath }),
      "utf-8",
    );
  }
  return Buffer.from(bytes);
}

/**
 * Materializes any `cid://<cid>` references found in HTML/CSS/SVG assets:
 * - If the CID is already listed in the site (`cidToSitePath`), rewrites directly to that site path.
 * - Otherwise downloads the CID from Storage and writes it under `/_cid/<cid><ext>`,
 *   and marks pages referencing unlisted (unhashed) CIDs as unverified.
 */
async function materializeAndSanitizeAssets(
  rawAssets,
  cidToSitePath,
  {
    name,
    hash,
    source,
    storage,
    maxSiteFiles,
    maxSiteBytes,
    totalBytes = 0,
    singlePage = false,
    allEntriesVerified = true,
  },
) {
  let bytesUsed = totalBytes;
  const referenced = new Map();
  const refsBySitePath = new Map();

  for (const [sitePath, item] of rawAssets.entries()) {
    assertAllowedAsset(name, sitePath, item.contentType);
    const kind = assetKind(item.contentType, sitePath);
    if (kind === "binary") continue;
    const text = new TextDecoder("utf-8", { fatal: false }).decode(item.bytes);
    const extracted = extractCidReferences(text, kind);
    const pathCids = new Set();
    for (const ref of extracted) {
      pathCids.add(ref.cid);
      if (!referenced.has(ref.cid) || (!referenced.get(ref.cid).hintFilename && ref.hintFilename)) {
        referenced.set(ref.cid, ref);
      }
    }
    if (pathCids.size > 0) refsBySitePath.set(sitePath, pathCids);
  }

  const unlistedCids = new Set();
  for (const { cid, hintFilename } of referenced.values()) {
    if (cidToSitePath.has(cid)) continue;
    if (!storage || !storage.configured) {
      throw new Error(`Refused "${name}": cid://${cid} asset requires LOGOS_STORAGE_API`);
    }
    if (rawAssets.size >= maxSiteFiles) {
      throw new Error(`Refused "${name}": site exceeds ${maxSiteFiles} files (while materializing cid://${cid})`);
    }
    const remaining = maxSiteBytes - bytesUsed;
    if (remaining <= 0) {
      throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
    }
    const blob = await storage.download(cid, { maxBytes: remaining });
    bytesUsed += blob.bytes.length;
    if (bytesUsed > maxSiteBytes) {
      throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
    }
    const sniffed = sniffContentType(blob.bytes, blob.contentType);
    const ext = safeExtFromHint(hintFilename, sniffed);
    const sitePath = `/_cid/${cid}${ext}`;
    assertAllowedAsset(name, sitePath, sniffed);
    cidToSitePath.set(cid, sitePath);
    unlistedCids.add(cid);
    rawAssets.set(sitePath, { bytes: blob.bytes, contentType: sniffed });
  }

  const resolveCidUrl = (cid) => {
    const mapped = cidToSitePath.get(cid);
    return mapped ? `/lns/${name}${mapped}` : null;
  };

  const files = new Map();
  for (const [sitePath, item] of rawAssets.entries()) {
    const pageRefs = refsBySitePath.get(sitePath);
    let pageUsesUnlisted = false;
    if (pageRefs) {
      for (const c of pageRefs) {
        if (unlistedCids.has(c)) {
          pageUsesUnlisted = true;
          break;
        }
      }
    }
    const processed = processAssetBytes(item.bytes, item.contentType, sitePath, {
      name,
      hash,
      source,
      resolveCidUrl,
      verified: allEntriesVerified && !pageUsesUnlisted,
    });
    files.set(sitePath, processed);
  }

  if (!files.has("/404.html")) {
    files.set("/404.html", Buffer.from(buildNotFoundHtml({ name, singlePage }), "utf-8"));
  }

  return files;
}

async function fetchLinksSite({
  name,
  rootList,
  rootCid,
  rootSha256,
  rootBytesLen = 0,
  source,
  storage,
  maxSiteFiles,
  maxSiteBytes,
  allowUnverified = false,
}) {
  if (!storage || !storage.configured) {
    throw new Error(`Refused "${name}": LOGOS_STORAGE_API is not set`);
  }

  let totalBytes = rootBytesLen;
  if (totalBytes > maxSiteBytes) {
    throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
  }
  let allEntriesVerified = true;

  const loadFolderList = async (cid, expectedSha256) => {
    if (!expectedSha256) {
      if (!allowUnverified) {
        throw new Error(`Refused "${name}": lns-links/1 subfolder CID ${cid} is missing sha256`);
      }
      allEntriesVerified = false;
    }
    const remaining = maxSiteBytes - totalBytes;
    if (remaining <= 0) {
      throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
    }
    const blob = await storage.download(cid, {
      expectedSha256: expectedSha256 || null,
      maxBytes: Math.min(remaining, 2 * 1024 * 1024),
    });
    if (expectedSha256 && (!blob.verified || blob.sha256 !== expectedSha256.toLowerCase())) {
      throw new Error(`Refused "${name}": SHA-256 verification failed for folder CID ${cid}`);
    }
    totalBytes += blob.bytes.length;
    if (totalBytes > maxSiteBytes) {
      throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(blob.bytes);
    const parsed = parseLinksList(text);
    if (!parsed.ok) {
      throw new Error(`Refused "${name}": invalid lns-links/1 subfolder (${cid}): ${parsed.error}`);
    }
    return { list: parsed, sha256: blob.sha256, byteLength: blob.bytes.length };
  };

  const tree = await walkLinksTree(rootList, loadFolderList, {
    rootCid,
    rootSha256,
    maxFiles: maxSiteFiles,
    maxFolders: Math.max(maxSiteFiles * 2, 5000),
  });
  if (tree.files.size === 0) {
    throw new Error(`Refused "${name}": lns-links/1 tree contains no files`);
  }

  const rawAssets = new Map();
  const cidToSitePath = new Map(tree.byCid);

  for (const [sitePath, entry] of tree.files.entries()) {
    const contentType = mimeForPath(sitePath);
    assertAllowedAsset(name, sitePath, contentType);
    if (!entry.sha256) {
      if (!allowUnverified) {
        throw new Error(`Refused "${name}": lns-links/1 entry "${sitePath}" is missing sha256`);
      }
      allEntriesVerified = false;
    }
    const remaining = maxSiteBytes - totalBytes;
    if (remaining <= 0) {
      throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
    }
    const asset = await storage.download(entry.cid, {
      expectedSha256: entry.sha256 || null,
      maxBytes: remaining,
    });
    if (entry.sha256 && (!asset.verified || asset.sha256 !== entry.sha256.toLowerCase())) {
      throw new Error(`Refused "${name}": SHA-256 verification failed for "${sitePath}"`);
    }
    totalBytes += asset.bytes.length;
    if (totalBytes > maxSiteBytes) {
      throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
    }
    rawAssets.set(sitePath, { bytes: asset.bytes, contentType });
  }

  // If any folder declares a non-default `# index <name>` (e.g. home.html) and has no `index.html`,
  // also alias it to `<dir>/index.html` for static HTTP serving (counting against maxSiteFiles).
  for (const [dirPath, folderInfo] of tree.folders.entries()) {
    const idxName = folderInfo.list.index || "index.html";
    if (idxName !== "index.html") {
      const prefix = dirPath === "/" ? "" : dirPath;
      const customPath = `${prefix}/${idxName}`;
      const defaultPath = `${prefix}/index.html`;
      if (rawAssets.has(customPath) && !rawAssets.has(defaultPath)) {
        if (rawAssets.size >= maxSiteFiles) {
          throw new Error(
            `Refused "${name}": site exceeds maximum of ${maxSiteFiles} files (including index alias ${defaultPath})`,
          );
        }
        rawAssets.set(defaultPath, rawAssets.get(customPath));
      }
    }
  }

  const files = await materializeAndSanitizeAssets(rawAssets, cidToSitePath, {
    name,
    hash: rootSha256,
    source,
    storage,
    maxSiteFiles,
    maxSiteBytes,
    totalBytes,
    singlePage: false,
    allEntriesVerified,
  });

  return {
    name,
    source,
    hash: rootSha256,
    cid: rootCid,
    files,
  };
}

function wrapPlainTextAsHtml(name, text) {
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>lns://${escapeHtml(name)}</title>` +
    `<style>body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:24px;background:#fff;color:#111}pre{white-space:pre-wrap;word-break:break-word}</style>` +
    `</head><body><pre>${escapeHtml(text)}</pre></body></html>`
  );
}

/**
 * Resolves one LNS name, downloads its on-chain page or CID bundle, verifies every SHA-256,
 * and returns `{ name, source, hash, cid, files }` (Map<sitePath, Buffer>) without writing to disk.
 * Refuses anything whose hash is missing or does not match.
 */
export async function fetchAndVerifySite(
  rawName,
  {
    sequencer,
    registry,
    storage,
    fetchImpl = fetch,
    now = Date.now(),
    maxSiteFiles = DEFAULT_MAX_SITE_FILES,
    maxSiteBytes = DEFAULT_MAX_SITE_BYTES,
    allowUnverified = false,
  },
) {
  const name = normalizeName(rawName);
  if (!isValidName(name)) {
    throw new Error(`invalid LNS name: ${rawName}`);
  }

  const record = await resolveName(sequencer, registry, name, { now, fetchImpl });
  if (!record) {
    throw new Error(`LNS name "${name}" is not registered`);
  }

  if (record.cid) {
    if (!record.cidSha256) {
      throw new Error(`Refused "${name}": CID ${record.cid} has no on-chain cid.sha256`);
    }
    if (!storage || !storage.configured) {
      throw new Error(`Refused "${name}": LOGOS_STORAGE_API is not set`);
    }

    const rootMaxBytes =
      record.cidType === "links" || record.cidType === "manifest"
        ? Math.min(maxSiteBytes, 2 * 1024 * 1024)
        : maxSiteBytes;
    const rootBlob = await storage.download(record.cid, {
      expectedSha256: record.cidSha256,
      maxBytes: rootMaxBytes,
    });
    if (!rootBlob.verified || rootBlob.sha256 !== record.cidSha256.toLowerCase()) {
      throw new Error(`Refused "${name}": root CID SHA-256 verification failed`);
    }

    // 1. Per-folder `lns-links/1` root list
    const rootText = new TextDecoder("utf-8", { fatal: false }).decode(rootBlob.bytes);
    if (record.cidType === "links" || isLinksListText(rootText)) {
      const parsedRoot = parseLinksList(rootText);
      if (!parsedRoot.ok) {
        throw new Error(`Refused "${name}": invalid lns-links/1 root list: ${parsedRoot.error}`);
      }
      return fetchLinksSite({
        name,
        rootList: parsedRoot,
        rootCid: record.cid,
        rootSha256: rootBlob.sha256,
        rootBytesLen: rootBlob.bytes.length,
        source: "cid",
        storage,
        maxSiteFiles,
        maxSiteBytes,
        allowUnverified,
      });
    }

    // 2. Legacy v1 JSON `lns-site-manifest`
    const manifest = tryParseManifest(rootBlob.bytes);
    if (manifest) {
      const entries = Object.entries(manifest.files);
      if (entries.length === 0) {
        throw new Error(`Refused "${name}": site manifest contains no files`);
      }
      if (entries.length > maxSiteFiles) {
        throw new Error(`Refused "${name}": site manifest exceeds ${maxSiteFiles} files`);
      }

      const rawAssets = new Map();
      const cidToSitePath = new Map();
      let totalBytes = rootBlob.bytes.length;
      for (const [rawPath, entry] of entries) {
        const sitePath = normalizeSitePath(rawPath);
        if (sitePath === "/") {
          throw new Error(`Refused "${name}": invalid file path "${rawPath}" in manifest`);
        }
        const contentType = entry.contentType || mimeForPath(sitePath);
        assertAllowedAsset(name, sitePath, contentType);
        if (!entry.sha256) {
          throw new Error(`Refused "${name}": manifest entry "${sitePath}" is missing sha256`);
        }
        const remaining = maxSiteBytes - totalBytes;
        if (remaining <= 0) {
          throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
        }
        const asset = await storage.download(entry.cid, {
          expectedSha256: entry.sha256,
          expectedSize: entry.size,
          maxBytes: remaining,
        });
        if (!asset.verified || asset.sha256 !== entry.sha256.toLowerCase()) {
          throw new Error(`Refused "${name}": SHA-256 verification failed for "${sitePath}"`);
        }
        totalBytes += asset.bytes.length;
        if (totalBytes > maxSiteBytes) {
          throw new Error(`Refused "${name}": site bundle exceeds ${maxSiteBytes} bytes`);
        }
        rawAssets.set(sitePath, { bytes: asset.bytes, contentType });
        if (!cidToSitePath.has(entry.cid)) cidToSitePath.set(entry.cid, sitePath);
      }

      if (!rawAssets.has("/index.html") && manifest.index && rawAssets.has(manifest.index)) {
        if (rawAssets.size >= maxSiteFiles) {
          throw new Error(`Refused "${name}": site exceeds maximum of ${maxSiteFiles} files`);
        }
        rawAssets.set("/index.html", rawAssets.get(manifest.index));
      }

      const files = await materializeAndSanitizeAssets(rawAssets, cidToSitePath, {
        name,
        hash: rootBlob.sha256,
        source: "cid",
        storage,
        maxSiteFiles,
        maxSiteBytes,
        totalBytes,
        singlePage: false,
      });

      return {
        name,
        source: "cid",
        hash: rootBlob.sha256,
        cid: record.cid,
        files,
      };
    }

    if (record.cidType === "manifest") {
      throw new Error(`Refused "${name}": cid.type is "manifest" but root CID is not a valid manifest`);
    }

    // 3. Single-file CID
    const contentType = sniffContentType(rootBlob.bytes, rootBlob.contentType).toLowerCase();
    let htmlSource;
    if (contentType.startsWith("text/html")) {
      htmlSource = rootText;
    } else if (contentType.startsWith("text/plain")) {
      htmlSource = wrapPlainTextAsHtml(name, rootText);
    } else {
      throw new Error(`Refused "${name}": unsupported single-file CID content type "${contentType}"`);
    }

    const rawAssets = new Map([["/index.html", { bytes: Buffer.from(htmlSource, "utf-8"), contentType: "text/html" }]]);
    const files = await materializeAndSanitizeAssets(rawAssets, new Map(), {
      name,
      hash: rootBlob.sha256,
      source: "cid",
      storage,
      maxSiteFiles,
      maxSiteBytes,
      totalBytes: rootBlob.bytes.length,
      singlePage: true,
    });
    return {
      name,
      source: "cid",
      hash: rootBlob.sha256,
      cid: record.cid,
      files,
    };
  }

  // Fallback: on-chain page (SetPage)
  const page = await resolveOnChainPage(sequencer, registry, name, { now, fetchImpl });
  if (!page || !page.body || page.body.length === 0) {
    throw new Error(`LNS name "${name}" has no CID or on-chain page`);
  }
  if (page.body.length > MAX_ONCHAIN_PAGE_BYTES) {
    throw new Error(`Refused "${name}": on-chain page exceeds ${MAX_ONCHAIN_PAGE_BYTES} bytes`);
  }

  const hash = sha256Hex(page.body);
  const ct = String(page.contentType || "text/html").toLowerCase();
  const decodedBody = new TextDecoder("utf-8", { fatal: false }).decode(page.body);

  // Tiny site with on-chain `lns-links/1` root list (< 10 KB)
  if (isLinksContentType(ct) || isLinksListText(decodedBody)) {
    if (page.body.length >= MAX_ONCHAIN_LINKS_BYTES) {
      throw new Error(
        `Refused "${name}": on-chain lns-links/1 root list (${page.body.length} bytes) must be under ${MAX_ONCHAIN_LINKS_BYTES} bytes`,
      );
    }
    const parsedRoot = parseLinksList(decodedBody);
    if (!parsedRoot.ok) {
      throw new Error(`Refused "${name}": invalid on-chain lns-links/1 list: ${parsedRoot.error}`);
    }
    return fetchLinksSite({
      name,
      rootList: parsedRoot,
      rootCid: null,
      rootSha256: hash,
      rootBytesLen: page.body.length,
      source: "chain",
      storage,
      maxSiteFiles,
      maxSiteBytes,
      allowUnverified,
    });
  }

  let htmlSource;
  if (ct.startsWith("text/html")) {
    htmlSource = decodedBody;
  } else if (ct.startsWith("text/plain")) {
    htmlSource = wrapPlainTextAsHtml(name, decodedBody);
  } else {
    throw new Error(`Refused "${name}": unsupported on-chain page content type "${page.contentType}"`);
  }

  const finalHtml = Buffer.from(sanitizeHtml(htmlSource, { name, hash, source: "chain" }), "utf-8");
  const notFoundHtml = Buffer.from(buildNotFoundHtml({ name, singlePage: true }), "utf-8");
  return {
    name,
    source: "chain",
    hash,
    cid: null,
    files: new Map([
      ["/index.html", finalHtml],
      ["/404.html", notFoundHtml],
    ]),
  };
}

async function writeIfChanged(filePath, newBytes) {
  const buf = Buffer.isBuffer(newBytes) ? newBytes : Buffer.from(newBytes);
  try {
    const existing = await readFile(filePath);
    if (existing.equals(buf)) {
      return false;
    }
  } catch (err) {
    if (err.code !== "ENOENT") throw err;
  }
  await mkdir(dirname(filePath), { recursive: true });
  await writeFile(filePath, buf);
  return true;
}

async function listFilesRecursive(dir, relPrefix = "", out = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") return out;
    throw err;
  }
  for (const entry of entries) {
    const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await listFilesRecursive(full, rel, out);
    } else if (entry.isFile()) {
      out.push(rel);
    }
  }
  return out;
}

async function pruneEmptyDirs(dir, isRoot = true) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (err) {
    if (err.code === "ENOENT") return;
    throw err;
  }
  for (const entry of entries) {
    if (entry.isDirectory()) {
      await pruneEmptyDirs(join(dir, entry.name), false);
    }
  }
  if (!isRoot) {
    const remaining = await readdir(dir);
    if (remaining.length === 0) {
      await rmdir(dir);
    }
  }
}

async function syncSiteDirectory(siteDir, filesMap) {
  const absRoot = resolve(siteDir);
  const expectedRel = new Set();
  let written = 0;
  let unchanged = 0;
  let removed = 0;

  for (const [sitePath, bytes] of filesMap.entries()) {
    const rel = sitePath.replace(/^\/+/, "");
    const target = resolve(absRoot, rel);
    if (target !== absRoot && !target.startsWith(absRoot + sep)) {
      throw new Error(`path escapes site directory: ${sitePath}`);
    }
    expectedRel.add(rel);
    const didWrite = await writeIfChanged(target, bytes);
    if (didWrite) written += 1;
    else unchanged += 1;
  }

  const existingFiles = await listFilesRecursive(absRoot);
  for (const rel of existingFiles) {
    if (!expectedRel.has(rel)) {
      await rm(join(absRoot, rel), { force: true });
      removed += 1;
    }
  }
  if (removed > 0) {
    await pruneEmptyDirs(absRoot, true);
  }

  return { written, unchanged, removed };
}

async function readExistingIndex(indexPath) {
  const map = new Map();
  try {
    const raw = await readFile(indexPath, "utf-8");
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      for (const item of parsed) {
        if (item && typeof item.name === "string") {
          map.set(item.name, item);
        }
      }
    }
  } catch (err) {
    if (err.code !== "ENOENT") {
      // Ignore malformed previous index and rebuild cleanly
    }
  }
  return map;
}

/**
 * Runs a full snapshot pass for all configured LNS names.
 * Writes only files whose bytes changed (and preserves unchanged timestamps in index.json).
 */
export async function runSnapshot({
  names = null,
  namesFile = DEFAULT_NAMES_FILE,
  outDir = DEFAULT_OUT_DIR,
  sequencer = process.env.LNS_SEQUENCER_URL || DEFAULT_CONFIG.sequencer,
  registry = process.env.LNS_REGISTRY || DEFAULT_CONFIG.registry,
  storageApi = process.env.LOGOS_STORAGE_API ?? DEFAULT_CONFIG.storageApi,
  maxSiteFiles = parsePositiveInt(process.env.LNS_MAX_SITE_FILES, DEFAULT_MAX_SITE_FILES),
  maxSiteBytes = parsePositiveInt(process.env.LNS_MAX_SITE_BYTES, DEFAULT_MAX_SITE_BYTES),
  allowUnverified = false,
  fetchImpl = fetch,
  now = () => Date.now(),
  nodeVersion = process.versions.node,
  cryptoMod = undefined,
} = {}) {
  if (cryptoMod === undefined) {
    assertSupportedNode(nodeVersion);
  } else {
    assertSupportedNode(nodeVersion, cryptoMod);
  }

  const nameList =
    names !== null
      ? parseNamesList(names)
      : parseNamesList(JSON.parse(await readFile(namesFile, "utf-8")));

  const storage = new StorageClient(storageApi, { fetchImpl });
  const lnsRoot = join(outDir, "lns");
  const indexPath = join(lnsRoot, "index.json");
  const existingIndex = await readExistingIndex(indexPath);

  const sites = [];
  const errors = [];
  const nextIndexEntries = [];
  let totalWritten = 0;
  let totalUnchanged = 0;
  let totalRemoved = 0;

  for (const name of nameList) {
    const nowMs = typeof now === "function" ? now() : now;
    try {
      const site = await fetchAndVerifySite(name, {
        sequencer,
        registry,
        storage,
        fetchImpl,
        now: nowMs,
        maxSiteFiles,
        maxSiteBytes,
        allowUnverified,
      });
      const sync = await syncSiteDirectory(join(lnsRoot, name), site.files);
      totalWritten += sync.written;
      totalUnchanged += sync.unchanged;
      totalRemoved += sync.removed;

      const prev = existingIndex.get(name);
      const changed =
        !prev ||
        prev.source !== site.source ||
        prev.hash !== site.hash ||
        sync.written > 0 ||
        sync.removed > 0;
      const time = !changed && typeof prev.time === "string" ? prev.time : new Date(nowMs).toISOString();

      nextIndexEntries.push({
        name: site.name,
        source: site.source,
        hash: site.hash,
        time,
      });
      sites.push({
        name: site.name,
        ok: true,
        source: site.source,
        hash: site.hash,
        written: sync.written,
        unchanged: sync.unchanged,
        removed: sync.removed,
      });
    } catch (err) {
      errors.push({ name, error: err.message });
      sites.push({ name, ok: false, error: err.message });
      const prev = existingIndex.get(name);
      if (prev) {
        nextIndexEntries.push(prev);
      }
    }
  }

  nextIndexEntries.sort((a, b) => a.name.localeCompare(b.name));

  let indexWritten = false;
  if (nextIndexEntries.length > 0 || existingIndex.size > 0) {
    const indexBytes = Buffer.from(JSON.stringify(nextIndexEntries, null, 2) + "\n", "utf-8");
    indexWritten = await writeIfChanged(indexPath, indexBytes);
  }

  return {
    sites,
    errors,
    index: nextIndexEntries,
    filesWritten: totalWritten + (indexWritten ? 1 : 0),
    filesUnchanged: totalUnchanged,
    filesRemoved: totalRemoved,
    indexWritten,
  };
}

function parseCliArgs(argv) {
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (key === "help" || key === "allow-unverified") {
        flags[key] = true;
      } else if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

async function main() {
  assertSupportedNode();
  const flags = parseCliArgs(process.argv.slice(2));
  if (flags.help) {
    console.log(
      "Usage: node snapshot.mjs [--names names.json] [--out out] [--sequencer URL] [--registry ID] [--storage URL] [--max-site-files N] [--max-site-bytes BYTES]",
    );
    return;
  }

  const strFlag = (val) => (typeof val === "string" ? val : undefined);
  const result = await runSnapshot({
    namesFile: strFlag(flags.names) || process.env.LNS_NAMES_FILE || DEFAULT_NAMES_FILE,
    outDir: strFlag(flags.out) || process.env.LNS_OUT_DIR || DEFAULT_OUT_DIR,
    sequencer: strFlag(flags.sequencer) || process.env.LNS_SEQUENCER_URL || DEFAULT_CONFIG.sequencer,
    registry: strFlag(flags.registry) || process.env.LNS_REGISTRY || DEFAULT_CONFIG.registry,
    storageApi: strFlag(flags.storage) ?? process.env.LOGOS_STORAGE_API ?? DEFAULT_CONFIG.storageApi,
    maxSiteFiles: parsePositiveInt(strFlag(flags["max-site-files"]) ?? process.env.LNS_MAX_SITE_FILES, DEFAULT_MAX_SITE_FILES),
    maxSiteBytes: parsePositiveInt(strFlag(flags["max-site-bytes"]) ?? process.env.LNS_MAX_SITE_BYTES, DEFAULT_MAX_SITE_BYTES),
    allowUnverified: Boolean(flags["allow-unverified"]),
  });

  for (const s of result.sites) {
    if (s.ok) {
      console.log(`ok   lns://${s.name} (${s.source}, ${s.hash.slice(0, 12)}, written=${s.written}, unchanged=${s.unchanged})`);
    } else {
      console.error(`fail lns://${s.name}: ${s.error}`);
    }
  }
  console.log(`done: written=${result.filesWritten}, unchanged=${result.filesUnchanged}, errors=${result.errors.length}`);

  if (result.errors.length > 0) {
    process.exitCode = 1;
  }
}

const isMain = Boolean(process.argv[1]) && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
