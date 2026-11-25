// Per-folder `lns-links/1` helpers for `lns-gateway`, re-using the package-free parser
// and step resolver from `basecamp/qml/logic.mjs`.

import {
  cmpCodePoint,
  formatLinksList,
  isBinaryDownloadPath,
  isLinksContentType,
  isLinksListText,
  isValidSegmentName,
  LINKS_CONTENT_TYPE,
  LINKS_HEADER,
  MAX_LINKS_DEPTH,
  MAX_LINKS_ENTRIES,
  MAX_LINKS_LIST_BYTES,
  MAX_ONCHAIN_LINKS_BYTES,
  normalizePath,
  parseLinksList,
  parseUrl,
  resolveLinksSync,
  resolveRelativeSitePath,
  stepLinksResolve,
} from "../basecamp/qml/logic.mjs";

export {
  cmpCodePoint,
  formatLinksList,
  isBinaryDownloadPath,
  isLinksContentType,
  isLinksListText,
  isValidSegmentName,
  LINKS_CONTENT_TYPE,
  LINKS_HEADER,
  MAX_LINKS_DEPTH,
  MAX_LINKS_ENTRIES,
  MAX_LINKS_LIST_BYTES,
  MAX_ONCHAIN_LINKS_BYTES,
  normalizePath,
  parseLinksList,
  parseUrl,
  resolveLinksSync,
  resolveRelativeSitePath,
  stepLinksResolve,
};

export const DEFAULT_MAX_FOLDERS = 5000;

function unwrapFolderRecord(value) {
  if (!value || typeof value !== "object") return null;
  if (value.list && value.list.ok) {
    return {
      list: value.list,
      sha256: typeof value.sha256 === "string" && value.sha256 ? value.sha256.toLowerCase() : null,
      byteLength: Number.isInteger(value.byteLength) ? value.byteLength : null,
    };
  }
  if (value.ok) {
    return {
      list: value,
      sha256: typeof value.sha256 === "string" && value.sha256 ? value.sha256.toLowerCase() : null,
      byteLength: Number.isInteger(value.byteLength) ? value.byteLength : null,
    };
  }
  return null;
}

function checkCachedFolder(cache, cid, expectedSha256) {
  const raw = cache.get(cid);
  const rec = unwrapFolderRecord(raw);
  if (!rec) return { hit: false, mismatch: false, record: null };
  const exp = expectedSha256 ? String(expectedSha256).trim().toLowerCase() : null;
  if (exp) {
    if (!rec.sha256) {
      return { hit: false, mismatch: false, record: null };
    }
    if (rec.sha256 !== exp) {
      return {
        hit: false,
        mismatch: true,
        record: null,
        error: `SHA-256 mismatch for cached folder CID ${cid}: expected ${exp}, got ${rec.sha256}`,
      };
    }
  }
  return { hit: true, mismatch: false, record: rec };
}

/**
 * Async nested folder resolver over `lns-links/1` lists with SHA-256-aware CID caching.
 * `loadFolderList(cid, expectedSha256)` may return a parsed `LinksList` or `{ list, sha256 }` (or throw).
 */
export async function resolveLinksTree(rootList, rawPath, loadFolderList, cache = new Map()) {
  const norm = normalizePath(rawPath);
  if (!norm.ok) {
    return { ok: false, status: "invalid", error: norm.error };
  }
  let current = rootList;
  let idx = 0;
  let depth = 0;
  let foldersVerified = true;

  while (depth <= MAX_LINKS_DEPTH) {
    const step = stepLinksResolve(current, norm.segments, idx, norm.trailingSlash);
    if (step.action === "found") {
      return {
        ok: true,
        status: "found",
        entry: step.entry,
        resolvedPath: step.resolvedPath,
        canonicalUrlPath: step.canonicalUrlPath,
        canonicalDir: step.canonicalDir,
        folderEntries: step.folderEntries,
        folderTitle: step.folderTitle,
        fragment: norm.fragment,
        foldersVerified,
      };
    }
    if (step.action === "not_found") {
      return {
        ok: false,
        status: "not_found",
        requestedPath: step.requestedPath,
        isDirectory: Boolean(step.isDirectory),
        canonicalUrlPath: step.canonicalUrlPath || "",
        folderEntries: step.folderEntries || [],
        error: step.error,
      };
    }
    depth += 1;
    if (depth > MAX_LINKS_DEPTH) {
      return { ok: false, status: "error", error: `Folder nesting exceeds limit (${MAX_LINKS_DEPTH})` };
    }
    const expSha = step.sha256 ? String(step.sha256).trim().toLowerCase() : null;
    if (!expSha) {
      foldersVerified = false;
    }
    const cached = checkCachedFolder(cache, step.cid, expSha);
    if (cached.mismatch) {
      return { ok: false, status: "error", cid: step.cid, error: cached.error };
    }
    let nextRecord = cached.hit ? cached.record : null;
    if (!nextRecord) {
      const loaded = await loadFolderList(step.cid, expSha);
      const unwrapped = unwrapFolderRecord(loaded);
      if (!unwrapped) {
        return {
          ok: false,
          status: "error",
          cid: step.cid,
          error: loaded?.error || `Failed to load subfolder CID ${step.cid}`,
        };
      }
      if (expSha && unwrapped.sha256 && unwrapped.sha256 !== expSha) {
        return {
          ok: false,
          status: "error",
          cid: step.cid,
          error: `SHA-256 mismatch for subfolder CID ${step.cid}: expected ${expSha}, got ${unwrapped.sha256}`,
        };
      }
      nextRecord = {
        list: unwrapped.list,
        sha256: unwrapped.sha256 || expSha || null,
        byteLength: unwrapped.byteLength,
      };
      cache.set(step.cid, nextRecord);
    }
    current = nextRecord.list;
    idx = step.nextIndex;
  }

  return { ok: false, status: "error", error: `Folder nesting exceeds limit (${MAX_LINKS_DEPTH})` };
}

/**
 * Recursively walks an entire per-folder `lns-links/1` tree.
 * Enforces `maxFiles`, `maxFolders` (blocking exponential DAG bombs), `maxDepth`, and cycle detection.
 * Returns `{ files: Map<sitePath, entry>, folders: Map<dirPath, { path, cid, sha256, pinnedSha256, list }>, byCid: Map<cid, sitePath> }`.
 */
export async function walkLinksTree(
  rootList,
  loadFolderList,
  {
    rootCid = null,
    rootSha256 = null,
    maxFiles = 2000,
    maxFolders = DEFAULT_MAX_FOLDERS,
    maxDepth = MAX_LINKS_DEPTH,
    cache = new Map(),
  } = {},
) {
  const files = new Map();
  const folders = new Map();
  const byCid = new Map();

  async function visit(list, relSegments, folderCid, folderSha256, pinnedSha256, activeCids) {
    if (folders.size >= maxFolders) {
      throw new Error(`Site exceeds maximum of ${maxFolders} folders`);
    }
    const dirPath = relSegments.length === 0 ? "/" : "/" + relSegments.join("/");
    folders.set(dirPath, {
      path: dirPath,
      cid: folderCid || null,
      sha256: folderSha256 ? String(folderSha256).toLowerCase() : null,
      pinnedSha256: pinnedSha256 ? String(pinnedSha256).toLowerCase() : null,
      list,
    });

    for (const entry of list.entries) {
      if (entry.kind === "dir") {
        if (relSegments.length + 1 > maxDepth) {
          throw new Error(`Folder nesting exceeds limit (${maxDepth}) at ${dirPath}/${entry.name}`);
        }
        if (folders.size >= maxFolders) {
          throw new Error(`Site exceeds maximum of ${maxFolders} folders`);
        }
        if (activeCids.has(entry.cid)) {
          throw new Error(`Cycle detected in lns-links/1 folder tree at CID ${entry.cid}`);
        }
        const expSha = entry.sha256 ? String(entry.sha256).trim().toLowerCase() : null;
        const cached = checkCachedFolder(cache, entry.cid, expSha);
        if (cached.mismatch) {
          throw new Error(cached.error);
        }
        let childRecord = cached.hit ? cached.record : null;
        if (!childRecord) {
          const loaded = await loadFolderList(entry.cid, expSha);
          const unwrapped = unwrapFolderRecord(loaded);
          if (!unwrapped) {
            throw new Error(loaded?.error || `Invalid subfolder list at ${dirPath}/${entry.name}`);
          }
          if (expSha && unwrapped.sha256 && unwrapped.sha256 !== expSha) {
            throw new Error(
              `SHA-256 mismatch for subfolder CID ${entry.cid}: expected ${expSha}, got ${unwrapped.sha256}`,
            );
          }
          childRecord = {
            list: unwrapped.list,
            sha256: unwrapped.sha256 || expSha || null,
            byteLength: unwrapped.byteLength,
          };
          cache.set(entry.cid, childRecord);
        }
        const nextActive = new Set(activeCids);
        nextActive.add(entry.cid);
        await visit(
          childRecord.list,
          [...relSegments, entry.name],
          entry.cid,
          childRecord.sha256 || expSha || null,
          expSha,
          nextActive,
        );
      } else {
        if (files.size >= maxFiles) {
          throw new Error(`Site exceeds maximum of ${maxFiles} files`);
        }
        const sitePath = relSegments.length === 0 ? `/${entry.name}` : `/${relSegments.join("/")}/${entry.name}`;
        files.set(sitePath, {
          path: sitePath,
          name: entry.name,
          cid: entry.cid,
          sha256: entry.sha256 || null,
          dirPath,
        });
        if (!byCid.has(entry.cid)) {
          byCid.set(entry.cid, sitePath);
        }
      }
    }
  }

  const initialActive = new Set();
  if (rootCid) initialActive.add(rootCid);
  await visit(rootList, [], rootCid, rootSha256, rootSha256, initialActive);
  return { files, folders, byCid };
}
