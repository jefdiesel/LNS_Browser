#!/usr/bin/env node
// Incremental per-folder `lns-links/1` publisher (`lns publish <folder> <name>`).
// Builds per-folder `lns-links/1` lists bottom-up, diffs against the current root tree on chain
// (or `--prev-root`), uploads only new/changed files and their ancestor folder lists to Logos
// Storage (using bare MIME types with automatic `application/octet-stream` fallback), and prints
// the exact `names profile` (or `< 10 KB` `names set-page`) command.
// Zero npm dependencies, Node 24+.

import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildPublishDeepLink } from "../basecamp/qml/logic.mjs";
import {
  assertSupportedNode,
  DEFAULT_CONFIG,
  isValidCid,
  isValidName,
  normalizeName,
  resolveName,
  resolveOnChainPage,
  sha256Hex,
} from "./derive.mjs";
import {
  cmpCodePoint,
  formatLinksList,
  isLinksContentType,
  isLinksListText,
  isValidSegmentName,
  LINKS_CONTENT_TYPE,
  MAX_ONCHAIN_LINKS_BYTES,
  parseLinksList,
  walkLinksTree,
} from "./links.mjs";
import { mimeForPath, StorageClient } from "./storage.mjs";

/**
 * Recursively scans a local directory into a sorted tree of `{ relPath, files, dirs }`.
 * Skips dotfiles/hidden entries (starting with `.`) and empty subdirectories.
 * Explicitly rejects symlinks and special filesystem entries so partial trees are never silently published.
 */
async function scanLocalTree(rootDir, relPath = "") {
  const absDir = relPath ? join(rootDir, relPath) : rootDir;
  const dirEntries = await readdir(absDir, { withFileTypes: true });
  dirEntries.sort((a, b) => cmpCodePoint(a.name, b.name));

  const files = [];
  const dirs = new Map();

  for (const entry of dirEntries) {
    if (entry.name.startsWith(".")) continue;
    if (!isValidSegmentName(entry.name)) {
      throw new Error(`Invalid file/folder name for lns-links/1: ${JSON.stringify(entry.name)}`);
    }
    const childRel = relPath ? `${relPath}/${entry.name}` : entry.name;
    const childAbs = join(absDir, entry.name);

    if (entry.isSymbolicLink()) {
      throw new Error(
        `Refused to publish symlink ${JSON.stringify(childRel)} (replace with a regular file or directory)`,
      );
    } else if (entry.isDirectory()) {
      const sub = await scanLocalTree(rootDir, childRel);
      if (sub.files.length > 0 || sub.dirs.size > 0) {
        dirs.set(entry.name, sub);
      }
    } else if (entry.isFile()) {
      const bytes = await readFile(childAbs);
      const sitePath = "/" + childRel;
      files.push({
        name: entry.name,
        relPath: childRel,
        sitePath,
        bytes,
        size: bytes.length,
        sha256: sha256Hex(bytes),
        contentType: mimeForPath(entry.name),
      });
    } else {
      throw new Error(`Unsupported filesystem entry in publish folder: ${JSON.stringify(childRel)}`);
    }
  }

  return { relPath, files, dirs };
}

/**
 * Loads the previous `lns-links/1` folder tree (only folder lists — never file blobs)
 * so unchanged files and subtrees can be reused without re-uploading.
 */
async function loadPreviousTree({
  name,
  storage,
  sequencer,
  registry,
  fetchImpl,
  prevRootCid,
  prevRootSha256,
  now,
}) {
  let rootList = null;
  let rootCid = null;
  let rootSha256 = null;

  const loadFolderList = async (cid, expectedSha256) => {
    const blob = await storage.download(cid, {
      expectedSha256: expectedSha256 || null,
      maxBytes: 2 * 1024 * 1024,
    });
    const text = new TextDecoder("utf-8", { fatal: true }).decode(blob.bytes);
    const parsed = parseLinksList(text);
    if (!parsed.ok) {
      throw new Error(`Invalid previous lns-links/1 folder list (${cid}): ${parsed.error}`);
    }
    return { list: parsed, sha256: blob.sha256, byteLength: blob.bytes.length };
  };

  if (prevRootCid) {
    if (!isValidCid(prevRootCid)) {
      throw new Error(`Invalid --prev-root CID: ${prevRootCid}`);
    }
    if (!storage || !storage.configured) {
      return new Map();
    }
    const blob = await storage.download(prevRootCid, {
      expectedSha256: prevRootSha256 || null,
      maxBytes: 2 * 1024 * 1024,
    });
    const text = new TextDecoder("utf-8", { fatal: true }).decode(blob.bytes);
    const parsed = parseLinksList(text);
    if (!parsed.ok) {
      throw new Error(`Previous root CID ${prevRootCid} is not a valid lns-links/1 list: ${parsed.error}`);
    }
    rootList = parsed;
    rootCid = prevRootCid;
    rootSha256 = blob.sha256;
  } else if (sequencer && storage && storage.configured) {
    const record = await resolveName(sequencer, registry, name, { now, fetchImpl });
    if (!record) return new Map();

    if (record.cid) {
      try {
        const blob = await storage.download(record.cid, {
          expectedSha256: record.cidSha256 || null,
          maxBytes: 2 * 1024 * 1024,
        });
        const text = new TextDecoder("utf-8", { fatal: false }).decode(blob.bytes);
        if (record.cidType === "links" || isLinksListText(text)) {
          const parsed = parseLinksList(text);
          if (parsed.ok) {
            rootList = parsed;
            rootCid = record.cid;
            rootSha256 = blob.sha256;
          }
        }
      } catch {
        // Previous root unreachable or not a links list — start fresh
        return new Map();
      }
    } else {
      const page = await resolveOnChainPage(sequencer, registry, name, { now, fetchImpl });
      if (page && page.body && page.body.length > 0) {
        const text = new TextDecoder("utf-8", { fatal: false }).decode(page.body);
        if (isLinksContentType(page.contentType) || isLinksListText(text)) {
          const parsed = parseLinksList(text);
          if (parsed.ok) {
            rootList = parsed;
            rootCid = null;
            rootSha256 = sha256Hex(page.body);
          }
        }
      }
    }
  }

  if (!rootList) return new Map();

  try {
    const walked = await walkLinksTree(rootList, loadFolderList, {
      rootCid,
      rootSha256,
      maxFiles: 50_000,
      maxFolders: 50_000,
    });
    return walked.folders;
  } catch (err) {
    if (prevRootCid) {
      throw new Error(`Failed to walk --prev-root tree (${prevRootCid}): ${err.message}`);
    }
    return new Map();
  }
}

export function buildNamesProfileCommand(name, { rootCid, rootSha256 }) {
  const cleanName = name || "<your-name>";
  const parts = ["names", "profile", cleanName, "--cid", rootCid];
  if (rootSha256) parts.push("--set", `cid.sha256=${rootSha256}`);
  parts.push("--set", "cid.type=links");
  return parts.join(" ");
}

export function buildNamesSetPageCommand(name, rootListFilePath = "<root-links.txt>") {
  const cleanName = name || "<your-name>";
  return `names set-page ${cleanName} --content-type "${LINKS_CONTENT_TYPE}; version=1" --file ${rootListFilePath}`;
}

/**
 * Publishes a local folder as a per-folder `lns-links/1` tree to Logos Storage.
 * Reuses CIDs of unchanged files and unchanged subtrees bottom-up.
 */
export async function publishSite(
  folderPath,
  rawName,
  {
    storage = null,
    storageApi = process.env.LOGOS_STORAGE_API || "",
    sequencer = process.env.LNS_SEQUENCER_URL || DEFAULT_CONFIG.sequencer,
    registry = process.env.LNS_REGISTRY || DEFAULT_CONFIG.registry,
    fetchImpl = fetch,
    prevRootCid = null,
    prevRootSha256 = null,
    noDiff = false,
    dryRun = false,
    onChain = false,
    title = null,
    rootOutFile = null,
    now = Date.now(),
    nodeVersion = process.versions.node,
    cryptoMod = undefined,
  } = {},
) {
  const name = normalizeName(rawName);
  if (!isValidName(name)) {
    throw new Error(`Invalid LNS name: ${rawName}`);
  }

  const info = await stat(folderPath);
  if (!info.isDirectory()) {
    throw new Error(`Target must be a folder: ${folderPath}`);
  }

  const tree = await scanLocalTree(folderPath);
  if (tree.files.length === 0 && tree.dirs.size === 0) {
    throw new Error(`Folder is empty: ${folderPath}`);
  }

  const client = storage || new StorageClient(storageApi, { fetchImpl });
  if (!dryRun && !client.configured) {
    throw new Error(
      "No Logos Storage node is configured. Pass --storage <URL> or set LOGOS_STORAGE_API (note: port 8080 is Logos Blockchain, not Storage).",
    );
  }

  // Only require Node 24 Argon2id when resolving against LEZ (when prevRootCid is not provided and !noDiff)
  if (!noDiff && !prevRootCid && sequencer && client.configured) {
    if (cryptoMod === undefined) {
      assertSupportedNode(nodeVersion);
    } else {
      assertSupportedNode(nodeVersion, cryptoMod);
    }
  }

  const prevFolders = noDiff
    ? new Map()
    : await loadPreviousTree({
        name,
        storage: client,
        sequencer,
        registry,
        fetchImpl,
        prevRootCid,
        prevRootSha256,
        now,
      });

  const uploadedFiles = [];
  const reusedFiles = [];
  const uploadedFolders = [];
  const reusedFolders = [];
  let totalFiles = 0;
  let totalFolders = 0;

  async function publishDir(dirNode) {
    totalFolders += 1;
    const dirSitePath = dirNode.relPath === "" ? "/" : "/" + dirNode.relPath;
    const prevFolder = prevFolders.get(dirSitePath) || null;
    const entries = [];

    // 1. Files in this folder
    for (const file of dirNode.files) {
      totalFiles += 1;
      const prevEntry =
        prevFolder && prevFolder.list && prevFolder.list.byName[file.name]
          ? prevFolder.list.byName[file.name]
          : null;

      if (prevEntry && prevEntry.kind === "file" && prevEntry.sha256 && prevEntry.sha256 === file.sha256) {
        reusedFiles.push({
          path: file.sitePath,
          cid: prevEntry.cid,
          sha256: file.sha256,
          size: file.size,
        });
        entries.push({
          name: file.name,
          kind: "file",
          cid: prevEntry.cid,
          sha256: file.sha256,
        });
      } else {
        let cid;
        let usedContentType = file.contentType;
        if (dryRun) {
          cid = `DRYRUNFILE${file.sha256.slice(0, 24)}`;
        } else {
          const uploaded = await client.upload(file.bytes, {
            filename: file.name,
            contentType: file.contentType,
          });
          cid = uploaded.cid;
          usedContentType = uploaded.contentType;
        }
        uploadedFiles.push({
          path: file.sitePath,
          cid,
          sha256: file.sha256,
          size: file.size,
          contentType: usedContentType,
        });
        entries.push({
          name: file.name,
          kind: "file",
          cid,
          sha256: file.sha256,
        });
      }
    }

    // 2. Subfolders (bottom-up: publish every child folder before building this folder's list)
    for (const [childName, childNode] of dirNode.dirs.entries()) {
      const childRes = await publishDir(childNode);
      entries.push({
        name: childName,
        kind: "dir",
        cid: childRes.cid,
        sha256: childRes.sha256,
      });
    }

    // 3. Format this folder's lns-links/1 list
    const hasIndexHtml = dirNode.files.some((f) => f.name === "index.html");
    const formatted = formatLinksList({
      title: dirNode.relPath === "" ? title : null,
      index: hasIndexHtml ? "index.html" : null,
      entries,
    });
    if (!formatted.ok) {
      throw new Error(`Failed to format links list for ${dirSitePath}: ${formatted.error}`);
    }

    const listBytes = Buffer.from(formatted.text, "utf-8");
    const listSha256 = sha256Hex(listBytes);
    const isRoot = dirNode.relPath === "";

    // On-chain root mode: keep root list in SetPage (< 10 KB), do not upload root list to Storage
    if (isRoot && onChain) {
      if (listBytes.length >= MAX_ONCHAIN_LINKS_BYTES) {
        throw new Error(
          `Root links list is ${listBytes.length} bytes, exceeding the ${MAX_ONCHAIN_LINKS_BYTES}-byte on-chain page limit; publish via profile CID instead.`,
        );
      }
      if (prevFolder && prevFolder.sha256 === listSha256) {
        reusedFolders.push({ path: "/", cid: null, sha256: listSha256, size: listBytes.length });
      } else {
        uploadedFolders.push({ path: "/", cid: null, sha256: listSha256, size: listBytes.length, onChain: true });
      }
      return { cid: null, sha256: listSha256, bytes: listBytes, text: formatted.text };
    }

    // Reuse unchanged folder list CID if its exact hash matches the previous tree
    if (prevFolder && prevFolder.cid && prevFolder.sha256 === listSha256) {
      reusedFolders.push({
        path: dirSitePath,
        cid: prevFolder.cid,
        sha256: listSha256,
        size: listBytes.length,
      });
      return { cid: prevFolder.cid, sha256: listSha256, bytes: listBytes, text: formatted.text };
    }

    let folderCid;
    if (dryRun) {
      folderCid = `DRYRUNDIR${listSha256.slice(0, 25)}`;
    } else {
      const uploaded = await client.upload(listBytes, {
        filename: "lns-links.txt",
        contentType: "text/plain",
      });
      folderCid = uploaded.cid;
    }
    uploadedFolders.push({
      path: dirSitePath,
      cid: folderCid,
      sha256: listSha256,
      size: listBytes.length,
    });
    return { cid: folderCid, sha256: listSha256, bytes: listBytes, text: formatted.text };
  }

  const rootRes = await publishDir(tree);
  if (onChain && rootOutFile && !dryRun) {
    await writeFile(rootOutFile, rootRes.bytes);
  }

  const unchanged = uploadedFiles.length === 0 && uploadedFolders.length === 0;
  const isDryRunPlaceholder = dryRun && !unchanged && !onChain;
  const publicRootCid = isDryRunPlaceholder ? null : rootRes.cid;
  const namesCommand = onChain
    ? buildNamesSetPageCommand(name, rootOutFile || "<root-links.txt>")
    : isDryRunPlaceholder
      ? buildNamesProfileCommand(name, {
          rootCid: "<CID-computed-on-real-publish>",
          rootSha256: "<SHA256-computed-on-real-publish>",
        })
      : buildNamesProfileCommand(name, { rootCid: rootRes.cid, rootSha256: rootRes.sha256 });
  const deepLink =
    onChain || isDryRunPlaceholder
      ? null
      : buildPublishDeepLink({
          name,
          cid: rootRes.cid,
          sha256: rootRes.sha256,
          site_type: "links",
          return_app: "lns_browser",
        });

  return {
    name,
    dryRun,
    onChain,
    unchanged,
    rootCid: publicRootCid,
    rootSha256: isDryRunPlaceholder ? null : rootRes.sha256,
    rootSize: rootRes.bytes.length,
    rootText: rootRes.text,
    uploadedFiles,
    reusedFiles,
    uploadedFolders,
    reusedFolders,
    totalFiles,
    totalFolders,
    namesCommand,
    deepLink,
  };
}

export function formatPublishPlan(result) {
  const lines = [];
  if (result.dryRun) {
    lines.push(`Dry run for lns://${result.name} (no files uploaded):`);
  } else if (result.unchanged) {
    lines.push(`No changes for lns://${result.name} (0 uploads; existing tree reused).`);
  } else {
    lines.push(`Published lns://${result.name}:`);
  }
  lines.push(
    `  Files:   ${result.uploadedFiles.length} ${result.dryRun ? "to upload" : "uploaded"}, ${result.reusedFiles.length} reused (${result.totalFiles} total)`,
  );
  lines.push(
    `  Folders: ${result.uploadedFolders.length} ${result.dryRun ? "to upload" : "uploaded"}, ${result.reusedFolders.length} reused (${result.totalFolders} total)`,
  );
  if (result.onChain) {
    lines.push(`  Root:    on-chain SetPage (${result.rootSize} / ${MAX_ONCHAIN_LINKS_BYTES} bytes, sha256=${result.rootSha256})`);
  } else if (result.dryRun && !result.unchanged) {
    lines.push(`  Root:    <CID computed on real publish> (${result.rootSize} bytes)`);
  } else {
    lines.push(`  Root:    ${result.rootCid} (${result.rootSize} bytes, sha256=${result.rootSha256})`);
  }
  if (result.uploadedFiles.length > 0) {
    lines.push(`  ${result.dryRun ? "Planned file uploads" : "Uploaded files"}:`);
    for (const f of result.uploadedFiles) {
      lines.push(`    + ${f.path} (${f.size} bytes)`);
    }
  }
  if (result.uploadedFolders.length > 0) {
    lines.push(`  ${result.dryRun ? "Planned folder list uploads" : "Uploaded folder lists"}:`);
    for (const d of result.uploadedFolders) {
      lines.push(`    + ${d.path} (${d.size} bytes)`);
    }
  }
  if (!result.unchanged || result.dryRun) {
    lines.push("");
    if (result.dryRun && !result.unchanged) {
      lines.push("Update on-chain record (dry run — re-run without --dry-run to get real CIDs):");
    } else {
      lines.push("Update on-chain record:");
    }
    lines.push(`  ${result.namesCommand}`);
    if (result.deepLink) {
      lines.push(`  Basecamp deep link: ${result.deepLink}`);
    }
  }
  return lines.join("\n");
}

function parseCliArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (
        key === "dry-run" ||
        key === "no-diff" ||
        key === "onchain" ||
        key === "json" ||
        key === "help"
      ) {
        flags[key] = true;
      } else if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

async function main() {
  const { positional, flags } = parseCliArgs(process.argv.slice(2));
  const args = positional[0] === "publish" ? positional.slice(1) : positional;
  if (flags.help || args.length < 2) {
    console.log(
      [
        "Usage: node publish.mjs <folder> <name> [options]",
        "",
        "Options:",
        "  --storage <URL>      Logos Storage REST API URL (or LOGOS_STORAGE_API)",
        "  --sequencer <URL>    LEZ 0.4 RPC URL (or LNS_SEQUENCER_URL)",
        "  --registry <ID>      LNS registry program account ID (or LNS_REGISTRY)",
        "  --prev-root <CID>    Diff against a specific previous root CID instead of LEZ",
        "  --no-diff            Skip diffing and upload the full tree fresh",
        "  --dry-run            Print the upload plan without uploading anything",
        "  --onchain            Target on-chain SetPage (< 10 KB) instead of profile CID",
        "  --root-out <FILE>    Write root lns-links/1 list to a local file (with --onchain)",
        "  --title <TEXT>       Optional # title header on the root list",
        "  --json               Print machine-readable JSON result",
      ].join("\n"),
    );
    process.exit(flags.help ? 0 : 1);
  }

  const [folderPath, rawName] = args;
  const strFlag = (v) => (typeof v === "string" ? v : undefined);
  const result = await publishSite(folderPath, rawName, {
    storageApi: strFlag(flags.storage) ?? process.env.LOGOS_STORAGE_API ?? DEFAULT_CONFIG.storageApi,
    sequencer: strFlag(flags.sequencer) || process.env.LNS_SEQUENCER_URL || DEFAULT_CONFIG.sequencer,
    registry: strFlag(flags.registry) || process.env.LNS_REGISTRY || DEFAULT_CONFIG.registry,
    prevRootCid: strFlag(flags["prev-root"]) || null,
    noDiff: Boolean(flags["no-diff"]),
    dryRun: Boolean(flags["dry-run"]),
    onChain: Boolean(flags.onchain),
    title: strFlag(flags.title) || null,
    rootOutFile: strFlag(flags["root-out"]) || null,
  });

  if (flags.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(formatPublishPlan(result));
  }
}

const isMain = Boolean(process.argv[1]) && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (isMain) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
