import test from "node:test";
import assert from "node:assert/strict";
import {
  formatLinksList,
  isLinksContentType,
  isLinksListText,
  parseLinksList,
  parseUrl,
  resolveLinksTree,
  walkLinksTree,
} from "../links.mjs";

const CID_HOME = "z4W2jRootHtml0000000000000000000000000000000000000";
const CID_CSS = "z4W2jSiteCss00000000000000000000000000000000000000";
const CID_ASSETS_DIR = "z4W2jAssetsDir000000000000000000000000000000000000";
const CID_BROWSER_DIR = "z4W2jBrowserDir00000000000000000000000000000000000";
const CID_BROWSER_HTML = "z4W2jBrowserHtml0000000000000000000000000000000000";
const CID_SHOT = "z4W2jBrowserShot0000000000000000000000000000000000";
const CID_FILES_DIR = "z4W2jFilesDir0000000000000000000000000000000000000";
const CID_LGX = "z4W2jBrowserUiLgx00000000000000000000000000000000";
const HASH_LGX = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";

test("lns-gateway/links.mjs re-exports parser and rejects malformed or unsafe lists", () => {
  assert.equal(isLinksContentType("text/vnd.logos.lns-links; version=1"), true);
  assert.equal(isLinksListText("# lns-links/1\nindex.html " + CID_HOME + "\n"), true);

  const ok = parseLinksList(`# lns-links/1\n# index index.html\nbrowser/ ${CID_BROWSER_DIR}\nindex.html ${CID_HOME}\n`);
  assert.equal(ok.ok, true);
  assert.equal(ok.entries.length, 2);

  // Rejections
  assert.equal(parseLinksList("not a list").ok, false);
  assert.equal(parseLinksList(`# lns-links/1\n../evil ${CID_HOME}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\na/b ${CID_HOME}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\nindex.html ${CID_HOME}\nindex.html ${CID_CSS}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\nfoo ${CID_HOME}\nfoo/ ${CID_BROWSER_DIR}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\nfoo ${CID_HOME} badhash\n`).ok, false);

  // Bare name/path URLs
  const u = parseUrl("nameswallet/browser/files/lns-browser-0.2.8.lgx");
  assert.equal(u.ok, true);
  assert.equal(u.name, "nameswallet");
  assert.equal(u.path, "/browser/files/lns-browser-0.2.8.lgx");
  assert.equal(parseUrl("a.b/c").ok, false);
});

test("resolveLinksTree walks nested folders asynchronously with CID cache and handles trailing slashes & 404", async () => {
  const root = parseLinksList(
    `# lns-links/1\n# index index.html\nassets/ ${CID_ASSETS_DIR}\nbrowser/ ${CID_BROWSER_DIR}\nindex.html ${CID_HOME}\n`,
  );
  const assets = parseLinksList(`# lns-links/1\nsite.css ${CID_CSS}\n`);
  const browser = parseLinksList(
    `# lns-links/1\n# index index.html\nfiles/ ${CID_FILES_DIR}\nindex.html ${CID_BROWSER_HTML}\nshot.png ${CID_SHOT}\n`,
  );
  const files = parseLinksList(`# lns-links/1\nlns-browser-0.2.8.lgx ${CID_LGX} ${HASH_LGX}\n`);

  const byCid = new Map([
    [CID_ASSETS_DIR, assets],
    [CID_BROWSER_DIR, browser],
    [CID_FILES_DIR, files],
  ]);

  const cache = new Map();
  let loads = 0;
  const loader = async (cid) => {
    loads += 1;
    const found = byCid.get(cid);
    if (!found) throw new Error(`missing ${cid}`);
    return found;
  };

  // `/browser` canonicalizes to `/browser/` -> `/browser/index.html`
  const r1 = await resolveLinksTree(root, "/browser", loader, cache);
  assert.equal(r1.ok, true);
  assert.equal(r1.resolvedPath, "/browser/index.html");
  assert.equal(r1.canonicalUrlPath, "/browser/");
  assert.equal(r1.entry.cid, CID_BROWSER_HTML);
  assert.equal(loads, 1);

  // `/browser/` hits cache (loads unchanged)
  const r2 = await resolveLinksTree(root, "/browser/", loader, cache);
  assert.equal(r2.ok, true);
  assert.equal(r2.resolvedPath, "/browser/index.html");
  assert.equal(loads, 1);

  // `/browser/files/lns-browser-0.2.8.lgx` loads only `files/`
  const r3 = await resolveLinksTree(root, "/browser/files/lns-browser-0.2.8.lgx", loader, cache);
  assert.equal(r3.ok, true);
  assert.equal(r3.entry.cid, CID_LGX);
  assert.equal(r3.entry.sha256, HASH_LGX);
  assert.equal(r3.canonicalUrlPath, "/browser/files/lns-browser-0.2.8.lgx");
  assert.equal(loads, 2);

  // Missing path returns not_found
  const r4 = await resolveLinksTree(root, "/browser/nope.html", loader, cache);
  assert.equal(r4.ok, false);
  assert.equal(r4.status, "not_found");

  // walkLinksTree enumerates all files and maps CIDs to site paths
  const walked = await walkLinksTree(root, loader, { cache });
  assert.deepEqual(
    Array.from(walked.files.keys()).sort(),
    [
      "/assets/site.css",
      "/browser/files/lns-browser-0.2.8.lgx",
      "/browser/index.html",
      "/browser/shot.png",
      "/index.html",
    ],
  );
  assert.equal(walked.byCid.get(CID_SHOT), "/browser/shot.png");
  assert.equal(walked.byCid.get(CID_LGX), "/browser/files/lns-browser-0.2.8.lgx");
});

test("walkLinksTree detects folder cycles and rejects oversized trees", async () => {
  const cidA = "z4W2jCycleDirA000000000000000000000000000000000000";
  const cidB = "z4W2jCycleDirB000000000000000000000000000000000000";
  const dirA = parseLinksList(`# lns-links/1\nb/ ${cidB}\n`);
  const dirB = parseLinksList(`# lns-links/1\na/ ${cidA}\n`);
  const loader = async (cid) => (cid === cidA ? dirA : dirB);

  await assert.rejects(
    () => walkLinksTree(dirA, loader, { rootCid: cidA }),
    /Cycle detected/i,
  );

  // formatLinksList round-trip with sha256 on both file and subfolder
  const formatted = formatLinksList({
    index: "index.html",
    entries: [
      { name: "index.html", kind: "file", cid: CID_HOME, sha256: HASH_LGX },
      { name: "browser", kind: "dir", cid: CID_BROWSER_DIR, sha256: "" },
    ],
  });
  assert.equal(formatted.ok, true);
  assert.equal(
    formatted.text,
    `# lns-links/1\n# index index.html\nbrowser/ ${CID_BROWSER_DIR}\nindex.html ${CID_HOME} ${HASH_LGX}\n`,
  );
});

test("Finding 6: walkLinksTree stops exponential DAG bomb via maxFolders cap", async () => {
  // 31 levels of 2-child DAG references -> 2^31 folders with 0 files
  const levels = [];
  const leafCid = "z4W2jDagLeaf00000000000000000000000000000000000000";
  const byCid = new Map([[leafCid, parseLinksList("# lns-links/1\n")]]);
  let childCid = leafCid;
  for (let k = 30; k >= 0; k--) {
    const cid = `z4W2jDagLvl${String(k).padStart(2, "0")}00000000000000000000000000000000000`;
    const list = parseLinksList(`# lns-links/1\na/ ${childCid}\nb/ ${childCid}\n`);
    byCid.set(cid, list);
    levels[k] = { cid, list };
    childCid = cid;
  }
  const loader = async (cid) => byCid.get(cid);

  await assert.rejects(
    () => walkLinksTree(levels[0].list, loader, { rootCid: levels[0].cid, maxFolders: 200 }),
    /maximum of 200 folders/i,
  );
});

test("Finding 7: resolveLinksTree and walkLinksTree verify expectedSha256 on CID cache hit", async () => {
  const realSha = "a".repeat(64);
  const badSha = "b".repeat(64);
  const subList = parseLinksList(`# lns-links/1\nindex.html ${CID_BROWSER_HTML}\n`);
  const rootUnpinned = parseLinksList(`# lns-links/1\nsub/ ${CID_BROWSER_DIR}\n`);
  const rootPinnedBad = parseLinksList(`# lns-links/1\nsub/ ${CID_BROWSER_DIR} ${badSha}\n`);
  const rootDual = parseLinksList(
    `# lns-links/1\na/ ${CID_BROWSER_DIR}\nb/ ${CID_BROWSER_DIR} ${badSha}\n`,
  );

  const cache = new Map();
  const loader = async () => ({ list: subList, sha256: realSha });

  const r1 = await resolveLinksTree(rootUnpinned, "/sub/", loader, cache);
  assert.equal(r1.ok, true);
  assert.equal(r1.foldersVerified, false);

  // Second call pins a different sha256 for the same cached CID -> must fail
  const r2 = await resolveLinksTree(rootPinnedBad, "/sub/", loader, cache);
  assert.equal(r2.ok, false);
  assert.match(r2.error, /SHA-256 mismatch/i);

  // walkLinksTree: folder loaded unpinned first, then referenced with wrong sha256 -> must throw
  await assert.rejects(
    () => walkLinksTree(rootDual, loader),
    /SHA-256 mismatch/i,
  );
});
