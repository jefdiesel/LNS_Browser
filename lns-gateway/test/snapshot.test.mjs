import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, utimes } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DEFAULT_CONFIG,
  deriveName,
  encodeNameRecord,
  encodePage,
  encodePageContent,
  encodeProfile,
  pageAddress,
  recordAddress,
  seal,
  sha256Hex,
} from "../derive.mjs";
import { MANIFEST_KIND } from "../storage.mjs";
import { runSnapshot } from "../snapshot.mjs";

const FAKE_CHAIN_URL = "fake://chain";
const FAKE_STORAGE_URL = "fake://storage/api/storage/v1";
const utf8 = new TextEncoder();

/** Pure in-memory fake LEZ 0.4 chain + fake Logos Storage node (zero network). */
function createFakeEnv(programId = DEFAULT_CONFIG.registry) {
  const accounts = new Map();
  const blobs = new Map();
  let cidSeq = 0;

  async function putName(name, texts = {}) {
    const { id, key } = await deriveName(name);
    const addr = await recordAddress(programId, id);
    const sealed = await seal(key, encodeProfile({ name, texts }), "record");
    accounts.set(addr, encodeNameRecord({ version: 6, sealed }));
    return addr;
  }

  async function putOnChainPage(name, html, contentType = "text/html; charset=utf-8") {
    const { id, key } = await deriveName(name);
    const recAddr = await recordAddress(programId, id);
    if (!accounts.has(recAddr)) {
      await putName(name, {});
    }
    const bodyBytes = typeof html === "string" ? utf8.encode(html) : new Uint8Array(html);
    const plaintext = encodePageContent(contentType, bodyBytes);
    const sealed = await seal(key, plaintext, "page");
    const pAddr = await pageAddress(programId, id);
    accounts.set(pAddr, encodePage(sealed));
    return { hash: sha256Hex(bodyBytes), bytes: bodyBytes };
  }

  function putBlob(content, contentType = "application/octet-stream") {
    const bytes = typeof content === "string" ? Buffer.from(content, "utf-8") : Buffer.from(content);
    const sha256 = sha256Hex(bytes);
    cidSeq += 1;
    const cid = `zDvFakeCid${String(cidSeq).padStart(4, "0")}${sha256.slice(0, 12)}`;
    blobs.set(cid, { bytes, contentType });
    return { cid, sha256, size: bytes.length, contentType };
  }

  async function putCidBundle(name, fileEntries, { title = "Bundle", index = "/index.html" } = {}) {
    const files = {};
    for (const [sitePath, spec] of Object.entries(fileEntries)) {
      const content = typeof spec === "string" || Buffer.isBuffer(spec) ? spec : spec.content;
      const contentType = typeof spec === "object" && !Buffer.isBuffer(spec) ? spec.contentType : "text/html; charset=utf-8";
      const uploaded = putBlob(content, contentType);
      files[sitePath] = uploaded;
    }
    const manifest = { kind: MANIFEST_KIND, version: 1, title, index, files };
    const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + "\n", "utf-8");
    const root = putBlob(manifestBytes, "application/vnd.logos.site-manifest+json");
    await putName(name, {
      cid: root.cid,
      "cid.sha256": root.sha256,
      "cid.type": "manifest",
    });
    return { root, files, manifest };
  }

  async function fetchImpl(url, init = {}) {
    const target = String(url);
    if (target === FAKE_CHAIN_URL) {
      const body = JSON.parse(init.body || "{}");
      if (body.method === "getAccountView") {
        const { account_id, program_account_id } = body.params[0];
        const stateBytes = accounts.get(account_id);
        const result = stateBytes
          ? { data: { actor_states: { [program_account_id]: Array.from(stateBytes) } } }
          : null;
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("bad rpc", { status: 400 });
    }

    if (target.startsWith(FAKE_STORAGE_URL)) {
      const m = target.slice(FAKE_STORAGE_URL.length).match(/^\/data\/([A-Za-z0-9]+)(?:\/network\/stream)?$/);
      if (m) {
        const item = blobs.get(m[1]);
        if (!item) return new Response("not found", { status: 404 });
        return new Response(item.bytes, {
          status: 200,
          headers: { "Content-Type": item.contentType },
        });
      }
      return new Response("not found", { status: 404 });
    }

    throw new Error(`unexpected fetch URL in offline test: ${target}`);
  }

  return { accounts, blobs, putName, putOnChainPage, putBlob, putCidBundle, fetchImpl };
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

test("good on-chain page is verified, sanitized, given CSP + header bar, and indexed", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-chain-"));
  try {
    const env = createFakeEnv();
    const rawHtml =
      '<!doctype html><html><head><meta charset="utf-8"><title>Docs</title></head>' +
      '<body><h1>On-Chain Docs</h1><p><a href="lns://guide">Guide</a></p></body></html>';
    const { hash } = await env.putOnChainPage("docs", rawHtml);

    const res = await runSnapshot({
      names: ["docs"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: "",
      fetchImpl: env.fetchImpl,
      now: () => Date.parse("2026-11-24T12:00:00.000Z"),
    });

    assert.equal(res.errors.length, 0);
    assert.equal(res.sites[0].source, "chain");
    assert.equal(res.sites[0].hash, hash);

    const writtenHtml = await readFile(join(outDir, "lns", "docs", "index.html"), "utf-8");
    assert.match(writtenHtml, /<meta http-equiv="Content-Security-Policy" content="[^"]*default-src 'none'[^"]*script-src 'none'[^"]*connect-src 'none'/);
    assert.match(writtenHtml, /<meta name="referrer" content="no-referrer">/);
    assert.ok(writtenHtml.includes(`lns://docs · verified ${hash.slice(0, 12)} · from chain`));
    assert.match(writtenHtml, /href="\/lns\/guide\/"/);

    const index = JSON.parse(await readFile(join(outDir, "lns", "index.json"), "utf-8"));
    assert.deepEqual(index, [
      {
        name: "docs",
        source: "chain",
        hash,
        time: "2026-11-24T12:00:00.000Z",
      },
    ]);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("good CID bundle verifies manifest + every child file and writes all assets", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-cid-"));
  try {
    const env = createFakeEnv();
    const bundle = await env.putCidBundle("demo", {
      "/index.html": {
        contentType: "text/html; charset=utf-8",
        content:
          '<!doctype html><html><head><link rel="stylesheet" href="style.css"></head>' +
          '<body><h1>Demo</h1><a href="about.html">About</a><a href="lns://docs/intro.html">Docs</a></body></html>',
      },
      "/about.html": {
        contentType: "text/html; charset=utf-8",
        content: '<!doctype html><html><head></head><body><h1>About</h1><a href="/">Home</a></body></html>',
      },
      "/style.css": {
        contentType: "text/css; charset=utf-8",
        content: 'body { color: #111; background: url("https://external/bg.png"); }',
      },
    });

    const res = await runSnapshot({
      names: ["demo"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
      now: () => Date.parse("2026-11-24T12:30:00.000Z"),
    });

    assert.equal(res.errors.length, 0);
    assert.equal(res.sites[0].source, "cid");
    assert.equal(res.sites[0].hash, bundle.root.sha256);

    const indexHtml = await readFile(join(outDir, "lns", "demo", "index.html"), "utf-8");
    assert.ok(indexHtml.includes(`lns://demo · verified ${bundle.root.sha256.slice(0, 12)} · from CID`));
    assert.match(indexHtml, /<link rel="stylesheet" href="\/lns\/demo\/style\.css">/);
    assert.match(indexHtml, /href="\/lns\/docs\/intro\.html"/);

    const aboutHtml = await readFile(join(outDir, "lns", "demo", "about.html"), "utf-8");
    assert.match(aboutHtml, /href="\/lns\/demo\/"/);

    const css = await readFile(join(outDir, "lns", "demo", "style.css"), "utf-8");
    assert.doesNotMatch(css, /https:\/\/external/i);
    assert.match(css, /background:\s*none/);

    const index = JSON.parse(await readFile(join(outDir, "lns", "index.json"), "utf-8"));
    assert.equal(index.length, 1);
    assert.equal(index[0].name, "demo");
    assert.equal(index[0].source, "cid");
    assert.equal(index[0].hash, bundle.root.sha256);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("wrong hash (root CID, child asset, or missing sha256) is refused and writes nothing", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-bad-"));
  try {
    const env = createFakeEnv();

    // 1. Root CID bytes tampered after pinning
    const badRoot = env.putBlob("<html><body>original</body></html>", "text/html");
    await env.putName("badroot", {
      cid: badRoot.cid,
      "cid.sha256": badRoot.sha256,
      "cid.type": "single",
    });
    env.blobs.get(badRoot.cid).bytes = Buffer.from("<html><body>tampered</body></html>");

    // 2. Child asset in manifest tampered (while index.html is valid)
    const badChild = await env.putCidBundle("badchild", {
      "/index.html": { contentType: "text/html; charset=utf-8", content: "<h1>OK</h1>" },
      "/style.css": { contentType: "text/css; charset=utf-8", content: "body{color:#111}" },
    });
    env.blobs.get(badChild.files["/style.css"].cid).bytes = Buffer.from("body{color:#f00}");

    // 3. Missing cid.sha256 on chain
    const noHash = env.putBlob("<html><body>unpinned</body></html>", "text/html");
    await env.putName("nohash", { cid: noHash.cid, "cid.type": "single" });

    const res = await runSnapshot({
      names: ["badroot", "badchild", "nohash"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
    });

    assert.equal(res.errors.length, 3);
    assert.match(res.errors[0].error, /SHA-256 mismatch/i);
    assert.match(res.errors[1].error, /SHA-256 mismatch/i);
    assert.match(res.errors[2].error, /no on-chain cid\.sha256/i);
    assert.equal(res.filesWritten, 0);

    assert.equal(await exists(join(outDir, "lns", "badroot")), false);
    assert.equal(await exists(join(outDir, "lns", "badchild")), false);
    assert.equal(await exists(join(outDir, "lns", "nohash")), false);
    assert.equal(await exists(join(outDir, "lns", "index.json")), false);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("links are rewritten, external loads and scripts are stripped, and strict CSP is enforced", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-san-"));
  try {
    const env = createFakeEnv();
    const hostileHtml = `<!doctype html>
<html>
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval'">
  <meta http-equiv="refresh" content="0;url=https://external/phish">
  <base href="https://external/">
  <link rel="stylesheet" href="https://external/evil.css">
  <link rel="preconnect" href="https://external">
  <link rel="stylesheet" href="/local.css">
  <script src="https://external/evil.js"></script>
  <style>
    @import url("https://external/font.css");
    body { background: url("https://external/track.png"); color: #111; }
  </style>
</head>
<body>
  <script>alert(1)</script>
  <iframe src="https://external/frame"></iframe>
  <img src="https://external/pixel.gif" alt="tracker">
  <img src="data:image/png;base64,iVBORw0KGgo=" alt="inline">
  <div onclick="alert(2)" style="background-image:url(https://external/x.png)">Clean</div>
  <a href="lns://other">Other</a>
  <a href="lns://other/docs/page.html#sec">Other Page</a>
  <a href="/sub/page.html">Root Rel</a>
  <a href="javascript:alert(3)">Bad JS Link</a>
  <a href="https://nameswallet.app/" ping="https://external/ping">External Link</a>
</body>
</html>`;

    await env.putOnChainPage("links", hostileHtml);

    const res = await runSnapshot({
      names: ["links"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: "",
      fetchImpl: env.fetchImpl,
    });

    assert.equal(res.errors.length, 0);
    const outHtml = await readFile(join(outDir, "lns", "links", "index.html"), "utf-8");

    // Strict CSP present; author weak CSP & meta refresh stripped
    assert.match(outHtml, /<meta http-equiv="Content-Security-Policy" content="default-src 'none';/);
    assert.doesNotMatch(outHtml, /unsafe-eval/i);
    assert.doesNotMatch(outHtml, /http-equiv="refresh"/i);
    assert.doesNotMatch(outHtml, /<base\b/i);

    // Zero external loads or scripts
    assert.doesNotMatch(outHtml, /https:\/\/external/i);
    assert.doesNotMatch(outHtml, /<script\b/i);
    assert.doesNotMatch(outHtml, /<iframe\b/i);
    assert.doesNotMatch(outHtml, /\bonclick=/i);
    assert.doesNotMatch(outHtml, /\bping=/i);
    assert.doesNotMatch(outHtml, /javascript:/i);

    // Local assets and safe data image preserved and scoped
    assert.match(outHtml, /<link rel="stylesheet" href="\/lns\/links\/local\.css">/);
    assert.match(outHtml, /<img src="data:image\/png;base64,iVBORw0KGgo=" alt="inline">/);

    // Links rewritten properly
    assert.match(outHtml, /<a href="\/lns\/other\/">Other<\/a>/);
    assert.match(outHtml, /<a href="\/lns\/other\/docs\/page\.html#sec">Other Page<\/a>/);
    assert.match(outHtml, /<a href="\/lns\/links\/sub\/page\.html">Root Rel<\/a>/);
    assert.match(outHtml, /<a>Bad JS Link<\/a>/);
    assert.match(outHtml, /<a href="https:\/\/nameswallet\.app\/" rel="noopener noreferrer">External Link<\/a>/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("unchanged input writes nothing (mtimes and index.json stay untouched)", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-noop-"));
  try {
    const env = createFakeEnv();
    await env.putOnChainPage("docs", "<!doctype html><html><head></head><body><h1>V1</h1></body></html>");
    await env.putCidBundle("demo", {
      "/index.html": { contentType: "text/html; charset=utf-8", content: "<h1>CID V1</h1>" },
    });

    const t1 = Date.parse("2026-11-24T10:00:00.000Z");
    const run1 = await runSnapshot({
      names: ["docs", "demo"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
      now: () => t1,
    });
    assert.equal(run1.errors.length, 0);
    assert.equal(run1.filesWritten, 5); // docs/{index,404}.html, demo/{index,404}.html, index.json
    assert.equal(run1.indexWritten, true);

    // Stamp all output files with a known old mtime
    const past = new Date("2020-01-01T00:00:00.000Z");
    const docsPath = join(outDir, "lns", "docs", "index.html");
    const docs404Path = join(outDir, "lns", "docs", "404.html");
    const demoPath = join(outDir, "lns", "demo", "index.html");
    const demo404Path = join(outDir, "lns", "demo", "404.html");
    const indexPath = join(outDir, "lns", "index.json");
    for (const f of [docsPath, docs404Path, demoPath, demo404Path, indexPath]) {
      await utimes(f, past, past);
    }

    // Second run with identical chain/storage state at a later clock time
    const t2 = Date.parse("2026-11-24T10:10:00.000Z");
    const run2 = await runSnapshot({
      names: ["docs", "demo"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
      now: () => t2,
    });
    assert.equal(run2.errors.length, 0);
    assert.equal(run2.filesWritten, 0);
    assert.equal(run2.indexWritten, false);

    // Confirm OS mtime did not move for any file
    for (const f of [docsPath, docs404Path, demoPath, demo404Path, indexPath]) {
      const info = await stat(f);
      assert.equal(Math.floor(info.mtimeMs), past.getTime());
    }
    const indexAfterRun2 = JSON.parse(await readFile(indexPath, "utf-8"));
    assert.equal(indexAfterRun2.find((e) => e.name === "docs").time, "2026-11-24T10:00:00.000Z");

    // Update only `docs` -> only docs/index.html and index.json are rewritten; demo stays untouched
    await env.putOnChainPage("docs", "<!doctype html><html><head></head><body><h1>V2</h1></body></html>");
    const t3 = Date.parse("2026-11-24T10:20:00.000Z");
    const run3 = await runSnapshot({
      names: ["docs", "demo"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
      now: () => t3,
    });
    assert.equal(run3.errors.length, 0);
    assert.equal(run3.filesWritten, 2); // docs/index.html + index.json
    assert.equal(run3.indexWritten, true);

    const demoStat = await stat(demoPath);
    assert.equal(Math.floor(demoStat.mtimeMs), past.getTime());
    const indexAfterRun3 = JSON.parse(await readFile(indexPath, "utf-8"));
    assert.equal(indexAfterRun3.find((e) => e.name === "docs").time, "2026-11-24T10:20:00.000Z");
    assert.equal(indexAfterRun3.find((e) => e.name === "demo").time, "2026-11-24T10:00:00.000Z");
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("runSnapshot refuses below Node 24 with a plain message", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-node22-"));
  try {
    await assert.rejects(
      () =>
        runSnapshot({
          names: ["demo"],
          outDir,
          sequencer: FAKE_CHAIN_URL,
          registry: DEFAULT_CONFIG.registry,
          storageApi: "",
          nodeVersion: "22.14.0",
          cryptoMod: {},
        }),
      /requires Node 24 or newer/i,
    );
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("nested per-folder lns-links/1 site materializes cid:// assets, writes 404.html, and honors configurable limits", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-links-"));
  try {
    const env = createFakeEnv();
    const pngBytes = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01]);
    const shot = env.putBlob(pngBytes, "image/png");
    const extraFrozen = env.putBlob(pngBytes, "image/png");
    const lgx = env.putBlob(Buffer.from("LGX-MODULE-BYTES"), "application/octet-stream");
    const siteCss = env.putBlob("body { color: #111; }\n", "text/css");

    const browserHtml = env.putBlob(
      `<!doctype html><html><head><link rel="stylesheet" href="/assets/site.css"></head><body>` +
        `<h1>Browser</h1>` +
        `<img src="cid://${shot.cid}" alt="Listed Shot">` +
        `<img src="cid://${extraFrozen.cid}" alt="Frozen CID">` +
        `<a href="cid://${lgx.cid}" download="lns-browser-0.2.8.lgx">Download UI</a>` +
        `</body></html>`,
      "text/html",
    );
    const rootHtml = env.putBlob(
      `<!doctype html><html><head></head><body><h1>Home</h1><a href="/browser/">Browser</a></body></html>`,
      "text/html",
    );

    const filesDir = env.putBlob(
      `# lns-links/1\nlns-browser-0.2.8.lgx ${lgx.cid} ${lgx.sha256}\n`,
      "text/plain",
    );
    const browserDir = env.putBlob(
      `# lns-links/1\n# index index.html\nfiles/ ${filesDir.cid} ${filesDir.sha256}\nindex.html ${browserHtml.cid} ${browserHtml.sha256}\nshot.png ${shot.cid} ${shot.sha256}\n`,
      "text/plain",
    );
    const assetsDir = env.putBlob(
      `# lns-links/1\nsite.css ${siteCss.cid} ${siteCss.sha256}\n`,
      "text/plain",
    );
    const rootDir = env.putBlob(
      `# lns-links/1\n# index index.html\nassets/ ${assetsDir.cid} ${assetsDir.sha256}\nbrowser/ ${browserDir.cid} ${browserDir.sha256}\nindex.html ${rootHtml.cid} ${rootHtml.sha256}\n`,
      "text/plain",
    );

    await env.putName("nameswallet", {
      cid: rootDir.cid,
      "cid.sha256": rootDir.sha256,
      "cid.type": "links",
    });

    // Limit below site file count fails cleanly
    const limited = await runSnapshot({
      names: ["nameswallet"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      maxSiteFiles: 2,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(limited.errors.length, 1);
    assert.match(limited.errors[0].error, /exceeds maximum of 2 files/i);

    // Full snapshot with sufficient limits succeeds
    const res = await runSnapshot({
      names: ["nameswallet"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      maxSiteFiles: 1000,
      maxSiteBytes: 150 * 1024 * 1024,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(res.errors.length, 0);
    assert.equal(res.sites[0].source, "cid");

    // Listed cid:// rewritten to matching site path; unlisted frozen cid:// materialized under /_cid/
    // Page with unlisted cid:// is marked unverified; root page with only listed hashed entries stays verified.
    const outRootHtml = await readFile(join(outDir, "lns", "nameswallet", "index.html"), "utf-8");
    assert.match(outRootHtml, /data-lns-verified="true"/);
    assert.match(outRootHtml, /· verified /);
    const outBrowserHtml = await readFile(join(outDir, "lns", "nameswallet", "browser", "index.html"), "utf-8");
    assert.match(outBrowserHtml, /data-lns-verified="false"/);
    assert.doesNotMatch(outBrowserHtml, /· verified /);
    assert.match(outBrowserHtml, /src="\/lns\/nameswallet\/browser\/shot\.png"/);
    assert.match(outBrowserHtml, new RegExp(`src="/lns/nameswallet/_cid/${extraFrozen.cid}\\.png"`));
    assert.match(outBrowserHtml, /href="\/lns\/nameswallet\/browser\/files\/lns-browser-0\.2\.8\.lgx"/);
    assert.equal(await exists(join(outDir, "lns", "nameswallet", "_cid", `${extraFrozen.cid}.png`)), true);

    // Per-site 404.html generated with strict CSP and link back to root
    const notFound = await readFile(join(outDir, "lns", "nameswallet", "404.html"), "utf-8");
    assert.match(notFound, /No such page/);
    assert.match(notFound, /script-src 'none'/);
    assert.match(notFound, /href="\/lns\/nameswallet\/"/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("on-chain < 10 KB lns-links/1 root resolves nested storage folders, and tampered subfolder is refused", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-onchain-links-"));
  try {
    const env = createFakeEnv();
    const home = env.putBlob("<!doctype html><html><body><h1>Tiny On-Chain Root</h1></body></html>", "text/html");
    const subPage = env.putBlob("<!doctype html><html><body><h1>Sub</h1></body></html>", "text/html");
    const subDir = env.putBlob(`# lns-links/1\n# index index.html\nindex.html ${subPage.cid} ${subPage.sha256}\n`, "text/plain");
    const rootText = `# lns-links/1\n# index index.html\nindex.html ${home.cid} ${home.sha256}\nsub/ ${subDir.cid} ${subDir.sha256}\n`;

    await env.putOnChainPage("tiny", rootText, "text/vnd.logos.lns-links; version=1");

    const res = await runSnapshot({
      names: ["tiny"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(res.errors.length, 0);
    assert.equal(res.sites[0].source, "chain");
    const subOut = await readFile(join(outDir, "lns", "tiny", "sub", "index.html"), "utf-8");
    assert.match(subOut, /<h1>Sub<\/h1>/);

    // Tamper subfolder bytes -> SHA-256 mismatch refused
    env.blobs.get(subDir.cid).bytes = Buffer.from(`# lns-links/1\nindex.html ${home.cid}\n`);
    const bad = await runSnapshot({
      names: ["tiny"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(bad.errors.length, 1);
    assert.match(bad.errors[0].error, /SHA-256 mismatch/i);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("Finding 2 & 11: snapshot refuses .xhtml/.xml/.svgz active assets and unhashed 2-column lns-links/1 entries", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-sec-"));
  try {
    const env = createFakeEnv();
    const xssXhtml = env.putBlob(
      '<html xmlns="http://www.w3.org/1999/xhtml"><script>alert(document.domain)</script></html>',
      "application/xhtml+xml",
    );
    const xhtmlRoot = env.putBlob(
      `# lns-links/1\nxss.xhtml ${xssXhtml.cid} ${xssXhtml.sha256}\n`,
      "text/plain",
    );
    await env.putName("badxhtml", {
      cid: xhtmlRoot.cid,
      "cid.sha256": xhtmlRoot.sha256,
      "cid.type": "links",
    });

    const svgzBlob = env.putBlob(Buffer.from([0x1f, 0x8b, 0x08, 0x00]), "image/svg+xml");
    const svgzRoot = env.putBlob(
      `# lns-links/1\nicon.svgz ${svgzBlob.cid} ${svgzBlob.sha256}\n`,
      "text/plain",
    );
    await env.putName("badsvgz", {
      cid: svgzRoot.cid,
      "cid.sha256": svgzRoot.sha256,
      "cid.type": "links",
    });

    // Finding 11: 2-column unhashed file entry is refused by default
    const okPage = env.putBlob("<!doctype html><html><body><h1>Hi</h1></body></html>", "text/html");
    const unhashedRoot = env.putBlob(`# lns-links/1\nindex.html ${okPage.cid}\n`, "text/plain");
    await env.putName("unhashed", {
      cid: unhashedRoot.cid,
      "cid.sha256": unhashedRoot.sha256,
      "cid.type": "links",
    });

    const res = await runSnapshot({
      names: ["badxhtml", "badsvgz", "unhashed"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(res.errors.length, 3);
    assert.match(res.errors[0].error, /active XML\/compressed-SVG/i);
    assert.match(res.errors[1].error, /active XML\/compressed-SVG/i);
    assert.match(res.errors[2].error, /missing sha256/i);
    assert.equal(await exists(join(outDir, "lns", "badxhtml")), false);
    assert.equal(await exists(join(outDir, "lns", "unhashed")), false);

    // With explicit allowUnverified: true, unhashed 2-column site builds with unverified banner (never "verified")
    const allowed = await runSnapshot({
      names: ["unhashed"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      allowUnverified: true,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(allowed.errors.length, 0);
    const unverifiedHtml = await readFile(join(outDir, "lns", "unhashed", "index.html"), "utf-8");
    assert.match(unverifiedHtml, /data-lns-verified="false"/);
    assert.doesNotMatch(unverifiedHtml, /· verified /);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("Finding 19: folder list bytes count toward maxSiteBytes, index aliases respect maxSiteFiles, and empty dirs are pruned", async () => {
  const outDir = await mkdtemp(join(tmpdir(), "lns-gw-f19-"));
  try {
    const env = createFakeEnv();
    const home = env.putBlob("<h1>Home</h1>", "text/html");
    const subPage = env.putBlob("<h1>Sub</h1>", "text/html");
    const subDir = env.putBlob(
      `# lns-links/1\n# index home.html\nhome.html ${subPage.cid} ${subPage.sha256}\n`,
      "text/plain",
    );
    const rootDir = env.putBlob(
      `# lns-links/1\n# index index.html\nindex.html ${home.cid} ${home.sha256}\nsub/ ${subDir.cid} ${subDir.sha256}\n`,
      "text/plain",
    );
    await env.putName("limits", {
      cid: rootDir.cid,
      "cid.sha256": rootDir.sha256,
      "cid.type": "links",
    });

    // 1. Folder list bytes count toward maxSiteBytes (root ~233B + sub ~134B = ~367B > 300B,
    //    whereas root + files alone would be ~258B < 300B)
    const byteCapped = await runSnapshot({
      names: ["limits"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      maxSiteBytes: 300,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(byteCapped.errors.length, 1);
    assert.match(byteCapped.errors[0].error, /exceeds/i);

    // 2. Custom `# index home.html` alias in `/sub` pushes total files from 2 to 3 -> refused when maxSiteFiles = 2
    const fileCapped = await runSnapshot({
      names: ["limits"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      maxSiteFiles: 2,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(fileCapped.errors.length, 1);
    assert.match(fileCapped.errors[0].error, /exceeds maximum of 2 files/i);

    // 3. With maxSiteFiles = 3, build succeeds and creates `sub/`
    const ok1 = await runSnapshot({
      names: ["limits"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      maxSiteFiles: 3,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(ok1.errors.length, 0);
    assert.equal(await exists(join(outDir, "lns", "limits", "sub")), true);

    // 4. Remove `sub/` from the site -> syncSiteDirectory removes the stale files AND prunes empty `sub/` directory
    const rootNoSub = env.putBlob(
      `# lns-links/1\n# index index.html\nindex.html ${home.cid} ${home.sha256}\n`,
      "text/plain",
    );
    await env.putName("limits", {
      cid: rootNoSub.cid,
      "cid.sha256": rootNoSub.sha256,
      "cid.type": "links",
    });
    const ok2 = await runSnapshot({
      names: ["limits"],
      outDir,
      sequencer: FAKE_CHAIN_URL,
      registry: DEFAULT_CONFIG.registry,
      storageApi: FAKE_STORAGE_URL,
      maxSiteFiles: 3,
      fetchImpl: env.fetchImpl,
    });
    assert.equal(ok2.errors.length, 0);
    assert.equal(await exists(join(outDir, "lns", "limits", "sub")), false);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});
