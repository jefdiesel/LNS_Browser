import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  DEFAULT_CONFIG,
  deriveName,
  encodeNameRecord,
  encodeProfile,
  parseLnsUrl,
  recordAddress,
  seal,
} from "../src/lns.js";
import { StorageClient, bareMimeType, sha256Hex } from "../src/storage.js";
import { buildPublishDeepLink, injectLnsBridge, publishPath } from "../src/manifest.js";
import { createBrowserServer } from "../src/server.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_SITE_DIR = join(__dirname, "..", "examples", "demo-site");

/** Starts a mock Logos Storage node implementing POST /data and GET /data/:cid/network/stream. */
async function startMockStorage() {
  const blobs = new Map();
  let seq = 0;

  const server = createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/api/storage/v1/debug/info") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "16Uiu2HAmMockStoragePeer" }));
      return;
    }
    if (req.method === "POST" && req.url === "/api/storage/v1/data") {
      const ct = req.headers["content-type"] || "";
      if (ct.includes(";")) {
        res.writeHead(422, { "Content-Type": "text/plain" });
        res.end(`The MIME type '${ct}' is not valid`);
        return;
      }
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const buf = Buffer.concat(chunks);
      seq += 1;
      const cid = `zDvMockCid${String(seq).padStart(4, "0")}${sha256Hex(buf).slice(0, 12)}`;
      blobs.set(cid, {
        bytes: buf,
        contentType: ct || "application/octet-stream",
      });
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(cid);
      return;
    }
    const m = req.url?.match(/^\/api\/storage\/v1\/data\/([A-Za-z0-9]+)(?:\/network\/stream)?$/);
    if (req.method === "GET" && m) {
      const item = blobs.get(m[1]);
      if (!item) {
        res.writeHead(404);
        res.end("not found");
        return;
      }
      res.writeHead(200, { "Content-Type": item.contentType, "Content-Length": item.bytes.length });
      res.end(item.bytes);
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  return {
    baseUrl: `http://127.0.0.1:${port}/api/storage/v1`,
    blobs,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

/** Starts a mock LEZ 0.4 rc3 sequencer answering `getAccountView` with `actor_states`. */
async function startMockSequencer(programId) {
  const accounts = new Map();

  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = JSON.parse(Buffer.concat(chunks).toString("utf-8"));
    if (body.method === "getAccountView") {
      const { account_id, program_account_id } = body.params[0];
      const stateBytes = accounts.get(account_id);
      const result = stateBytes
        ? { data: { actor_states: { [program_account_id]: Array.from(stateBytes) } } }
        : null;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      return;
    }
    res.writeHead(400);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;

  return {
    rpcUrl: `http://127.0.0.1:${port}/`,
    async putName(name, texts) {
      const { id, key } = await deriveName(name);
      const addr = await recordAddress(programId, id);
      const sealed = await seal(key, encodeProfile({ name, texts }), "record");
      const recordBytes = encodeNameRecord({ version: 6, sealed });
      accounts.set(addr, recordBytes);
      return addr;
    },
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

test("parseLnsUrl handles lns://, .lez, cid://, and sanitizes traversal", () => {
  assert.deepEqual(parseLnsUrl("lns://Jef.lez/docs/../about.html?x=1#top"), {
    kind: "lns",
    name: "jef",
    path: "/about.html",
    canonical: "lns://jef/about.html",
  });
  assert.deepEqual(parseLnsUrl("cid://zDvZRwzm8K4nJ2a7q9WTqN1"), {
    kind: "cid",
    cid: "zDvZRwzm8K4nJ2a7q9WTqN1",
    path: "/",
    canonical: "cid://zDvZRwzm8K4nJ2a7q9WTqN1",
  });
  assert.throws(() => parseLnsUrl("not a valid name!"));
});

test("end-to-end: publish multi-file site -> bind on-chain LNS -> resolve & serve -> reject tampering & DNS rebinding", async () => {
  const registry = DEFAULT_CONFIG.registry;
  const mockStorage = await startMockStorage();
  const mockSeq = await startMockSequencer(registry);
  const browser = createBrowserServer({
    port: 0,
    sequencer: mockSeq.rpcUrl,
    registry,
    storageApi: mockStorage.baseUrl,
    cacheTtlMs: 0,
  });

  try {
    const { url: baseUrl, port } = await browser.listen(0);

    // 1. Publish multi-file demo site to Logos Storage
    const storageClient = new StorageClient(mockStorage.baseUrl);
    const published = await publishPath(storageClient, DEMO_SITE_DIR, { title: "Demo Site" });
    assert.equal(published.mode, "manifest");
    assert.equal(published.files.length, 3);
    assert.ok(published.rootCid.startsWith("zDvMockCid"));

    // 2. Write the root CID + SHA-256 onto the mock LEZ 0.4 chain under `demo`
    await mockSeq.putName("demo", {
      display: "Demo Site",
      cid: published.rootCid,
      "cid.sha256": published.sha256,
      "cid.type": "manifest",
    });

    // 3. Resolve lns://demo via /api/resolve
    const resolveRes = await fetch(`${baseUrl}/api/resolve?url=${encodeURIComponent("lns://demo")}`);
    assert.equal(resolveRes.status, 200);
    const resolved = await resolveRes.json();
    assert.equal(resolved.ok, true);
    assert.equal(resolved.mode, "manifest");
    assert.equal(resolved.verified, true);
    assert.equal(resolved.cid, published.rootCid);
    assert.equal(resolved.sha256, published.sha256);

    // 4. Serve /site/demo/ (index.html), /site/demo/about.html, and /site/demo/style.css
    const indexRes = await fetch(`${baseUrl}/site/demo/`);
    assert.equal(indexRes.status, 200);
    assert.match(indexRes.headers.get("content-type"), /^text\/html/);
    assert.match(indexRes.headers.get("content-security-policy"), /connect-src 'none'/);
    assert.equal(indexRes.headers.get("referrer-policy"), "no-referrer");
    const indexHtml = await indexRes.text();
    assert.match(indexHtml, /Served from On-Chain CID/);
    assert.match(indexHtml, /lns-navigate/); // navigation bridge injected

    const cssRes = await fetch(`${baseUrl}/site/demo/style.css`);
    assert.equal(cssRes.status, 200);
    assert.match(cssRes.headers.get("content-type"), /^text\/css/);
    assert.match(await cssRes.text(), /--accent/);

    const aboutRes = await fetch(`${baseUrl}/site/demo/about.html`);
    assert.equal(aboutRes.status, 200);
    assert.match(await aboutRes.text(), /Multi-File Site Manifests/);

    // 5. Tamper with the stored bytes for the root manifest -> must be rejected with SHA-256 mismatch
    mockStorage.blobs.get(published.rootCid).bytes = Buffer.from("<html>evil tampered content</html>");
    const tamperedRes = await fetch(`${baseUrl}/site/demo/`);
    assert.equal(tamperedRes.status, 502);
    assert.match(await tamperedRes.text(), /SHA-256 mismatch/);

    // 6. Anti-DNS-rebinding: non-loopback Host header must be rejected with 403
    const rawHostCheck = await new Promise((resolve, reject) => {
      import("node:http").then(({ request }) => {
        const req = request(
          { host: "127.0.0.1", port, path: "/api/config", headers: { Host: "evil.example.com" } },
          (res) => resolve(res.statusCode),
        );
        req.on("error", reject);
        req.end();
      });
    });
    assert.equal(rawHostCheck, 403);

    // 7. WYSIWYG /editor route serves self-contained HTML with zero external script/stylesheet URLs
    const editorRes = await fetch(`${baseUrl}/editor`);
    assert.equal(editorRes.status, 200);
    assert.match(editorRes.headers.get("content-type"), /^text\/html/);
    const editorHtml = await editorRes.text();
    assert.match(editorHtml, /LNS Site Builder/);
    assert.doesNotMatch(editorHtml, /<script[^>]+src=/i);
    assert.doesNotMatch(editorHtml, /<link[^>]+href="https?:/i);

    // 8. POST /api/publish returns basecamp://intent/names.publish_site deepLink
    const pubRes = await fetch(`${baseUrl}/api/publish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "helloworld", files: { "/index.html": "<h1>Hi</h1>" } }),
    });
    assert.equal(pubRes.status, 200);
    const pubData = await pubRes.json();
    assert.equal(pubData.ok, true);
    assert.match(pubData.deepLink, /^basecamp:\/\/intent\/names\.publish_site\?p=/);
    const decoded = JSON.parse(Buffer.from(pubData.deepLink.split("?p=")[1], "base64url").toString("utf-8"));
    assert.equal(decoded.name, "helloworld");
    assert.equal(decoded.cid, pubData.rootCid);
    assert.equal(decoded.sha256, pubData.sha256);
  } finally {
    await browser.close();
    await mockSeq.close();
    await mockStorage.close();
  }
});

test("injectLnsBridge intercepts both lns:// navigation and https:// external links", () => {
  const out = injectLnsBridge(Buffer.from("<html><body><a href=\"https://nameswallet.app/browser\">Go</a></body></html>")).toString("utf-8");
  assert.match(out, /lns-navigate/);
  assert.match(out, /lns-external-link/);
  const link = buildPublishDeepLink({ name: "lns://HelloWorld.lez", html: "<h1>Hi</h1>" });
  const payload = JSON.parse(Buffer.from(link.split("?p=")[1], "base64url").toString("utf-8"));
  assert.deepEqual(payload, { name: "helloworld", html: "<h1>Hi</h1>" });
});

test("StorageClient refuses publishing to stand-in local-storage.js and reports unreachable CIDs plainly", async () => {
  assert.equal(DEFAULT_CONFIG.storageApi, "");

  // Stand-in stub server (reports mock: true + 16Uiu2HAmLocalLogosStorageSeed)
  const standin = createServer((req, res) => {
    if (req.url === "/api/storage/v1/debug/info") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ id: "16Uiu2HAmLocalLogosStorageSeed", mock: true }));
      return;
    }
    res.writeHead(404);
    res.end("not found");
  });
  await new Promise((r) => standin.listen(0, "127.0.0.1", r));
  const port = standin.address().port;
  try {
    const client = new StorageClient(`http://127.0.0.1:${port}/api/storage/v1`);
    await assert.rejects(() => client.upload(Buffer.from("<h1>Hi</h1>")), /Refused to publish to the stand-in/i);
    await assert.rejects(
      () => client.download("z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP"),
      /not on any Logos Storage node this browser can reach/i,
    );
    const unconfigured = new StorageClient("");
    await assert.rejects(
      () => unconfigured.download("z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP"),
      /No Logos Storage node is configured/i,
    );
  } finally {
    await new Promise((r) => standin.close(r));
  }
});

test("StorageClient.upload strips MIME parameters (e.g. charset) while publishPath keeps them in the manifest", async () => {
  assert.equal(bareMimeType("text/html; charset=utf-8"), "text/html");
  assert.equal(bareMimeType("Text/CSS; charset=UTF-8; foo=bar"), "text/css");
  assert.equal(bareMimeType("application/vnd.logos.site-manifest+json"), "application/vnd.logos.site-manifest+json");
  assert.equal(bareMimeType(""), "application/octet-stream");

  const mockStorage = await startMockStorage();
  try {
    const client = new StorageClient(mockStorage.baseUrl);
    const uploaded = await client.upload(Buffer.from("<h1>Hi</h1>"), {
      filename: "index.html",
      contentType: "text/html; charset=utf-8",
    });
    assert.equal(mockStorage.blobs.get(uploaded.cid).contentType, "text/html");

    const published = await publishPath(client, DEMO_SITE_DIR, { title: "Demo Site" });
    const manifestBlob = mockStorage.blobs.get(published.rootCid);
    assert.equal(manifestBlob.contentType, "application/vnd.logos.site-manifest+json");
    const manifest = JSON.parse(manifestBlob.bytes.toString("utf-8"));
    assert.equal(manifest.files["/index.html"].contentType, "text/html; charset=utf-8");
    assert.equal(mockStorage.blobs.get(manifest.files["/index.html"].cid).contentType, "text/html");
  } finally {
    await mockStorage.close();
  }
});
