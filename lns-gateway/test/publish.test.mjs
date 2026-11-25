import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sha256Hex } from "../derive.mjs";
import { parseLinksList, resolveLinksTree } from "../links.mjs";
import { formatPublishPlan, publishSite } from "../publish.mjs";
import { STANDIN_SEED_PEER_ID, StorageClient } from "../storage.mjs";

const FAKE_STORAGE_URL = "fake://storage/api/storage/v1";

function createFakeStorage({ rejectMimeTypes = new Set(), isStandin = false } = {}) {
  const blobs = new Map();
  const uploads = [];
  let seq = 0;

  async function fetchImpl(url, init = {}) {
    const target = String(url);
    if (!target.startsWith(FAKE_STORAGE_URL)) {
      throw new Error(`unexpected fetch URL: ${target}`);
    }
    const route = target.slice(FAKE_STORAGE_URL.length);
    const method = (init.method || "GET").toUpperCase();

    if (route === "/debug/info" && method === "GET") {
      return new Response(
        JSON.stringify({
          id: isStandin ? STANDIN_SEED_PEER_ID : "16Uiu2HAmRealTestStorageNode111111111111111111",
          mock: isStandin,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }

    if (route === "/data" && method === "POST") {
      const ct = String(init.headers?.["Content-Type"] || "");
      // Real Logos Storage nodes reject MIME parameters (`; charset=...`) with 422
      if (ct.includes(";") || rejectMimeTypes.has(ct)) {
        return new Response(`unsupported content-type: ${ct}`, { status: 422 });
      }
      const bytes = Buffer.from(init.body);
      const hash = sha256Hex(bytes);
      seq += 1;
      const cid = `z4W2jPub${String(seq).padStart(4, "0")}${hash.slice(0, 20)}`;
      blobs.set(cid, { bytes, contentType: ct });
      uploads.push({ cid, contentType: ct, size: bytes.length, sha256: hash });
      return new Response(cid, { status: 200, headers: { "Content-Type": "text/plain" } });
    }

    const dm = route.match(/^\/data\/([A-Za-z0-9]+)(?:\/network\/stream)?$/);
    if (dm && method === "GET") {
      const item = blobs.get(dm[1]);
      if (!item) return new Response("not found", { status: 404 });
      return new Response(item.bytes, {
        status: 200,
        headers: { "Content-Type": item.contentType },
      });
    }

    return new Response("not found", { status: 404 });
  }

  return { blobs, uploads, fetchImpl };
}

async function writeSampleSite(dir) {
  await mkdir(join(dir, "assets"), { recursive: true });
  await mkdir(join(dir, "browser", "files"), { recursive: true });
  await writeFile(join(dir, "index.html"), "<!doctype html><html><body><h1>Home</h1></body></html>");
  await writeFile(join(dir, "assets", "site.css"), "body { color: #111; }\n");
  await writeFile(join(dir, "browser", "index.html"), "<!doctype html><html><body><h1>Browser v1</h1></body></html>");
  await writeFile(join(dir, "browser", "shot.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  await writeFile(join(dir, "browser", "files", "lns-browser-0.2.8.lgx"), Buffer.from("LGX-BINARY-V1"));
  // Dotfiles should be skipped automatically
  await writeFile(join(dir, ".DS_Store"), "ignored");
}

test("full publish builds bottom-up per-folder lists, prints names profile command, and resolves cleanly", async () => {
  const dir = await mkdtemp(join(tmpdir(), "lns-pub-full-"));
  try {
    await writeSampleSite(dir);
    const fake = createFakeStorage({ rejectMimeTypes: new Set(["text/css"]) });
    const storage = new StorageClient(FAKE_STORAGE_URL, { fetchImpl: fake.fetchImpl });

    const res = await publishSite(dir, "nameswallet", {
      storage,
      noDiff: true,
      title: "Names Wallet",
    });

    assert.equal(res.unchanged, false);
    assert.equal(res.totalFiles, 5);
    assert.equal(res.totalFolders, 4); // /, /assets, /browser, /browser/files
    assert.equal(res.uploadedFiles.length, 5);
    assert.equal(res.uploadedFolders.length, 4);
    assert.equal(res.reusedFiles.length, 0);
    assert.equal(res.reusedFolders.length, 0);

    // Rejected MIME type (`text/css`) fell back cleanly to `application/octet-stream`
    const cssUpload = res.uploadedFiles.find((f) => f.path === "/assets/site.css");
    assert.equal(cssUpload.contentType, "application/octet-stream");
    // No upload ever sent a MIME parameter (`; charset=...`)
    assert.ok(fake.uploads.every((u) => !u.contentType.includes(";")));

    // Exact names profile command
    assert.equal(
      res.namesCommand,
      `names profile nameswallet --cid ${res.rootCid} --set cid.sha256=${res.rootSha256} --set cid.type=links`,
    );
    assert.ok(res.deepLink.startsWith("basecamp://intent/names.publish_site?p="));

    // Verify published tree resolves every path via `resolveLinksTree`
    const rootList = parseLinksList(res.rootText);
    assert.equal(rootList.ok, true);
    const loader = async (cid) => {
      const item = fake.blobs.get(cid);
      assert.ok(item, `missing folder CID ${cid}`);
      return parseLinksList(item.bytes.toString("utf-8"));
    };
    const rBrowser = await resolveLinksTree(rootList, "/browser", loader);
    assert.equal(rBrowser.ok, true);
    assert.equal(rBrowser.resolvedPath, "/browser/index.html");
    const rLgx = await resolveLinksTree(rootList, "/browser/files/lns-browser-0.2.8.lgx", loader);
    assert.equal(rLgx.ok, true);
    assert.equal(rLgx.entry.sha256, sha256Hex(Buffer.from("LGX-BINARY-V1")));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("one-file change re-uploads ONLY that file and its ancestor folder lists; unchanged tree uploads nothing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "lns-pub-diff-"));
  try {
    await writeSampleSite(dir);
    const fake = createFakeStorage();
    const storage = new StorageClient(FAKE_STORAGE_URL, { fetchImpl: fake.fetchImpl });

    // 1. Initial publish
    const pub1 = await publishSite(dir, "nameswallet", { storage, noDiff: true });
    const uploadsAfterFirst = fake.uploads.length;
    assert.equal(uploadsAfterFirst, 9); // 5 files + 4 folder lists

    // 2. Re-publish unchanged tree -> 0 uploads!
    const pub2 = await publishSite(dir, "nameswallet", {
      storage,
      prevRootCid: pub1.rootCid,
      prevRootSha256: pub1.rootSha256,
    });
    assert.equal(pub2.unchanged, true);
    assert.equal(pub2.rootCid, pub1.rootCid);
    assert.equal(pub2.uploadedFiles.length, 0);
    assert.equal(pub2.uploadedFolders.length, 0);
    assert.equal(pub2.reusedFiles.length, 5);
    assert.equal(pub2.reusedFolders.length, 4);
    assert.equal(fake.uploads.length, uploadsAfterFirst);

    // 3. Edit ONLY `/browser/files/lns-browser-0.2.8.lgx`
    await writeFile(join(dir, "browser", "files", "lns-browser-0.2.8.lgx"), Buffer.from("LGX-BINARY-V2"));
    const pub3 = await publishSite(dir, "nameswallet", {
      storage,
      prevRootCid: pub1.rootCid,
      prevRootSha256: pub1.rootSha256,
    });
    assert.equal(pub3.unchanged, false);
    assert.notEqual(pub3.rootCid, pub1.rootCid);
    // Only the 1 changed file + its 3 ancestor lists (/browser/files, /browser, /) were uploaded!
    assert.deepEqual(
      pub3.uploadedFiles.map((f) => f.path),
      ["/browser/files/lns-browser-0.2.8.lgx"],
    );
    assert.deepEqual(
      pub3.uploadedFolders.map((d) => d.path),
      ["/browser/files", "/browser", "/"],
    );
    // `/assets` folder list and the other 4 files were reused untouched!
    assert.deepEqual(
      pub3.reusedFolders.map((d) => d.path),
      ["/assets"],
    );
    assert.equal(pub3.reusedFiles.length, 4);
    assert.equal(fake.uploads.length, uploadsAfterFirst + 4);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--dry-run prints the upload plan without uploading anything, and mock storage is refused", async () => {
  const dir = await mkdtemp(join(tmpdir(), "lns-pub-dry-"));
  try {
    await writeSampleSite(dir);
    const fake = createFakeStorage();
    const storage = new StorageClient(FAKE_STORAGE_URL, { fetchImpl: fake.fetchImpl });

    const dry = await publishSite(dir, "nameswallet", { storage, noDiff: true, dryRun: true });
    assert.equal(dry.dryRun, true);
    assert.equal(fake.uploads.length, 0);
    assert.equal(dry.uploadedFiles.length, 5);
    assert.equal(dry.uploadedFolders.length, 4);
    assert.equal(dry.rootCid, null);
    assert.equal(dry.deepLink, null);
    const plan = formatPublishPlan(dry);
    assert.match(plan, /Dry run for lns:\/\/nameswallet/);
    assert.match(plan, /names profile nameswallet/);
    assert.match(plan, /<CID-computed-on-real-publish>/);
    assert.doesNotMatch(plan, /DRYRUNDIR|DRYRUNFILE|basecamp:\/\//);

    // Stand-in mock storage is refused on real publish
    const mockFake = createFakeStorage({ isStandin: true });
    const mockStorage = new StorageClient(FAKE_STORAGE_URL, { fetchImpl: mockFake.fetchImpl });
    await assert.rejects(
      () => publishSite(dir, "nameswallet", { storage: mockStorage, noDiff: true }),
      /Refused to publish to a stand-in mock/i,
    );

    // On-chain root option works when root list is under 10 KB
    const onchain = await publishSite(dir, "nameswallet", { storage, noDiff: true, onChain: true });
    assert.equal(onchain.onChain, true);
    assert.equal(onchain.rootCid, null);
    assert.match(onchain.namesCommand, /names set-page nameswallet --content-type "text\/vnd\.logos\.lns-links; version=1"/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("Finding 9 & 13: 2-column folder reuse, symlink refusal, non-ASCII filenames, --prev-root errors, and streaming cap", async () => {
  const dir = await mkdtemp(join(tmpdir(), "lns-pub-f13-"));
  try {
    await mkdir(join(dir, "assets"), { recursive: true });
    await writeFile(join(dir, "index.html"), "<h1>Home</h1>");
    await writeFile(join(dir, "café.html"), "<h1>Café</h1>");
    await writeFile(join(dir, "assets", "site.css"), "body{color:#111}");

    const fake = createFakeStorage();
    const storage = new StorageClient(FAKE_STORAGE_URL, { fetchImpl: fake.fetchImpl });

    // Non-ASCII filename (`café.html`) uploads cleanly without ByteString header crash
    const pub1 = await publishSite(dir, "demo", { storage, noDiff: true });
    assert.equal(pub1.totalFiles, 3);
    assert.ok(pub1.uploadedFiles.some((f) => f.path === "/café.html"));

    // Build a 2-column root list referencing `assets/` WITHOUT a sha256 column
    const assetsFolder = pub1.uploadedFolders.find((d) => d.path === "/assets");
    const rootParsed = parseLinksList(pub1.rootText);
    const twoColRootLines = [
      "# lns-links/1",
      "# index index.html",
      `assets/ ${assetsFolder.cid}`,
      `café.html ${rootParsed.byName["café.html"].cid} ${rootParsed.byName["café.html"].sha256}`,
      `index.html ${rootParsed.byName["index.html"].cid} ${rootParsed.byName["index.html"].sha256}`,
      "",
    ].join("\n");
    const twoColRootBlob = await storage.upload(Buffer.from(twoColRootLines, "utf-8"), {
      filename: "lns-links.txt",
      contentType: "text/plain",
    });

    // Diffing against the 2-column root reuses `/assets` folder list instead of re-uploading it!
    const pub2 = await publishSite(dir, "demo", {
      storage,
      prevRootCid: twoColRootBlob.cid,
    });
    assert.deepEqual(
      pub2.reusedFolders.map((d) => d.path),
      ["/assets"],
    );
    assert.equal(pub2.uploadedFiles.length, 0);

    // Explicit --prev-root with missing/broken subfolder propagates error instead of silently ignoring
    const brokenRoot = await storage.upload(
      Buffer.from("# lns-links/1\nbroken/ z4W2jMissingDir0000000000000000000000000000000000\n", "utf-8"),
      { filename: "lns-links.txt", contentType: "text/plain" },
    );
    await assert.rejects(
      () => publishSite(dir, "demo", { storage, prevRootCid: brokenRoot.cid }),
      /Failed to walk --prev-root/i,
    );

    // Symlink in publish folder is explicitly rejected (never silently skipped)
    await symlink(join(dir, "index.html"), join(dir, "latest.html"));
    await assert.rejects(
      () => publishSite(dir, "demo", { storage, noDiff: true }),
      /Refused to publish symlink/i,
    );

    // Finding 9: StorageClient.download aborts oversized streaming bodies before buffering all chunks
    let chunksRead = 0;
    const hugeStreamStorage = new StorageClient(FAKE_STORAGE_URL, {
      fetchImpl: async () => {
        const stream = new ReadableStream({
          pull(controller) {
            chunksRead += 1;
            controller.enqueue(new Uint8Array(1024));
            if (chunksRead >= 500) controller.close();
          },
        });
        return new Response(stream, { status: 200, headers: { "Content-Type": "application/octet-stream" } });
      },
    });
    await assert.rejects(
      () => hugeStreamStorage.download("z4W2jHugeBlob000000000000000000000000000000000000", { maxBytes: 4096 }),
      /exceeds limit of 4096 bytes/i,
    );
    assert.ok(chunksRead < 20, `expected early stream cancel, got ${chunksRead} chunks`);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
