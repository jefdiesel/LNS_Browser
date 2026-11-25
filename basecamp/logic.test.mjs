import test from "node:test";
import assert from "node:assert/strict";
import {
  answer,
  base64DecodedLength,
  base64ToBytes,
  buildLoopbackEntryUrl,
  buildProfileEntries,
  buildPublishDeepLink,
  buildSaveTargetPath,
  bytesToBase64,
  bytesToUtf8,
  bytesToUtf8Strict,
  canTabGoBack,
  canTabGoForward,
  clampWindowGeometry,
  clampZoomPercent,
  classifyWebViewUrl,
  closeTabState,
  cmpCodePoint,
  countTextMatches,
  createSafeMap,
  createTab,
  drawSvgToCanvas,
  escapeHtml,
  extractRecentSites,
  extractSiteInfo,
  extractSvgCanvasOps,
  findPinnedSha256,
  formatLinksList,
  formatStorageFetchError,
  formatTabTitle,
  formatUnreachableCidError,
  formatWindowTitle,
  getCachedImageEntry,
  getCachedLinksEntry,
  isArrayLike,
  isBinaryDownloadPath,
  isBookmarked,
  isBusyReply,
  isExternalHttpsUrl,
  isLinksContentType,
  isLinksListText,
  isPort8080Url,
  isStaleDownload,
  isValidName,
  isValidSegmentName,
  MAX_LINKS_ENTRIES,
  MAX_LINKS_LIST_BYTES,
  normalizeModuleValue,
  normalizeName,
  normalizePath,
  parseLinksList,
  parseQueryString,
  parseStorageEventPayload,
  parseStoragePeers,
  parseUrl,
  pushTabHistory,
  recordHistoryEntry,
  resolveLinksSync,
  resolveRelativeSitePath,
  safeMapSet,
  sanitizeHtmlFallback,
  sha256HexUtf8,
  shortHash,
  sitePathFromLoopbackUrl,
  sniffImageMimeBytes,
  stepLinksResolve,
  toArray,
  toggleBookmark,
  utf8ToBytes,
  validateSaveFilename,
} from "./qml/logic.mjs";

test("parseUrl normalizes lns://, .lez, @name, and cid:// without ES2018 lookbehind", () => {
  assert.deepEqual(parseUrl("lns://helloworld"), {
    ok: true,
    kind: "lns",
    name: "helloworld",
    path: "/",
    siteBase: "lns://helloworld",
    canonical: "lns://helloworld",
  });
  assert.deepEqual(parseUrl("lns://Jef.lez/about.html"), {
    ok: true,
    kind: "lns",
    name: "jef",
    path: "/about.html",
    siteBase: "lns://jef",
    canonical: "lns://jef/about.html",
  });
  assert.deepEqual(parseUrl("@logos"), {
    ok: true,
    kind: "lns",
    name: "logos",
    path: "/",
    siteBase: "lns://logos",
    canonical: "lns://logos",
  });
  assert.deepEqual(parseUrl("a"), {
    ok: true,
    kind: "lns",
    name: "a",
    path: "/",
    siteBase: "lns://a",
    canonical: "lns://a",
  });
  assert.equal(parseUrl("-bad").ok, false);
  assert.equal(parseUrl("bad-").ok, false);
  assert.equal(parseUrl("bad name!").ok, false);
  assert.deepEqual(parseUrl("cid://zDvZRwzm8K4nJ2a7q9WTqN1/index.html"), {
    ok: true,
    kind: "cid",
    cid: "zDvZRwzm8K4nJ2a7q9WTqN1",
    path: "/index.html",
    siteBase: "cid://zDvZRwzm8K4nJ2a7q9WTqN1",
    canonical: "cid://zDvZRwzm8K4nJ2a7q9WTqN1/index.html",
  });
});

test("isExternalHttpsUrl allows safe https:// and blocks unsafe schemes", () => {
  assert.equal(isExternalHttpsUrl("https://nameswallet.app/browser"), true);
  assert.equal(isExternalHttpsUrl("http://nameswallet.app/browser"), false);
  assert.equal(isExternalHttpsUrl("https://user:pass@evil.com/x"), false);
  assert.equal(isExternalHttpsUrl("javascript:alert(1)"), false);
  assert.equal(isExternalHttpsUrl("lns://helloworld"), false);
});

test("buildPublishDeepLink encodes basecamp://intent/names.publish_site payload", () => {
  const link = buildPublishDeepLink({
    name: "lns://HelloWorld.lez",
    cid: "z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP",
    sha256: "cf7f4efa13d714d8e7b4af39d8e3c6bf8ba07daf938ba7c42b78c2cc8790d490",
    site_type: "single",
    return_app: "lns_browser",
  });
  assert.ok(link.startsWith("basecamp://intent/names.publish_site?p="));
  const encoded = link.split("?p=")[1];
  const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  assert.deepEqual(decoded, {
    name: "helloworld",
    cid: "z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP",
    sha256: "cf7f4efa13d714d8e7b4af39d8e3c6bf8ba07daf938ba7c42b78c2cc8790d490",
    site_type: "single",
    return_app: "lns_browser",
  });
  assert.equal(normalizeName("lns://HelloWorld.lez/foo"), "helloworld");
  assert.equal(isValidName("helloworld"), true);
});

test("extractSiteInfo reads cid, cid.sha256, and cid.type", () => {
  const hash = "a".repeat(64);
  const info = extractSiteInfo({
    name: "jef",
    texts: {
      display: "Jef",
      cid: "zDvZRwzm8K4nJ2a7q9WTqN1",
      "cid.sha256": hash.toUpperCase(),
      "cid.type": "manifest",
    },
  });
  assert.equal(info.hasSite, true);
  assert.equal(info.cid, "zDvZRwzm8K4nJ2a7q9WTqN1");
  assert.equal(info.sha256, hash);
  assert.equal(info.siteType, "manifest");
});

test("buildProfileEntries validates CID and SHA-256", () => {
  const ok = buildProfileEntries("zDvZRwzm8K4nJ2a7q9WTqN1", "b".repeat(64), "manifest");
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.entries, {
    cid: "zDvZRwzm8K4nJ2a7q9WTqN1",
    "cid.sha256": "b".repeat(64),
    "cid.type": "manifest",
  });
  assert.equal(buildProfileEntries("bad/cid", "", "").ok, false);
  assert.equal(buildProfileEntries("zDvZRwzm8K4nJ2a7q9WTqN1", "not-hex", "").ok, false);
});

test("answer + shortHash", () => {
  assert.deepEqual(answer(JSON.stringify({ success: true, value: { name: "jef" } })), { ok: true, value: { name: "jef" } });
  assert.deepEqual(answer(JSON.stringify({ code: "invalid_args", message: "expected [tstr] array" })), {
    ok: false,
    error: "expected [tstr] array",
  });
  assert.deepEqual(answer({ success: false, message: "exact bridge error" }), {
    ok: false,
    error: "exact bridge error",
  });
  assert.equal(shortHash("0123456789abcdef0123456789abcdef", 6, 4), "012345...cdef");
});

test("storage_module helpers: sha256, base64, port 8080 check, unreachable CID error, and HTML fallback", () => {
  assert.equal(sha256HexUtf8("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  const roundtrip = bytesToUtf8(base64ToBytes(bytesToBase64(utf8ToBytes("Hello → LNS 🌐"))));
  assert.equal(roundtrip, "Hello → LNS 🌐");
  assert.equal(isPort8080Url("http://127.0.0.1:8080/api/storage/v1"), true);
  assert.equal(isPort8080Url("http://localhost:8080"), true);
  assert.equal(isPort8080Url("http://127.0.0.1:8089/api/storage/v1"), false);
  const msg = formatUnreachableCidError("z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP", "HTTP 404");
  assert.match(msg, /not on any Logos Storage node this browser can reach/i);
  // Never rewrite bridge/argument refusals as "CID not reachable"
  const refused = formatUnreachableCidError(
    "z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP",
    "Call refused: expected integer at arg 2, got number",
  );
  assert.equal(refused, "Call refused: expected integer at arg 2, got number");
  // names.resolve busy detection
  assert.equal(isBusyReply(JSON.stringify({ success: false, busy: true, error: "busy" }), "busy"), true);
  assert.equal(isBusyReply({ success: false, error: "Names module is busy" }, "Names module is busy"), true);
  assert.equal(isBusyReply({ success: false, error: "not found" }, "not found"), false);
  const clean = sanitizeHtmlFallback(
    `<html><head><style>body{background:#fff;color:#111} a{color:#0055ff} .hero{fill:#0055ff} .shadow{fill:#b8d0ff}</style></head><body><h1 class="sr">Hi</h1><svg class="hero" viewBox="0 0 63 8" aria-label="HELLO WORLD"><defs><path id="px" d="M0 0h1v7h-1z"/></defs><use class="shadow" href="#px" x="0.6" y="0.6"/><use href="#px" x="0" y="0"/></svg><p><a href="https://nameswallet.app/browser">Go &rarr;</a></p></body></html>`,
    "lns://helloworld",
  );
  assert.equal(clean.bg_color, "#ffffff");
  assert.equal(clean.fg_color, "#111111");
  assert.equal(clean.link_color, "#0055ff");
  const svgBlock = clean.blocks.find((b) => b.kind === "svg");
  assert.ok(svgBlock);
  assert.equal(svgBlock.ops.length, 2);
  assert.equal(svgBlock.ops[0].fill, "#b8d0ff");
  assert.equal(svgBlock.ops[1].fill, "#0055ff");
  assert.match(clean.html, /https:\/\/nameswallet\.app\/browser/);
  assert.match(clean.html, /Go →/);

  // Verify drawSvgToCanvas traces paths and fills both shadow and foreground layers
  const calls = [];
  const mockCtx = {
    globalAlpha: 1,
    fillStyle: "",
    clearRect: (...a) => calls.push(["clearRect", ...a]),
    save: () => calls.push(["save"]),
    restore: () => calls.push(["restore"]),
    scale: (...a) => calls.push(["scale", ...a]),
    translate: (...a) => calls.push(["translate", ...a]),
    beginPath: () => calls.push(["beginPath"]),
    moveTo: (...a) => calls.push(["moveTo", ...a]),
    lineTo: (...a) => calls.push(["lineTo", ...a]),
    closePath: () => calls.push(["closePath"]),
    fill: () => calls.push(["fill", mockCtx.fillStyle]),
    fillRect: (...a) => calls.push(["fillRect", ...a]),
    arc: (...a) => calls.push(["arc", ...a]),
  };
  drawSvgToCanvas(mockCtx, svgBlock, 630, 80);
  assert.deepEqual(calls.filter((c) => c[0] === "fill"), [
    ["fill", "#b8d0ff"],
    ["fill", "#0055ff"],
  ]);
  assert.ok(calls.some((c) => c[0] === "scale" && c[1] === 10 && c[2] === 10));
  assert.ok(calls.some((c) => c[0] === "lineTo" && c[1] === 1 && c[2] === 7));

  const peersOk = parseStoragePeers(
    "# seed peer\n16Uiu2HAm3xPbYz2zsq5XVGDCMqKhhNXZWyYV6WLVv3yzzUiRJWnW /ip4/178.128.140.206/tcp/8070\n\n16Uiu2HAmVFXLh9fs5mExDDwzsah2rWdiHR2Fy3cPmF5xPx29vrbB /ip4/129.212.221.44/tcp/8070 /ip4/129.212.221.44/tcp/8071\n",
  );
  assert.equal(peersOk.ok, true);
  assert.equal(peersOk.peers.length, 2);
  assert.deepEqual(peersOk.peers[0].addrs, ["/ip4/178.128.140.206/tcp/8070"]);
  assert.equal(peersOk.peers[1].addrs.length, 2);
  const peersBad = parseStoragePeers("short /ip4/1.2.3.4/tcp/8070\n16Uiu2HAm3xPbYz2zsq5XVGDCMqKhhNXZWyYV6WLVv3yzzUiRJWnW not-a-multiaddr");
  assert.equal(peersBad.ok, false);
  assert.equal(peersBad.errors.length, 2);

  // Exact Basecamp storageConnect / storage_* event payload shapes (Array, Qt QVariantList-like, and JSON string)
  assert.deepEqual(parseStorageEventPayload(["{\"message\":\"\",\"success\":true}"]), {
    message: "",
    success: true,
  });
  // Qt QML QVariantList where Array.isArray() is false
  const qVariantList = { 0: "{\"message\":\"\",\"success\":true}", length: 1 };
  assert.equal(Array.isArray(qVariantList), false);
  assert.deepEqual(parseStorageEventPayload(qVariantList), {
    message: "",
    success: true,
  });
  // Double-encoded stringified array
  assert.deepEqual(parseStorageEventPayload(JSON.stringify(["{\"sessionId\":\"zCid123\",\"success\":true}"])), {
    sessionId: "zCid123",
    success: true,
  });
  assert.deepEqual(parseStorageEventPayload(["{\"sessionId\":\"zCid123\",\"chunk\":\"SGVsbG8=\",\"success\":true}"]), {
    sessionId: "zCid123",
    chunk: "SGVsbG8=",
    success: true,
  });
  assert.equal(parseStorageEventPayload([]), null);
});

test("Qt QVariantList-like objects (Array.isArray === false) work across drawSvgToCanvas, answer(), and toArray()", () => {
  const qOps = {
    0: { op: "path", d: "M0 0h2v4h-2z", x: 0.5, y: 0.5, fill: "#b8d0ff", opacity: 1 },
    1: { op: "rect", x: 4, y: 1, w: 3, h: 5, fill: "#0055ff", opacity: 0.9 },
    2: { op: "circle", x: 10, y: 4, r: 2, fill: "#e8662f", opacity: 1 },
    length: 3,
  };
  assert.equal(Array.isArray(qOps), false);
  assert.equal(isArrayLike(qOps), true);
  assert.equal(toArray(qOps).length, 3);
  assert.equal(isArrayLike({ length: 0 }), true);
  assert.equal(isArrayLike({ kind: "svg", length: 5 }), false);
  assert.equal(isArrayLike("not-a-list"), false);
  assert.equal(isArrayLike(null), false);

  // drawSvgToCanvas must render when block.ops is a QVariantList-like object (not a JS Array)
  const qBlock = {
    kind: "svg",
    vb_x: 0,
    vb_y: 0,
    vb_w: 20,
    vb_h: 10,
    width: 200,
    height: 100,
    ops: qOps,
  };
  const calls = [];
  const mockCtx = {
    globalAlpha: 1,
    fillStyle: "",
    clearRect: (...a) => calls.push(["clearRect", ...a]),
    save: () => calls.push(["save"]),
    restore: () => calls.push(["restore"]),
    scale: (...a) => calls.push(["scale", ...a]),
    translate: (...a) => calls.push(["translate", ...a]),
    beginPath: () => calls.push(["beginPath"]),
    moveTo: (...a) => calls.push(["moveTo", ...a]),
    lineTo: (...a) => calls.push(["lineTo", ...a]),
    closePath: () => calls.push(["closePath"]),
    fill: () => calls.push(["fill", mockCtx.fillStyle]),
    fillRect: (...a) => calls.push(["fillRect", mockCtx.fillStyle, ...a]),
    arc: (...a) => calls.push(["arc", ...a]),
  };
  drawSvgToCanvas(mockCtx, qBlock, 200, 100);
  assert.deepEqual(calls.filter((c) => c[0] === "fill"), [
    ["fill", "#b8d0ff"],
    ["fill", "#e8662f"],
  ]);
  assert.deepEqual(calls.filter((c) => c[0] === "fillRect"), [
    ["fillRect", "#0055ff", 4, 1, 3, 5],
  ]);

  // answer() recursively converts nested QVariantList-like blocks, ops, files, and peers into real JS Arrays
  const qReply = {
    success: true,
    value: {
      blocks: { 0: qBlock, length: 1 },
      files: { 0: { path: "/index.html", cid: "zCid1" }, length: 1 },
      peers: { 0: "16Uiu2HAmTest", length: 1 },
    },
  };
  assert.equal(Array.isArray(qReply.value.blocks), false);
  assert.equal(Array.isArray(qReply.value.blocks[0].ops), false);
  const unwrapped = answer(qReply);
  assert.equal(unwrapped.ok, true);
  assert.equal(Array.isArray(unwrapped.value.blocks), true);
  assert.equal(Array.isArray(unwrapped.value.blocks[0].ops), true);
  assert.equal(unwrapped.value.blocks[0].ops.length, 3);
  assert.equal(Array.isArray(unwrapped.value.files), true);
  assert.equal(Array.isArray(unwrapped.value.peers), true);

  // Bare { busy: true } replies (as returned by names.resolve and names.page) are detected as busy
  assert.equal(isBusyReply({ busy: true }, ""), true);
  assert.equal(isBusyReply(JSON.stringify({ busy: true }), ""), true);
  assert.equal(isBusyReply({ success: true, value: { busy: true } }, ""), true);
  assert.equal(normalizeModuleValue({ length: 0 }).length, 0);
});

test("parseUrl supports bare name/path, query/fragment, normalization, and rejects subnames/control chars", () => {
  assert.deepEqual(parseUrl("nameswallet/browser"), {
    ok: true,
    kind: "lns",
    name: "nameswallet",
    path: "/browser",
    siteBase: "lns://nameswallet",
    canonical: "lns://nameswallet/browser",
  });
  assert.deepEqual(parseUrl("nameswallet/browser/files/x.lgx"), {
    ok: true,
    kind: "lns",
    name: "nameswallet",
    path: "/browser/files/x.lgx",
    siteBase: "lns://nameswallet",
    canonical: "lns://nameswallet/browser/files/x.lgx",
  });
  assert.deepEqual(parseUrl("nameswallet/a/../browser/?v=2#dl"), {
    ok: true,
    kind: "lns",
    name: "nameswallet",
    path: "/browser/",
    siteBase: "lns://nameswallet",
    canonical: "lns://nameswallet/browser/",
    fragment: "#dl",
  });
  assert.deepEqual(parseUrl("nameswallet/../../etc/passwd"), {
    ok: true,
    kind: "lns",
    name: "nameswallet",
    path: "/etc/passwd",
    siteBase: "lns://nameswallet",
    canonical: "lns://nameswallet/etc/passwd",
  });
  assert.equal(parseUrl("sub.nameswallet/browser").ok, false);
  assert.equal(parseUrl("nameswallet/bad\0path").ok, false);
  assert.equal(parseUrl("nameswallet/bad\npath").ok, false);
  assert.equal(normalizePath("/browser/./shot.png?x=1#top").path, "/browser/shot.png");
  assert.equal(resolveRelativeSitePath("./shot.png", "/browser/index.html"), "/browser/shot.png");
  assert.equal(resolveRelativeSitePath("../assets/site.css", "/browser/index.html"), "/assets/site.css");
  assert.equal(resolveRelativeSitePath("/bridge/", "/browser/index.html"), "/bridge/");
});

test("per-folder lns-links/1 parser, formatter, rejection rules, and nested resolver", () => {
  const cidHome = "z4W2jHomeHtml00000000000000000000000000000000000";
  const cidBrowserDir = "z4W2jBrowserDir000000000000000000000000000000000";
  const cidBrowserHtml = "z4W2jBrowserHtml00000000000000000000000000000000";
  const cidShot = "z4W2jShotPng000000000000000000000000000000000000";
  const cidFilesDir = "z4W2jFilesDir00000000000000000000000000000000000";
  const cidLgx = "z4W2jBrowserLgx000000000000000000000000000000000";
  const hashLgx = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";

  const rootText = [
    "# lns-links/1",
    "# title Names Wallet",
    "# index index.html",
    "",
    "# comment line",
    `index.html ${cidHome}`,
    `browser/ ${cidBrowserDir}`,
    "",
  ].join("\n");

  assert.equal(isLinksListText(rootText), true);
  assert.equal(isLinksListText("<html><body>hi</body></html>"), false);
  assert.equal(isLinksContentType("text/vnd.logos.lns-links; version=1"), true);
  assert.equal(isLinksContentType("text/html; charset=utf-8"), false);

  const rootList = parseLinksList(rootText);
  assert.equal(rootList.ok, true);
  assert.equal(rootList.title, "Names Wallet");
  assert.equal(rootList.index, "index.html");
  assert.deepEqual(
    rootList.entries.map((e) => [e.name, e.kind]),
    [
      ["browser", "dir"],
      ["index.html", "file"],
    ],
  );

  // Formatting is deterministic and round-trips cleanly
  const formatted = formatLinksList(rootList);
  assert.equal(formatted.ok, true);
  assert.equal(
    formatted.text,
    `# lns-links/1\n# title Names Wallet\n# index index.html\nbrowser/ ${cidBrowserDir}\nindex.html ${cidHome}\n`,
  );
  assert.deepEqual(parseLinksList(formatted.text), rootList);

  // Reject bad header, bad lines, invalid CID/hash, duplicates, file/dir collision, traversal, control chars
  assert.equal(parseLinksList("index.html " + cidHome).ok, false);
  assert.equal(parseLinksList("# lns-links/2\n").ok, false);
  assert.equal(parseLinksList(`# lns-links/1\nonlyone\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\na.html ${cidHome} ${hashLgx} extra\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\na.html bad!cid\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\na.html ${cidHome} nothex\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\na.html ${cidHome}\na.html ${cidShot}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\nbrowser ${cidHome}\nbrowser/ ${cidBrowserDir}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\n.. ${cidHome}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\n. ${cidHome}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\nsub/a.html ${cidHome}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\n/a.html ${cidHome}\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\n# index ../bad\n`).ok, false);
  assert.equal(parseLinksList(`# lns-links/1\na\0b ${cidHome}\n`).ok, false);

  // Walk nested folders with CID cache
  const browserList = parseLinksList(
    `# lns-links/1\n# index index.html\nfiles/ ${cidFilesDir}\nindex.html ${cidBrowserHtml}\nshot.png ${cidShot}\n`,
  );
  const filesList = parseLinksList(`# lns-links/1\nlns-browser-0.2.8.lgx ${cidLgx} ${hashLgx}\n`);
  const store = {};
  store[cidBrowserDir] = browserList;
  store[cidFilesDir] = filesList;

  const cache = {};
  let loads = 0;
  function loadFolder(cid) {
    loads += 1;
    return store[cid] || { ok: false, error: "not found" };
  }

  // Root `/`
  const rRoot = resolveLinksSync(rootList, "/", loadFolder, cache);
  assert.equal(rRoot.ok, true);
  assert.equal(rRoot.entry.cid, cidHome);
  assert.equal(rRoot.resolvedPath, "/index.html");
  assert.equal(rRoot.canonicalUrlPath, "/");
  assert.equal(loads, 0);

  // Folder without trailing slash -> canonicalized with trailing `/`
  const rBrowser = resolveLinksSync(rootList, "/browser", loadFolder, cache);
  assert.equal(rBrowser.ok, true);
  assert.equal(rBrowser.entry.cid, cidBrowserHtml);
  assert.equal(rBrowser.resolvedPath, "/browser/index.html");
  assert.equal(rBrowser.canonicalUrlPath, "/browser/");
  assert.equal(loads, 1);

  // Nested file reuses cached `browser/` list
  const rLgx = resolveLinksSync(rootList, "/browser/files/lns-browser-0.2.8.lgx", loadFolder, cache);
  assert.equal(rLgx.ok, true);
  assert.equal(rLgx.entry.cid, cidLgx);
  assert.equal(rLgx.entry.sha256, hashLgx);
  assert.equal(rLgx.resolvedPath, "/browser/files/lns-browser-0.2.8.lgx");
  assert.equal(rLgx.canonicalUrlPath, "/browser/files/lns-browser-0.2.8.lgx");
  assert.equal(loads, 2);

  // Exact file with trailing slash -> not_found
  const rBadSlash = resolveLinksSync(rootList, "/browser/shot.png/", loadFolder, cache);
  assert.equal(rBadSlash.ok, false);
  assert.equal(rBadSlash.status, "not_found");

  // Directory without index file -> not_found (isDirectory = true)
  const rNoIdx = resolveLinksSync(rootList, "/browser/files/", loadFolder, cache);
  assert.equal(rNoIdx.ok, false);
  assert.equal(rNoIdx.status, "not_found");
  assert.equal(rNoIdx.isDirectory, true);

  // Missing path -> not_found
  const rMissing = resolveLinksSync(rootList, "/missing/page.html", loadFolder, cache);
  assert.equal(rMissing.ok, false);
  assert.equal(rMissing.status, "not_found");

  // stepLinksResolve directly
  assert.equal(stepLinksResolve(rootList, ["browser"], 0, false).action, "fetch_dir");
});

test("sanitizeHtmlFallback extracts cid:// and relative <img> blocks, downloads, and formats storage fetch errors", () => {
  const html =
    '<html><body>' +
    '<p><a href="./guide.html">Guide</a></p>' +
    '<img src="cid://z4W2jBrowserShot0000000000000000000000000000000000" alt="Shot">' +
    '<img src="./icon.png" alt="Icon">' +
    '<img src="https://evil.example/track.png" alt="Blocked">' +
    '<a href="cid://z4W2jBrowserUiLgx00000000000000000000000000000000" download="lns-browser-0.2.8.lgx">Download UI</a>' +
    '</body></html>';
  const clean = sanitizeHtmlFallback(html, "lns://nameswallet", "/browser/index.html");
  assert.match(clean.html, /href="lns:\/\/nameswallet\/browser\/guide\.html"/);
  const imgs = clean.blocks.filter((b) => b.kind === "image");
  assert.equal(imgs.length, 2);
  assert.equal(imgs[0].src_cid, "z4W2jBrowserShot0000000000000000000000000000000000");
  assert.equal(imgs[1].src_path, "/browser/icon.png");
  assert.equal(clean.downloads.length, 1);
  assert.equal(clean.downloads[0].filename, "lns-browser-0.2.8.lgx");
  assert.equal(clean.downloads[0].cid, "z4W2jBrowserUiLgx00000000000000000000000000000000");

  assert.equal(isBinaryDownloadPath("/browser/files/lns-browser-0.2.8.lgx"), true);
  assert.equal(isBinaryDownloadPath("/browser/index.html"), false);
  assert.equal(sniffImageMimeBytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), "image/png");
  assert.equal(sniffImageMimeBytes([0xff, 0xd8, 0xff, 0xe0]), "image/jpeg");

  const errMsg = formatStorageFetchError("z4W2jBrowserHtml00000000000000000000000000000000", "/browser/", "HTTP 404");
  assert.match(errMsg, /\/browser\//);
  assert.match(errMsg, /z4W2jBrowser/);
});

test("Finding 4 & 5: escapeHtml, save filename/path validation (no /tmp fallback), and pinned sha256 lookup", () => {
  // Finding 4: binary filename HTML escaping
  assert.equal(escapeHtml("<b><i>SPOOFED.lgx"), "&lt;b&gt;&lt;i&gt;SPOOFED.lgx");

  // Finding 5: reject `.`, `..`, leading dot, control chars, separators
  assert.equal(validateSaveFilename(".").ok, false);
  assert.equal(validateSaveFilename("..").ok, false);
  assert.equal(validateSaveFilename(".bashrc").ok, false);
  assert.equal(validateSaveFilename(".zshrc").ok, false);
  assert.equal(validateSaveFilename("bad\0name.lgx").ok, false);
  assert.equal(validateSaveFilename("bad\u0085name.lgx").ok, false);
  assert.equal(validateSaveFilename("../escape.lgx").ok, false);
  assert.equal(validateSaveFilename("sub/file.lgx").ok, false);
  assert.equal(validateSaveFilename("lns-browser-0.2.8.lgx").ok, true);

  // No /tmp fallback when downloadsDir is empty
  assert.equal(buildSaveTargetPath("", "app.lgx").ok, false);
  const target = buildSaveTargetPath("/Users/alice/Downloads/", "app.lgx");
  assert.equal(target.ok, true);
  assert.equal(target.path, "/Users/alice/Downloads/app.lgx");
  assert.equal(buildSaveTargetPath("/Users/alice/Downloads", "..").ok, false);
  assert.equal(buildSaveTargetPath("/Users/alice/Downloads", ".bashrc").ok, false);

  // findPinnedSha256 resolves pinned sha256 from pageData.files or pageData.cid
  const pinnedHash = "a".repeat(64);
  const pageData = {
    cid: "z4W2jPage0000000000000000000000000000000000000000",
    sha256: "b".repeat(64),
    files: [
      { path: "/browser/files/app.lgx", cid: "z4W2jLgx0000000000000000000000000000000000000000", sha256: pinnedHash },
    ],
  };
  assert.equal(findPinnedSha256("z4W2jLgx0000000000000000000000000000000000000000", "", pageData), pinnedHash);
  assert.equal(findPinnedSha256("z4W2jPage0000000000000000000000000000000000000000", "", pageData), "b".repeat(64));
  assert.equal(findPinnedSha256("z4W2jUnlisted00000000000000000000000000000000000", "", pageData), "");
});

test("Finding 7: CID caches verify expectedSha256, resist Object.prototype keys, and fold foldersVerified", () => {
  const cidSub = "z4W2jSubDir00000000000000000000000000000000000000";
  const cidPage = "z4W2jSubPage0000000000000000000000000000000000000";
  const realSha = "1".repeat(64);
  const wrongSha = "2".repeat(64);
  const subList = parseLinksList(`# lns-links/1\nindex.html ${cidPage} ${realSha}\n`);

  // Safe map ignores Object.prototype keys like "toString", "constructor", "hasOwnProperty"
  const plainCache = {};
  assert.equal(getCachedLinksEntry(plainCache, "toString", "").hit, false);
  assert.equal(getCachedLinksEntry(plainCache, "constructor", "").hit, false);
  assert.equal(getCachedImageEntry(plainCache, "hasOwnProperty", "").hit, false);

  const safeCache = createSafeMap();
  safeMapSet(safeCache, cidSub, { list: subList, sha256: realSha });
  assert.equal(getCachedLinksEntry(safeCache, cidSub, realSha).hit, true);
  const badHit = getCachedLinksEntry(safeCache, cidSub, wrongSha);
  assert.equal(badHit.hit, false);
  assert.equal(badHit.mismatch, true);

  // Unhashed cache entry must miss (re-fetch) when a pinned sha256 is requested
  const unhashedCache = createSafeMap();
  safeMapSet(unhashedCache, cidSub, { list: subList, sha256: "" });
  assert.equal(getCachedLinksEntry(unhashedCache, cidSub, realSha).hit, false);
  assert.equal(getCachedLinksEntry(unhashedCache, cidSub, realSha).mismatch, false);

  // resolveLinksSync verifies cached hashes and tracks foldersVerified
  const rootUnpinned = parseLinksList(`# lns-links/1\nsub/ ${cidSub}\n`);
  const rootPinnedWrong = parseLinksList(`# lns-links/1\nsub/ ${cidSub} ${wrongSha}\n`);
  const rootPinnedRight = parseLinksList(`# lns-links/1\nsub/ ${cidSub} ${realSha}\n`);

  const treeCache = createSafeMap();
  const r1 = resolveLinksSync(rootUnpinned, "/sub/", () => ({ ok: true, list: subList, sha256: realSha }), treeCache);
  assert.equal(r1.ok, true);
  assert.equal(r1.foldersVerified, false);

  const r2 = resolveLinksSync(rootPinnedRight, "/sub/", () => {
    throw new Error("should hit verified cache");
  }, treeCache);
  assert.equal(r2.ok, true);
  assert.equal(r2.foldersVerified, true);

  const r3 = resolveLinksSync(rootPinnedWrong, "/sub/", () => {
    throw new Error("should reject mismatched cached hash");
  }, treeCache);
  assert.equal(r3.ok, false);
  assert.match(r3.error, /SHA-256 mismatch/i);
});

test("Finding 9, 12 & 15: list limits, base64DecodedLength, JS/Rust parity, strict UTF-8, and stale download guard", () => {
  // Finding 9: base64DecodedLength + parseLinksList size & entry limits
  assert.equal(base64DecodedLength(bytesToBase64(utf8ToBytes("hello"))), 5);
  assert.equal(base64DecodedLength(bytesToBase64(utf8ToBytes("hi"))), 2);
  assert.equal(parseLinksList("# lns-links/1\n" + " ".repeat(MAX_LINKS_LIST_BYTES + 1)).ok, false);
  let many = "# lns-links/1\n";
  for (let i = 0; i <= MAX_LINKS_ENTRIES; i++) {
    many += "f" + i + ".txt z4W2jHomeHtml00000000000000000000000000000000000\n";
  }
  assert.equal(parseLinksList(many).ok, false);

  // Finding 12: C1 control chars rejected
  assert.equal(parseLinksList("# lns-links/1\nfoo\u0085bar z4W2jHomeHtml00000000000000000000000000000000000\n").ok, false);
  assert.equal(isValidSegmentName("foo\u0085bar"), false);
  assert.equal(normalizePath("/a\u009fb").ok, false);
  assert.equal(parseUrl("nameswallet/bad\u0085path").ok, false);

  // Finding 12: 255-byte UTF-8 cap (not UTF-16 code units)
  assert.equal(isValidSegmentName("é".repeat(130)), false); // 260 UTF-8 bytes
  assert.equal(isValidSegmentName("é".repeat(127)), true);  // 254 UTF-8 bytes

  // Finding 12: canonical sort order matches Rust UTF-8 / Unicode scalar order
  assert.ok(cmpCodePoint("\uFF01.png", "🚀.png") < 0);
  const sortedList = parseLinksList(
    "# lns-links/1\n🚀.png z4W2jHomeHtml00000000000000000000000000000000000\n\uFF01.png z4W2jShotPng000000000000000000000000000000000000\n",
  );
  assert.equal(sortedList.ok, true);
  assert.deepEqual(sortedList.entries.map((e) => e.name), ["\uFF01.png", "🚀.png"]);

  // Finding 12: `# title` with `\t` round-trips cleanly
  const tabbed = parseLinksList("# lns-links/1\n# title A\tB\n");
  assert.equal(tabbed.ok, true);
  assert.equal(tabbed.title, "A B");
  const formattedTab = formatLinksList(tabbed);
  assert.equal(formattedTab.ok, true);
  assert.match(formattedTab.text, /# title A B\n/);

  // Finding 12: bytesToUtf8Strict rejects invalid UTF-8 sequences
  assert.equal(bytesToUtf8Strict([0xff, 0xfe]).ok, false);
  assert.equal(bytesToUtf8Strict([0xc0, 0xaf]).ok, false); // overlong
  assert.equal(bytesToUtf8Strict([0xed, 0xa0, 0x80]).ok, false); // surrogate
  assert.equal(bytesToUtf8Strict(utf8ToBytes("Hello 🚀")).text, "Hello 🚀");

  // Finding 15: stale download guard
  assert.equal(isStaleDownload({ navSeq: 1 }, 2), true);
  assert.equal(isStaleDownload({ navSeq: 2 }, 2), false);
  assert.equal(isStaleDownload(null, 2), true);
});

test("Finding 10: sanitizeHtmlFallback blocks slash-separated attributes and prototype-key colors/defs", () => {
  const hostile =
    '<html><head><style>body{background:toString;color:constructor} a{color:valueOf}</style></head>' +
    '<body><table/background="https://evil.example/t.png"><a/href="http://evil.example">Go</a></table>' +
    '<a/href="javascript:alert(1)">XSS</a>' +
    '<svg viewBox="0 0 10 10"><use href="#constructor"/></svg></body></html>';
  const clean = sanitizeHtmlFallback(hostile, "lns://demo", "/");
  assert.equal(clean.bg_color, null);
  assert.equal(clean.fg_color, null);
  assert.equal(clean.link_color, null);
  assert.doesNotMatch(clean.html, /evil\.example/i);
  assert.doesNotMatch(clean.html, /<table/i);
  assert.doesNotMatch(clean.html, /javascript:/i);
  assert.doesNotMatch(clean.html, /<a\b/i);
  assert.equal(extractSvgCanvasOps('<svg><use href="#constructor"/></svg>', "#000000", {}).length, 0);
});

test("Round 6: classifyWebViewUrl enforces loopback origin/token isolation and routes ext/lns/dl", () => {
  const origin = "http://127.0.0.1:51234";
  const token = "0123456789abcdef0123456789abcdef";
  const siteBase = "lns://nameswallet";

  assert.equal(classifyWebViewUrl("about:blank", origin, token, siteBase).action, "ignore");

  // Same-site loopback path allowed and mapped back to canonical LNS URL
  const okNav = classifyWebViewUrl(`${origin}/${token}/browser/index.html#dl`, origin, token, siteBase);
  assert.equal(okNav.action, "allow");
  assert.equal(okNav.sitePath, "/browser/index.html");
  assert.equal(okNav.canonical, "lns://nameswallet/browser/index.html#dl");

  // Rewritten /_ext, /_lns, /_dl endpoints
  const ext = classifyWebViewUrl(`${origin}/${token}/_ext?u=https%3A%2F%2Fnameswallet.app%2Fbrowser`, origin, token, siteBase);
  assert.deepEqual(ext, { action: "ext", url: "https://nameswallet.app/browser" });

  const lns = classifyWebViewUrl(`${origin}/${token}/_lns?u=lns%3A%2F%2Fjef%2Fabout`, origin, token, siteBase);
  assert.deepEqual(lns, { action: "lns", url: "lns://jef/about" });

  const dl = classifyWebViewUrl(`${origin}/${token}/_dl?path=%2Fbrowser%2Ffiles%2Fapp.lgx&name=app.lgx`, origin, token, siteBase);
  assert.deepEqual(dl, { action: "dl", cid: "", path: "/browser/files/app.lgx", filename: "app.lgx" });

  // Direct https://, lns://, cid:// routed properly
  assert.deepEqual(classifyWebViewUrl("https://nameswallet.app/docs", origin, token, siteBase), {
    action: "ext",
    url: "https://nameswallet.app/docs",
  });
  assert.deepEqual(classifyWebViewUrl("lns://helloworld/page", origin, token, siteBase), {
    action: "lns",
    url: "lns://helloworld/page",
  });

  // Wrong port, wrong token, traversal, and dangerous schemes blocked
  assert.equal(classifyWebViewUrl(`http://127.0.0.1:59999/${token}/`, origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl(`${origin}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/`, origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl(`${origin}/${token}/../etc/passwd`, origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl(`${origin}/${token}/%2e%2e/secret`, origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl("http://evil.example/leak", origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl("file:///etc/passwd", origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl("basecamp://intent/wallet.send", origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl("javascript:alert(1)", origin, token, siteBase).action, "block");
  assert.equal(classifyWebViewUrl("https://user:pass@evil.example/", origin, token, siteBase).action, "block");

  // Helper round-trips
  assert.equal(buildLoopbackEntryUrl(origin, token, "/browser/"), `${origin}/${token}/browser/`);
  assert.equal(sitePathFromLoopbackUrl(`${origin}/${token}/browser/?x=1#top`, origin, token).path, "/browser/");
  assert.equal(parseQueryString("a=1&b=hello+world")["b"], "hello world");
});

test("Round 6: tabs, window title/geometry, zoom, bookmarks, history, recent sites, and find", () => {
  const t1 = createTab(1, { kind: "lns", host: "nameswallet", url: "lns://nameswallet", siteBase: "lns://nameswallet" });
  const t2 = createTab(2, { kind: "cid", host: "z4W2jHomeHtml00000000000000000000000000000000000" });
  const t3 = createTab(3, {});

  assert.equal(formatWindowTitle(t1), "nameswallet — LNS Browser");
  assert.equal(formatWindowTitle(t2), "z4W2jHomeH...000000 — LNS Browser");
  assert.equal(formatWindowTitle(t3), "LNS Browser");
  assert.equal(formatTabTitle(t1), "nameswallet");
  assert.equal(formatTabTitle(t3), "New Tab");

  // History per tab
  const h1 = pushTabHistory(t1, "lns://nameswallet");
  t1.history = h1.history; t1.historyIdx = h1.historyIdx;
  const h2 = pushTabHistory(t1, "lns://nameswallet/browser/");
  t1.history = h2.history; t1.historyIdx = h2.historyIdx;
  assert.equal(canTabGoBack(t1), true);
  assert.equal(canTabGoForward(t1), false);
  t1.historyIdx -= 1;
  assert.equal(canTabGoBack(t1), false);
  assert.equal(canTabGoForward(t1), true);

  // Closing tabs adjusts activeIndex and signals window close on last tab
  const c1 = closeTabState([t1, t2, t3], 2, 1);
  assert.equal(c1.tabs.length, 2);
  assert.equal(c1.activeIndex, 1);
  assert.equal(c1.shouldCloseWindow, false);
  const cLast = closeTabState([t1], 0, 0);
  assert.equal(cLast.tabs.length, 0);
  assert.equal(cLast.shouldCloseWindow, true);

  // Window geometry & zoom clamping
  assert.deepEqual(clampWindowGeometry({ x: -5000, y: -50, width: 200, height: 100 }), {
    x: -200,
    y: 0,
    width: 720,
    height: 480,
  });
  assert.equal(clampZoomPercent(30), 50);
  assert.equal(clampZoomPercent(112), 110);
  assert.equal(clampZoomPercent(400), 200);

  // Bookmarks toggle & lookup
  let bms = [];
  const addRes = toggleBookmark(bms, { url: "lns://nameswallet", title: "Names Wallet", name: "nameswallet", added_at: 10 });
  bms = addRes.bookmarks;
  assert.equal(addRes.bookmarked, true);
  assert.equal(isBookmarked(bms, "lns://nameswallet"), true);
  const rmRes = toggleBookmark(bms, { url: "lns://nameswallet" });
  assert.equal(rmRes.bookmarked, false);
  assert.equal(isBookmarked(rmRes.bookmarks, "lns://nameswallet"), false);

  // History & recent sites extraction
  let hist = [];
  hist = recordHistoryEntry(hist, { url: "lns://nameswallet", title: "Names Wallet", name: "nameswallet", visited_at: 1 });
  hist = recordHistoryEntry(hist, { url: "lns://nameswallet/browser/", title: "Browser", name: "nameswallet", visited_at: 2 });
  hist = recordHistoryEntry(hist, { url: "lns://helloworld", title: "Hello", name: "helloworld", visited_at: 3 });
  assert.equal(hist.length, 3);
  const recent = extractRecentSites(hist, 8);
  assert.deepEqual(recent.map((r) => r.siteBase), ["lns://helloworld", "lns://nameswallet"]);

  // Reader Mode find count
  assert.equal(countTextMatches("<h1>Logos Browser</h1><p>Welcome to logos LNS!</p>", "logos"), 2);
  assert.equal(countTextMatches("<p>hello</p>", ""), 0);
});
