import test from "node:test";
import assert from "node:assert/strict";
import {
  answer,
  base64ToBytes,
  buildProfileEntries,
  buildPublishDeepLink,
  bytesToBase64,
  bytesToUtf8,
  drawSvgToCanvas,
  extractSiteInfo,
  formatUnreachableCidError,
  isExternalHttpsUrl,
  isPort8080Url,
  isValidName,
  normalizeName,
  parseUrl,
  sanitizeHtmlFallback,
  sha256HexUtf8,
  shortHash,
  utf8ToBytes,
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
});
