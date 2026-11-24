import test from "node:test";
import assert from "node:assert/strict";
import {
  answer,
  buildProfileEntries,
  buildPublishDeepLink,
  extractSiteInfo,
  isExternalHttpsUrl,
  isValidName,
  normalizeName,
  parseUrl,
  shortHash,
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
