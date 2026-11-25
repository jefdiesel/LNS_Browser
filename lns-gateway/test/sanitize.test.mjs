import test from "node:test";
import assert from "node:assert/strict";

import {
  rewriteHref,
  rewriteLocalAssetUrl,
  sanitizeCss,
  sanitizeHtml,
  sanitizeSvg,
} from "../sanitize.mjs";

const SAMPLE_HASH = "a".repeat(64);

test("Finding 1: blocks <textarea><head> CSP bypass, </style x> breakout, and <title><head>", () => {
  const xssPayload =
    "<!doctype html><html><textarea><head></textarea>" +
    "<style></style x><script>alert(document.domain)</script></style></html>";
  const out = sanitizeHtml(xssPayload, { name: "evil", hash: SAMPLE_HASH, source: "cid" });

  assert.doesNotMatch(out, /<script/i);
  assert.doesNotMatch(out, /alert\(document\.domain\)/i);
  assert.doesNotMatch(out, /<textarea/i);
  assert.match(out, /<html>\n<head><meta http-equiv="Content-Security-Policy"/i);

  // </style x> injecting <meta http-equiv="refresh"> is also stripped
  const refreshBreakout =
    '<!doctype html><html><head><style></style x><meta http-equiv="refresh" content="0;url=https://evil.example/"></style></head><body>Hi</body></html>';
  const out2 = sanitizeHtml(refreshBreakout, { name: "evil", hash: SAMPLE_HASH, source: "cid" });
  assert.doesNotMatch(out2, /http-equiv="refresh"/i);
  assert.doesNotMatch(out2, /evil\.example/i);

  // <title><head></title> must not trick CSP injection into emitting CSP inside <title> RCDATA
  const titleTrick = "<!doctype html><html><title><head></title><body><p>Hello</p></body></html>";
  const out3 = sanitizeHtml(titleTrick, { name: "demo", hash: SAMPLE_HASH, source: "chain" });
  assert.match(out3, /<title>&lt;head&gt;<\/title>/);
  const headIdx = out3.indexOf("<head><meta http-equiv=\"Content-Security-Policy\"");
  const titleIdx = out3.indexOf("<title>");
  assert.ok(headIdx !== -1 && headIdx < titleIdx);
});

test("Finding 3: sanitizeSvg strips <?xml-stylesheet?>, DOCTYPE/ENTITY, SMIL <set>/<animate>, xml:base, and adds rel on external <a>", () => {
  const hostileSvg = `<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet type="text/xsl" href="https://evil.example/x.xsl"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "https://evil.example/xxe"> ]>
<svg xmlns="http://www.w3.org/2000/svg" xml:base="https://evil.example/">
  <image width="10" height="10"><set attributeName="href" to="https://evil.example/track.png" begin="0s"/></image>
  <rect width="10" height="10"><animate attributeName="x" values="0;10"/></rect>
  <feImage href="https://evil.example/f.png"/>
  <a href="https://nameswallet.app/"><set attributeName="href" to="javascript:alert(document.domain)" begin="0s"/><text y="20">Click</text></a>
</svg>`;
  const out = sanitizeSvg(hostileSvg, "demo");

  assert.match(out, /^<\?xml version="1\.0" encoding="UTF-8"\?>/);
  assert.doesNotMatch(out, /xml-stylesheet/i);
  assert.doesNotMatch(out, /<!DOCTYPE|<!ENTITY/i);
  assert.doesNotMatch(out, /xml:base/i);
  assert.doesNotMatch(out, /<set\b|<animate\b|<feImage\b/i);
  assert.doesNotMatch(out, /evil\.example/i);
  assert.doesNotMatch(out, /javascript:/i);
  assert.match(out, /<a href="https:\/\/nameswallet\.app\/" rel="noopener noreferrer">/);
});

test("Finding 8: relative URL rewriting blocks /lns/<name>/ escape, resolves ../ at depth >= 2, and preserves trailing /", () => {
  // Escapes via ./../ or a/../../../ are clamped inside /lns/evil/
  assert.equal(
    rewriteLocalAssetUrl("./../victim/style.css", "evil", { sitePath: "/index.html" }),
    "/lns/evil/victim/style.css",
  );
  assert.equal(
    rewriteHref("a/../../../admin", "evil", { sitePath: "/index.html" }),
    "/lns/evil/admin",
  );

  // Depth >= 2 relative ../ resolves against the current file's directory
  assert.equal(
    rewriteLocalAssetUrl("../shot.png", "nameswallet", { sitePath: "/browser/files/page.html" }),
    "/lns/nameswallet/browser/shot.png",
  );
  assert.equal(
    rewriteHref("../index.html#top", "nameswallet", { sitePath: "/browser/files/page.html" }),
    "/lns/nameswallet/browser/index.html#top",
  );

  // Trailing slash preserved on folder links and lns:// URLs
  assert.equal(
    rewriteHref("/browser/", "nameswallet", { sitePath: "/index.html" }),
    "/lns/nameswallet/browser/",
  );
  assert.equal(
    rewriteHref("lns://other/browser/", "nameswallet", { sitePath: "/index.html" }),
    "/lns/other/browser/",
  );
  assert.equal(
    rewriteHref("./sub/", "nameswallet", { sitePath: "/browser/index.html" }),
    "/lns/nameswallet/browser/sub/",
  );

  // End-to-end inside sanitizeHtml with sitePath
  const nestedHtml =
    '<!doctype html><html><head><link rel="stylesheet" href="./../victim/style.css"></head>' +
    '<body><img src="../shot.png"><a href="a/../../../admin">Admin</a><a href="/browser/">Dir</a></body></html>';
  const out = sanitizeHtml(nestedHtml, {
    name: "nameswallet",
    hash: SAMPLE_HASH,
    source: "cid",
    sitePath: "/browser/files/page.html",
  });
  assert.match(out, /href="\/lns\/nameswallet\/browser\/victim\/style\.css"/);
  assert.match(out, /src="\/lns\/nameswallet\/browser\/shot\.png"/);
  assert.match(out, /href="\/lns\/nameswallet\/admin"/);
  assert.match(out, /href="\/lns\/nameswallet\/browser\/"/);
});

test("Finding 16: sanitizeCss blocks CSS escape bypasses, image-set external URLs, and <body background> leak", () => {
  const hostileCss = [
    '@\\69mport "https://evil.example/a.css";',
    'body { background: \\75rl("https://evil.example/t.png"); }',
    'div { background-image: image-set("https://evil.example/track.png" 1x); }',
    'span { background-image: -webkit-image-set("../img/ok.png" 1x, "https://evil.example/2x.png" 2x); }',
  ].join("\n");
  const outCss = sanitizeCss(hostileCss, "demo", { sitePath: "/assets/site.css" });

  assert.doesNotMatch(outCss, /evil\.example/i);
  assert.doesNotMatch(outCss, /@import/i);
  assert.match(outCss, /background:\s*none/);
  assert.match(outCss, /background-image:\s*none/);
  assert.match(outCss, /"\/lns\/demo\/img\/ok\.png" 1x/);

  const bgHtml =
    '<!doctype html><html><head></head><body background="https://evil.example/bg.png">' +
    '<table background="./local-bg.png"><tr><td>Hi</td></tr></table></body></html>';
  const outHtml = sanitizeHtml(bgHtml, {
    name: "demo",
    hash: SAMPLE_HASH,
    source: "cid",
    sitePath: "/sub/index.html",
  });
  assert.doesNotMatch(outHtml, /evil\.example/i);
  assert.match(outHtml, /<body\s*>/);
  assert.match(outHtml, /<table background="\/lns\/demo\/sub\/local-bg\.png">/);
});
