// Pure JS helpers for the native Basecamp LNS Web Browser QML view (tested under Node).
// Note: Qt QML's QV4 engine does NOT support ES2018 regex lookbehind (`(?<!...)`), TextDecoder,
// or atob, so everything here is self-contained ES5/ES6-safe JS.

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
const CID_RE = /^[A-Za-z0-9]{8,128}$/;
const SHA256_RE = /^[0-9a-f]{64}$/i;
const HTTPS_RE = /^https:\/\/[^\s/@]+\.[^\s/]+/i;
const B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function answer(reply) {
  let cur = reply;
  for (let depth = 0; depth < 3 && typeof cur === "string"; depth++) {
    try {
      cur = JSON.parse(cur);
    } catch (e) {
      break;
    }
  }
  if (cur === undefined || cur === null || cur === "") {
    return { ok: false, error: "empty reply from core module" };
  }
  if (typeof cur === "boolean") {
    return { ok: true, value: cur };
  }
  if (typeof cur !== "object") {
    return { ok: false, error: "unexpected reply from core module: " + String(cur) };
  }
  if (cur.success === true) return { ok: true, value: cur.value };
  if (cur.success === false) {
    return {
      ok: false,
      error: String(cur.error || cur.message || JSON.stringify(cur)),
    };
  }
  if (cur.error || (cur.code && cur.message)) {
    return {
      ok: false,
      error: String(cur.error || cur.message || JSON.stringify(cur)),
    };
  }
  return { ok: true, value: cur };
}

export function parseStorageEventPayload(data) {
  let raw = data;
  // Unwrap Qt QVariantList (array-like object where Array.isArray can be false in QV4),
  // real JS Arrays, and single/double-encoded JSON strings, e.g. ["{\"message\":\"\",\"success\":true}"].
  for (let depth = 0; depth < 4; depth++) {
    if (raw === null || raw === undefined) return null;
    if (typeof raw === "string") {
      try {
        raw = JSON.parse(raw);
        continue;
      } catch (e) {
        return null;
      }
    }
    if (Array.isArray(raw)) {
      if (raw.length === 0) return null;
      raw = raw[0];
      continue;
    }
    if (
      typeof raw === "object" &&
      typeof raw.length === "number" &&
      raw.length > 0 &&
      raw[0] !== undefined &&
      raw.success === undefined &&
      raw.sessionId === undefined
    ) {
      raw = raw[0];
      continue;
    }
    break;
  }
  return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
}

export function isPort8080Url(url) {
  return /^https?:\/\/(?:127\.0\.0\.1|localhost):8080(?:\/|$)/i.test(String(url || "").trim());
}

/**
 * Parses a multiline "Storage peers" string (one per line: `peerId /ip4/…/tcp/…`).
 * Blank lines and `#` comments are skipped.
 */
export function parseStoragePeers(rawText) {
  const lines = String(rawText || "").split(/\r?\n/);
  const peers = [];
  const errors = [];
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (!trimmed || trimmed.charAt(0) === "#") continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) {
      errors.push("Line " + (i + 1) + ": expected `peerId /ip4/…/tcp/…`");
      continue;
    }
    const peerId = parts[0];
    if (!/^[A-Za-z0-9]{16,128}$/.test(peerId)) {
      errors.push("Line " + (i + 1) + ": invalid peerId `" + peerId + "`");
      continue;
    }
    const addrs = [];
    let badAddr = "";
    for (let j = 1; j < parts.length; j++) {
      const a = parts[j];
      if (a.charAt(0) !== "/" || a.length < 4) {
        badAddr = a;
        break;
      }
      addrs.push(a);
    }
    if (badAddr) {
      errors.push("Line " + (i + 1) + ": invalid address `" + badAddr + "` (expected /ip4/…/tcp/…)");
      continue;
    }
    peers.push({ peerId: peerId, addrs: addrs, line: parts.join(" ") });
  }
  return { ok: errors.length === 0, peers: peers, errors: errors };
}

export function formatUnreachableCidError(cid, detail) {
  const short = shortHash(cid, 12, 8);
  const raw = String(detail || "").trim();
  const lower = raw.toLowerCase();
  if (
    lower.indexOf("sha-256 mismatch") !== -1 ||
    lower.indexOf("integrity mismatch") !== -1
  ) {
    return raw;
  }
  if (
    lower.indexOf("404") !== -1 ||
    lower.indexOf("not found") !== -1 ||
    lower.indexOf("not available") !== -1 ||
    lower.indexOf("timed out") !== -1 ||
    lower.indexOf("timeout") !== -1 ||
    lower.indexOf("no peer") !== -1 ||
    lower.indexOf("manifest") !== -1
  ) {
    return (
      "CID " +
      short +
      " is not on any Logos Storage node this browser can reach. It may only exist on a private local node, or no peer is currently seeding it."
    );
  }
  return (
    "Could not fetch CID " +
    short +
    " from any reachable Logos Storage node" +
    (raw ? " (" + raw + ")" : "") +
    "."
  );
}

export function normalizeName(raw) {
  let host = String(raw || "").trim().toLowerCase();
  if (host.indexOf("lns://") === 0) host = host.slice(6);
  else if (host.indexOf("lns:") === 0) host = host.slice(4);
  if (host.charAt(0) === "@") host = host.slice(1);
  const slash = host.indexOf("/");
  if (slash !== -1) host = host.slice(0, slash);
  if (host.length > 4 && host.slice(-4) === ".lez") host = host.slice(0, -4);
  return host;
}

export function isValidName(name) {
  return NAME_RE.test(String(name || ""));
}

export function isExternalHttpsUrl(raw) {
  const s = String(raw || "").trim();
  if (!HTTPS_RE.test(s) || s.length > 1024) return false;
  const rest = s.slice(8);
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  return authority.indexOf("@") === -1;
}

export function parseUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) return { ok: false, error: "Enter an LNS URL (e.g. lns://jef) or CID (cid://...)" };

  if (/^cid:\/\//i.test(s)) {
    const rest = s.slice(6);
    const slash = rest.indexOf("/");
    const cid = slash === -1 ? rest : rest.slice(0, slash);
    const path = slash === -1 ? "/" : rest.slice(slash) || "/";
    if (!CID_RE.test(cid)) return { ok: false, error: "Invalid CID format" };
    return {
      ok: true,
      kind: "cid",
      cid: cid,
      path: path,
      siteBase: "cid://" + cid,
      canonical: "cid://" + cid + (path === "/" ? "" : path),
    };
  }

  let body = s;
  if (/^lns:\/\//i.test(body)) body = body.slice(6);
  else if (/^lns:/i.test(body)) body = body.slice(4);
  if (body.charAt(0) === "@") body = body.slice(1);

  const slash = body.indexOf("/");
  let host = (slash === -1 ? body : body.slice(0, slash)).toLowerCase();
  if (host.length > 4 && host.slice(-4) === ".lez") host = host.slice(0, -4);
  const path = slash === -1 ? "/" : body.slice(slash) || "/";

  if (!NAME_RE.test(host)) {
    return { ok: false, error: "Invalid LNS name: " + host };
  }
  return {
    ok: true,
    kind: "lns",
    name: host,
    path: path,
    siteBase: "lns://" + host,
    canonical: "lns://" + host + (path === "/" ? "" : path),
  };
}

export function extractSiteInfo(record) {
  const texts = (record && record.texts) || {};
  const rawCid =
    typeof texts.cid === "string"
      ? texts.cid.trim().replace(/^cid\s*(?:=|:\/\/|:)\s*/i, "")
      : "";
  const cid = CID_RE.test(rawCid) ? rawCid : "";
  const sha256 =
    typeof texts["cid.sha256"] === "string" && SHA256_RE.test(texts["cid.sha256"])
      ? texts["cid.sha256"].toLowerCase()
      : "";
  const siteType = typeof texts["cid.type"] === "string" ? texts["cid.type"] : "";
  return {
    name: (record && record.name) || "",
    display: texts.display || (record && record.name) || "",
    bio: texts.bio || "",
    cid: cid,
    sha256: sha256,
    siteType: siteType,
    hasSite: cid.length > 0,
    texts: texts,
  };
}

export function buildProfileEntries(cid, sha256, siteType) {
  const cleanCid = String(cid || "").trim();
  if (!CID_RE.test(cleanCid)) return { ok: false, error: "CID must be 8-128 alphanumeric characters" };
  const entries = { cid: cleanCid };
  const cleanHash = String(sha256 || "").trim().toLowerCase();
  if (cleanHash) {
    if (!SHA256_RE.test(cleanHash)) return { ok: false, error: "SHA-256 must be 64 hex characters" };
    entries["cid.sha256"] = cleanHash;
  }
  const cleanType = String(siteType || "").trim();
  if (cleanType) entries["cid.type"] = cleanType;
  return { ok: true, entries: entries };
}

export function utf8ToBytes(str) {
  const s = String(str || "");
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const c2 = s.charCodeAt(++i);
      const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return out;
}

export function bytesToUtf8(bytes) {
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i++];
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
    } else if ((b0 & 0xe0) === 0xc0 && i < bytes.length) {
      const b1 = bytes[i++];
      out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
    } else if ((b0 & 0xf0) === 0xe0 && i + 1 < bytes.length) {
      const b1 = bytes[i++];
      const b2 = bytes[i++];
      out += String.fromCharCode(((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f));
    } else if ((b0 & 0xf8) === 0xf0 && i + 2 < bytes.length) {
      const b1 = bytes[i++];
      const b2 = bytes[i++];
      const b3 = bytes[i++];
      let cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
  }
  return out;
}

export function base64ToBytes(b64) {
  const s = String(b64 || "").replace(/[^A-Za-z0-9+/=]/g, "");
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const c0 = B64_ALPHA.indexOf(s.charAt(i));
    const c1 = B64_ALPHA.indexOf(s.charAt(i + 1));
    const c2 = s.charAt(i + 2) === "=" ? -1 : B64_ALPHA.indexOf(s.charAt(i + 2));
    const c3 = s.charAt(i + 3) === "=" ? -1 : B64_ALPHA.indexOf(s.charAt(i + 3));
    if (c0 < 0 || c1 < 0) break;
    out.push((c0 << 2) | (c1 >> 4));
    if (c2 >= 0) out.push(((c1 & 15) << 4) | (c2 >> 2));
    if (c3 >= 0) out.push(((c2 & 3) << 6) | c3);
  }
  return out;
}

export function bytesToBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64_ALPHA[(n >> 18) & 63];
    out += B64_ALPHA[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64_ALPHA[(n >> 6) & 63] : "=";
    out += i + 2 < bytes.length ? B64_ALPHA[n & 63] : "=";
  }
  return out;
}

function base64UrlEncodeUtf8(str) {
  return bytesToBase64(utf8ToBytes(str)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Pure JS SHA-256 (FIPS 180-4) for QML QV4 verification of storage_module chunks.
const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

export function sha256HexBytes(bytes) {
  const len = bytes.length;
  const bitLenHi = Math.floor(len / 0x20000000);
  const bitLenLo = (len << 3) >>> 0;
  const paddedLen = ((len + 9 + 63) & ~63);
  const buf = new Array(paddedLen);
  for (let i = 0; i < len; i++) buf[i] = bytes[i] & 0xff;
  buf[len] = 0x80;
  for (let i = len + 1; i < paddedLen - 8; i++) buf[i] = 0;
  buf[paddedLen - 8] = (bitLenHi >>> 24) & 0xff;
  buf[paddedLen - 7] = (bitLenHi >>> 16) & 0xff;
  buf[paddedLen - 6] = (bitLenHi >>> 8) & 0xff;
  buf[paddedLen - 5] = bitLenHi & 0xff;
  buf[paddedLen - 4] = (bitLenLo >>> 24) & 0xff;
  buf[paddedLen - 3] = (bitLenLo >>> 16) & 0xff;
  buf[paddedLen - 2] = (bitLenLo >>> 8) & 0xff;
  buf[paddedLen - 1] = bitLenLo & 0xff;

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Array(64);

  for (let off = 0; off < paddedLen; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = ((buf[off + i * 4] << 24) | (buf[off + i * 4 + 1] << 16) | (buf[off + i * 4 + 2] << 8) | buf[off + i * 4 + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA_K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }
  const hs = [h0, h1, h2, h3, h4, h5, h6, h7];
  let hex = "";
  for (let i = 0; i < 8; i++) {
    hex += ("00000000" + hs[i].toString(16)).slice(-8);
  }
  return hex;
}

export function sha256HexUtf8(str) {
  return sha256HexBytes(utf8ToBytes(str));
}

export function tryParseManifestJson(text) {
  const s = String(text || "").trim();
  if (!s || s.charAt(0) !== "{") return null;
  try {
    const obj = JSON.parse(s);
    if (obj && obj.kind === "lns-site-manifest" && obj.files && typeof obj.files === "object") {
      return obj;
    }
  } catch (e) {}
  return null;
}

function safeHexColor(val) {
  const tok = String(val || "").trim().split(/\s+/)[0].toLowerCase();
  if (/^#[0-9a-f]{6}$/.test(tok)) return tok;
  if (/^#[0-9a-f]{3}$/.test(tok)) {
    return "#" + tok[1] + tok[1] + tok[2] + tok[2] + tok[3] + tok[3];
  }
  const map = { white: "#ffffff", black: "#000000", blue: "#0055ff", red: "#dc2626", green: "#16a34a" };
  return map[tok] || "";
}

function decodeHtmlEntities(s) {
  return String(s || "")
    .replace(/&rarr;/g, "→")
    .replace(/&larr;/g, "←")
    .replace(/&mdash;/g, "—")
    .replace(/&ndash;/g, "–")
    .replace(/&middot;/g, "·")
    .replace(/&hellip;/g, "…")
    .replace(/&nbsp;/g, " ")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Fallback safe HTML sanitizer for Basecamp when bytes arrive via `storage_module` and the
// installed `lns_browser_core` binary does not yet expose `render_html`.
export function sanitizeHtmlFallback(rawHtml, siteBase) {
  const src = String(rawHtml || "").slice(0, 131072);
  let title = "";
  const tm = src.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (tm) title = decodeHtmlEntities(tm[1].trim()).slice(0, 200);

  let bgColor = "";
  let fgColor = "";
  let linkColor = "";
  let svgFill = "";
  const classFills = {};
  const styleRe = /<style[^>]*>([\s\S]*?)<\/style>/gi;
  let sm;
  while ((sm = styleRe.exec(src)) !== null) {
    const css = sm[1].replace(/\/\*[\s\S]*?\*\//g, "");
    const bodyM = css.match(/(?:^|[}\s])body\s*\{([^}]*)\}/i);
    if (bodyM) {
      const bgM = bodyM[1].match(/background(?:-color)?\s*:\s*([^;]+)/i);
      if (bgM) bgColor = safeHexColor(bgM[1]) || bgColor;
      const fgM = bodyM[1].match(/(?:^|;)\s*color\s*:\s*([^;]+)/i);
      if (fgM) fgColor = safeHexColor(fgM[1]) || fgColor;
    }
    const aM = css.match(/(?:^|[}\s])a\s*\{([^}]*)\}/i);
    if (aM) {
      const lcM = aM[1].match(/(?:^|;)\s*color\s*:\s*([^;]+)/i);
      if (lcM) linkColor = safeHexColor(lcM[1]) || linkColor;
    }
    const clsRe = /\.([a-zA-Z0-9_-]+)\s*\{([^}]*)\}/g;
    let cm;
    while ((cm = clsRe.exec(css)) !== null) {
      const fM = cm[2].match(/(?:fill|color)\s*:\s*([^;]+)/i);
      const col = fM ? safeHexColor(fM[1]) : "";
      if (col) {
        classFills[cm[1].toLowerCase()] = col;
        if (cm[1].toLowerCase() === "hero") svgFill = col;
      }
    }
  }

  const blocks = [];
  let body = src
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<head[\s\S]*?<\/head>/gi, "")
    .replace(/<iframe[\s\S]*?<\/iframe>/gi, "")
    .replace(/<img\b[^>]*src\s*=\s*["']https?:[^"']*["'][^>]*>/gi, "");

  // Extract safe inline <svg> blocks in order
  const svgRe = /<svg\b[^>]*>[\s\S]*?<\/svg>/gi;
  const hasSvg = svgRe.test(body);
  svgRe.lastIndex = 0;
  if (hasSvg) {
    body = body.replace(/<h1\b[^>]*class\s*=\s*["'][^"']*\bsr\b[^"']*["'][^>]*>[\s\S]*?<\/h1>/gi, "");
  }

  function cleanFragment(frag) {
    // Strip tags outside the safe allowlist, keep <a href> only for lns://, cid://, https://, relative
    const out = frag.replace(/<\/?([a-zA-Z0-9]+)(\s[^>]*)?>/g, function (full, tag, attrs) {
      const low = tag.toLowerCase();
      const isClose = full.charAt(1) === "/";
      if (["h1", "h2", "h3", "h4", "p", "ul", "ol", "li", "b", "strong", "i", "em", "code", "pre", "blockquote", "br", "hr", "span", "div"].indexOf(low) >= 0) {
        return isClose ? "</" + low + ">" : "<" + low + ">";
      }
      if (low === "a") {
        if (isClose) return "</a>";
        const hm = String(attrs || "").match(/href\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
        const href = hm ? decodeHtmlEntities((hm[1] || hm[2] || "").trim()) : "";
        if (/^(lns|cid):\/\//i.test(href) || isExternalHttpsUrl(href)) {
          return '<a href="' + escapeHtml(href) + '">';
        }
        if (href && href.indexOf(":") === -1 && href.indexOf("//") !== 0 && siteBase) {
          const cleanPath = href.charAt(0) === "/" ? href : "/" + href;
          return '<a href="' + escapeHtml(siteBase + cleanPath) + '">';
        }
        return "";
      }
      return "";
    });
    return out.replace(/&[a-zA-Z#0-9]+;/g, function (ent) {
      const dec = decodeHtmlEntities(ent);
      return dec === ent ? ent : escapeHtml(dec);
    });
  }

  let lastIdx = 0;
  let m;
  while ((m = svgRe.exec(body)) !== null) {
    const before = cleanFragment(body.slice(lastIdx, m.index)).trim();
    if (before) blocks.push({ kind: "html", html: before });
    const rawSvg = m[0];
    const lowSvg = rawSvg.toLowerCase();
    const safeSvg =
      rawSvg.length <= 65536 &&
      lowSvg.indexOf("<script") === -1 &&
      lowSvg.indexOf("<foreignobject") === -1 &&
      lowSvg.indexOf("javascript:") === -1 &&
      lowSvg.indexOf("http://") === -1 &&
      lowSvg.indexOf("https://") === -1 &&
      !/\son[a-z]+\s*=/i.test(lowSvg);
    if (safeSvg) {
      const vb = rawSvg.match(/viewBox\s*=\s*["']\s*([\d.-]+)[\s,]+([\d.-]+)[\s,]+([\d.]+)[\s,]+([\d.]+)/i);
      const vbX = vb ? Number(vb[1]) : 0;
      const vbY = vb ? Number(vb[2]) : 0;
      const vbW = vb && Number(vb[3]) > 0 ? Number(vb[3]) : 600;
      const vbH = vb && Number(vb[4]) > 0 ? Number(vb[4]) : 120;
      const w = vbW < 120 ? Math.min(760, Math.ceil(vbW * 10)) : Math.min(760, Math.ceil(vbW));
      const h = vbW > 0 ? Math.max(24, Math.round((w * vbH) / vbW)) : 120;
      const fillMatch = rawSvg.slice(0, rawSvg.indexOf(">")).match(/\bfill\s*=\s*["']([^"']+)["']/i);
      const defaultFill = (fillMatch && safeHexColor(fillMatch[1])) || svgFill || linkColor || fgColor || "#0055ff";
      const altMatch = rawSvg.slice(0, rawSvg.indexOf(">")).match(/aria-label\s*=\s*["']([^"']+)["']/i);
      const alt = altMatch ? decodeHtmlEntities(altMatch[1]) : "";
      const ops = extractSvgCanvasOps(rawSvg, defaultFill, classFills);
      if (ops.length > 0) {
        blocks.push({
          kind: "svg",
          alt: alt,
          vb_x: vbX,
          vb_y: vbY,
          vb_w: vbW,
          vb_h: vbH,
          width: w,
          height: h,
          ops: ops,
        });
      } else if (alt) {
        blocks.push({ kind: "html", html: "<h2>" + escapeHtml(alt) + "</h2>" });
      }
    }
    lastIdx = m.index + rawSvg.length;
  }
  const tail = cleanFragment(body.slice(lastIdx)).trim();
  if (tail) blocks.push({ kind: "html", html: tail });

  const htmlAll = blocks.filter(function (b) { return b.kind === "html"; }).map(function (b) { return b.html; }).join("");
  return {
    title: title,
    html: htmlAll,
    bg_color: bgColor || null,
    fg_color: fgColor || null,
    link_color: linkColor || null,
    blocks: blocks,
  };
}

function getSvgAttr(attrs, name) {
  const re = new RegExp("(?:^|\\s)" + name + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')", "i");
  const m = String(attrs || "").match(re);
  return m ? (m[1] !== undefined ? m[1] : m[2]) : "";
}

function resolveSvgElemFill(attrs, defaultFill, classFills) {
  const rawFill = getSvgAttr(attrs, "fill");
  if (rawFill) {
    const low = rawFill.trim().toLowerCase();
    if (low === "none" || low === "transparent") return "";
    if (low === "currentcolor") return defaultFill;
    const c = safeHexColor(rawFill);
    if (c) return c;
  }
  const clsAttr = getSvgAttr(attrs, "class");
  if (clsAttr && classFills) {
    const parts = clsAttr.trim().split(/\s+/);
    for (let i = 0; i < parts.length; i++) {
      const c = classFills[parts[i].toLowerCase()];
      if (c) return c;
    }
  }
  return defaultFill;
}

export function extractSvgCanvasOps(rawSvg, defaultFill, classFills) {
  const defs = {};
  const ops = [];
  let inDefs = false;
  const tagRe = /<(\/?)([a-zA-Z0-9:_-]+)([^>]*)>/g;
  let m;
  while ((m = tagRe.exec(String(rawSvg || ""))) !== null && ops.length < 512) {
    const isClose = m[1] === "/";
    const tag = m[2].toLowerCase();
    const attrs = m[3] || "";
    if (tag === "defs") {
      inDefs = !isClose;
      continue;
    }
    if (isClose) continue;
    const opRaw = getSvgAttr(attrs, "opacity") || getSvgAttr(attrs, "fill-opacity");
    const opacity = opRaw !== "" && !isNaN(Number(opRaw)) ? Math.max(0, Math.min(1, Number(opRaw))) : 1;

    if (tag === "path") {
      const d = getSvgAttr(attrs, "d");
      if (!d) continue;
      const id = getSvgAttr(attrs, "id");
      if (id) defs[id.trim()] = d;
      if (inDefs) continue;
      const fill = resolveSvgElemFill(attrs, defaultFill, classFills);
      if (!fill) continue;
      ops.push({ op: "path", d: d, x: 0, y: 0, fill: fill, opacity: opacity });
    } else if (tag === "use" && !inDefs) {
      const href = (getSvgAttr(attrs, "href") || getSvgAttr(attrs, "xlink:href") || "").trim().replace(/^#/, "");
      const d = defs[href];
      if (!d) continue;
      const fill = resolveSvgElemFill(attrs, defaultFill, classFills);
      if (!fill) continue;
      const x = Number(getSvgAttr(attrs, "x") || 0) || 0;
      const y = Number(getSvgAttr(attrs, "y") || 0) || 0;
      ops.push({ op: "path", d: d, x: x, y: y, fill: fill, opacity: opacity });
    } else if (tag === "rect" && !inDefs) {
      const fill = resolveSvgElemFill(attrs, defaultFill, classFills);
      if (!fill) continue;
      const x = Number(getSvgAttr(attrs, "x") || 0) || 0;
      const y = Number(getSvgAttr(attrs, "y") || 0) || 0;
      const w = Number(String(getSvgAttr(attrs, "width") || "").replace(/px$/i, ""));
      const h = Number(String(getSvgAttr(attrs, "height") || "").replace(/px$/i, ""));
      if (w > 0 && h > 0) ops.push({ op: "rect", x: x, y: y, w: w, h: h, fill: fill, opacity: opacity });
    } else if (tag === "circle" && !inDefs) {
      const fill = resolveSvgElemFill(attrs, defaultFill, classFills);
      if (!fill) continue;
      const cx = Number(getSvgAttr(attrs, "cx") || 0) || 0;
      const cy = Number(getSvgAttr(attrs, "cy") || 0) || 0;
      const r = Number(getSvgAttr(attrs, "r") || 0);
      if (r > 0) ops.push({ op: "circle", x: cx, y: cy, r: r, fill: fill, opacity: opacity });
    } else if (tag === "polygon" && !inDefs) {
      const fill = resolveSvgElemFill(attrs, defaultFill, classFills);
      const pts = getSvgAttr(attrs, "points");
      if (fill && pts) ops.push({ op: "polygon", points: pts, x: 0, y: 0, fill: fill, opacity: opacity });
    }
  }
  return ops;
}

// Draws a sanitized `kind: "svg"` block onto a QtQuick Canvas 2D context (zero QtSvg dependency).
export function drawSvgToCanvas(ctx, block, canvasW, canvasH) {
  if (!ctx || !block || !Array.isArray(block.ops) || canvasW <= 0 || canvasH <= 0) return;
  const vbX = Number(block.vb_x || 0) || 0;
  const vbY = Number(block.vb_y || 0) || 0;
  const vbW = Number(block.vb_w || 0) > 0 ? Number(block.vb_w) : 100;
  const vbH = Number(block.vb_h || 0) > 0 ? Number(block.vb_h) : 100;

  ctx.clearRect(0, 0, canvasW, canvasH);
  ctx.save();
  ctx.scale(canvasW / vbW, canvasH / vbH);
  if (vbX !== 0 || vbY !== 0) ctx.translate(-vbX, -vbY);

  for (let i = 0; i < block.ops.length; i++) {
    const item = block.ops[i];
    if (!item || !item.fill) continue;
    ctx.save();
    ctx.globalAlpha = typeof item.opacity === "number" ? item.opacity : 1;
    ctx.fillStyle = item.fill;

    if (item.op === "rect") {
      ctx.fillRect(item.x || 0, item.y || 0, item.w || 0, item.h || 0);
    } else if (item.op === "circle") {
      ctx.beginPath();
      ctx.arc(item.x || 0, item.y || 0, item.r || 0, 0, Math.PI * 2);
      ctx.fill();
    } else if (item.op === "polygon" && item.points) {
      const nums = String(item.points).match(/-?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?/gi) || [];
      if (nums.length >= 4) {
        ctx.beginPath();
        ctx.moveTo(Number(nums[0]), Number(nums[1]));
        for (let p = 2; p + 1 < nums.length; p += 2) {
          ctx.lineTo(Number(nums[p]), Number(nums[p + 1]));
        }
        ctx.closePath();
        ctx.fill();
      }
    } else if (item.op === "path" && item.d) {
      if (item.x || item.y) ctx.translate(item.x || 0, item.y || 0);
      traceSvgPath(ctx, item.d);
      ctx.fill();
    }
    ctx.restore();
  }
  ctx.restore();
}

function traceSvgPath(ctx, d) {
  const tokens = String(d || "").match(/[a-zA-Z]|-?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?/gi) || [];
  let i = 0;
  let cmd = "";
  let cx = 0;
  let cy = 0;
  let sx = 0;
  let sy = 0;
  ctx.beginPath();

  function isCmd(tok) {
    return tok && tok.length === 1 && /[a-zA-Z]/.test(tok);
  }
  function nextNum() {
    return i < tokens.length ? Number(tokens[i++]) : 0;
  }

  while (i < tokens.length) {
    if (isCmd(tokens[i])) {
      cmd = tokens[i++];
    } else if (!cmd) {
      break;
    }
    if (cmd === "M" || cmd === "m") {
      const nx = nextNum();
      const ny = nextNum();
      cx = cmd === "m" ? cx + nx : nx;
      cy = cmd === "m" ? cy + ny : ny;
      sx = cx;
      sy = cy;
      ctx.moveTo(cx, cy);
      cmd = cmd === "m" ? "l" : "L";
    } else if (cmd === "L" || cmd === "l") {
      const nx = nextNum();
      const ny = nextNum();
      cx = cmd === "l" ? cx + nx : nx;
      cy = cmd === "l" ? cy + ny : ny;
      ctx.lineTo(cx, cy);
    } else if (cmd === "H" || cmd === "h") {
      const nx = nextNum();
      cx = cmd === "h" ? cx + nx : nx;
      ctx.lineTo(cx, cy);
    } else if (cmd === "V" || cmd === "v") {
      const ny = nextNum();
      cy = cmd === "v" ? cy + ny : ny;
      ctx.lineTo(cx, cy);
    } else if (cmd === "C" || cmd === "c") {
      const x1 = nextNum(), y1 = nextNum(), x2 = nextNum(), y2 = nextNum(), x = nextNum(), y = nextNum();
      if (cmd === "c") {
        ctx.bezierCurveTo(cx + x1, cy + y1, cx + x2, cy + y2, cx + x, cy + y);
        cx += x; cy += y;
      } else {
        ctx.bezierCurveTo(x1, y1, x2, y2, x, y);
        cx = x; cy = y;
      }
    } else if (cmd === "Q" || cmd === "q") {
      const x1 = nextNum(), y1 = nextNum(), x = nextNum(), y = nextNum();
      if (cmd === "q") {
        ctx.quadraticCurveTo(cx + x1, cy + y1, cx + x, cy + y);
        cx += x; cy += y;
      } else {
        ctx.quadraticCurveTo(x1, y1, x, y);
        cx = x; cy = y;
      }
    } else if (cmd === "Z" || cmd === "z") {
      ctx.closePath();
      cx = sx;
      cy = sy;
      cmd = "";
    } else {
      // Skip unsupported command token gracefully
      cmd = "";
    }
  }
}

export function buildPublishDeepLink(params) {
  const payload = {};
  const name = normalizeName(params && params.name);
  if (name) payload.name = name;
  if (params && params.cid) payload.cid = String(params.cid).trim();
  if (params && params.sha256) payload.sha256 = String(params.sha256).trim().toLowerCase();
  if (params && params.site_type) payload.site_type = String(params.site_type).trim();
  if (params && params.html) payload.html = String(params.html);
  if (params && params.return_app) payload.return_app = String(params.return_app).trim();
  return "basecamp://intent/names.publish_site?p=" + base64UrlEncodeUtf8(JSON.stringify(payload));
}

export function shortHash(value, head, tail) {
  const s = String(value || "");
  const h = head || 10;
  const t = tail || 8;
  if (s.length <= h + t + 3) return s;
  return s.slice(0, h) + "..." + s.slice(-t);
}
