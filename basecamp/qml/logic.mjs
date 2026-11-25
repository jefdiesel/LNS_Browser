// Pure JS helpers for the native Basecamp LNS Web Browser QML view (tested under Node).
// Note: Qt QML's QV4 engine does NOT support ES2018 regex lookbehind (`(?<!...)`), TextDecoder,
// or atob, so everything here is self-contained ES5/ES6-safe JS.

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
const CID_RE = /^[A-Za-z0-9]{8,128}$/;
const SHA256_RE = /^[0-9a-f]{64}$/i;
const HTTPS_RE = /^https:\/\/[^\s/@]+\.[^\s/]+/i;
const CTRL_RE = /[\x00-\x1f\x7f-\x9f]/;
const B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export const LINKS_HEADER = "# lns-links/1";
export const LINKS_CONTENT_TYPE = "text/vnd.logos.lns-links";
export const MAX_ONCHAIN_LINKS_BYTES = 10 * 1024;
export const MAX_LINKS_DEPTH = 32;
export const MAX_LINKS_LIST_BYTES = 2 * 1024 * 1024;
export const MAX_LINKS_ENTRIES = 10000;

export function isArrayLike(x) {
  if (Array.isArray(x)) return true;
  if (!x || typeof x !== "object") return false;
  if (typeof x.length !== "number" || x.length < 0 || !isFinite(x.length) || Math.floor(x.length) !== x.length) {
    return false;
  }
  if (x.length === 0) {
    for (const k in x) {
      if (Object.prototype.hasOwnProperty.call(x, k) && k !== "length") return false;
    }
    return true;
  }
  return 0 in x || x[0] !== undefined;
}

export function toArray(x) {
  if (Array.isArray(x)) return x;
  if (!isArrayLike(x)) return [];
  const out = [];
  for (let i = 0; i < x.length; i++) out.push(x[i]);
  return out;
}

export function normalizeModuleValue(val, depth) {
  const d = depth || 0;
  if (val === null || val === undefined || typeof val !== "object" || d > 12) return val;
  if (isArrayLike(val)) {
    const arr = [];
    for (let i = 0; i < val.length; i++) {
      arr.push(normalizeModuleValue(val[i], d + 1));
    }
    return arr;
  }
  const out = {};
  const keys = Object.keys(val);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    out[k] = normalizeModuleValue(val[k], d + 1);
  }
  return out;
}

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
  cur = normalizeModuleValue(cur);
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
    if (isArrayLike(raw)) {
      if (raw.length === 0) return null;
      raw = raw[0];
      continue;
    }
    break;
  }
  return raw && typeof raw === "object" && !isArrayLike(raw) ? normalizeModuleValue(raw) : null;
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

export function isBusyReply(reply, errText) {
  let cur = reply;
  for (let depth = 0; depth < 3 && typeof cur === "string"; depth++) {
    try {
      cur = JSON.parse(cur);
    } catch (e) {
      break;
    }
  }
  if (cur && typeof cur === "object") {
    if (cur.busy === true) return true;
    if (cur.value && typeof cur.value === "object" && cur.value.busy === true) return true;
    if (String(cur.code || "").toLowerCase() === "busy") return true;
  }
  const low = String(errText || (cur && (cur.error || cur.message)) || "").toLowerCase();
  return low === "busy" || low.indexOf("module is busy") !== -1 || low.indexOf("currently busy") !== -1;
}

export function formatUnreachableCidError(cid, detail) {
  const short = shortHash(cid, 12, 8);
  const raw = String(detail || "").trim();
  const lower = raw.toLowerCase();
  // Never rewrite bridge/SDK/argument refusals or integrity mismatches as "CID not reachable".
  if (
    lower.indexOf("call refused") !== -1 ||
    lower.indexOf("expected integer") !== -1 ||
    lower.indexOf("invalid_args") !== -1 ||
    lower.indexOf("invalid arg") !== -1 ||
    lower.indexOf("unknown method") !== -1 ||
    lower.indexOf("unauthorized") !== -1 ||
    lower.indexOf("sdk error") !== -1 ||
    lower.indexOf("refused:") !== -1 ||
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

export function formatStorageFetchError(cid, path, detail) {
  const short = shortHash(cid, 12, 8);
  const cleanPath = String(path || "/");
  const raw = String(detail || "").trim();
  const base = formatUnreachableCidError(cid, detail);
  if (raw && base === raw) {
    return "Failed to fetch " + cleanPath + " (CID " + short + "): " + raw;
  }
  return "Failed to fetch " + cleanPath + " (CID " + short + "): " + base;
}

export function normalizePath(rawPath) {
  const s = String(rawPath === undefined || rawPath === null ? "/" : rawPath);
  if (CTRL_RE.test(s)) {
    return { ok: false, error: "Path contains control characters" };
  }
  const hashIdx = s.indexOf("#");
  const fragment = hashIdx !== -1 ? s.slice(hashIdx) : "";
  const withoutFrag = hashIdx !== -1 ? s.slice(0, hashIdx) : s;
  const qIdx = withoutFrag.indexOf("?");
  const pathPart = qIdx !== -1 ? withoutFrag.slice(0, qIdx) : withoutFrag;

  const hadTrailingSlash = pathPart === "" || pathPart.charAt(pathPart.length - 1) === "/";
  const rawSegs = pathPart.split("/");
  const segments = [];
  for (let i = 0; i < rawSegs.length; i++) {
    const seg = rawSegs[i];
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      if (segments.length > 0) segments.pop();
      continue;
    }
    segments.push(seg);
  }
  if (segments.length === 0) {
    return { ok: true, path: "/", segments: [], trailingSlash: true, fragment: fragment };
  }
  const normalized = "/" + segments.join("/") + (hadTrailingSlash ? "/" : "");
  return {
    ok: true,
    path: normalized,
    segments: segments,
    trailingSlash: hadTrailingSlash,
    fragment: fragment,
  };
}

export function resolveRelativeSitePath(href, currentPath) {
  const raw = String(href || "").trim();
  if (!raw || CTRL_RE.test(raw)) return null;
  if (raw.indexOf(":") !== -1 || raw.indexOf("//") === 0 || raw.charAt(0) === "#") return null;
  const cur = String(currentPath || "/");
  let joined;
  if (raw.charAt(0) === "/") {
    joined = raw;
  } else {
    const cleanCur = cur.split(/[?#]/)[0] || "/";
    const lastSlash = cleanCur.lastIndexOf("/");
    const dir = lastSlash >= 0 ? cleanCur.slice(0, lastSlash + 1) : "/";
    joined = dir + raw;
  }
  const norm = normalizePath(joined);
  if (!norm.ok) return null;
  return norm.path + (norm.fragment || "");
}

export function parseUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) return { ok: false, error: "Enter an LNS URL (e.g. lns://jef) or CID (cid://...)" };
  if (CTRL_RE.test(s)) return { ok: false, error: "URL contains invalid control characters" };

  if (/^cid:\/\//i.test(s)) {
    const rest = s.slice(6);
    const sepMatch = rest.search(/[/?#]/);
    const cid = sepMatch === -1 ? rest : rest.slice(0, sepMatch);
    const tail = sepMatch === -1 ? "/" : rest.slice(sepMatch);
    if (!CID_RE.test(cid)) return { ok: false, error: "Invalid CID format" };
    const norm = normalizePath(tail.charAt(0) === "/" ? tail : "/" + tail);
    if (!norm.ok) return { ok: false, error: norm.error };
    const res = {
      ok: true,
      kind: "cid",
      cid: cid,
      path: norm.path,
      siteBase: "cid://" + cid,
      canonical: "cid://" + cid + (norm.path === "/" ? "" : norm.path),
    };
    if (norm.fragment) res.fragment = norm.fragment;
    return res;
  }

  let body = s;
  if (/^lns:\/\//i.test(body)) body = body.slice(6);
  else if (/^lns:/i.test(body)) body = body.slice(4);
  if (body.charAt(0) === "@") body = body.slice(1);

  const sepIdx = body.search(/[/?#]/);
  let host = (sepIdx === -1 ? body : body.slice(0, sepIdx)).toLowerCase();
  if (host.length > 4 && host.slice(-4) === ".lez") host = host.slice(0, -4);
  const tail = sepIdx === -1 ? "/" : body.slice(sepIdx);

  if (!NAME_RE.test(host)) {
    return { ok: false, error: "Invalid LNS name: " + host };
  }
  const norm = normalizePath(tail.charAt(0) === "/" ? tail : "/" + tail);
  if (!norm.ok) return { ok: false, error: norm.error };
  const res = {
    ok: true,
    kind: "lns",
    name: host,
    path: norm.path,
    siteBase: "lns://" + host,
    canonical: "lns://" + host + (norm.path === "/" ? "" : norm.path),
  };
  if (norm.fragment) res.fragment = norm.fragment;
  return res;
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
      const c2 = s.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        i += 1;
        const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
        out.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f)
        );
        continue;
      }
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return out;
}

export function bytesToUtf8Strict(bytes) {
  const b = bytes || [];
  let out = "";
  let i = 0;
  while (i < b.length) {
    const b0 = b[i++];
    if (b0 < 0x80) {
      out += String.fromCharCode(b0);
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      if (i >= b.length) return { ok: false, error: "Truncated UTF-8 sequence" };
      const b1 = b[i++];
      if ((b1 & 0xc0) !== 0x80) return { ok: false, error: "Invalid UTF-8 continuation byte" };
      out += String.fromCharCode(((b0 & 0x1f) << 6) | (b1 & 0x3f));
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      if (i + 1 >= b.length) return { ok: false, error: "Truncated UTF-8 sequence" };
      const b1 = b[i++];
      const b2 = b[i++];
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80) {
        return { ok: false, error: "Invalid UTF-8 continuation byte" };
      }
      if (b0 === 0xe0 && b1 < 0xa0) return { ok: false, error: "Overlong UTF-8 sequence" };
      if (b0 === 0xed && b1 >= 0xa0) return { ok: false, error: "UTF-8 surrogate code point" };
      out += String.fromCharCode(((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f));
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      if (i + 2 >= b.length) return { ok: false, error: "Truncated UTF-8 sequence" };
      const b1 = b[i++];
      const b2 = b[i++];
      const b3 = b[i++];
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80 || (b3 & 0xc0) !== 0x80) {
        return { ok: false, error: "Invalid UTF-8 continuation byte" };
      }
      if (b0 === 0xf0 && b1 < 0x90) return { ok: false, error: "Overlong UTF-8 sequence" };
      if (b0 === 0xf4 && b1 > 0x8f) return { ok: false, error: "UTF-8 code point out of range" };
      let cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
      cp -= 0x10000;
      out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    } else {
      return { ok: false, error: "Invalid UTF-8 leading byte" };
    }
  }
  return { ok: true, text: out };
}

export function base64DecodedLength(b64) {
  const s = String(b64 || "").replace(/[^A-Za-z0-9+/=]/g, "");
  if (s.length === 0) return 0;
  let pad = 0;
  if (s.length >= 1 && s.charAt(s.length - 1) === "=") pad += 1;
  if (s.length >= 2 && s.charAt(s.length - 2) === "=") pad += 1;
  return Math.max(0, Math.floor((s.length * 3) / 4) - pad);
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

export function isValidSegmentName(name) {
  if (typeof name !== "string" || name.length === 0) return false;
  if (name === "." || name === "..") return false;
  if (CTRL_RE.test(name)) return false;
  if (/[\/\\?#\s]/.test(name)) return false;
  if (utf8ToBytes(name).length > 255) return false;
  return true;
}

export function validateSaveFilename(rawName) {
  const name = String(rawName === undefined || rawName === null ? "" : rawName).trim();
  if (!name) return { ok: false, error: "Download filename must not be empty" };
  if (name === "." || name === "..") {
    return { ok: false, error: "Unsafe download filename: " + name };
  }
  if (name.charAt(0) === ".") {
    return { ok: false, error: "Hidden dotfile download names are not allowed: " + name };
  }
  if (CTRL_RE.test(name)) {
    return { ok: false, error: "Download filename contains control characters" };
  }
  if (/[\/\\:*?"<>|]/.test(name)) {
    return { ok: false, error: "Download filename contains forbidden characters" };
  }
  if (utf8ToBytes(name).length > 255) {
    return { ok: false, error: "Download filename exceeds 255 bytes" };
  }
  return { ok: true, filename: name };
}

export function buildSaveTargetPath(downloadsDir, rawName) {
  const cleanDir = String(downloadsDir || "").trim().replace(/\/+$/, "");
  if (!cleanDir) {
    return { ok: false, error: "Downloads folder is unavailable (no /tmp fallback allowed)." };
  }
  if (CTRL_RE.test(cleanDir)) {
    return { ok: false, error: "Downloads folder path contains control characters." };
  }
  const checked = validateSaveFilename(rawName);
  if (!checked.ok) return checked;
  return { ok: true, filename: checked.filename, path: cleanDir + "/" + checked.filename };
}

export function findPinnedSha256(cid, relPath, pageData) {
  const cleanCid = String(cid || "").trim();
  const cleanPath = String(relPath || "").trim();
  if (!pageData || typeof pageData !== "object") return "";
  if (cleanCid && pageData.cid === cleanCid && typeof pageData.sha256 === "string" && SHA256_RE.test(pageData.sha256)) {
    return pageData.sha256.toLowerCase();
  }
  const files = toArray(pageData.files);
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    if (!f || typeof f !== "object") continue;
    const matchCid = cleanCid && f.cid === cleanCid;
    const matchPath = cleanPath && f.path === cleanPath;
    if ((matchCid || matchPath) && typeof f.sha256 === "string" && SHA256_RE.test(f.sha256)) {
      return f.sha256.toLowerCase();
    }
  }
  return "";
}

export function createSafeMap() {
  return Object.create(null);
}

export function safeMapGet(map, key) {
  if (!map || typeof map !== "object") return undefined;
  return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

export function safeMapSet(map, key, value) {
  if (map && typeof map === "object") {
    map[key] = value;
  }
}

export function getCachedLinksEntry(cache, cid, expectedSha256) {
  const entry = safeMapGet(cache, cid);
  if (!entry || typeof entry !== "object") {
    return { hit: false, mismatch: false, list: null, sha256: "" };
  }
  const list = entry.list && entry.list.ok ? entry.list : (entry.ok ? entry : null);
  const cachedSha = typeof entry.sha256 === "string" ? entry.sha256.toLowerCase() : "";
  if (!list) {
    return { hit: false, mismatch: false, list: null, sha256: "" };
  }
  const exp = expectedSha256 ? String(expectedSha256).trim().toLowerCase() : "";
  if (exp) {
    if (!cachedSha) {
      return { hit: false, mismatch: false, list: null, sha256: "" };
    }
    if (cachedSha !== exp) {
      return {
        hit: false,
        mismatch: true,
        list: null,
        sha256: cachedSha,
        error: "SHA-256 mismatch for cached folder CID " + shortHash(cid) + ": expected " + shortHash(exp) + ", got " + shortHash(cachedSha),
      };
    }
  }
  return { hit: true, mismatch: false, list: list, sha256: cachedSha };
}

export function getCachedImageEntry(cache, cid, expectedSha256) {
  const entry = safeMapGet(cache, cid);
  if (!entry) return { hit: false, mismatch: false, uri: "", sha256: "" };
  const uri = typeof entry === "string" ? entry : (typeof entry.uri === "string" ? entry.uri : "");
  const cachedSha = typeof entry === "object" && typeof entry.sha256 === "string" ? entry.sha256.toLowerCase() : "";
  if (!uri) return { hit: false, mismatch: false, uri: "", sha256: "" };
  const exp = expectedSha256 ? String(expectedSha256).trim().toLowerCase() : "";
  if (exp) {
    if (!cachedSha) return { hit: false, mismatch: false, uri: "", sha256: "" };
    if (cachedSha !== exp) {
      return { hit: false, mismatch: true, uri: "", sha256: cachedSha, error: "SHA-256 mismatch for cached image CID " + shortHash(cid) };
    }
  }
  return { hit: true, mismatch: false, uri: uri, sha256: cachedSha };
}

export function isStaleDownload(dl, currentNavSeq) {
  if (!dl || typeof dl !== "object") return true;
  if (typeof dl.navSeq !== "number") return false;
  return dl.navSeq !== currentNavSeq;
}

export function isLinksContentType(ct) {
  const bare = String(ct || "").split(";")[0].trim().toLowerCase();
  return bare === LINKS_CONTENT_TYPE;
}

export function isLinksListText(text) {
  const s = String(text || "");
  const nl = s.indexOf("\n");
  const first = (nl === -1 ? s : s.slice(0, nl)).replace(/\r$/, "").trim();
  return first === LINKS_HEADER;
}

export function cmpCodePoint(a, b) {
  const ba = utf8ToBytes(a);
  const bb = utf8ToBytes(b);
  const len = ba.length < bb.length ? ba.length : bb.length;
  for (let i = 0; i < len; i++) {
    if (ba[i] !== bb[i]) return ba[i] < bb[i] ? -1 : 1;
  }
  return ba.length < bb.length ? -1 : (ba.length > bb.length ? 1 : 0);
}

/**
 * Parses a per-folder `lns-links/1` list.
 * - Line 1 must be `# lns-links/1`.
 * - Optional `# index <name>` (default `index.html`) and `# title <text>`.
 * - Files: `<name> <cid>[ <sha256>]`
 * - Subfolders: `<name>/ <cid>[ <sha256>]`
 * - Rejects bad lines, duplicates (including file/folder collision), traversal, and invalid CIDs/hashes.
 */
export function parseLinksList(text) {
  const src = String(text === undefined || text === null ? "" : text);
  if (src.length > MAX_LINKS_LIST_BYTES || (src.length > Math.floor(MAX_LINKS_LIST_BYTES / 3) && utf8ToBytes(src).length > MAX_LINKS_LIST_BYTES)) {
    return { ok: false, error: "Links list exceeds maximum size of " + MAX_LINKS_LIST_BYTES + " bytes" };
  }
  // Reject NUL or control chars (ASCII + C1) other than \t, \r, \n
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(src)) {
    return { ok: false, error: "Links list contains invalid control characters" };
  }
  const lines = src.split("\n");
  const firstLine = (lines[0] || "").replace(/\r$/, "").trim();
  if (firstLine !== LINKS_HEADER) {
    return { ok: false, error: "Links list must start with '" + LINKS_HEADER + "'" };
  }

  let indexName = "index.html";
  let hasIndexDirective = false;
  let title = "";
  const byName = Object.create(null);
  const entries = [];

  for (let i = 1; i < lines.length; i++) {
    const lineNo = i + 1;
    const rawLine = lines[i].replace(/\r$/, "");
    const trimmed = rawLine.trim();
    if (!trimmed) continue;

    if (trimmed.charAt(0) === "#") {
      const rest = trimmed.slice(1).trim();
      if (rest === "index" || rest.indexOf("index ") === 0 || rest.indexOf("index\t") === 0) {
        const val = rest.slice(5).trim();
        if (!isValidSegmentName(val)) {
          return { ok: false, error: "Line " + lineNo + ": invalid # index name '" + val + "'" };
        }
        if (hasIndexDirective) {
          return { ok: false, error: "Line " + lineNo + ": duplicate # index directive" };
        }
        indexName = val;
        hasIndexDirective = true;
      } else if (rest.indexOf("title ") === 0 || rest.indexOf("title\t") === 0) {
        title = rest.slice(5).replace(/\t/g, " ").trim().slice(0, 200);
      }
      continue;
    }

    if (entries.length >= MAX_LINKS_ENTRIES) {
      return { ok: false, error: "Links list exceeds maximum of " + MAX_LINKS_ENTRIES + " entries" };
    }

    const parts = trimmed.split(/[ \t]+/);
    if (parts.length < 2 || parts.length > 3) {
      return { ok: false, error: "Line " + lineNo + ": expected '<name>[/] <cid>[ <sha256>]'" };
    }

    const rawName = parts[0];
    const cid = parts[1];
    const rawSha = parts.length === 3 ? parts[2] : "";

    const isDir = rawName.charAt(rawName.length - 1) === "/";
    const name = isDir ? rawName.slice(0, -1) : rawName;
    if (!isValidSegmentName(name)) {
      return { ok: false, error: "Line " + lineNo + ": invalid entry name '" + rawName + "'" };
    }
    if (!CID_RE.test(cid)) {
      return { ok: false, error: "Line " + lineNo + ": invalid CID '" + cid + "'" };
    }
    let sha256 = "";
    if (rawSha) {
      if (!SHA256_RE.test(rawSha)) {
        return { ok: false, error: "Line " + lineNo + ": invalid SHA-256 '" + rawSha + "'" };
      }
      sha256 = rawSha.toLowerCase();
    }
    if (Object.prototype.hasOwnProperty.call(byName, name)) {
      return { ok: false, error: "Line " + lineNo + ": duplicate entry '" + name + "'" };
    }

    const entry = {
      name: name,
      kind: isDir ? "dir" : "file",
      cid: cid,
      sha256: sha256,
    };
    byName[name] = entry;
    entries.push(entry);
  }

  entries.sort(function (a, b) {
    return cmpCodePoint(a.name, b.name);
  });

  return {
    ok: true,
    version: 1,
    index: indexName,
    title: title,
    entries: entries,
    byName: byName,
  };
}

/**
 * Formats a per-folder `lns-links/1` list with deterministic sorted lines.
 */
export function formatLinksList(spec) {
  const s = spec || {};
  const lines = [LINKS_HEADER];
  const title = s.title ? String(s.title).replace(/[\r\n\t]/g, " ").trim().slice(0, 200) : "";
  if (title) {
    if (CTRL_RE.test(title)) {
      return { ok: false, error: "Title contains control characters" };
    }
    lines.push("# title " + title);
  }
  if (s.index !== undefined && s.index !== null && String(s.index) !== "") {
    const idx = String(s.index);
    if (!isValidSegmentName(idx)) {
      return { ok: false, error: "Invalid index name '" + idx + "'" };
    }
    lines.push("# index " + idx);
  }

  const rawEntries = toArray(s.entries);
  const seen = Object.create(null);
  const normalized = [];
  for (let i = 0; i < rawEntries.length; i++) {
    const item = rawEntries[i];
    if (!item || typeof item !== "object") {
      return { ok: false, error: "Invalid entry at index " + i };
    }
    const name = String(item.name || "");
    const kind = item.kind === "dir" ? "dir" : "file";
    const cid = String(item.cid || "").trim();
    const sha = item.sha256 ? String(item.sha256).trim().toLowerCase() : "";
    if (!isValidSegmentName(name)) {
      return { ok: false, error: "Invalid entry name '" + name + "'" };
    }
    if (!CID_RE.test(cid)) {
      return { ok: false, error: "Invalid CID for '" + name + "'" };
    }
    if (sha && !SHA256_RE.test(sha)) {
      return { ok: false, error: "Invalid SHA-256 for '" + name + "'" };
    }
    if (Object.prototype.hasOwnProperty.call(seen, name)) {
      return { ok: false, error: "Duplicate entry '" + name + "'" };
    }
    seen[name] = true;
    normalized.push({ name: name, kind: kind, cid: cid, sha256: sha });
  }

  normalized.sort(function (a, b) {
    return cmpCodePoint(a.name, b.name);
  });

  for (let i = 0; i < normalized.length; i++) {
    const e = normalized[i];
    let line = e.name + (e.kind === "dir" ? "/" : "") + " " + e.cid;
    if (e.sha256) line += " " + e.sha256;
    lines.push(line);
  }

  return { ok: true, text: lines.join("\n") + "\n" };
}

/**
 * Single synchronous step of walking a per-folder `lns-links/1` tree.
 * Returns `{ action: "fetch_dir" | "found" | "not_found", ... }`.
 */
export function stepLinksResolve(list, segments, stepIndex, trailingSlash) {
  const segs = toArray(segments);
  const idx = stepIndex || 0;
  const reqPath = segs.length === 0 ? "/" : "/" + segs.join("/") + (trailingSlash ? "/" : "");

  if (!list || !list.byName) {
    return { action: "not_found", requestedPath: reqPath, error: "Missing folder list" };
  }

  // Reached target directory (either root `/` or after descending into final folder segment)
  if (idx >= segs.length) {
    const indexName = list.index || "index.html";
    const indexEntry = Object.prototype.hasOwnProperty.call(list.byName, indexName)
      ? list.byName[indexName]
      : null;
    const dirPrefix = segs.length === 0 ? "" : "/" + segs.join("/");
    const canonicalDir = dirPrefix + "/";
    if (indexEntry && indexEntry.kind === "file") {
      return {
        action: "found",
        entry: indexEntry,
        resolvedPath: canonicalDir + indexEntry.name,
        canonicalUrlPath: canonicalDir,
        canonicalDir: canonicalDir,
        folderEntries: toArray(list.entries),
        folderTitle: list.title || "",
      };
    }
    return {
      action: "not_found",
      requestedPath: reqPath,
      isDirectory: true,
      canonicalUrlPath: canonicalDir,
      folderEntries: toArray(list.entries),
      error: "No index page (" + indexName + ") in " + canonicalDir,
    };
  }

  const seg = segs[idx];
  const isLast = idx === segs.length - 1;
  const entry = Object.prototype.hasOwnProperty.call(list.byName, seg) ? list.byName[seg] : null;
  if (!entry) {
    return {
      action: "not_found",
      requestedPath: reqPath,
      isDirectory: false,
      error: "No such page: " + reqPath,
    };
  }

  if (entry.kind === "dir") {
    return {
      action: "fetch_dir",
      name: entry.name,
      cid: entry.cid,
      sha256: entry.sha256 || "",
      nextIndex: idx + 1,
    };
  }

  // Exact file entry
  if (!isLast || trailingSlash) {
    return {
      action: "not_found",
      requestedPath: reqPath,
      isDirectory: false,
      error: "No such page: " + reqPath,
    };
  }

  const resolvedPath = "/" + segs.join("/");
  const canonicalDir = segs.length <= 1 ? "/" : "/" + segs.slice(0, -1).join("/") + "/";
  return {
    action: "found",
    entry: entry,
    resolvedPath: resolvedPath,
    canonicalUrlPath: resolvedPath,
    canonicalDir: canonicalDir,
    folderEntries: toArray(list.entries),
    folderTitle: list.title || "",
  };
}

/**
 * Synchronous tree resolver (QV4-safe) using a `loadFolderFn(cid, sha256)` callback and CID cache.
 */
export function resolveLinksSync(rootList, rawPath, loadFolderFn, cache) {
  const norm = normalizePath(rawPath);
  if (!norm.ok) {
    return { ok: false, status: "invalid", error: norm.error };
  }
  const cidCache = cache || Object.create(null);
  let current = rootList;
  let idx = 0;
  let depth = 0;
  let foldersVerified = true;

  while (depth <= MAX_LINKS_DEPTH) {
    const step = stepLinksResolve(current, norm.segments, idx, norm.trailingSlash);
    if (step.action === "found") {
      return {
        ok: true,
        status: "found",
        entry: step.entry,
        resolvedPath: step.resolvedPath,
        canonicalUrlPath: step.canonicalUrlPath,
        canonicalDir: step.canonicalDir,
        folderEntries: step.folderEntries,
        folderTitle: step.folderTitle,
        fragment: norm.fragment,
        foldersVerified: foldersVerified,
      };
    }
    if (step.action === "not_found") {
      return {
        ok: false,
        status: "not_found",
        requestedPath: step.requestedPath,
        isDirectory: !!step.isDirectory,
        canonicalUrlPath: step.canonicalUrlPath || "",
        folderEntries: step.folderEntries || [],
        error: step.error,
      };
    }
    depth += 1;
    if (depth > MAX_LINKS_DEPTH) {
      return { ok: false, status: "error", error: "Folder nesting exceeds limit (" + MAX_LINKS_DEPTH + ")" };
    }
    if (!step.sha256) {
      foldersVerified = false;
    }
    const cached = getCachedLinksEntry(cidCache, step.cid, step.sha256);
    if (cached.mismatch) {
      return { ok: false, status: "error", cid: step.cid, error: cached.error };
    }
    let nextList = cached.hit ? cached.list : null;
    if (!nextList) {
      if (typeof loadFolderFn !== "function") {
        return { ok: false, status: "error", cid: step.cid, error: "No folder loader provided for CID " + step.cid };
      }
      const loaded = loadFolderFn(step.cid, step.sha256);
      const loadedList = loaded && loaded.list && loaded.list.ok ? loaded.list : (loaded && loaded.ok ? loaded : null);
      const loadedSha = loaded && typeof loaded.sha256 === "string" ? loaded.sha256.toLowerCase() : "";
      if (!loadedList) {
        return {
          ok: false,
          status: "error",
          cid: step.cid,
          error: (loaded && loaded.error) || ("Failed to load subfolder CID " + step.cid),
        };
      }
      if (step.sha256 && loadedSha && loadedSha !== step.sha256.toLowerCase()) {
        return {
          ok: false,
          status: "error",
          cid: step.cid,
          error: "SHA-256 mismatch for subfolder CID " + step.cid,
        };
      }
      nextList = loadedList;
      safeMapSet(cidCache, step.cid, { list: nextList, sha256: loadedSha || (step.sha256 ? step.sha256.toLowerCase() : "") });
    }
    current = nextList;
    idx = step.nextIndex;
  }
  return { ok: false, status: "error", error: "Folder nesting exceeds limit" };
}

export function isBinaryDownloadPath(path) {
  const clean = String(path || "").split(/[?#]/)[0].toLowerCase();
  return /\.(?:lgx|wasm|zip|tar|gz|tgz|xz|bz2|bin|dmg|deb|rpm|appimage|exe|msi|apk|pdf)$/.test(clean);
}

export function sniffImageMimeBytes(bytes) {
  const b = bytes || [];
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
    return "image/png";
  }
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    return "image/jpeg";
  }
  if (b.length >= 6 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) {
    return "image/gif";
  }
  if (
    b.length >= 12 &&
    b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
    b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50
  ) {
    return "image/webp";
  }
  return "";
}

function safeHexColor(val) {
  const tok = String(val || "").trim().split(/\s+/)[0].toLowerCase();
  if (/^#[0-9a-f]{6}$/.test(tok)) return tok;
  if (/^#[0-9a-f]{3}$/.test(tok)) {
    return "#" + tok[1] + tok[1] + tok[2] + tok[2] + tok[3] + tok[3];
  }
  const map = { white: "#ffffff", black: "#000000", blue: "#0055ff", red: "#dc2626", green: "#16a34a" };
  return Object.prototype.hasOwnProperty.call(map, tok) ? map[tok] : "";
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

export function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Fallback safe HTML sanitizer for Basecamp when bytes arrive via `storage_module` and the
// installed `lns_browser_core` binary does not yet expose `render_html`.
export function sanitizeHtmlFallback(rawHtml, siteBase, currentPath) {
  const src = String(rawHtml || "").slice(0, 131072);
  const curPath = String(currentPath || "/");
  let title = "";
  const tm = src.match(/<title(?:[\s/][^>]*)?>([\s\S]*?)<\/title[^>]*>/i);
  if (tm) title = decodeHtmlEntities(tm[1].trim()).slice(0, 200);

  let bgColor = "";
  let fgColor = "";
  let linkColor = "";
  let svgFill = "";
  const classFills = Object.create(null);
  const styleRe = /<style(?:[\s/][^>]*)?>([\s\S]*?)<\/style[^>]*>/gi;
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
  const downloads = [];
  let body = src
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script(?:[\s/][^>]*)?>[\s\S]*?<\/script[^>]*>/gi, "")
    .replace(/<style(?:[\s/][^>]*)?>[\s\S]*?<\/style[^>]*>/gi, "")
    .replace(/<head(?:[\s/][^>]*)?>[\s\S]*?<\/head[^>]*>/gi, "")
    .replace(/<iframe(?:[\s/][^>]*)?>[\s\S]*?<\/iframe[^>]*>/gi, "")
    .replace(/<textarea(?:[\s/][^>]*)?>[\s\S]*?<\/textarea[^>]*>/gi, "")
    .replace(/<noscript(?:[\s/][^>]*)?>[\s\S]*?<\/noscript[^>]*>/gi, "")
    .replace(/<xmp(?:[\s/][^>]*)?>[\s\S]*?<\/xmp[^>]*>/gi, "")
    .replace(/<img(?:[\s/][^>]*)?src\s*=\s*["']https?:[^"']*["'][^>]*>/gi, "");

  // Extract safe inline <svg> blocks and <img> blocks in document order
  const hasSvg = /<svg(?:[\s/][^>]*)?>[\s\S]*?<\/svg[^>]*>/i.test(body);
  if (hasSvg) {
    body = body.replace(/<h1(?:[\s/][^>]*)?class\s*=\s*["'][^"']*\bsr\b[^"']*["'][^>]*>[\s\S]*?<\/h1[^>]*>/gi, "");
  }

  // Collect <a href="..." download="..."> links for native Save buttons
  const dlRe = /<a(?:[\s/]([^>]*))?>([\s\S]*?)<\/a[^>]*>/gi;
  let dm;
  while ((dm = dlRe.exec(body)) !== null) {
    const aAttrs = dm[1] || "";
    const dlAttrM = aAttrs.match(/(?:^|[\s/])download(?:\s*=\s*(?:"([^"]*)"|'([^']*)'))?/i);
    const hm = aAttrs.match(/(?:^|[\s/])href\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    const href = hm ? decodeHtmlEntities((hm[1] || hm[2] || "").trim()) : "";
    if (!href) continue;
    const isCid = /^cid:\/\/([A-Za-z0-9]{8,128})$/i.exec(href);
    const relResolved = !isCid ? resolveRelativeSitePath(href, curPath) : null;
    const explicitDownload = Boolean(dlAttrM);
    const isBinary = relResolved ? isBinaryDownloadPath(relResolved) : false;
    if (!explicitDownload && !isBinary) continue;
    const label = decodeHtmlEntities(dm[2].replace(/<[^>]*>/g, "").trim());
    let filename = dlAttrM ? decodeHtmlEntities((dlAttrM[1] || dlAttrM[2] || "").trim()) : "";
    if (!filename && relResolved) {
      const parts = relResolved.split(/[?#]/)[0].split("/");
      filename = parts[parts.length - 1] || "";
    }
    if (!filename && isCid) filename = isCid[1].slice(0, 12) + ".bin";
    if (isCid) {
      downloads.push({
        href: "cid://" + isCid[1],
        cid: isCid[1],
        path: "",
        filename: filename,
        label: label || filename,
      });
    } else if (relResolved && siteBase) {
      downloads.push({
        href: siteBase + relResolved,
        cid: "",
        path: relResolved.split(/[?#]/)[0],
        filename: filename,
        label: label || filename,
      });
    }
  }

  const SAFE_TAGS = {
    h1: true, h2: true, h3: true, h4: true, p: true, ul: true, ol: true, li: true,
    b: true, strong: true, i: true, em: true, code: true, pre: true, blockquote: true,
    br: true, hr: true, span: true, div: true,
  };

  function cleanFragment(frag) {
    const s = String(frag || "");
    let out = "";
    let idx = 0;
    while (idx < s.length) {
      const lt = s.indexOf("<", idx);
      if (lt === -1) {
        out += escapeHtml(decodeHtmlEntities(s.slice(idx)));
        break;
      }
      if (lt > idx) {
        out += escapeHtml(decodeHtmlEntities(s.slice(idx, lt)));
      }
      if (s.slice(lt, lt + 4) === "<!--") {
        const cEnd = s.indexOf("-->", lt + 4);
        idx = cEnd === -1 ? s.length : cEnd + 3;
        continue;
      }
      const gt = s.indexOf(">", lt + 1);
      if (gt === -1) {
        out += escapeHtml(s.slice(lt));
        break;
      }
      const inside = s.slice(lt + 1, gt);
      const isClose = inside.charAt(0) === "/";
      const rest = isClose ? inside.slice(1) : inside;
      const nameM = rest.match(/^([a-zA-Z][a-zA-Z0-9]*)/);
      if (!nameM) {
        idx = gt + 1;
        continue;
      }
      const low = nameM[1].toLowerCase();
      const attrPart = rest.slice(nameM[0].length);
      if (attrPart.length > 0 && !/^[\s/]/.test(attrPart)) {
        idx = gt + 1;
        continue;
      }
      if (Object.prototype.hasOwnProperty.call(SAFE_TAGS, low)) {
        out += isClose ? "</" + low + ">" : "<" + low + ">";
      } else if (low === "a") {
        if (isClose) {
          out += "</a>";
        } else {
          const hm = attrPart.match(/(?:^|[\s/])href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s/>]+))/i);
          const rawHref = hm ? (hm[1] !== undefined ? hm[1] : (hm[2] !== undefined ? hm[2] : hm[3])) : "";
          const href = decodeHtmlEntities(String(rawHref || "").trim());
          if (/^(lns|cid):\/\//i.test(href) || isExternalHttpsUrl(href)) {
            out += '<a href="' + escapeHtml(href) + '">';
          } else if (href && siteBase) {
            const cleanPath = resolveRelativeSitePath(href, curPath);
            if (cleanPath) {
              out += '<a href="' + escapeHtml(siteBase + cleanPath) + '">';
            }
          }
        }
      }
      idx = gt + 1;
    }
    return out;
  }

  function parseImgTagToBlock(rawImg) {
    const attrs = rawImg.slice(4, rawImg.length - 1);
    const src = decodeHtmlEntities(getSvgAttr(attrs, "src") || "").trim();
    if (!src || CTRL_RE.test(src)) return null;
    const alt = decodeHtmlEntities(getSvgAttr(attrs, "alt") || "");
    const wRaw = Number(String(getSvgAttr(attrs, "width") || "").replace(/px$/i, ""));
    const hRaw = Number(String(getSvgAttr(attrs, "height") || "").replace(/px$/i, ""));
    const width = wRaw > 0 && wRaw <= 2000 ? Math.round(wRaw) : null;
    const height = hRaw > 0 && hRaw <= 2000 ? Math.round(hRaw) : null;

    if (/^data:image\/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\r\n]+$/i.test(src) && src.length <= 131072) {
      return { kind: "image", data_uri: src, src_cid: "", src_path: "", alt: alt, width: width, height: height };
    }
    const cidM = /^cid:\/\/([A-Za-z0-9]{8,128})$/i.exec(src);
    if (cidM) {
      return { kind: "image", data_uri: "", src_cid: cidM[1], src_path: "", alt: alt, width: width, height: height };
    }
    if (src.indexOf(":") === -1 && src.indexOf("//") !== 0 && siteBase) {
      const rel = resolveRelativeSitePath(src, curPath);
      if (rel) {
        return {
          kind: "image",
          data_uri: "",
          src_cid: "",
          src_path: rel.split(/[?#]/)[0],
          alt: alt,
          width: width,
          height: height,
        };
      }
    }
    return null;
  }

  const mediaRe = /<svg(?:[\s/][^>]*)?>[\s\S]*?<\/svg[^>]*>|<img(?:[\s/][^>]*)?>/gi;
  let lastIdx = 0;
  let m;
  while ((m = mediaRe.exec(body)) !== null) {
    const before = cleanFragment(body.slice(lastIdx, m.index)).trim();
    if (before) blocks.push({ kind: "html", html: before });
    const rawTag = m[0];
    if (/^<img\b/i.test(rawTag)) {
      const imgBlock = parseImgTagToBlock(rawTag);
      if (imgBlock) blocks.push(imgBlock);
      lastIdx = m.index + rawTag.length;
      continue;
    }
    const rawSvg = rawTag;
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
    downloads: downloads,
  };
}

function getSvgAttr(attrs, name) {
  const re = new RegExp("(?:^|[\\s/])" + name + "\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)')", "i");
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
      const key = parts[i].toLowerCase();
      const c = Object.prototype.hasOwnProperty.call(classFills, key) ? classFills[key] : "";
      if (c) return c;
    }
  }
  return defaultFill;
}

export function extractSvgCanvasOps(rawSvg, defaultFill, classFills) {
  const defs = Object.create(null);
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
      const d = Object.prototype.hasOwnProperty.call(defs, href) ? defs[href] : "";
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
// Accepts both JS Arrays and Qt QVariantList array-like objects for `block.ops`.
export function drawSvgToCanvas(ctx, block, canvasW, canvasH) {
  if (!ctx || !block || canvasW <= 0 || canvasH <= 0) return;
  const ops = toArray(block.ops);
  if (ops.length === 0) return;
  const vbX = Number(block.vb_x || 0) || 0;
  const vbY = Number(block.vb_y || 0) || 0;
  const vbW = Number(block.vb_w || 0) > 0 ? Number(block.vb_w) : 100;
  const vbH = Number(block.vb_h || 0) > 0 ? Number(block.vb_h) : 100;

  ctx.clearRect(0, 0, canvasW, canvasH);
  ctx.save();
  ctx.scale(canvasW / vbW, canvasH / vbH);
  if (vbX !== 0 || vbY !== 0) ctx.translate(-vbX, -vbY);

  for (let i = 0; i < ops.length; i++) {
    const item = ops[i];
    if (!item || !item.fill) continue;
    ctx.save();
    ctx.globalAlpha = item.opacity !== undefined && item.opacity !== null && !isNaN(Number(item.opacity)) ? Number(item.opacity) : 1;
    ctx.fillStyle = item.fill;

    if (item.op === "rect") {
      ctx.fillRect(Number(item.x || 0) || 0, Number(item.y || 0) || 0, Number(item.w || 0) || 0, Number(item.h || 0) || 0);
    } else if (item.op === "circle") {
      ctx.beginPath();
      ctx.arc(Number(item.x || 0) || 0, Number(item.y || 0) || 0, Number(item.r || 0) || 0, 0, Math.PI * 2);
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
      const ox = Number(item.x || 0) || 0;
      const oy = Number(item.y || 0) || 0;
      if (ox || oy) ctx.translate(ox, oy);
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

// ── Round 6: Browser Window, Tabs, Loopback Guard, Bookmarks & History ────

export function parseQueryString(rawQuery) {
  const map = Object.create(null);
  const q = String(rawQuery || "").replace(/^\?/, "");
  if (!q) return map;
  const pairs = q.split("&");
  for (let i = 0; i < pairs.length; i++) {
    const pair = pairs[i];
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const rawK = eq === -1 ? pair : pair.slice(0, eq);
    const rawV = eq === -1 ? "" : pair.slice(eq + 1);
    let k = rawK.replace(/\+/g, " ");
    let v = rawV.replace(/\+/g, " ");
    try { k = decodeURIComponent(k); } catch (e) {}
    try { v = decodeURIComponent(v); } catch (e) {}
    if (k) map[k] = v;
  }
  return map;
}

export function buildLoopbackEntryUrl(origin, token, rawPath) {
  const cleanOrigin = String(origin || "").trim().replace(/\/+$/, "");
  const cleanTok = String(token || "").trim();
  const norm = normalizePath(rawPath || "/");
  const p = norm.ok ? norm.path : "/";
  const frag = norm.ok && norm.fragment ? norm.fragment : "";
  return cleanOrigin + "/" + cleanTok + p + frag;
}

export function sitePathFromLoopbackUrl(rawUrl, origin, token) {
  const s = String(rawUrl || "").trim();
  const cleanOrigin = String(origin || "").trim().replace(/\/+$/, "");
  const cleanTok = String(token || "").trim();
  if (!s || !cleanOrigin || !cleanTok) return { ok: false };
  const prefix = cleanOrigin + "/" + cleanTok;
  if (s.indexOf(prefix) !== 0) return { ok: false };
  const after = s.slice(prefix.length);
  if (after.length > 0 && after.charAt(0) !== "/" && after.charAt(0) !== "?" && after.charAt(0) !== "#") {
    return { ok: false };
  }
  const hashIdx = after.indexOf("#");
  const fragment = hashIdx !== -1 ? after.slice(hashIdx) : "";
  const noFrag = hashIdx !== -1 ? after.slice(0, hashIdx) : after;
  const qIdx = noFrag.indexOf("?");
  const pathPart = qIdx !== -1 ? noFrag.slice(0, qIdx) : noFrag;
  const queryPart = qIdx !== -1 ? noFrag.slice(qIdx + 1) : "";
  return {
    ok: true,
    path: pathPart || "/",
    query: queryPart,
    fragment: fragment,
  };
}

function hasUnsafeLoopbackPath(pathPart) {
  const p = String(pathPart || "");
  if (CTRL_RE.test(p) || p.indexOf("\\") !== -1) return true;
  const low = p.toLowerCase();
  if (low.indexOf("%00") !== -1 || low.indexOf("%2f") !== -1 || low.indexOf("%5c") !== -1) return true;
  const segs = p.split("/");
  for (let i = 0; i < segs.length; i++) {
    if (segs[i] === "..") return true;
    let dec = segs[i];
    try { dec = decodeURIComponent(segs[i]); } catch (e) { return true; }
    if (dec === ".." || dec.indexOf("/") !== -1 || dec.indexOf("\\") !== -1 || CTRL_RE.test(dec)) {
      return true;
    }
  }
  return false;
}

/**
 * Security guard for `WebView.onLoadingChanged`:
 * Stops anything outside the active site's loopback origin+token and routes
 * `/_ext`, `/_lns`, `/_dl`, direct `lns://`, `cid://`, and `https://` cleanly.
 */
export function classifyWebViewUrl(rawUrl, activeOrigin, activeToken, activeSiteBase) {
  const s = String(rawUrl || "").trim();
  if (!s || s === "about:blank") {
    return { action: "ignore" };
  }
  if (CTRL_RE.test(s)) {
    return { action: "block", reason: "URL contains control characters" };
  }
  if (/^(?:lns|cid):\/\//i.test(s)) {
    const parsed = parseUrl(s);
    if (!parsed.ok) return { action: "block", reason: parsed.error };
    return { action: "lns", url: parsed.canonical + (parsed.fragment || "") };
  }
  if (/^https:\/\//i.test(s)) {
    if (!isExternalHttpsUrl(s)) {
      return { action: "block", reason: "Refused malformed or credentialed https:// URL" };
    }
    return { action: "ext", url: s };
  }

  const lb = sitePathFromLoopbackUrl(s, activeOrigin, activeToken);
  if (!lb.ok) {
    return { action: "block", reason: "Blocked navigation outside active site loopback origin" };
  }
  if (hasUnsafeLoopbackPath(lb.path)) {
    return { action: "block", reason: "Blocked path traversal in loopback URL" };
  }
  if (lb.path === "/_ext") {
    const q = parseQueryString(lb.query);
    const u = String(q.u || "").trim();
    if (isExternalHttpsUrl(u)) {
      return { action: "ext", url: u };
    }
    return { action: "block", reason: "Blocked invalid external URL" };
  }
  if (lb.path === "/_lns") {
    const q = parseQueryString(lb.query);
    const u = String(q.u || "").trim();
    const parsed = parseUrl(u);
    if (parsed.ok) {
      return { action: "lns", url: parsed.canonical + (parsed.fragment || "") };
    }
    return { action: "block", reason: "Blocked invalid LNS/CID link" };
  }
  if (lb.path === "/_dl") {
    const q = parseQueryString(lb.query);
    return {
      action: "dl",
      cid: String(q.cid || "").trim(),
      path: String(q.path || "").trim(),
      filename: String(q.name || "").trim(),
    };
  }
  const base = String(activeSiteBase || "").replace(/\/+$/, "");
  const displayPath = lb.path === "/index.html" ? "/" : lb.path;
  const canonical = base
    ? base + (displayPath === "/" ? "" : displayPath) + (lb.fragment || "")
    : lb.path;
  return {
    action: "allow",
    sitePath: lb.path,
    fragment: lb.fragment || "",
    canonical: canonical,
  };
}

export function createTab(id, opts) {
  const o = opts || {};
  return {
    id: id,
    title: String(o.title || ""),
    url: String(o.url || ""),
    siteBase: String(o.siteBase || ""),
    host: String(o.host || ""),
    kind: String(o.kind || ""),
    path: String(o.path || "/"),
    loopbackOrigin: String(o.loopbackOrigin || ""),
    loopbackToken: String(o.loopbackToken || ""),
    loopbackUrl: String(o.loopbackUrl || ""),
    mode: String(o.mode || ""),
    rootCid: String(o.rootCid || ""),
    rootSha256: String(o.rootSha256 || ""),
    verified: Boolean(o.verified),
    loading: Boolean(o.loading),
    loadProgress: Number(o.loadProgress || 0),
    readerMode: Boolean(o.readerMode),
    zoomPercent: clampZoomPercent(o.zoomPercent !== undefined ? o.zoomPercent : 100),
    history: toArray(o.history),
    historyIdx: typeof o.historyIdx === "number" ? o.historyIdx : -1,
    pageData: o.pageData || null,
    siteInfo: o.siteInfo || null,
    notFoundState: o.notFoundState || null,
    storageError: o.storageError || null,
    siteStats: o.siteStats || null,
    navSeq: Number(o.navSeq || 0),
  };
}

export function closeTabState(tabs, activeIndex, closeIndex) {
  const list = toArray(tabs).slice();
  if (closeIndex < 0 || closeIndex >= list.length) {
    return { tabs: list, activeIndex: activeIndex, closedTab: null, shouldCloseWindow: list.length === 0 };
  }
  const closedTab = list.splice(closeIndex, 1)[0];
  if (list.length === 0) {
    return { tabs: [], activeIndex: -1, closedTab: closedTab, shouldCloseWindow: true };
  }
  let nextIdx = activeIndex;
  if (closeIndex < activeIndex) {
    nextIdx = activeIndex - 1;
  } else if (closeIndex === activeIndex) {
    nextIdx = Math.min(closeIndex, list.length - 1);
  }
  return { tabs: list, activeIndex: nextIdx, closedTab: closedTab, shouldCloseWindow: false };
}

export function pushTabHistory(tab, canonical) {
  const hist = toArray(tab && tab.history);
  const idx = tab && typeof tab.historyIdx === "number" ? tab.historyIdx : -1;
  if (idx >= 0 && hist[idx] === canonical) {
    return { history: hist, historyIdx: idx };
  }
  const next = hist.slice(0, idx + 1);
  next.push(canonical);
  return { history: next, historyIdx: next.length - 1 };
}

export function canTabGoBack(tab) {
  return Boolean(tab && typeof tab.historyIdx === "number" && tab.historyIdx > 0);
}

export function canTabGoForward(tab) {
  return Boolean(tab && typeof tab.historyIdx === "number" && tab.historyIdx >= 0 && tab.historyIdx < toArray(tab.history).length - 1);
}

export function formatWindowTitle(tab) {
  if (!tab) return "LNS Browser";
  if (tab.kind === "lns" && tab.host) {
    return tab.host + " — LNS Browser";
  }
  if (tab.kind === "cid" && tab.host) {
    return shortHash(tab.host, 10, 6) + " — LNS Browser";
  }
  if (tab.title && String(tab.title).trim()) {
    return String(tab.title).trim() + " — LNS Browser";
  }
  return "LNS Browser";
}

export function formatTabTitle(tab) {
  if (!tab) return "New Tab";
  if (tab.host) {
    return tab.kind === "cid" ? shortHash(tab.host, 8, 4) : tab.host;
  }
  if (tab.title && String(tab.title).trim()) {
    return String(tab.title).trim();
  }
  return "New Tab";
}

export function clampWindowGeometry(geom) {
  const g = geom && typeof geom === "object" ? geom : {};
  const rawW = Number(g.width);
  const rawH = Number(g.height);
  const rawX = Number(g.x);
  const rawY = Number(g.y);
  const width = isFinite(rawW) && rawW > 0 ? Math.max(720, Math.min(4096, Math.round(rawW))) : 1120;
  const height = isFinite(rawH) && rawH > 0 ? Math.max(480, Math.min(2560, Math.round(rawH))) : 760;
  const x = isFinite(rawX) ? Math.max(-200, Math.min(6000, Math.round(rawX))) : 120;
  const y = isFinite(rawY) ? Math.max(0, Math.min(3000, Math.round(rawY))) : 80;
  return { x: x, y: y, width: width, height: height };
}

export function clampZoomPercent(pct) {
  const n = Number(pct);
  if (!isFinite(n) || n <= 0) return 100;
  return Math.max(50, Math.min(200, Math.round(n / 10) * 10));
}

export function isBookmarked(bookmarks, url) {
  const clean = String(url || "").trim();
  if (!clean) return false;
  const list = toArray(bookmarks);
  for (let i = 0; i < list.length; i++) {
    if (list[i] && list[i].url === clean) return true;
  }
  return false;
}

export function toggleBookmark(bookmarks, entry) {
  const list = toArray(bookmarks).slice();
  const url = String((entry && entry.url) || "").trim();
  if (!url) return { bookmarks: list, bookmarked: false };
  for (let i = 0; i < list.length; i++) {
    if (list[i] && list[i].url === url) {
      list.splice(i, 1);
      return { bookmarks: list, bookmarked: false };
    }
  }
  list.unshift({
    url: url,
    title: String((entry && entry.title) || url).slice(0, 200),
    name: String((entry && entry.name) || ""),
    added_at: Number((entry && (entry.added_at || entry.addedAt)) || Math.floor(Date.now() / 1000)),
  });
  return { bookmarks: list.slice(0, 500), bookmarked: true };
}

export function recordHistoryEntry(historyList, entry, maxEntries) {
  const limit = maxEntries || 200;
  const url = String((entry && entry.url) || "").trim();
  if (!url) return toArray(historyList);
  const existing = toArray(historyList);
  const out = [{
    url: url,
    title: String((entry && entry.title) || url).slice(0, 200),
    name: String((entry && entry.name) || ""),
    visited_at: Number((entry && (entry.visited_at || entry.visitedAt)) || Math.floor(Date.now() / 1000)),
  }];
  for (let i = 0; i < existing.length && out.length < limit; i++) {
    const item = existing[i];
    if (item && item.url && item.url !== url) {
      out.push(item);
    }
  }
  return out;
}

export function extractRecentSites(historyList, maxSites) {
  const limit = maxSites || 8;
  const list = toArray(historyList);
  const seen = Object.create(null);
  const out = [];
  for (let i = 0; i < list.length && out.length < limit; i++) {
    const item = list[i];
    if (!item || !item.url) continue;
    const parsed = parseUrl(item.url);
    if (!parsed.ok) continue;
    const key = parsed.siteBase;
    if (Object.prototype.hasOwnProperty.call(seen, key)) continue;
    seen[key] = true;
    out.push({
      siteBase: parsed.siteBase,
      url: parsed.siteBase,
      name: parsed.kind === "lns" ? parsed.name : shortHash(parsed.cid, 10, 6),
      title: item.title || (parsed.kind === "lns" ? parsed.name : shortHash(parsed.cid, 10, 6)),
      lastPath: parsed.path,
      visited_at: item.visited_at || 0,
    });
  }
  return out;
}

export function countTextMatches(htmlOrText, query) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return 0;
  const plain = decodeHtmlEntities(String(htmlOrText || "").replace(/<[^>]*>/g, " ")).toLowerCase();
  let count = 0;
  let pos = 0;
  while (true) {
    const idx = plain.indexOf(q, pos);
    if (idx === -1) break;
    count += 1;
    pos = idx + q.length;
  }
  return count;
}
