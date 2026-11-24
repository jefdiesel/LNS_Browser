// Pure JS helpers for the native Basecamp LNS Web Browser QML view (tested under Node).
// Note: Qt QML's QV4 engine does NOT support ES2018 regex lookbehind (`(?<!...)`), so all
// regexes here strictly use ES5-compatible syntax.

const NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$/;
const CID_RE = /^[A-Za-z0-9]{8,128}$/;
const SHA256_RE = /^[0-9a-f]{64}$/i;
const HTTPS_RE = /^https:\/\/[^\s/@]+\.[^\s/]+/i;

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
  if (typeof cur !== "object") {
    return { ok: false, error: "unexpected reply from core module: " + String(cur) };
  }
  if (cur.success) return { ok: true, value: cur.value };
  return { ok: false, error: cur.error || "unknown module error" };
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

function base64UrlEncodeUtf8(str) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) {
      bytes.push(c);
    } else if (c < 0x800) {
      bytes.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const c2 = str.charCodeAt(++i);
      const cp = 0x10000 + (((c & 0x3ff) << 10) | (c2 & 0x3ff));
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f)
      );
    } else {
      bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += chars[(n >> 18) & 63];
    out += chars[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += chars[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += chars[n & 63];
  }
  return out;
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
