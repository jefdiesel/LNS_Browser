// HTML, CSS, and SVG sanitizer + link rewriter for static LNS gateway snapshots.
// Enforces zero external subresources, script-src 'none' (shared origin safety),
// lns:// -> /lns/<name>/ link rewriting, strict CSP meta tag, and verification header bar.

import { normalizeSitePath, parseLnsUrl } from "./derive.mjs";

export const GATEWAY_CSP = [
  "default-src 'none'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "media-src 'self'",
  "script-src 'none'",
  "connect-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "form-action 'none'",
  "base-uri 'none'",
].join("; ");

const SAFE_DATA_IMAGE_RE = /^data:image\/(?:png|jpeg|jpg|gif|webp);base64,[a-z0-9+/=\s]+$/i;
const CID_URL_RE = /^cid:\/\/([A-Za-z0-9]{8,128})(?:\/[^?#]*)?$/i;
const DROP_WITH_BODY = new Set([
  "script",
  "iframe",
  "object",
  "applet",
  "textarea",
  "xmp",
  "noscript",
  "noembed",
  "noframes",
  "template",
]);
const SVG_DROP_WITH_BODY = new Set([
  ...DROP_WITH_BODY,
  "foreignobject",
  "animate",
  "animatemotion",
  "animatetransform",
  "animatecolor",
  "set",
  "handler",
  "listener",
  "feimage",
  "discard",
  "mpath",
  "audio",
  "video",
  "canvas",
]);
const DROP_VOID = new Set(["embed", "base"]);
const BLOCKED_META_HTTP_EQUIV = new Set(["content-security-policy", "refresh", "set-cookie"]);
const ALLOWED_LINK_REL_TOKENS = new Set(["stylesheet", "icon", "shortcut"]);
const BENIGN_XML_DECL_RE =
  /^<\?xml\s+version=["']1\.[01]["'](?:\s+encoding=["'][A-Za-z0-9._-]+["'])?(?:\s+standalone=["'](?:yes|no)["'])?\s*\?>$/i;

export function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function decodeBasicEntities(text) {
  return String(text ?? "")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&");
}

function isSafeExternalHttps(raw) {
  const s = String(raw || "").trim();
  if (!/^https:\/\/[^\s/@]+\.[^\s/]+/i.test(s) || s.length > 2048) return false;
  try {
    const u = new URL(s);
    if (u.protocol !== "https:") return false;
    if (u.username || u.password) return false;
    return true;
  } catch {
    return false;
  }
}

function safeFragment(raw) {
  const idx = raw.indexOf("#");
  if (idx === -1) return "";
  const frag = raw.slice(idx);
  return /^#[^\s"'<>`]*$/.test(frag) ? frag : "";
}

function resolveSiteRelative(pathOnly, sitePath = "/") {
  if (pathOnly.startsWith("/")) {
    return normalizeSitePath(pathOnly);
  }
  const cleanSite = String(sitePath || "/").split(/[?#]/)[0] || "/";
  const lastSlash = cleanSite.lastIndexOf("/");
  const baseDir = lastSlash >= 0 ? cleanSite.slice(0, lastSlash + 1) : "/";
  return normalizeSitePath(baseDir + pathOnly);
}

/**
 * Rewrites an <a href> target:
 * - `lns://other[/path][#frag]` -> `/lns/other/[path][#frag]`
 * - `cid://<cid>` -> resolved local site path when `resolveCidUrl` is provided, else null
 * - `/path` and relative paths are resolved against `sitePath` and clamped to `/lns/<currentName>/...`
 * - safe `https://` links stay external
 * - all unsafe schemes (`http:`, `javascript:`, `data:`, `//`, etc.) return null
 */
export function rewriteHref(rawHref, currentName, { resolveCidUrl = null, sitePath = "/" } = {}) {
  const trimmed = decodeBasicEntities(String(rawHref ?? "")).trim();
  if (!trimmed || trimmed.includes("\0")) return null;

  if (trimmed.startsWith("#")) {
    return safeFragment(trimmed) || null;
  }

  if (/^lns:/i.test(trimmed)) {
    try {
      const frag = safeFragment(trimmed);
      const parsed = parseLnsUrl(trimmed);
      if (parsed.kind !== "lns") return null;
      return `/lns/${parsed.name}${parsed.path}${frag}`;
    } catch {
      return null;
    }
  }

  if (/^cid:/i.test(trimmed)) {
    if (typeof resolveCidUrl !== "function") return null;
    const frag = safeFragment(trimmed);
    const withoutFrag = trimmed.split(/[?#]/)[0];
    const m = CID_URL_RE.exec(withoutFrag);
    if (!m) return null;
    const mapped = resolveCidUrl(m[1]);
    return mapped ? `${mapped}${frag}` : null;
  }

  if (/^https:\/\//i.test(trimmed)) {
    return isSafeExternalHttps(trimmed) ? trimmed : null;
  }

  if (trimmed.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(trimmed)) {
    return null;
  }

  const frag = safeFragment(trimmed);
  const hashIdx = trimmed.indexOf("#");
  const withoutFrag = hashIdx !== -1 ? trimmed.slice(0, hashIdx) : trimmed;
  const pathOnly = withoutFrag.split("?")[0];
  if (!pathOnly) return frag || null;

  try {
    const clean = resolveSiteRelative(pathOnly, sitePath);
    return currentName ? `/lns/${currentName}${clean}${frag}` : `${clean}${frag}`;
  } catch {
    return null;
  }
}

/**
 * Validates and scopes a subresource URL (stylesheet, image, font, media, CSS url).
 * Resolves `cid://<cid>` when `resolveCidUrl` is provided, resolves relative paths against `sitePath`,
 * and clamps all local paths under `/lns/<currentName>/`. Blocks all external origins and unsafe schemes.
 */
export function rewriteLocalAssetUrl(
  rawUrl,
  currentName,
  { allowDataImage = false, resolveCidUrl = null, sitePath = "/" } = {},
) {
  const trimmed = decodeBasicEntities(String(rawUrl ?? "")).trim();
  if (!trimmed || trimmed.includes("\0")) return null;

  if (allowDataImage && SAFE_DATA_IMAGE_RE.test(trimmed)) {
    return trimmed.replace(/\s+/g, "");
  }

  if (/^cid:/i.test(trimmed)) {
    if (typeof resolveCidUrl !== "function") return null;
    const withoutFrag = trimmed.split(/[?#]/)[0];
    const m = CID_URL_RE.exec(withoutFrag);
    if (!m) return null;
    return resolveCidUrl(m[1]) || null;
  }

  if (trimmed.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(trimmed)) {
    return null;
  }

  if (trimmed.startsWith("#")) {
    return safeFragment(trimmed) || null;
  }

  const pathOnly = trimmed.split(/[?#]/)[0];
  if (!pathOnly) return null;

  try {
    const clean = resolveSiteRelative(pathOnly, sitePath);
    return currentName ? `/lns/${currentName}${clean}` : clean;
  } catch {
    return null;
  }
}

function decodeCssEscapes(css) {
  return String(css ?? "")
    .replace(/\\(?:\r\n|[\n\r\f])/g, "")
    .replace(/\\([0-9a-fA-F]{1,6})(?:\r\n|[ \t\r\n\f])?|\\([^\r\n\f])/g, (_full, hex, ch) => {
      if (hex) {
        const cp = Number.parseInt(hex, 16);
        if (!Number.isFinite(cp) || cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) {
          return "\ufffd";
        }
        return String.fromCodePoint(cp);
      }
      return ch;
    });
}

/** Sanitizes CSS text by decoding escapes and blocking external @import, image-set(...), and url(...) calls. */
export function sanitizeCss(cssText, currentName, { resolveCidUrl = null, sitePath = "/" } = {}) {
  let css = String(cssText ?? "");
  css = css.replace(/\/\*[\s\S]*?\*\//g, "");
  css = decodeCssEscapes(css);
  css = css.replace(
    /@import\s+(?:url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)|"([^"]*)"|'([^']*)')([^;]*(?:;|$))/gi,
    (_full, u1, u2, u3, s1, s2, rest) => {
      const raw = u1 ?? u2 ?? u3 ?? s1 ?? s2 ?? "";
      const safe = rewriteLocalAssetUrl(raw, currentName, {
        allowDataImage: false,
        resolveCidUrl,
        sitePath,
      });
      return safe ? `@import url("${safe}")${rest}` : "";
    },
  );
  css = css.replace(/(?:-webkit-)?image-set\s*\(([^)]*)\)/gi, (full, inner) => {
    const prefix = full.slice(0, full.indexOf("(") + 1);
    const items = inner.split(",");
    const kept = [];
    for (const rawItem of items) {
      const trimmed = rawItem.trim();
      if (!trimmed) continue;
      if (/^url\s*\(/i.test(trimmed)) {
        kept.push(trimmed);
        continue;
      }
      const sm = trimmed.match(/^(?:"([^"]*)"|'([^']*)')([\s\S]*)$/);
      if (sm) {
        const rawUrl = sm[1] ?? sm[2] ?? "";
        const safe = rewriteLocalAssetUrl(rawUrl, currentName, {
          allowDataImage: true,
          resolveCidUrl,
          sitePath,
        });
        if (safe) kept.push(`"${safe}"${sm[3]}`);
      }
    }
    return kept.length > 0 ? `${prefix}${kept.join(", ")})` : "none";
  });
  css = css.replace(
    /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi,
    (_full, d1, d2, d3) => {
      const raw = (d1 ?? d2 ?? d3 ?? "").trim();
      const safe = rewriteLocalAssetUrl(raw, currentName, {
        allowDataImage: true,
        resolveCidUrl,
        sitePath,
      });
      return safe ? `url("${safe}")` : "none";
    },
  );
  css = css.replace(/expression\s*\(/gi, "blocked(");
  return css;
}

function parseAttrs(attrText) {
  const attrs = [];
  const s = String(attrText ?? "");
  let i = 0;
  const n = s.length;

  while (i < n) {
    while (i < n && /[\s/]/.test(s[i])) i += 1;
    if (i >= n) break;

    const nameStart = i;
    while (i < n && !/[\s=/>"']/.test(s[i])) i += 1;
    const rawName = s.slice(nameStart, i);
    if (!rawName) {
      i += 1;
      continue;
    }
    const name = rawName.toLowerCase();

    while (i < n && /\s/.test(s[i])) i += 1;
    if (i < n && s[i] === "=") {
      i += 1;
      while (i < n && /\s/.test(s[i])) i += 1;
      let val = "";
      if (i < n && (s[i] === '"' || s[i] === "'")) {
        const quote = s[i];
        i += 1;
        const valStart = i;
        while (i < n && s[i] !== quote) i += 1;
        val = s.slice(valStart, i);
        if (i < n && s[i] === quote) i += 1;
      } else {
        const valStart = i;
        while (i < n && !/[\s>]/.test(s[i])) i += 1;
        val = s.slice(valStart, i);
      }
      attrs.push({ name, value: decodeBasicEntities(val), hasValue: true });
    } else {
      attrs.push({ name, value: "", hasValue: false });
    }
  }

  return attrs;
}

function serializeAttrs(attrs) {
  let out = "";
  for (const attr of attrs) {
    if (attr.hasValue) {
      out += ` ${attr.name}="${escapeAttr(attr.value)}"`;
    } else {
      out += ` ${attr.name}`;
    }
  }
  return out;
}

function getAttrValue(attrs, name) {
  const found = attrs.find((a) => a.name === name);
  return found ? found.value : "";
}

function findTagEnd(html, start) {
  let quote = null;
  for (let i = start; i < html.length; i += 1) {
    const ch = html[i];
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === ">") {
      return i;
    }
  }
  return -1;
}

function findClosingTag(html, fromIndex, tagName) {
  const re = new RegExp(`<\\/${tagName}(?=[\\s/>])[^>]*>`, "gi");
  re.lastIndex = fromIndex;
  const m = re.exec(html);
  return m ? { start: m.index, end: m.index + m[0].length } : null;
}

function findMatchingSvgEnd(html, fromIndex) {
  const re = /<(\/?)svg(?:\s[^>]*|\/[^>]*)?>/gi;
  re.lastIndex = fromIndex;
  let depth = 1;
  let m;
  while ((m = re.exec(html)) !== null) {
    const full = m[0];
    if (m[1] === "/") {
      depth -= 1;
      if (depth === 0) return { start: m.index, end: m.index + full.length };
    } else if (!full.endsWith("/>")) {
      depth += 1;
    }
  }
  return null;
}

function skipBangDeclaration(src, lt) {
  let depth = 0;
  let quote = null;
  for (let j = lt + 2; j < src.length; j += 1) {
    const ch = src[j];
    if (quote) {
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === "[") {
      depth += 1;
    } else if (ch === "]" && depth > 0) {
      depth -= 1;
    } else if (ch === ">" && depth === 0) {
      return j + 1;
    }
  }
  return src.length;
}

function rewriteSrcset(rawSrcset, currentName, allowDataImage, resolveCidUrl = null, sitePath = "/") {
  const candidates = String(rawSrcset ?? "").split(",");
  const kept = [];
  for (const part of candidates) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const pieces = trimmed.split(/\s+/);
    const safe = rewriteLocalAssetUrl(pieces[0], currentName, {
      allowDataImage,
      resolveCidUrl,
      sitePath,
    });
    if (!safe) continue;
    kept.push(pieces.length > 1 ? `${safe} ${pieces.slice(1).join(" ")}` : safe);
  }
  return kept.join(", ");
}

/**
 * Extracts `cid://<cid>` asset references from HTML, CSS, or SVG so the snapshot builder
 * can materialize unlisted frozen CIDs into `/_cid/<cid><ext>` before rewriting.
 */
export function extractCidReferences(text, kind = "html") {
  const src = String(text ?? "");
  const refs = new Map();
  const record = (cid, hintFilename = "") => {
    const existing = refs.get(cid);
    if (!existing || (!existing.hintFilename && hintFilename)) {
      refs.set(cid, { cid, hintFilename });
    }
  };

  if (kind === "css") {
    const re = /cid:\/\/([A-Za-z0-9]{8,128})/gi;
    let m;
    while ((m = re.exec(src)) !== null) {
      record(m[1], "");
    }
    return Array.from(refs.values());
  }

  // HTML/SVG: inspect tags (skipping script/iframe/object/applet/textarea/xmp/noscript/template blocks)
  const stripped = src
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|iframe|object|applet|textarea|xmp|noscript|noembed|noframes|template)\b[\s\S]*?<\/\1(?=[\s/>])[^>]*>/gi, "");

  // Capture `<a href="cid://..." download="name.lgx">` filename hints
  const tagRe = /<([a-zA-Z][a-zA-Z0-9:-]*)(\s[^>]*)?>/g;
  let tm;
  while ((tm = tagRe.exec(stripped)) !== null) {
    const tagName = tm[1].toLowerCase();
    const attrs = parseAttrs(tm[2] || "");
    const downloadHint = tagName === "a" ? getAttrValue(attrs, "download").trim() : "";
    for (const attr of attrs) {
      if (
        attr.name === "src" ||
        attr.name === "href" ||
        attr.name === "srcset" ||
        attr.name === "poster" ||
        attr.name === "data" ||
        attr.name === "background" ||
        attr.name === "style"
      ) {
        const cidRe = /cid:\/\/([A-Za-z0-9]{8,128})/gi;
        let cm;
        while ((cm = cidRe.exec(attr.value)) !== null) {
          record(cm[1], attr.name === "href" ? downloadHint : "");
        }
      }
    }
  }

  // Also capture `cid://` inside `<style>...</style>` blocks
  const styleRe = /<style\b[^>]*>([\s\S]*?)<\/style(?=[\s/>])[^>]*>/gi;
  let sm;
  while ((sm = styleRe.exec(stripped)) !== null) {
    const cidRe = /cid:\/\/([A-Za-z0-9]{8,128})/gi;
    let cm;
    while ((cm = cidRe.exec(sm[1])) !== null) {
      record(cm[1], "");
    }
  }

  return Array.from(refs.values());
}

/** Sanitizes an inline or standalone SVG block, stripping scripts, SMIL animation, xml-stylesheet, foreignObject, handlers, and external URLs. */
export function sanitizeSvg(svgText, currentName = "", { resolveCidUrl = null, sitePath = "/" } = {}) {
  const src = String(svgText ?? "");
  let out = "";
  let i = 0;

  while (i < src.length) {
    const lt = src.indexOf("<", i);
    if (lt === -1) {
      out += src.slice(i);
      break;
    }
    out += src.slice(i, lt);

    if (src.startsWith("<!--", lt)) {
      const end = src.indexOf("-->", lt + 4);
      i = end === -1 ? src.length : end + 3;
      continue;
    }

    if (src.startsWith("<?", lt)) {
      const end = src.indexOf("?>", lt + 2);
      if (end === -1) break;
      const decl = src.slice(lt, end + 2);
      if (BENIGN_XML_DECL_RE.test(decl)) {
        out += decl;
      }
      i = end + 2;
      continue;
    }

    if (src.startsWith("<![CDATA[", lt)) {
      const end = src.indexOf("]]>", lt + 9);
      if (end === -1) break;
      out += escapeHtml(src.slice(lt + 9, end));
      i = end + 3;
      continue;
    }

    if (src.startsWith("<!", lt)) {
      i = skipBangDeclaration(src, lt);
      continue;
    }

    if (src[lt + 1] === "/") {
      const end = src.indexOf(">", lt + 2);
      if (end === -1) break;
      const closeMatch = src.slice(lt + 2, end).trim().match(/^([a-zA-Z][a-zA-Z0-9:_-]*)/);
      if (closeMatch) {
        const rawClose = closeMatch[1];
        const closeName = rawClose.toLowerCase();
        if (!SVG_DROP_WITH_BODY.has(closeName) && !DROP_VOID.has(closeName) && closeName !== "style") {
          out += `</${rawClose}>`;
        }
      }
      i = end + 1;
      continue;
    }

    const end = findTagEnd(src, lt + 1);
    if (end === -1) break;
    const rawInside = src.slice(lt + 1, end);
    const nameMatch = rawInside.match(/^([a-zA-Z][a-zA-Z0-9:_-]*)/);
    if (!nameMatch) {
      out += "&lt;";
      i = lt + 1;
      continue;
    }

    const tagName = nameMatch[1].toLowerCase();
    const selfClose = rawInside.trimEnd().endsWith("/");
    const attrPart = rawInside.slice(nameMatch[0].length, selfClose ? rawInside.lastIndexOf("/") : undefined);

    if (SVG_DROP_WITH_BODY.has(tagName)) {
      if (!selfClose) {
        const closing = findClosingTag(src, end + 1, tagName);
        i = closing ? closing.end : src.length;
      } else {
        i = end + 1;
      }
      continue;
    }

    if (DROP_VOID.has(tagName)) {
      i = end + 1;
      continue;
    }

    if (tagName === "style" && !selfClose) {
      const closing = findClosingTag(src, end + 1, "style");
      const cssBody = closing ? src.slice(end + 1, closing.start) : src.slice(end + 1);
      const safeCss = sanitizeCss(cssBody, currentName, { resolveCidUrl, sitePath }).replace(/</g, "\\3c ");
      out += `<style>${safeCss}</style>`;
      i = closing ? closing.end : src.length;
      continue;
    }

    const parsed = parseAttrs(attrPart);
    const cleaned = [];
    let isExternalLink = false;
    let relIdx = -1;
    for (const attr of parsed) {
      if (
        attr.name.startsWith("on") ||
        attr.name === "src" ||
        attr.name === "ping" ||
        attr.name === "xml:base" ||
        attr.name === "formaction" ||
        attr.name === "attributename" ||
        attr.name === "to" ||
        attr.name === "from" ||
        attr.name === "values" ||
        attr.name === "by"
      ) {
        continue;
      }
      if (attr.name === "style") {
        cleaned.push({
          name: "style",
          value: sanitizeCss(attr.value, currentName, { resolveCidUrl, sitePath }),
          hasValue: true,
        });
        continue;
      }
      if (attr.name === "href" || attr.name === "xlink:href") {
        if (tagName === "a") {
          const safe = rewriteHref(attr.value, currentName, { resolveCidUrl, sitePath });
          if (safe) {
            if (safe.startsWith("https://")) isExternalLink = true;
            cleaned.push({ name: attr.name, value: safe, hasValue: true });
          }
        } else if (/^#[a-zA-Z0-9_.:-]+$/.test(attr.value.trim())) {
          cleaned.push({ name: attr.name, value: attr.value.trim(), hasValue: true });
        }
        continue;
      }
      if (tagName === "a" && attr.name === "rel") {
        relIdx = cleaned.length;
      }
      cleaned.push(attr);
    }

    if (tagName === "a" && isExternalLink) {
      const existingTokens = relIdx >= 0 ? cleaned[relIdx].value.split(/\s+/).filter(Boolean) : [];
      const merged = Array.from(new Set([...existingTokens, "noopener", "noreferrer"])).join(" ");
      if (relIdx >= 0) {
        cleaned[relIdx] = { name: "rel", value: merged, hasValue: true };
      } else {
        cleaned.push({ name: "rel", value: merged, hasValue: true });
      }
    }

    out += `<${nameMatch[1]}${serializeAttrs(cleaned)}${selfClose ? "/" : ""}>`;
    i = end + 1;
  }

  return out;
}

export function shortHash(hash) {
  const clean = String(hash || "").trim().toLowerCase();
  return clean.length > 12 ? clean.slice(0, 12) : clean;
}

export function buildHeaderBar({ name, hash, source, verified = true }) {
  const fromLabel = source === "cid" ? "CID" : "chain";
  const safeName = escapeHtml(name);
  const safeHash = escapeHtml(hash);
  const safeShort = escapeHtml(shortHash(hash));
  const verifiedFlag = verified ? "true" : "false";
  const label = verified
    ? `lns://${safeName} · verified ${safeShort} · from ${fromLabel}`
    : `lns://${safeName} · unverified assets (root ${safeShort}) · from ${fromLabel}`;
  return (
    `<div id="lns-gateway-bar" role="banner" data-lns-name="${safeName}" data-lns-source="${fromLabel}" data-lns-sha256="${safeHash}" data-lns-verified="${verifiedFlag}" ` +
    `style="position:sticky;top:0;z-index:2147483647;margin:0;padding:8px 14px;background:#11161f;color:#e6edf3;` +
    `border-bottom:1px solid #2b3442;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;` +
    `display:flex;justify-content:space-between;align-items:center;gap:12px;">` +
    `<span title="SHA-256: ${safeHash}">${label}</span>` +
    `<a href="/lns/index.json" style="color:#93c5fd;text-decoration:none;">index</a>` +
    `</div>`
  );
}

function sanitizeHtmlBody(rawHtml, currentName, { resolveCidUrl = null, sitePath = "/" } = {}) {
  const src = String(rawHtml ?? "");
  let out = "";
  let i = 0;
  let headEndPos = -1;
  let htmlEndPos = -1;
  let bodyEndPos = -1;
  let headCloseEndPos = -1;

  while (i < src.length) {
    const lt = src.indexOf("<", i);
    if (lt === -1) {
      out += src.slice(i);
      break;
    }
    out += src.slice(i, lt);

    // Strip HTML comments to prevent parser differentials
    if (src.startsWith("<!--", lt)) {
      const end = src.indexOf("-->", lt + 4);
      i = end === -1 ? src.length : end + 3;
      continue;
    }

    // Strip processing instructions
    if (src.startsWith("<?", lt)) {
      const end = src.indexOf(">", lt + 2);
      i = end === -1 ? src.length : end + 1;
      continue;
    }

    // Preserve <!doctype html>
    if (src.startsWith("<!", lt)) {
      const nextIdx = skipBangDeclaration(src, lt);
      const decl = src.slice(lt, nextIdx);
      if (/^<!doctype\s+html\s*>$/i.test(decl)) {
        out += decl;
      }
      i = nextIdx;
      continue;
    }

    // Closing tag
    if (src[lt + 1] === "/") {
      const end = src.indexOf(">", lt + 2);
      if (end === -1) break;
      const closeMatch = src.slice(lt + 2, end).trim().match(/^([a-zA-Z][a-zA-Z0-9:-]*)/);
      if (closeMatch) {
        const closeName = closeMatch[1].toLowerCase();
        if (!DROP_WITH_BODY.has(closeName) && !DROP_VOID.has(closeName) && closeName !== "style" && closeName !== "plaintext") {
          out += `</${closeName}>`;
          if (closeName === "head" && headCloseEndPos === -1) {
            headCloseEndPos = out.length;
          }
        }
      }
      i = end + 1;
      continue;
    }

    const end = findTagEnd(src, lt + 1);
    if (end === -1) {
      out += escapeHtml(src.slice(lt));
      break;
    }

    const rawInside = src.slice(lt + 1, end);
    const nameMatch = rawInside.match(/^([a-zA-Z][a-zA-Z0-9:-]*)/);
    if (!nameMatch) {
      out += "&lt;";
      i = lt + 1;
      continue;
    }

    const tagName = nameMatch[1].toLowerCase();
    const selfClose = rawInside.trimEnd().endsWith("/");
    const attrPart = rawInside.slice(nameMatch[0].length, selfClose ? rawInside.lastIndexOf("/") : undefined);

    if (tagName === "plaintext") {
      i = src.length;
      continue;
    }

    if (DROP_WITH_BODY.has(tagName)) {
      if (!selfClose) {
        const closing = findClosingTag(src, end + 1, tagName);
        i = closing ? closing.end : src.length;
      } else {
        i = end + 1;
      }
      continue;
    }

    if (DROP_VOID.has(tagName)) {
      i = end + 1;
      continue;
    }

    if (tagName === "title" && !selfClose) {
      const closing = findClosingTag(src, end + 1, "title");
      const titleBody = closing ? src.slice(end + 1, closing.start) : src.slice(end + 1);
      out += `<title>${escapeHtml(decodeBasicEntities(titleBody))}</title>`;
      i = closing ? closing.end : src.length;
      continue;
    }

    if (tagName === "style" && !selfClose) {
      const closing = findClosingTag(src, end + 1, "style");
      const cssBody = closing ? src.slice(end + 1, closing.start) : src.slice(end + 1);
      const attrs = parseAttrs(attrPart).filter((a) => !a.name.startsWith("on") && a.name !== "style");
      const safeCss = sanitizeCss(cssBody, currentName, { resolveCidUrl, sitePath }).replace(/</g, "\\3c ");
      out += `<style${serializeAttrs(attrs)}>${safeCss}</style>`;
      i = closing ? closing.end : src.length;
      continue;
    }

    if (tagName === "svg") {
      if (selfClose) {
        out += sanitizeSvg(src.slice(lt, end + 1), currentName, { resolveCidUrl, sitePath });
        i = end + 1;
      } else {
        const closing = findMatchingSvgEnd(src, end + 1);
        const svgEnd = closing ? closing.end : src.length;
        out += sanitizeSvg(src.slice(lt, svgEnd), currentName, { resolveCidUrl, sitePath });
        i = svgEnd;
      }
      continue;
    }

    const attrs = parseAttrs(attrPart);

    if (tagName === "meta") {
      const httpEquiv = getAttrValue(attrs, "http-equiv").trim().toLowerCase();
      if (BLOCKED_META_HTTP_EQUIV.has(httpEquiv)) {
        i = end + 1;
        continue;
      }
      const cleanMeta = attrs.filter((a) => !a.name.startsWith("on") && a.name !== "style");
      out += `<meta${serializeAttrs(cleanMeta)}>`;
      i = end + 1;
      continue;
    }

    if (tagName === "link") {
      const relTokens = getAttrValue(attrs, "rel")
        .trim()
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
      const relAllowed =
        relTokens.length > 0 &&
        relTokens.every((t) => ALLOWED_LINK_REL_TOKENS.has(t)) &&
        (relTokens.includes("stylesheet") || relTokens.includes("icon"));
      const rawHref = getAttrValue(attrs, "href");
      const safeHref = relAllowed
        ? rewriteLocalAssetUrl(rawHref, currentName, {
            allowDataImage: relTokens.includes("icon"),
            resolveCidUrl,
            sitePath,
          })
        : null;
      if (!safeHref) {
        i = end + 1;
        continue;
      }
      const cleanLink = [];
      for (const attr of attrs) {
        if (attr.name.startsWith("on") || attr.name === "style" || attr.name === "integrity") continue;
        if (attr.name === "href") {
          cleanLink.push({ name: "href", value: safeHref, hasValue: true });
        } else {
          cleanLink.push(attr);
        }
      }
      out += `<link${serializeAttrs(cleanLink)}>`;
      i = end + 1;
      continue;
    }

    if (tagName === "img" || tagName === "source" || tagName === "track") {
      const allowDataImage = tagName === "img" || tagName === "source";
      let dropTag = false;
      let hasValidMedia = false;
      const cleanMedia = [];
      for (const attr of attrs) {
        if (attr.name.startsWith("on") || attr.name === "ping") continue;
        if (attr.name === "style") {
          cleanMedia.push({
            name: "style",
            value: sanitizeCss(attr.value, currentName, { resolveCidUrl, sitePath }),
            hasValue: true,
          });
          continue;
        }
        if (attr.name === "src") {
          const safe = rewriteLocalAssetUrl(attr.value, currentName, {
            allowDataImage,
            resolveCidUrl,
            sitePath,
          });
          if (!safe) {
            dropTag = true;
            break;
          }
          hasValidMedia = true;
          cleanMedia.push({ name: "src", value: safe, hasValue: true });
          continue;
        }
        if (attr.name === "srcset") {
          const safeSet = rewriteSrcset(attr.value, currentName, allowDataImage, resolveCidUrl, sitePath);
          if (safeSet) {
            hasValidMedia = true;
            cleanMedia.push({ name: "srcset", value: safeSet, hasValue: true });
          }
          continue;
        }
        cleanMedia.push(attr);
      }
      if (!dropTag && hasValidMedia) {
        out += `<${tagName}${serializeAttrs(cleanMedia)}${selfClose ? "/" : ""}>`;
      }
      i = end + 1;
      continue;
    }

    if (tagName === "a" || tagName === "area") {
      let isExternal = false;
      const cleanAnchor = [];
      let relIdx = -1;
      for (const attr of attrs) {
        if (attr.name.startsWith("on") || attr.name === "ping") continue;
        if (attr.name === "style") {
          cleanAnchor.push({
            name: "style",
            value: sanitizeCss(attr.value, currentName, { resolveCidUrl, sitePath }),
            hasValue: true,
          });
          continue;
        }
        if (attr.name === "href") {
          const safe = rewriteHref(attr.value, currentName, { resolveCidUrl, sitePath });
          if (safe) {
            if (safe.startsWith("https://")) isExternal = true;
            cleanAnchor.push({ name: "href", value: safe, hasValue: true });
          }
          continue;
        }
        if (attr.name === "rel") {
          relIdx = cleanAnchor.length;
        }
        cleanAnchor.push(attr);
      }
      if (isExternal) {
        const existingTokens = relIdx >= 0 ? cleanAnchor[relIdx].value.split(/\s+/).filter(Boolean) : [];
        const merged = Array.from(new Set([...existingTokens, "noopener", "noreferrer"])).join(" ");
        if (relIdx >= 0) {
          cleanAnchor[relIdx] = { name: "rel", value: merged, hasValue: true };
        } else {
          cleanAnchor.push({ name: "rel", value: merged, hasValue: true });
        }
      }
      out += `<${tagName}${serializeAttrs(cleanAnchor)}${selfClose ? "/" : ""}>`;
      i = end + 1;
      continue;
    }

    // General tag sanitization
    const cleanGeneral = [];
    for (const attr of attrs) {
      if (
        attr.name.startsWith("on") ||
        attr.name === "srcdoc" ||
        attr.name === "ping" ||
        attr.name === "formaction" ||
        attr.name === "action"
      ) {
        continue;
      }
      if (attr.name === "style") {
        cleanGeneral.push({
          name: "style",
          value: sanitizeCss(attr.value, currentName, { resolveCidUrl, sitePath }),
          hasValue: true,
        });
        continue;
      }
      if (attr.name === "src" || attr.name === "poster" || attr.name === "data" || attr.name === "background") {
        const safe = rewriteLocalAssetUrl(attr.value, currentName, {
          allowDataImage: attr.name === "poster" || attr.name === "background",
          resolveCidUrl,
          sitePath,
        });
        if (safe) cleanGeneral.push({ name: attr.name, value: safe, hasValue: true });
        continue;
      }
      if (attr.name === "href" || attr.name === "xlink:href") {
        const safe = rewriteLocalAssetUrl(attr.value, currentName, {
          allowDataImage: false,
          resolveCidUrl,
          sitePath,
        });
        if (safe) cleanGeneral.push({ name: attr.name, value: safe, hasValue: true });
        continue;
      }
      cleanGeneral.push(attr);
    }

    out += `<${tagName}${serializeAttrs(cleanGeneral)}${selfClose ? "/" : ""}>`;
    if (tagName === "head" && headEndPos === -1) headEndPos = out.length;
    if (tagName === "html" && htmlEndPos === -1) htmlEndPos = out.length;
    if (tagName === "body" && bodyEndPos === -1) bodyEndPos = out.length;
    i = end + 1;
  }

  return { html: out, headEndPos, htmlEndPos, bodyEndPos, headCloseEndPos };
}

/**
 * Sanitizes an HTML document for static serving at `/lns/<name>/`,
 * injects strict CSP + no-referrer meta tags at tracked real `<head>` offsets,
 * and adds the verification header bar.
 */
export function sanitizeHtml(
  rawHtml,
  { name, hash, source, resolveCidUrl = null, sitePath = "/", verified = true },
) {
  const parsed = sanitizeHtmlBody(rawHtml, name, { resolveCidUrl, sitePath });
  let html = parsed.html;
  let bodyEndPos = parsed.bodyEndPos;
  let headCloseEndPos = parsed.headCloseEndPos;

  const metaBlock =
    `<meta http-equiv="Content-Security-Policy" content="${escapeAttr(GATEWAY_CSP)}">` +
    `<meta name="referrer" content="no-referrer">`;
  const bar = buildHeaderBar({ name, hash, source, verified });

  if (parsed.headEndPos !== -1) {
    const insert = "\n  " + metaBlock;
    html = html.slice(0, parsed.headEndPos) + insert + html.slice(parsed.headEndPos);
    if (bodyEndPos !== -1 && bodyEndPos >= parsed.headEndPos) bodyEndPos += insert.length;
    if (headCloseEndPos !== -1 && headCloseEndPos >= parsed.headEndPos) headCloseEndPos += insert.length;
  } else if (parsed.htmlEndPos !== -1) {
    const insert = `\n<head>${metaBlock}</head>`;
    html = html.slice(0, parsed.htmlEndPos) + insert + html.slice(parsed.htmlEndPos);
    if (bodyEndPos !== -1 && bodyEndPos >= parsed.htmlEndPos) bodyEndPos += insert.length;
    headCloseEndPos = parsed.htmlEndPos + insert.length;
  } else {
    return `<!doctype html><html><head><meta charset="utf-8">${metaBlock}</head><body>${bar}${html}</body></html>`;
  }

  if (bodyEndPos !== -1) {
    html = html.slice(0, bodyEndPos) + "\n" + bar + html.slice(bodyEndPos);
  } else if (headCloseEndPos !== -1) {
    html = html.slice(0, headCloseEndPos) + "\n" + bar + html.slice(headCloseEndPos);
  } else {
    html = bar + "\n" + html;
  }

  return html;
}

/**
 * Generates a static zero-JS per-site `404.html` ("No such page" card) with one link back to `/lns/<name>/`.
 */
export function buildNotFoundHtml({ name, singlePage = false }) {
  const safeName = escapeHtml(name);
  const metaBlock =
    `<meta http-equiv="Content-Security-Policy" content="${escapeAttr(GATEWAY_CSP)}">` +
    `<meta name="referrer" content="no-referrer">`;
  const detail = singlePage
    ? `This LNS name (<code>lns://${safeName}</code>) is a single-page site.`
    : `That path does not exist on <code>lns://${safeName}</code>.`;
  return (
    `<!doctype html><html lang="en"><head><meta charset="utf-8">${metaBlock}` +
    `<title>No such page — lns://${safeName}</title>` +
    `<style>` +
    `body{margin:0;padding:48px 20px;font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f8fafc;color:#0f172a}` +
    `.card{max-width:520px;margin:0 auto;padding:28px;background:#ffffff;border:1px solid #cbd5e1;border-radius:12px}` +
    `h1{margin:0 0 12px;font-size:22px}p{margin:0 0 16px;color:#334155}` +
    `code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:#f1f5f9;padding:2px 6px;border-radius:4px}` +
    `a{display:inline-block;padding:8px 14px;background:#0055ff;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600}` +
    `</style></head><body>` +
    `<main class="card" role="main"><h1>No such page</h1>` +
    `<p>${detail}</p>` +
    `<p><a href="/lns/${safeName}/">Back to lns://${safeName}/</a></p>` +
    `</main></body></html>\n`
  );
}
