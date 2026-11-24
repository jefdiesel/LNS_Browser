// Loopback-only HTTP server for the LNS + Logos Storage CID Web Browser.
// Security invariants (matching logos-names/SPEC.md §12.2):
//   - Listens on 127.0.0.1 only.
//   - Rejects any request whose Host header is not 127.0.0.1:<port> or localhost:<port> (anti-DNS-rebinding).
//   - Serves site content with a strict CSP that allows ONLY subresources from its own /site/<name>/
//     (or data: URLs) and blocks all external network connections (connect-src 'none').
//   - Verifies SHA-256 against the on-chain LNS record and manifest entries before serving bytes.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  DEFAULT_CONFIG,
  isValidCid,
  isValidName,
  normalizeSitePath,
  parseLnsUrl,
  resolveName,
  resolveOnChainPage,
} from "./lns.js";
import { StorageClient } from "./storage.js";
import {
  buildNamesProfileCommand,
  buildPublishDeepLink,
  injectLnsBridge,
  publishFiles,
  resolveManifestEntry,
  sniffContentType,
  tryParseManifest,
} from "./manifest.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_HTML_PATH = join(__dirname, "ui", "index.html");
const EDITOR_HTML_PATH = join(__dirname, "ui", "editor.html");

function escapeHtml(text) {
  return String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function sendJson(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf-8");
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": body.length,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(body);
}

function sendHtmlError(res, status, title, detail) {
  const html = Buffer.from(
    `<!doctype html><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;background:#11141a;color:#e6edf3;padding:2rem;line-height:1.5}
.box{max-width:640px;margin:2rem auto;padding:1.5rem;border:1px solid #30363d;border-radius:10px;background:#161b22}
h1{margin:0 0 .5rem;font-size:1.25rem;color:#f85149}code{background:#0d1117;padding:.15rem .4rem;border-radius:4px;word-break:break-all}</style>
<div class="box"><h1>${escapeHtml(title)}</h1><p>${escapeHtml(detail)}</p></div>`,
    "utf-8",
  );
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": html.length,
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(html);
}

function renderProfileCard(record) {
  const texts = record.texts ?? {};
  const display = texts.display || record.name;
  const bio = texts.bio || "";
  const rows = Object.entries(texts)
    .map(
      ([k, v]) =>
        `<tr><th>${escapeHtml(k)}</th><td><code>${escapeHtml(v)}</code></td></tr>`,
    )
    .join("");
  return Buffer.from(
    `<!doctype html><meta charset="utf-8"><title>${escapeHtml(display)} · lns://${escapeHtml(record.name)}</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;background:#0f141b;color:#e6edf3;margin:0;padding:2rem}
.card{max-width:680px;margin:1rem auto;padding:1.75rem;border:1px solid #2b323d;border-radius:12px;background:#161c26}
.pill{display:inline-block;font-size:.75rem;padding:.2rem .55rem;border-radius:999px;background:#1f2a3a;color:#93c5fd;margin-bottom:.75rem}
h1{margin:.2rem 0 .4rem;font-size:1.5rem}p.bio{color:#b6c2cf;margin:0 0 1.25rem}
table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:.45rem .5rem;border-top:1px solid #262e3a;vertical-align:top}
th{color:#8b949e;width:30%}code{word-break:break-all;color:#d2e3fc}.note{margin-top:1.25rem;color:#8b949e;font-size:.85rem}</style>
<div class="card">
  <span class="pill">lns://${escapeHtml(record.name)} · On-chain LNS Profile</span>
  <h1>${escapeHtml(display)}</h1>
  ${bio ? `<p class="bio">${escapeHtml(bio)}</p>` : ""}
  ${rows ? `<table>${rows}</table>` : `<p class="note">This name is registered on LEZ but has no CID site published yet.</p>`}
  <p class="note">To host a web page here, publish to Logos Storage and set this name's <code>cid</code> record.</p>
</div>`,
    "utf-8",
  );
}

async function readJsonBody(req, maxBytes = 10 * 1024 * 1024) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) throw new Error(`request body exceeds ${maxBytes} bytes`);
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf-8");
  return raw ? JSON.parse(raw) : {};
}

function siteCsp(originPrefix) {
  return [
    `default-src ${originPrefix}`,
    `script-src ${originPrefix} 'unsafe-inline'`,
    `style-src ${originPrefix} 'unsafe-inline'`,
    `img-src ${originPrefix} data: blob:`,
    `font-src ${originPrefix} data:`,
    `media-src ${originPrefix} data: blob:`,
    `connect-src 'none'`,
    `form-action 'none'`,
    `base-uri ${originPrefix}`,
  ].join("; ");
}

export function createBrowserServer(options = {}) {
  const config = {
    sequencer: options.sequencer ?? DEFAULT_CONFIG.sequencer,
    registry: options.registry ?? DEFAULT_CONFIG.registry,
    storageApi: options.storageApi ?? DEFAULT_CONFIG.storageApi,
    network: options.network ?? DEFAULT_CONFIG.network,
  };
  const fetchImpl = options.fetchImpl ?? fetch;
  let storage = options.storageClient ?? new StorageClient(config.storageApi, { fetchImpl });

  // Short-lived cache for resolved LNS records + parsed manifests so multi-asset pages load fast.
  const siteCache = new Map();
  const CACHE_TTL_MS = options.cacheTtlMs ?? 15_000;

  async function loadNameSite(name, { bypassCache = false } = {}) {
    const now = Date.now();
    const cached = siteCache.get(name);
    if (!bypassCache && cached && now - cached.fetchedAt < CACHE_TTL_MS) {
      return cached;
    }

    const record = await resolveName(config.sequencer, config.registry, name, { fetchImpl });
    if (!record) return null;

    let mode = "profile";
    let manifest = null;
    let rootBlob = null;
    let storageError = null;
    let onChainPage = null;

    if (record.cid) {
      try {
        rootBlob = await storage.download(record.cid, {
          expectedSha256: record.cidSha256,
        });
        manifest = tryParseManifest(rootBlob.bytes);
        mode = manifest ? "manifest" : "single";
      } catch (err) {
        storageError = err.message;
        mode = "cid-error";
      }
    } else {
      onChainPage = await resolveOnChainPage(config.sequencer, config.registry, name, { fetchImpl }).catch(
        () => null,
      );
      if (onChainPage) mode = "onchain-page";
    }

    const entry = {
      name,
      record,
      mode,
      manifest,
      rootBlob,
      onChainPage,
      storageError,
      fetchedAt: now,
    };
    siteCache.set(name, entry);
    return entry;
  }

  let boundPort = options.port ?? 0;

  const server = createServer(async (req, res) => {
    try {
      // Anti-DNS-rebinding: allow only loopback Host matching our bound port.
      const host = (req.headers.host || "").toLowerCase();
      const allowedHosts = new Set([`127.0.0.1:${boundPort}`, `localhost:${boundPort}`]);
      if (boundPort > 0 && !allowedHosts.has(host)) {
        res.writeHead(403, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("forbidden host");
        return;
      }

      const url = new URL(req.url || "/", `http://127.0.0.1:${boundPort || 7777}`);
      const pathname = url.pathname;

      // ── Browser Shell UI ──────────────────────────────────────────────
      if (req.method === "GET" && pathname === "/") {
        const uiHtml = await readFile(UI_HTML_PATH);
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Length": uiHtml.length,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        res.end(uiHtml);
        return;
      }

      // ── WYSIWYG LNS Site Builder (/editor) ────────────────────────────
      if (req.method === "GET" && pathname === "/editor") {
        const editorHtml = await readFile(EDITOR_HTML_PATH);
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Length": editorHtml.length,
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        });
        res.end(editorHtml);
        return;
      }

      // ── API: Health & Config ──────────────────────────────────────────
      if (req.method === "GET" && pathname === "/api/config") {
        let storageOnline = false;
        let storagePeerId = null;
        try {
          const info = await storage.info();
          storageOnline = true;
          storagePeerId = info?.id ?? null;
        } catch {
          storageOnline = false;
        }
        sendJson(res, 200, {
          ok: true,
          config: { ...config },
          storage: { online: storageOnline, peerId: storagePeerId },
        });
        return;
      }

      if (req.method === "POST" && pathname === "/api/config") {
        const body = await readJsonBody(req);
        if (typeof body.sequencer === "string" && body.sequencer.trim()) {
          config.sequencer = body.sequencer.trim();
        }
        if (typeof body.registry === "string" && body.registry.trim()) {
          config.registry = body.registry.trim();
        }
        if (typeof body.storageApi === "string" && body.storageApi.trim()) {
          config.storageApi = body.storageApi.trim();
          storage = new StorageClient(config.storageApi, { fetchImpl });
        }
        siteCache.clear();
        sendJson(res, 200, { ok: true, config: { ...config } });
        return;
      }

      // ── API: Resolve LNS or CID URL ───────────────────────────────────
      if (req.method === "GET" && pathname === "/api/resolve") {
        const rawUrl = url.searchParams.get("url") || "";
        const refresh = url.searchParams.get("refresh") === "1";
        let parsed;
        try {
          parsed = parseLnsUrl(rawUrl);
        } catch (err) {
          sendJson(res, 400, { ok: false, error: err.message });
          return;
        }

        if (parsed.kind === "cid") {
          try {
            const blob = await storage.download(parsed.cid);
            const manifest = tryParseManifest(blob.bytes);
            sendJson(res, 200, {
              ok: true,
              parsed,
              mode: manifest ? "manifest" : "single",
              cid: parsed.cid,
              sha256: blob.sha256,
              size: blob.size,
              verified: false,
              manifest,
              frameUrl: `/cid/${parsed.cid}${parsed.path === "/" ? "/" : parsed.path}`,
            });
          } catch (err) {
            sendJson(res, 502, { ok: false, parsed, error: err.message });
          }
          return;
        }

        const site = await loadNameSite(parsed.name, { bypassCache: refresh });
        if (!site) {
          sendJson(res, 404, {
            ok: false,
            parsed,
            error: `LNS name "${parsed.name}" is not registered on ${config.sequencer}`,
          });
          return;
        }

        const framePath = parsed.path === "/" ? "/" : parsed.path;
        sendJson(res, 200, {
          ok: true,
          parsed,
          mode: site.mode,
          record: site.record,
          cid: site.record.cid,
          sha256: site.rootBlob?.sha256 ?? site.record.cidSha256 ?? null,
          verified: Boolean(site.rootBlob?.verified),
          manifest: site.manifest,
          storageError: site.storageError,
          frameUrl: `/site/${site.name}${framePath}`,
        });
        return;
      }

      // ── API: Publish files/HTML to Logos Storage CID ──────────────────
      if (req.method === "POST" && pathname === "/api/publish") {
        const body = await readJsonBody(req);
        const files = body.files;
        if (!files || typeof files !== "object" || Object.keys(files).length === 0) {
          sendJson(res, 400, { ok: false, error: "provide a non-empty `files` object mapping paths to content" });
          return;
        }
        const decoded = {};
        for (const [filePath, entry] of Object.entries(files)) {
          if (typeof entry === "string") {
            decoded[filePath] = Buffer.from(entry, "utf-8");
          } else if (entry && typeof entry === "object" && typeof entry.base64 === "string") {
            decoded[filePath] = Buffer.from(entry.base64, "base64");
          } else {
            sendJson(res, 400, { ok: false, error: `invalid content for ${filePath}` });
            return;
          }
        }
        const published = await publishFiles(storage, decoded, {
          title: typeof body.title === "string" && body.title.trim() ? body.title.trim() : null,
          index: typeof body.index === "string" && body.index.trim() ? body.index.trim() : "/index.html",
        });
        const lnsName = typeof body.name === "string" && body.name.trim() ? body.name.trim() : "";
        const namesCommand = buildNamesProfileCommand(lnsName, published);
        const deepLink = buildPublishDeepLink({
          name: lnsName,
          cid: published.rootCid,
          sha256: published.sha256,
          siteType: published.mode,
          returnApp: "lns_browser",
        });
        sendJson(res, 200, {
          ok: true,
          ...published,
          cidUrl: `cid://${published.rootCid}`,
          namesCommand,
          deepLink,
        });
        return;
      }

      // ── Content Gateway: /site/<name>/<path> ──────────────────────────
      if (req.method === "GET" && pathname.startsWith("/site/")) {
        const rest = pathname.slice(6);
        const slash = rest.indexOf("/");
        const name = (slash === -1 ? rest : rest.slice(0, slash)).toLowerCase();
        const rawSubPath = slash === -1 ? "/" : rest.slice(slash);
        if (!isValidName(name)) {
          sendHtmlError(res, 400, "Invalid LNS Name", `"${name}" is not a valid LNS name.`);
          return;
        }
        const subPath = normalizeSitePath(rawSubPath);
        const site = await loadNameSite(name);
        if (!site) {
          sendHtmlError(res, 404, "Name Not Found", `lns://${name} is not registered on LEZ.`);
          return;
        }

        const originPrefix = `http://${host}/site/${name}/`;
        const csp = siteCsp(originPrefix);

        if (site.mode === "cid-error") {
          sendHtmlError(
            res,
            502,
            "CID Verification or Storage Error",
            `lns://${name} points to CID ${site.record.cid}, but loading failed: ${site.storageError}`,
          );
          return;
        }

        if (site.mode === "manifest") {
          const entry = resolveManifestEntry(site.manifest, subPath);
          if (!entry) {
            sendHtmlError(res, 404, "File Not Found in Site Manifest", `${subPath} is not listed in lns://${name}'s CID manifest.`);
            return;
          }
          let asset;
          try {
            asset = await storage.download(entry.cid, {
              expectedSha256: entry.sha256,
              expectedSize: entry.size,
            });
          } catch (err) {
            sendHtmlError(res, 502, "Asset Integrity / Storage Error", err.message);
            return;
          }
          const isHtml = entry.contentType.startsWith("text/html");
          const body = isHtml ? injectLnsBridge(asset.bytes) : Buffer.from(asset.bytes);
          res.writeHead(200, {
            "Content-Type": entry.contentType,
            "Content-Length": body.length,
            "Content-Security-Policy": csp,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-LNS-Name": name,
            "X-LNS-CID": entry.cid,
            "X-LNS-SHA256": asset.sha256,
            "Cache-Control": "no-store",
          });
          res.end(body);
          return;
        }

        if (site.mode === "single" && site.rootBlob) {
          const contentType = sniffContentType(site.rootBlob.bytes, site.rootBlob.contentType);
          const isHtml = contentType.startsWith("text/html");
          const body = isHtml ? injectLnsBridge(site.rootBlob.bytes) : Buffer.from(site.rootBlob.bytes);
          res.writeHead(200, {
            "Content-Type": contentType,
            "Content-Length": body.length,
            "Content-Security-Policy": csp,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-LNS-Name": name,
            "X-LNS-CID": site.record.cid,
            "X-LNS-SHA256": site.rootBlob.sha256,
            "Cache-Control": "no-store",
          });
          res.end(body);
          return;
        }

        if (site.mode === "onchain-page" && site.onChainPage) {
          const isHtml = site.onChainPage.contentType.startsWith("text/html");
          const body = isHtml ? injectLnsBridge(site.onChainPage.body) : Buffer.from(site.onChainPage.body);
          res.writeHead(200, {
            "Content-Type": site.onChainPage.contentType,
            "Content-Length": body.length,
            "Content-Security-Policy": csp,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
          });
          res.end(body);
          return;
        }

        const card = renderProfileCard(site.record);
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Content-Length": card.length,
          "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
          "Referrer-Policy": "no-referrer",
          "Cache-Control": "no-store",
        });
        res.end(card);
        return;
      }

      // ── Direct CID Gateway: /cid/<cid>/<path> ─────────────────────────
      if (req.method === "GET" && pathname.startsWith("/cid/")) {
        const rest = pathname.slice(5);
        const slash = rest.indexOf("/");
        const cid = slash === -1 ? rest : rest.slice(0, slash);
        const rawSubPath = slash === -1 ? "/" : rest.slice(slash);
        if (!isValidCid(cid)) {
          sendHtmlError(res, 400, "Invalid CID", `"${cid}" is not a valid Logos Storage CID.`);
          return;
        }
        let rootBlob;
        try {
          rootBlob = await storage.download(cid);
        } catch (err) {
          sendHtmlError(res, 502, "Storage Error", err.message);
          return;
        }
        const originPrefix = `http://${host}/cid/${cid}/`;
        const csp = siteCsp(originPrefix);
        const manifest = tryParseManifest(rootBlob.bytes);

        if (manifest) {
          const entry = resolveManifestEntry(manifest, normalizeSitePath(rawSubPath));
          if (!entry) {
            sendHtmlError(res, 404, "File Not Found", `${rawSubPath} is not in manifest ${cid}.`);
            return;
          }
          const asset = await storage.download(entry.cid, {
            expectedSha256: entry.sha256,
            expectedSize: entry.size,
          });
          const isHtml = entry.contentType.startsWith("text/html");
          const body = isHtml ? injectLnsBridge(asset.bytes) : Buffer.from(asset.bytes);
          res.writeHead(200, {
            "Content-Type": entry.contentType,
            "Content-Length": body.length,
            "Content-Security-Policy": csp,
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-LNS-CID": entry.cid,
            "X-LNS-SHA256": asset.sha256,
            "Cache-Control": "no-store",
          });
          res.end(body);
          return;
        }

        const contentType = sniffContentType(rootBlob.bytes, rootBlob.contentType);
        const isHtml = contentType.startsWith("text/html");
        const body = isHtml ? injectLnsBridge(rootBlob.bytes) : Buffer.from(rootBlob.bytes);
        res.writeHead(200, {
          "Content-Type": contentType,
          "Content-Length": body.length,
          "Content-Security-Policy": csp,
          "Referrer-Policy": "no-referrer",
          "X-Content-Type-Options": "nosniff",
          "X-LNS-CID": cid,
          "X-LNS-SHA256": rootBlob.sha256,
          "Cache-Control": "no-store",
        });
        res.end(body);
        return;
      }

      sendJson(res, 404, { ok: false, error: "not found" });
    } catch (err) {
      sendJson(res, 500, { ok: false, error: err.message });
    }
  });

  return {
    server,
    config,
    async listen(port = options.port ?? 7777) {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", () => {
          server.off("error", reject);
          resolve();
        });
      });
      boundPort = server.address().port;
      return { host: "127.0.0.1", port: boundPort, url: `http://127.0.0.1:${boundPort}` };
    },
    async close() {
      await new Promise((resolve) => server.close(() => resolve()));
    },
  };
}
