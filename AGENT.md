# AGENT.md — Authoring & Publishing `lns://` Websites

This document defines the exact rules, constraints, and workflows for AI agents creating and publishing websites on **Logos Names (LNS)** (`lns://<name>`).

---

## 1. Hosting Modes

Every `lns://<name>` site uses one of two content-verified hosting modes on **LEZ 0.4**:

| Mode | Where bytes live | Size limit | Best for | On-chain fields |
| --- | --- | --- | --- | --- |
| **On-Chain `SetPage`** | Encrypted directly inside the LNS name's on-chain Page account (`MAX_SEALED_PAGE_LEN = 80 * 1024` bytes; keep raw HTML **≤ 78 KB**) | ~78 KB raw UTF-8 HTML | Single-page sites, manifestos, announcements, landing pages that need zero storage node | `names page set <name>` / `set_page` |
| **Logos Storage CID** | Content-addressed on a Logos Storage node (`single` HTML file or `logos-site` v1 multi-file manifest), pinned by hash on the LNS profile | Unlimited (keep assets lean for fast sync) | Multi-page sites, images, CSS/JS bundles, docs, web apps | `cid`, `cid.sha256`, `cid.type` (`single` or `manifest`) |

> **Rule of thumb:** If a page is a self-contained single HTML document under **78 KB**, it can be published in *either* mode. If it has multiple files or exceeds 78 KB, use **Logos Storage CID**.

---

## 2. Non-Negotiable Security & Zero-Leak Rules

Both the localhost `lns-browser` and the native Basecamp `lns_browser` enforce strict zero-leak sandboxing (`default-src 'none'` / `connect-src 'none'` / `Referrer-Policy: no-referrer`):

1. **Zero external subresources.** NEVER include external `<script src="...">`, `<link rel="stylesheet" href="https://...">`, Google Fonts, CDN images (`<img src="https://...">`), external `<iframe src="...">`, CSS `url(https://...)`, or `fetch("https://...")`. They are blocked by CSP and stripped by the Basecamp sanitizer.
2. **Self-contained assets only.**
   - Inline `<style>...</style>` (or relative `./style.css` in a CID manifest).
   - Use **inline `<svg>`** (pure geometric paths/shapes — no `<script>`, `<foreignObject>`, event handlers, or external URLs) or **`data:image/png;base64,...`** for graphics.
   - Use system font stacks (`system-ui, -apple-system, sans-serif` / `ui-monospace, monospace`).
3. **Hyperlinks (`<a>`):**
   - **Internal LNS links:** `lns://<name>` or `lns://<name>/path.html` or relative `/about.html`.
   - **Direct CID links:** `cid://<cid>` or `cid://<cid>/file.html`.
   - **External web links:** `https://...` ONLY (e.g. `<a href="https://nameswallet.app/browser">`). Never use `http://`, `javascript:`, `data:`, `file:`, or credentialed URLs (`https://user:pass@...`). Both browsers intercept `https://` clicks and show a user confirmation bar (`Open in browser` / `Copy`, `noopener noreferrer`).

---

## 3. Cross-Renderer Compatibility (Full Browser + Basecamp Native Viewer)

Pages can be viewed in **two** renderers:
1. **Localhost `lns-browser` (`http://127.0.0.1:7777`)** — full HTML5/CSS/inline SVG/JS inside a zero-network sandboxed `<iframe>`.
2. **Basecamp native `lns_browser`** — zero-JS Qt RichText + safe color palette + native inline `<svg>` / `data:image/*` blocks.

To ensure your page looks great in **both**:

- **Set page palette explicitly on `body` and `a`** using hex colors (`#rrggbb`) in `<style>`:
  ```css
  body { background: #ffffff; color: #18202c; }
  a { color: #0055ff; }
  ```
- **Use semantic HTML tags** from the Basecamp allowlist: `h1`–`h6`, `p`, `ul`, `ol`, `li`, `b`/`strong`, `i`/`em`, `u`, `small`, `code`, `pre`, `blockquote`, `table`/`thead`/`tbody`/`tr`/`th`/`td`, `div`, `span`, `a`, `br`, `hr`.
- **Inline `<svg>` graphics:** Always include `xmlns="http://www.w3.org/2000/svg"`, explicit `viewBox="0 0 W H"`, `aria-label="..."`, and an explicit hex `fill="#0055ff"` (or class `fill` rule in `<style>`). Basecamp renders inline `<svg>` natively via **SVG-as-Canvas** (`<path>`, `<use href="#id">`, `<rect>`, `<circle>`, `<polygon>`, hex `fill`, and `opacity` — zero QtSvg dependency). Never put `<script>`, `<foreignObject>`, or `on*=` attributes inside `<svg>`.
- **Accessible fallback heading:** If your hero is an `<svg>` banner, include `<h1 class="sr">Page Title</h1>` with `.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0,0,0,0); }` — Basecamp automatically hides `.sr` when the `<svg>` renders and keeps it visible if no `<svg>` is present.
- **No JS required for core content:** Progressive enhancement is fine for the localhost browser, but core text and links must exist in static HTML so Basecamp (which runs zero JS) renders the complete page.

---

## 4. Minimal Reference Template

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hello World</title>
  <style>
    body { background: #ffffff; color: #18202c; font-family: system-ui, sans-serif; margin: 0; padding: 48px 24px; }
    main { max-width: 720px; margin: 0 auto; }
    h1 { color: #0055ff; }
    a { color: #0055ff; font-weight: 600; }
    code { background: #f2f5fa; color: #0044cc; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <h1>Hello World</h1>
    <p>This page is hosted on <code>lns://helloworld</code> with zero external dependencies.</p>
    <p><a href="https://nameswallet.app/browser">Open the LNS Browser &rarr;</a></p>
  </main>
</body>
</html>
```

---

## 5. Publishing Workflows

### A. Never Bypass Names Ownership Checks
The `names` core module refuses state-mutating calls (`set_profile`, `set_page`) from any module other than `names_ui`. Agents and external tools must publish through **one** of these sanctioned paths:

1. **Basecamp Deep Link (`names.publish_site`) — Recommended for GUI / Browser / WYSIWYG:**
   Encode a JSON payload as **base64url** (no padding) into:
   ```text
   basecamp://intent/names.publish_site?p=<base64url(JSON)>
   ```
   **CID payload:**
   ```json
   {
     "name": "helloworld",
     "cid": "z4W2jXDAE4ZM8yrBS1ThzzKkDLRPEiNPxDYBGA5mGPBdPKZ8pYP",
     "sha256": "cf7f4efa13d714d8e7b4af39d8e3c6bf8ba07daf938ba7c42b78c2cc8790d490",
     "site_type": "single",
     "return_app": "lns_browser"
   }
   ```
   **On-chain `SetPage` payload (≤ 78 KB HTML):**
   ```json
   {
     "name": "helloworld",
     "html": "<!doctype html>...",
     "return_app": "lns_browser"
   }
   ```
   Names verifies that the user's wallet owns `name`, displays a single-click approval card with fee estimate (preserving existing bio/avatar/profile entries), signs & broadcasts, and returns to `lns_browser`.

2. **CLI Publish (Logos Storage + Names CLI):**
   ```bash
   # 1. Upload file or directory to a REAL Logos Storage node and print CID + SHA-256
   #    (never port 8080 — port 8080 belongs to the Logos Blockchain node, not Storage)
   lns-browser publish ./my-site --storage http://127.0.0.1:<STORAGE_PORT>/api/storage/v1 --name helloworld --title "Hello World"

   # 2. Commit bare CID + SHA-256 on chain using the Names CLI (uses your wallet; no "cid=" or "cid://" prefix)
   names profile helloworld --cid <ROOT_CID> --set cid.sha256=<SHA256> --set cid.type=single
   ```
   - **Real Logos Storage MIME rule:** When posting directly to `POST /api/storage/v1/data`, always send a **bare** `Content-Type` with no `; charset=...` parameters (e.g. `text/html`, `text/css`, `application/json`, `application/vnd.logos.site-manifest+json`). Real Logos Storage nodes reject parameterized types like `text/html; charset=utf-8` with HTTP 422 (`The MIME type '...' is not valid`). Keep `; charset=utf-8` only inside the manifest entry's `contentType` field (`lns-browser` v0.1.8 / v0.2.8 strips parameters automatically on upload).
   - **Peer discovery workaround (upstream #1556):** If a Basecamp Storage node cannot automatically discover who holds a CID, add `peerId /ip4/…/tcp/…` lines in Basecamp LNS Browser under **Settings → Storage peers** (saved locally in `~/.config/lns-browser/config.json`; never commit peer configs to a repo).
   - **Busy retries:** Both `names.resolve` and `names.page` can reply with `{"busy": true}` while Names is syncing; retry every 1 s up to 20 s.

3. **Localhost HTTP API (`POST http://127.0.0.1:7777/api/publish`):**
   ```json
   {
     "name": "helloworld",
     "title": "Hello World",
     "files": {
       "/index.html": "<!doctype html>..."
     }
   }
   ```
   Returns `{ ok, mode, rootCid, sha256, cidUrl, namesCommand, deepLink }`.

4. **Visual WYSIWYG Builder:**
   Open `http://127.0.0.1:7777/editor` (source: `src/ui/editor.html`) to build pages visually with live Browser + Basecamp previews, byte-budget gauge, pixel-art SVG generator, CID upload, and one-click Names deep-link publishing.

---

## 6. Pre-Publish Verification Checklist for Agents

Before handing a page to the user or publishing:
- [ ] **No external URLs** in `src=`, `href=` on `<link>`, CSS `url()`, or `<script>`.
- [ ] **Only `lns://`, `cid://`, relative paths, or `https://`** in `<a href>`.
- [ ] **Byte size verified:** `Buffer.byteLength(html, "utf8") <= 78000` if targeting on-chain `SetPage`.
- [ ] **Explicit colors:** `body { background: #...; color: #...; }` and `a { color: #...; }` set if a light or custom theme is intended.
- [ ] **Inline SVG validated:** no `<script>`, no `<foreignObject>`, no `on*=` attributes, explicit `viewBox` and hex `fill`, using `<path>` / `<use>` / `<rect>` / `<circle>` / `<polygon>`.
- [ ] **Real Logos Storage node & bare MIME:** upload only to a real Logos Storage node (never port `8080`, never a local stand-in mock) with bare `Content-Type` on `POST /data` (no `; charset=...`).
- [ ] **SHA-256 recorded:** when publishing to Logos Storage CID, always set bare `cid` (no `cid=`/`cid://` prefix), `cid.sha256`, and `cid.type` (`single` or `manifest`) so browsers show `SHA-256 ✓`.
