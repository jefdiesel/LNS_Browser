# LNS Browser (`lns-browser`)

A local web browser, publisher, and Basecamp `ui_qml` app for **Logos Names (LNS)** + **Logos Storage CID** sites on **LEZ 0.4 rc3**.

## How It Works

1. **Publish content to Logos Storage (CID)**:
   - Single HTML file → uploaded directly to your local Logos Storage node (`/api/storage/v1/data`).
   - Multi-file directory → each file is uploaded to get a child CID + SHA-256, and a v1 JSON site manifest (`kind: "lns-site-manifest"`) is uploaded as the root CID.
2. **Pin the CID on-chain in LNS**:
   - Stored in the name's encrypted on-chain profile using the existing LNS text keys:
     - `cid` — root Logos Storage CID
     - `cid.sha256` — SHA-256 hex digest of the root CID bytes (verified before rendering)
     - `cid.type` — `manifest` or `single`
   - Works immediately on the live LEZ 0.4 rc3 LNS registry (`6Yxj5k8AiuBSuMAYVQFGrYKjJGUSSaWWgoB9D9XXN3gA`) via `https://lez.nameswallet.app/` with no new program deployment.
3. **Browse via LNS URLs**:
   - Type `lns://jef`, `jef.lez/about.html`, or `cid://<cid>` in the address bar.
   - The loopback gateway (`127.0.0.1`) resolves the LNS name privately (Argon2id + AES-GCM), streams bytes from your local Logos Storage node, verifies SHA-256, and renders the page inside a sandboxed `<iframe sandbox="allow-scripts">` with strict CSP (`connect-src 'none'`, `Referrer-Policy: no-referrer`) and Host-header DNS-rebinding protection.

## Quick Start

```bash
# Start the local LNS + CID web browser (opens on http://127.0.0.1:7777)
node src/cli.js serve

# Publish a multi-file site directory to your local Logos Storage node
node src/cli.js publish examples/demo-site --name jef --title "Demo Site"

# Resolve an LNS URL from the CLI
node src/cli.js resolve lns://jef

# Run tests
npm test
```

## Basecamp App (`basecamp/` v0.2.8 + `basecamp-module/` v0.1.8)

- `lns_browser` (`ui_qml`) + `lns_browser_core` (Rust core module) built with `logos-module-builder`.
- Resolves `lns://` URLs via `names.resolve` and on-chain `SetPage` HTML (`names.page`, ≤ 78 KB) on LEZ 0.4, automatically retrying both on `busy: true` (every 1 s, up to 20 s).
- Uses Basecamp's built-in `storage_module` when installed (never defaults to port `8080`, which belongs to the Logos Blockchain node), routing all `int`/`bool`/`[tstr]` `storage_module` calls (`connect`, `downloadChunks`, `downloadToUrl`, `uploadUrl`, `uploadInit`) through `lns_browser_core` via `logos-rust-sdk` with real Rust types, stripping MIME parameters (`; charset=...`) on HTTP `POST /data` uploads to real Logos Storage nodes, plus a local **Storage peers** setting (`~/.config/lns-browser/config.json`) as a workaround for upstream Logos Storage discovery (#1556). When no Storage module is installed, says so plainly and defaults Publish to **On-Chain HTML (≤ 78 KB)**.
- Renders pages natively with zero JS and zero external subresources: safe colors, **SVG-as-Canvas** (`Canvas` + structured ops with Qt `QVariantList` array-like normalization, zero QtSvg dependency), click-to-confirm `https://` links (**Open in Browser** via `lns_browser_core.open_external_url` + **Copy Link**).
- Publishes via Basecamp's `names.publish_site` intent so Names verifies ownership and asks for a single-click approval before signing.
- Includes a zero-dependency WYSIWYG Site Builder at `http://127.0.0.1:7777/editor` (`src/ui/editor.html`) and AI agent authoring guide in [`AGENT.md`](./AGENT.md).
