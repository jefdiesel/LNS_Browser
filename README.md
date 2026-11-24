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

## Basecamp Module (`basecamp/`)

`basecamp/` is a `ui_qml` Basecamp app (`lns_browser`) built with `logos-module-builder`:
- Depends on the `names` core module (`>=0.10.0`).
- Provides the `lns.browse` intent (`web: true`).
- Resolves `lns://` URLs via `logos.callModuleAsync("names", "resolve", ...)`, inspects the on-chain CID + SHA-256, lets name owners bind a new CID via `set_profile`, and opens the verified site in the local loopback browser.
