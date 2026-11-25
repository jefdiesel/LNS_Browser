# LNS Static Gateway (`lns-gateway`)

Builds verified, sanitized static snapshots of LNS name websites for ordinary browsers at `nameswallet.app/lns/<name>/...`.

No server code or Worker runs when a visitor loads a page. All chain reads, storage fetches, hash checks, and HTML rewrites happen offline on your own machine on a schedule.

## Requirements

- **Node 24 or newer** (uses built-in `node:crypto` `argon2`, SHA-256, and AES-256-GCM; `snapshot.mjs` checks `process.versions.node` and refuses with a plain message below Node 24 without falling back to npm).
- **Zero npm dependencies**: `package.json` lists no dependencies and no `node_modules` directory is installed or used.
- **Browser code rule**: any code that runs in a browser uses WebCrypto (`crypto.subtle`), and Argon2id comes from **one** vendored, audited, dependency-free file alongside its license file and a SHA-256 pin checked by tests (`vendor/pins.json`). No npm. (`lns-gateway` v1 ships no browser JS; all gateway snapshots enforce `script-src 'none'`.)

## Site Authoring Rule (Modern Web, No Build Step)

Sites hosted on LNS names are modern web with no build step:
- Plain HTML, modern CSS, native ES modules and import maps, and web components.
- No bundler, no framework, no `node_modules`.
- **The folder written is the folder published.** Upload that folder straight to Logos Storage (or publish a single HTML page under 78 KB on chain) and pin its CID and SHA-256 in the LNS name record.
- Gateway compatibility: because `nameswallet.app/lns/<name>/` serves multiple names on one origin with `script-src 'none'`, keep core content and links in plain HTML and CSS so pages work both in LNS Browser and on the static gateway.

## How It Works

1. Checks that Node is **Node 24 or newer** with built-in `crypto.argon2`.
2. Reads the bare LNS names listed in `names.json` (for example `["demo"]`).
3. Resolves each name on LEZ 0.4 using `derive.mjs` (`node:crypto` Argon2id + AES-256-GCM + SHA-256) and package-free helpers from `basecamp/qml/logic.mjs`.
4. Loads either:
   - the name's Logos Storage CID bundle (`cid` + `cid.sha256` + optional v1 manifest) from `LOGOS_STORAGE_API`, or
   - the name's on-chain page (`SetPage`, up to about 78 KB of HTML).
5. Checks SHA-256 of the root blob and every file in a manifest. Refuses the entire site if any hash is missing or wrong.
6. Sanitizes HTML, CSS, and SVG:
   - strips scripts, event handlers, frames, objects, meta redirects, and external subresources;
   - rewrites `lns://other` links to `/lns/other/` and scopes root-relative paths under `/lns/<name>/`;
   - adds a strict `<meta http-equiv="Content-Security-Policy">` (`default-src 'none'; script-src 'none'; connect-src 'none'; ...`) and `no-referrer`;
   - adds a small header bar: `lns://<name> · verified <hash> · from chain/CID`.
7. Writes `out/lns/<name>/...` and `out/lns/index.json` (`name`, `source`, `hash`, `time`) **only when content changes**.

## Running Once

Requires **Node 24 or newer** (no `npm install`). Set `LOGOS_STORAGE_API` to your Logos Storage node API URL (needed for CID sites; on-chain pages work without it):

```sh
LOGOS_STORAGE_API="<your-storage-api-url>" node snapshot.mjs
```

Run tests (no network, no `node_modules`):

```sh
node --test test/*.test.mjs
```

Optional environment variables or CLI flags:
- `LNS_NAMES_FILE` / `--names` (default: `names.json`)
- `LNS_OUT_DIR` / `--out` (default: `out`)
- `LNS_SEQUENCER_URL` / `--sequencer`
- `LNS_REGISTRY` / `--registry`
- `LOGOS_STORAGE_API` / `--storage`

## Running on a Schedule and Deploying `out/`

Run the snapshot job on your own machine (with **Node 24 or newer**) every 10 minutes and publish `out/` only when files changed.

Example cron entry:

```cron
*/10 * * * * cd <repo-dir>/lns-gateway && LOGOS_STORAGE_API="<your-storage-api-url>" node snapshot.mjs && <static-deploy-command> out/
```

For Cloudflare Pages (static files only, no Functions or Workers):
- Publish the `out/` directory with your static deploy tool (for example Wrangler Pages deploy or a Git push of `out/`).
- Do not add a `_worker.js` or `functions/` handler under `/lns/`.
- Because `snapshot.mjs` writes only changed files, you can skip the deploy step whenever `out/` has no diff.

## Cost Model (Zero Marginal Cost)

Every route under `/lns/` is a pre-built static file served from Cloudflare's edge cache. No Worker, function, or origin server runs per visitor.

| Path | Serving mode | Expected requests | Bot worst case (500 req/s) | Marginal cost |
| --- | --- | --- | --- | --- |
| `/lns/index.json` | Static JSON file | Low (directory / refresh checks) | 500 req/s served from CDN cache | $0 |
| `/lns/<name>/` | Static HTML file | Low to medium (page views) | 500 req/s served from CDN cache | $0 |
| `/lns/<name>/<asset>` | Static CSS / image / subpage | Medium (page subresources) | 500 req/s served from CDN cache | $0 |

Notes:
- Chain RPC and Logos Storage queries happen only during the scheduled build on our own machine, never on visitor traffic.
- A 500 req/s bot storm (~43 million requests/day) hits static CDN assets only and triggers zero origin compute and zero Worker invocations.

## Trust Note for Visitors

What a visitor **can** trust:
- Strict CSP (`script-src 'none'`, `connect-src 'none'`) blocks scripts and external tracking requests inside snapshotted pages.
- Every CID file was SHA-256 verified against the on-chain LNS record and site manifest at snapshot time.
- The verified hash is shown in the top bar and recorded in `/lns/index.json`, so you can compare it directly against LNS Browser or the chain.

What a visitor **cannot** trust without verifying locally:
- The snapshot may be older than the latest on-chain update (up to one refresh interval).
- Ordinary browsers cannot check LEZ state or Logos Storage hashes themselves here, so visitors trust our snapshot machine, our LEZ RPC, and Cloudflare not to alter the served HTML.
- For full end-to-end verification, open `lns://<name>` directly in LNS Browser or Basecamp connected to your own node.
