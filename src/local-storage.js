#!/usr/bin/env node
// DEV-ONLY stand-in mock for offline unit/demo testing.
// NEVER use this for real LNS publishing: it has no libp2p peers, so nobody else can open its CIDs.
// `lns-browser` refuses to publish to nodes that report `mock: true`.

import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256Hex, StorageClient } from "./storage.js";
import { publishPath } from "./manifest.js";
import { base58Encode } from "./lns.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = join(__dirname, "..", "examples", "demo-site");
const PORT = Number(process.env.STORAGE_PORT || 8089);

const blobs = new Map();

function makeCid(buf) {
  const hashHex = sha256Hex(buf);
  const hashBytes = Buffer.from(hashHex, "hex");
  // Multicodec-style deterministic base58 CID prefixed with 'z'
  const raw = Buffer.concat([Buffer.from([0x01, 0xcd, 0x01, 0x12, 0x20]), hashBytes]);
  return "z" + base58Encode(raw);
}

const server = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/api/storage/v1/debug/info") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ id: "16Uiu2HAmLocalLogosStorageSeed", mock: true, addrs: [`/ip4/127.0.0.1/tcp/${PORT}`] }));
    return;
  }

  if (req.method === "POST" && req.url === "/api/storage/v1/data") {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const buf = Buffer.concat(chunks);
    const cid = makeCid(buf);
    blobs.set(cid, {
      bytes: buf,
      contentType: req.headers["content-type"] || "application/octet-stream",
    });
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end(cid);
    return;
  }

  const m = req.url?.match(/^\/api\/storage\/v1\/data\/([A-Za-z0-9]+)(?:\/network\/stream)?$/);
  if (req.method === "GET" && m) {
    const item = blobs.get(m[1]);
    if (!item) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("CID not found");
      return;
    }
    res.writeHead(200, {
      "Content-Type": item.contentType,
      "Content-Length": item.bytes.length,
    });
    res.end(item.bytes);
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

await new Promise((resolve) => server.listen(PORT, "127.0.0.1", resolve));

// Auto-seed examples/demo-site into this dev-only mock on startup
const client = new StorageClient(`http://127.0.0.1:${PORT}/api/storage/v1`, { allowStandin: true });
const published = await publishPath(client, DEMO_DIR, { title: "Demo LNS + CID Site" });

console.log(`WARNING: Dev-only mock storage running at http://127.0.0.1:${PORT}/api/storage/v1`);
console.log(`CIDs stored here are NOT on the Logos Storage network and nobody else can open them.`);
console.log(`Seeded Demo Site (multi-file manifest):`);
console.log(`  URL:    cid://${published.rootCid}`);
console.log(`  CID:    ${published.rootCid}`);
console.log(`  SHA256: ${published.sha256}`);
for (const f of published.files) {
  console.log(`  File:   ${f.path} -> ${f.cid}`);
}
