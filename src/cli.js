#!/usr/bin/env node
// CLI for lns-browser:
//   lns-browser serve   [--port 7777] [--sequencer URL] [--registry ID] [--storage URL]
//   lns-browser publish <file-or-dir> [--name <lns-name>] [--title <title>] [--storage URL]
//   lns-browser resolve <lns-url>     [--sequencer URL] [--registry ID]

import { DEFAULT_CONFIG, parseLnsUrl, resolveName } from "./lns.js";
import { StorageClient } from "./storage.js";
import { buildNamesProfileCommand, publishPath } from "./manifest.js";
import { createBrowserServer } from "./server.js";

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

function usage() {
  console.log(`lns-browser — LNS + Logos Storage CID Web Browser & Publisher

Usage:
  lns-browser serve   [--port 7777] [--sequencer URL] [--registry ID] [--storage URL]
  lns-browser publish <file-or-dir> [--name NAME] [--title TITLE] [--storage URL]
  lns-browser resolve <lns-url>     [--sequencer URL] [--registry ID]

Defaults (LEZ 0.4 rc3):
  --sequencer ${DEFAULT_CONFIG.sequencer}
  --registry  ${DEFAULT_CONFIG.registry}
  --storage   ${DEFAULT_CONFIG.storageApi || "(not set — pass a real Logos Storage API URL; port 8080 is Logos Blockchain)"}`);
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const cmd = positional[0] || "serve";

if (cmd === "help" || flags.help) {
  usage();
  process.exit(0);
}

if (cmd === "serve") {
  const port = Number(flags.port ?? 7777);
  const instance = createBrowserServer({
    port,
    sequencer: flags.sequencer || DEFAULT_CONFIG.sequencer,
    registry: flags.registry || DEFAULT_CONFIG.registry,
    storageApi: flags.storage || DEFAULT_CONFIG.storageApi,
  });
  const addr = await instance.listen(port);
  console.log(`LNS Browser listening on ${addr.url}`);
  console.log(`  Sequencer: ${instance.config.sequencer}`);
  console.log(`  Registry:  ${instance.config.registry}`);
  console.log(`  Storage:   ${instance.config.storageApi || "(not configured — set in Settings or pass --storage URL)"}`);
} else if (cmd === "publish") {
  const target = positional[1];
  if (!target) {
    console.error("error: specify a file or directory to publish");
    process.exit(1);
  }
  const storageUrl = flags.storage || DEFAULT_CONFIG.storageApi;
  if (!storageUrl) {
    console.error("error: pass --storage <URL> (or set LOGOS_STORAGE_API) pointing to a real Logos Storage node. Note: port 8080 is Logos Blockchain, not Storage.");
    process.exit(1);
  }
  const storage = new StorageClient(storageUrl);
  const result = await publishPath(storage, target, {
    title: typeof flags.title === "string" ? flags.title : null,
  });
  const command = buildNamesProfileCommand(typeof flags.name === "string" ? flags.name : "", result);
  console.log(JSON.stringify({ ...result, cidUrl: `cid://${result.rootCid}`, namesCommand: command }, null, 2));
  console.error(`\nTo bind this CID on-chain to your LNS name:\n  ${command}`);
} else if (cmd === "resolve") {
  const raw = positional[1];
  if (!raw) {
    console.error("error: specify an LNS name or URL (e.g. lns://jef)");
    process.exit(1);
  }
  const parsed = parseLnsUrl(raw);
  if (parsed.kind !== "lns") {
    console.log(JSON.stringify(parsed, null, 2));
    process.exit(0);
  }
  const record = await resolveName(
    flags.sequencer || DEFAULT_CONFIG.sequencer,
    flags.registry || DEFAULT_CONFIG.registry,
    parsed.name,
  );
  if (!record) {
    console.error(`not registered: lns://${parsed.name}`);
    process.exit(1);
  }
  console.log(JSON.stringify({ parsed, record }, null, 2));
} else {
  usage();
  process.exit(1);
}
