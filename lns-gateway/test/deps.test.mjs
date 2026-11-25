import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyVendorPins } from "../vendor.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const GATEWAY_ROOT = resolve(__dirname, "..");

async function listJsFiles(dir, out = []) {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === "out") continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await listJsFiles(full, out);
    } else if (entry.isFile() && /\.(?:mjs|js|cjs)$/i.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function extractImportSpecifiers(source) {
  const found = [];
  const staticRe = /^\s*(?:import|export)\b[^;\n]*?\bfrom\s*["']([^"']+)["']/gm;
  const multilineFromRe =
    /^\s*(?:import|export)\s+(?:[\w$*]+\s*,\s*)?(?:\*\s+as\s+[\w$]+|\{[\s\S]*?\})\s*from\s*["']([^"']+)["']/gm;
  const sideEffectRe = /^\s*import\s*["']([^"']+)["']/gm;
  const dynamicRe = /(?<!\.)\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  const requireRe = /(?<!\.)\brequire\s*\(\s*["']([^"']+)["']\s*\)/g;

  for (const re of [staticRe, multilineFromRe, sideEffectRe, dynamicRe, requireRe]) {
    let m;
    while ((m = re.exec(source)) !== null) {
      found.push(m[1]);
    }
  }
  return Array.from(new Set(found));
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

test("package.json has zero dependencies and node_modules does not exist", async () => {
  const pkg = JSON.parse(await readFile(join(GATEWAY_ROOT, "package.json"), "utf-8"));
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const val = pkg[field];
    assert.equal(
      val === undefined || Object.keys(val).length === 0,
      true,
      `lns-gateway/package.json must not declare ${field}`,
    );
  }
  assert.match(String(pkg.engines?.node || ""), /24/);
  assert.equal(
    await exists(join(GATEWAY_ROOT, "node_modules")),
    false,
    "lns-gateway/node_modules must not exist",
  );
});

test("no file in lns-gateway (or its transitive imports) imports any npm package", async () => {
  const seeds = await listJsFiles(GATEWAY_ROOT);
  assert.ok(seeds.length > 0);

  const visited = new Set();
  const queue = [...seeds];

  while (queue.length > 0) {
    const filePath = resolve(queue.shift());
    if (visited.has(filePath)) continue;
    visited.add(filePath);

    const src = await readFile(filePath, "utf-8");
    const specs = extractImportSpecifiers(src);
    for (const spec of specs) {
      if (spec.startsWith("node:")) continue;
      assert.ok(
        spec.startsWith("./") || spec.startsWith("../"),
        `Forbidden non-builtin package import "${spec}" in ${filePath}`,
      );
      const target = resolve(dirname(filePath), spec);
      assert.equal(
        await exists(target),
        true,
        `Relative import "${spec}" in ${filePath} does not exist`,
      );
      if (!visited.has(target)) {
        queue.push(target);
      }
    }
  }
});

test("vendor/pins.json passes SHA-256 and license verification (and catches tampering)", async () => {
  const realCheck = await verifyVendorPins(join(GATEWAY_ROOT, "vendor"));
  assert.equal(realCheck.ok, true);

  // Verify pin checker accepts a valid vendored file + license and rejects tampering / missing license / stray files
  const tmpVendor = await mkdtemp(join(tmpdir(), "lns-gw-vendor-"));
  try {
    const sampleBytes = Buffer.from("// audited dependency-free browser argon2id\n", "utf-8");
    const sampleHash = createHash("sha256").update(sampleBytes).digest("hex");

    await writeFile(join(tmpVendor, "argon2id.js"), sampleBytes);
    await writeFile(join(tmpVendor, "argon2id.LICENSE.txt"), "MIT License\n");
    await writeFile(
      join(tmpVendor, "pins.json"),
      JSON.stringify(
        {
          files: [
            {
              file: "argon2id.js",
              role: "argon2id",
              license: "argon2id.LICENSE.txt",
              sha256: sampleHash,
            },
          ],
        },
        null,
        2,
      ),
    );

    const okRes = await verifyVendorPins(tmpVendor);
    assert.equal(okRes.ok, true);
    assert.equal(okRes.count, 1);

    // Tampered bytes must fail SHA-256 pin check
    await writeFile(join(tmpVendor, "argon2id.js"), "// tampered\n");
    await assert.rejects(() => verifyVendorPins(tmpVendor), /SHA-256 pin mismatch/i);

    // Restore valid bytes, add an unpinned file -> must fail
    await writeFile(join(tmpVendor, "argon2id.js"), sampleBytes);
    await writeFile(join(tmpVendor, "extra.js"), "// unpinned\n");
    await assert.rejects(() => verifyVendorPins(tmpVendor), /unpinned file/i);
    await rm(join(tmpVendor, "extra.js"));

    // Missing license -> must fail
    await rm(join(tmpVendor, "argon2id.LICENSE.txt"));
    await assert.rejects(() => verifyVendorPins(tmpVendor));
  } finally {
    await rm(tmpVendor, { recursive: true, force: true });
  }
});
