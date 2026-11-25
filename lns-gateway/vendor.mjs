// Verifies SHA-256 pins and license files for any vendored browser crypto files.
// Policy: browser code uses WebCrypto; Argon2id comes from ONE vendored, audited,
// dependency-free file with its license and a SHA-256 pin checked by tests. No npm.

import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join, resolve, sep } from "node:path";

const SHA256_RE = /^[0-9a-f]{64}$/;

function safeVendorPath(vendorDir, relFile) {
  if (typeof relFile !== "string" || !relFile || relFile.includes("\0") || relFile.startsWith("/")) {
    throw new Error(`invalid vendor path: ${JSON.stringify(relFile)}`);
  }
  const root = resolve(vendorDir);
  const full = resolve(root, relFile);
  if (!full.startsWith(root + sep)) {
    throw new Error(`vendor path escapes vendor directory: ${relFile}`);
  }
  return full;
}

/**
 * Verifies `vendor/pins.json` and every file inside `vendorDir`.
 * Fails if any file is unpinned, if a license file is missing, if more than one
 * Argon2id file is vendored, or if any file's SHA-256 does not match its pin.
 */
export async function verifyVendorPins(vendorDir) {
  const pinsPath = join(vendorDir, "pins.json");
  const raw = await readFile(pinsPath, "utf-8");
  const manifest = JSON.parse(raw);
  if (!manifest || !Array.isArray(manifest.files)) {
    throw new Error("vendor/pins.json must contain a files array");
  }

  const expectedFiles = new Set(["pins.json"]);
  let argon2Count = 0;

  for (const entry of manifest.files) {
    if (!entry || typeof entry !== "object") {
      throw new Error("invalid entry in vendor/pins.json");
    }
    if (typeof entry.file !== "string" || !entry.file) {
      throw new Error("vendor pin entry is missing file");
    }
    if (typeof entry.license !== "string" || !entry.license) {
      throw new Error(`vendor pin for ${entry.file} is missing license`);
    }
    const expectedHash = String(entry.sha256 || "").toLowerCase();
    if (!SHA256_RE.test(expectedHash)) {
      throw new Error(`vendor pin for ${entry.file} has invalid sha256`);
    }
    if (entry.role === "argon2id") {
      argon2Count += 1;
      if (argon2Count > 1) {
        throw new Error("only ONE vendored Argon2id file is allowed");
      }
    }

    const filePath = safeVendorPath(vendorDir, entry.file);
    const licensePath = safeVendorPath(vendorDir, entry.license);
    const fileBytes = await readFile(filePath);
    const licenseText = (await readFile(licensePath, "utf-8")).trim();
    if (!licenseText) {
      throw new Error(`vendor license file is empty: ${entry.license}`);
    }

    const actualHash = createHash("sha256").update(fileBytes).digest("hex");
    if (actualHash !== expectedHash) {
      throw new Error(
        `SHA-256 pin mismatch for vendor/${entry.file}: expected ${expectedHash}, got ${actualHash}`,
      );
    }

    expectedFiles.add(entry.file);
    expectedFiles.add(entry.license);
  }

  const entries = await readdir(vendorDir, { withFileTypes: true });
  for (const item of entries) {
    if (item.isDirectory()) {
      throw new Error(`unexpected subdirectory in vendor/: ${item.name}`);
    }
    if (!expectedFiles.has(item.name)) {
      throw new Error(`unpinned file in vendor/: ${item.name}`);
    }
  }

  return { ok: true, count: manifest.files.length };
}
