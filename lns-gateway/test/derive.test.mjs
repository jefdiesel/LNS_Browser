import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ASSOCIATED_DATA,
  assertSupportedNode,
  base58Decode,
  base58Encode,
  checkNodeVersion,
  decodeNameRecord,
  decodePage,
  decodePageContent,
  decodeProfile,
  DEFAULT_CONFIG,
  DERIVE_PARAMS,
  DERIVE_SALT,
  deriveFromMaster,
  deriveName,
  encodeNameRecord,
  encodePage,
  encodePageContent,
  encodeProfile,
  GRACE_MS,
  ID_DOMAIN,
  KEY_DOMAIN,
  MIN_NODE_MAJOR,
  NAME_SEED_DOMAIN,
  NONCE_LENGTH,
  openSealed,
  PAGE_SEED_DOMAIN,
  pageAddress,
  parseLnsUrl,
  PDA_PREFIX,
  PDA_PREFIX_TEXT,
  PROFILE_BLOCK,
  recordAddress,
  seal,
  sha256Hex,
  TAG_LENGTH,
} from "../derive.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const LNS_JS_PATH = join(__dirname, "..", "..", "src", "lns.js");
const utf8 = new TextEncoder();

function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

test("checkNodeVersion refuses below Node 24 and accepts Node 24+ with crypto.argon2", () => {
  assert.equal(MIN_NODE_MAJOR, 24);

  const node22 = checkNodeVersion("22.14.0", {});
  assert.equal(node22.ok, false);
  assert.match(node22.message, /Node 24 or newer/i);
  assert.match(node22.message, /22\.14\.0/);

  const node20 = checkNodeVersion("20.11.1", {});
  assert.equal(node20.ok, false);
  assert.match(node20.message, /Node 24 or newer/i);

  const node24NoArgon2 = checkNodeVersion("24.0.0", {});
  assert.equal(node24NoArgon2.ok, false);
  assert.match(node24NoArgon2.message, /crypto\.argon2/i);

  const fakeCrypto = { argon2() {}, argon2Sync() {} };
  assert.equal(checkNodeVersion("24.7.0", fakeCrypto).ok, true);
  assert.equal(checkNodeVersion("25.1.0", fakeCrypto).ok, true);

  assert.throws(() => assertSupportedNode("22.14.0", {}), /Node 24 or newer/i);
});

test("derive.mjs constants match lns-browser/src/lns.js verbatim (without importing lns.js)", async () => {
  const lnsSource = await readFile(LNS_JS_PATH, "utf-8");

  assert.ok(lnsSource.includes(`DERIVE_SALT = "${DERIVE_SALT}"`));
  assert.ok(lnsSource.includes(`t: ${DERIVE_PARAMS.t}`));
  assert.ok(lnsSource.includes(`m: ${DERIVE_PARAMS.m}`));
  assert.ok(lnsSource.includes(`p: ${DERIVE_PARAMS.p}`));
  assert.ok(lnsSource.includes(`dkLen: ${DERIVE_PARAMS.dkLen}`));
  assert.ok(lnsSource.includes(`version: 0x${DERIVE_PARAMS.version.toString(16)}`));
  assert.ok(lnsSource.includes(`ID_DOMAIN = "${ID_DOMAIN}"`));
  assert.ok(lnsSource.includes(`KEY_DOMAIN = "${KEY_DOMAIN}"`));
  assert.ok(lnsSource.includes(`NAME_SEED_DOMAIN = "${NAME_SEED_DOMAIN}"`));
  assert.ok(lnsSource.includes(`PAGE_SEED_DOMAIN = "${PAGE_SEED_DOMAIN}"`));
  assert.ok(lnsSource.includes(`record: "${ASSOCIATED_DATA.record}"`));
  assert.ok(lnsSource.includes(`page: "${ASSOCIATED_DATA.page}"`));
  assert.ok(lnsSource.includes(`pad32("${PDA_PREFIX_TEXT}")`));
  assert.ok(lnsSource.includes(`NONCE_LENGTH = ${NONCE_LENGTH}`));
  assert.ok(lnsSource.includes(`TAG_LENGTH = ${TAG_LENGTH}`));
  assert.ok(lnsSource.includes(`PROFILE_BLOCK = ${PROFILE_BLOCK}`));
  assert.ok(lnsSource.includes(`GRACE_MS = 2_592_000_000`));
  assert.equal(GRACE_MS, 2_592_000_000);
  assert.ok(lnsSource.includes(`registry: "${DEFAULT_CONFIG.registry}"`));
});

test("known vectors from lns-browser tests match derive.mjs", () => {
  // Known SHA-256 vector from lns-browser/basecamp/logic.test.mjs
  assert.equal(
    sha256Hex(utf8.encode("hello")),
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
  );

  // Known URL vectors from lns-browser/test/lns-browser.test.mjs
  assert.deepEqual(parseLnsUrl("lns://Jef/docs/../about.html?x=1#top"), {
    kind: "lns",
    name: "jef",
    path: "/about.html",
    canonical: "lns://jef/about.html",
  });
  assert.deepEqual(parseLnsUrl("cid://zDvZRwzm8K4nJ2a7q9WTqN1"), {
    kind: "cid",
    cid: "zDvZRwzm8K4nJ2a7q9WTqN1",
    path: "/",
    canonical: "cid://zDvZRwzm8K4nJ2a7q9WTqN1",
  });
  assert.throws(() => parseLnsUrl("not a valid name!"));
});

test("SHA-256, PDA address derivation, and AES-256-GCM match lns.js WebCrypto byte-for-byte", async () => {
  const master = Uint8Array.from({ length: 32 }, (_, i) => i);
  const { id, key } = deriveFromMaster(master);

  // Cross-check domain-separated SHA-256 against WebCrypto (exact lns.js formula)
  const expectedId = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", concatBytes(utf8.encode(ID_DOMAIN), master)),
  );
  const expectedKey = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", concatBytes(utf8.encode(KEY_DOMAIN), master)),
  );
  assert.deepEqual(id, expectedId);
  assert.deepEqual(key, expectedKey);

  // Cross-check recordAddress and pageAddress against WebCrypto PDA derivation
  const programBytes = base58Decode(DEFAULT_CONFIG.registry);
  const recSeed = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", concatBytes(utf8.encode(NAME_SEED_DOMAIN), id)),
  );
  const expectedRecAddr = base58Encode(
    new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", concatBytes(PDA_PREFIX, programBytes, recSeed)),
    ),
  );
  assert.equal(recordAddress(DEFAULT_CONFIG.registry, id), expectedRecAddr);

  const pageSeed = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", concatBytes(utf8.encode(PAGE_SEED_DOMAIN), id)),
  );
  const expectedPageAddr = base58Encode(
    new Uint8Array(
      await globalThis.crypto.subtle.digest("SHA-256", concatBytes(PDA_PREFIX, programBytes, pageSeed)),
    ),
  );
  assert.equal(pageAddress(DEFAULT_CONFIG.registry, id), expectedPageAddr);

  // Cross-check AES-256-GCM seal / openSealed against WebCrypto crypto.subtle (exact lns.js formula)
  const nonce = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  const webKey = await globalThis.crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);

  for (const kind of ["record", "page"]) {
    const plaintext =
      kind === "record"
        ? encodeProfile({ name: "demo", texts: { cid: "zDvMockCid0001", "cid.type": "single" } })
        : encodePageContent("text/html; charset=utf-8", utf8.encode("<h1>Hello</h1>"));

    const webEncrypted = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: utf8.encode(ASSOCIATED_DATA[kind]) },
        webKey,
        plaintext,
      ),
    );
    const expectedSealed = concatBytes(nonce, webEncrypted);
    const nodeSealed = seal(key, plaintext, kind, nonce);

    assert.deepEqual(nodeSealed, expectedSealed);
    assert.deepEqual(openSealed(key, expectedSealed, kind), plaintext);
  }

  // Tampering, wrong kind/AAD, wrong key, and truncation must fail closed (return null)
  const sampleSealed = seal(key, utf8.encode("secret"), "record", nonce);
  assert.equal(openSealed(key, sampleSealed, "page"), null);
  const wrongKey = new Uint8Array(key);
  wrongKey[0] ^= 0xff;
  assert.equal(openSealed(wrongKey, sampleSealed, "record"), null);
  const tampered = new Uint8Array(sampleSealed);
  tampered[tampered.length - 1] ^= 0x01;
  assert.equal(openSealed(key, tampered, "record"), null);
  assert.equal(openSealed(key, new Uint8Array(10), "record"), null);
});

test("deriveName matches Node 24 node:crypto argon2id with lns.js parameters and round-trips records", async () => {
  const derivedDemo = await deriveName("demo");
  const derivedJef = await deriveName("jef");

  // Independently derive using crypto.argon2Sync with exact lns.js parameters
  const syncMaster = crypto.argon2Sync("argon2id", {
    message: utf8.encode("demo"),
    nonce: utf8.encode(DERIVE_SALT),
    passes: DERIVE_PARAMS.t,
    memory: DERIVE_PARAMS.m,
    parallelism: DERIVE_PARAMS.p,
    tagLength: DERIVE_PARAMS.dkLen,
  });
  const expectedDemo = deriveFromMaster(
    new Uint8Array(syncMaster.buffer, syncMaster.byteOffset, syncMaster.byteLength),
  );

  assert.equal(derivedDemo.id.length, 32);
  assert.equal(derivedDemo.key.length, 32);
  assert.deepEqual(derivedDemo.id, expectedDemo.id);
  assert.deepEqual(derivedDemo.key, expectedDemo.key);

  // Cached second call returns identical values; distinct names diverge
  const cachedDemo = await deriveName("demo");
  assert.deepEqual(cachedDemo.id, derivedDemo.id);
  assert.notDeepEqual(derivedDemo.id, derivedJef.id);
  assert.notDeepEqual(derivedDemo.key, derivedJef.key);

  // Derived addresses decode to 32-byte LEZ account IDs
  const recAddr = recordAddress(DEFAULT_CONFIG.registry, derivedDemo.id);
  const pgAddr = pageAddress(DEFAULT_CONFIG.registry, derivedDemo.id);
  assert.equal(base58Decode(recAddr).length, 32);
  assert.equal(base58Decode(pgAddr).length, 32);
  assert.notEqual(recAddr, pgAddr);

  // Full binary record and page codec round-trip
  const profBytes = encodeProfile({ name: "demo", texts: { display: "Demo" } });
  const sealedRec = seal(derivedDemo.key, profBytes, "record");
  const decodedRec = decodeNameRecord(encodeNameRecord({ version: 6, sealed: sealedRec }));
  assert.equal(decodedRec.version, 6);
  const openedProf = decodeProfile(openSealed(derivedDemo.key, decodedRec.sealed, "record"));
  assert.equal(openedProf.name, "demo");
  assert.equal(openedProf.texts.display, "Demo");

  const pagePlain = encodePageContent("text/html; charset=utf-8", utf8.encode("<p>Hi</p>"));
  const decodedPage = decodePage(encodePage(seal(derivedDemo.key, pagePlain, "page")));
  const openedPage = decodePageContent(openSealed(derivedDemo.key, decodedPage.sealed, "page"));
  assert.equal(openedPage.contentType, "text/html; charset=utf-8");
  assert.equal(new TextDecoder().decode(openedPage.body), "<p>Hi</p>");
});
