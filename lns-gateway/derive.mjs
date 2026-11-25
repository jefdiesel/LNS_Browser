// LNS v5/v6 name derivation, AES-256-GCM sealing, SHA-256, binary codecs, and LEZ 0.4 resolver.
// Uses only Node 24+ built-in `node:crypto` (argon2, sha256, aes-256-gcm) and package-free helpers
// from `basecamp/qml/logic.mjs`. Zero npm dependencies.

import crypto from "node:crypto";
import {
  extractSiteInfo,
  isValidName,
  normalizeName,
  parseUrl,
} from "../basecamp/qml/logic.mjs";

const utf8 = new TextEncoder();

export const MIN_NODE_MAJOR = 24;

export const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const DERIVE_SALT = "logos-names/v5";
export const DERIVE_PARAMS = Object.freeze({
  t: 3,
  m: 65536,
  p: 1,
  dkLen: 32,
  version: 0x13,
});
export const ID_DOMAIN = "logos-names/v5/id";
export const KEY_DOMAIN = "logos-names/v5/key";
export const NAME_SEED_DOMAIN = "logos-names/v5/name/";
export const PAGE_SEED_DOMAIN = "logos-names/v5/page/";
export const ASSOCIATED_DATA = Object.freeze({
  record: "logos-names/v5/record",
  page: "logos-names/v5/page",
});
export const PDA_PREFIX_TEXT = "/LEE/v0.2/AccountId/PDA/";
export const PDA_PREFIX = pad32(PDA_PREFIX_TEXT);
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;
export const PROFILE_BLOCK = 256;
export const CID_PATTERN = /^[A-Za-z0-9]{8,128}$/;
export const GRACE_MS = 2_592_000_000;

export const DEFAULT_CONFIG = Object.freeze({
  sequencer: "https://lez.nameswallet.app/",
  registry: "6Yxj5k8AiuBSuMAYVQFGrYKjJGUSSaWWgoB9D9XXN3gA",
  storageApi: process.env.LOGOS_STORAGE_API || "",
  network: "lez-0.4-rc3",
});

// Cache Argon2id derivations in memory per process.
const deriveCache = new Map();

/**
 * Checks that the runtime is Node 24 or newer and provides built-in `crypto.argon2`.
 * Never falls back to npm packages.
 */
export function checkNodeVersion(versionString = process.versions.node, cryptoMod = crypto) {
  const raw = String(versionString || "").trim().replace(/^v/i, "");
  const major = Number.parseInt(raw.split(".")[0], 10);
  if (!Number.isInteger(major) || major < MIN_NODE_MAJOR) {
    return {
      ok: false,
      major: Number.isInteger(major) ? major : 0,
      version: raw || "unknown",
      message:
        `lns-gateway requires Node ${MIN_NODE_MAJOR} or newer (built-in node:crypto argon2). ` +
        `Found Node ${raw || "unknown"}. Upgrade Node; do not install npm dependencies.`,
    };
  }
  if (!cryptoMod || typeof cryptoMod.argon2 !== "function") {
    return {
      ok: false,
      major,
      version: raw,
      message:
        `lns-gateway requires Node ${MIN_NODE_MAJOR} or newer with built-in crypto.argon2 (Node 24.7+). ` +
        `Found Node ${raw} without crypto.argon2. Upgrade Node; do not install npm dependencies.`,
    };
  }
  return { ok: true, major, version: raw, message: "" };
}

export function assertSupportedNode(versionString = process.versions.node, cryptoMod = crypto) {
  const status = checkNodeVersion(versionString, cryptoMod);
  if (!status.ok) {
    throw new Error(status.message);
  }
  return status;
}

function pad32(text) {
  const bytes = new Uint8Array(32);
  bytes.set(utf8.encode(text));
  return bytes;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function sha256Bytes(bytes) {
  const digest = crypto.createHash("sha256").update(bytes).digest();
  return new Uint8Array(digest.buffer, digest.byteOffset, digest.byteLength);
}

export function sha256Hex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

export function base58Encode(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let text = "";
  while (value > 0n) {
    text = BASE58[Number(value % 58n)] + text;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    text = "1" + text;
  }
  return text;
}

export function base58Decode(text) {
  let value = 0n;
  for (const char of text) {
    const digit = BASE58.indexOf(char);
    if (digit < 0) throw new Error(`invalid base58 character: ${char}`);
    value = value * 58n + BigInt(digit);
  }
  const bytes = [];
  while (value > 0n) {
    bytes.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  for (const char of text) {
    if (char !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

function accountIdBytes(accountId) {
  const bytes = base58Decode(accountId);
  if (bytes.length !== 32) throw new Error(`account ID must be 32 bytes: ${accountId}`);
  return bytes;
}

const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function fromHex(text) {
  if (!/^([0-9a-f]{2})*$/i.test(text)) throw new Error(`invalid hex: ${text}`);
  return Uint8Array.from(text.match(/../g) ?? [], (pair) => parseInt(pair, 16));
}

export { isValidName, normalizeName };

export function isValidCid(cid) {
  return typeof cid === "string" && CID_PATTERN.test(cid);
}

/** Normalizes a site-relative path, collapsing traversal (`..`), preserving trailing `/`, and rejecting null bytes. */
export function normalizeSitePath(rawPath) {
  let clean = String(rawPath ?? "/").split(/[?#]/)[0];
  if (clean.includes("\0")) throw new Error("invalid path");
  const hadTrailingSlash = clean.endsWith("/");
  if (!clean.startsWith("/")) clean = "/" + clean;
  const parts = [];
  for (const seg of clean.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      if (parts.length > 0) parts.pop();
      continue;
    }
    parts.push(seg);
  }
  if (parts.length === 0) return "/";
  return "/" + parts.join("/") + (hadTrailingSlash ? "/" : "");
}

/** Parses an `lns://` or `cid://` URL and normalizes its path (reusing logic.mjs `parseUrl`). */
export function parseLnsUrl(raw) {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed) throw new Error("enter an LNS name (e.g. lns://jef) or CID (cid://...)");

  const withoutQueryFrag = trimmed.split(/[?#]/)[0];
  const parsed = parseUrl(withoutQueryFrag);
  if (!parsed.ok) {
    throw new Error(parsed.error || `invalid LNS URL: ${trimmed}`);
  }

  const path = normalizeSitePath(parsed.path);
  if (parsed.kind === "cid") {
    return {
      kind: "cid",
      cid: parsed.cid,
      path,
      canonical: `cid://${parsed.cid}${path === "/" ? "" : path}`,
    };
  }
  return {
    kind: "lns",
    name: parsed.name,
    path,
    canonical: `lns://${parsed.name}${path === "/" ? "" : path}`,
  };
}

/** Computes the domain-separated 32-byte LNS `id` and `key` from a 32-byte Argon2id master key. */
export function deriveFromMaster(master) {
  if (!(master instanceof Uint8Array) || master.length !== 32) {
    throw new Error("master key must be 32 bytes");
  }
  return {
    id: sha256Bytes(concat(utf8.encode(ID_DOMAIN), master)),
    key: sha256Bytes(concat(utf8.encode(KEY_DOMAIN), master)),
  };
}

function argon2idAsync(message, nonce) {
  assertSupportedNode();
  return new Promise((resolve, reject) => {
    crypto.argon2(
      "argon2id",
      {
        message,
        nonce,
        passes: DERIVE_PARAMS.t,
        memory: DERIVE_PARAMS.m,
        parallelism: DERIVE_PARAMS.p,
        tagLength: DERIVE_PARAMS.dkLen,
      },
      (err, derivedKey) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(new Uint8Array(derivedKey.buffer, derivedKey.byteOffset, derivedKey.byteLength));
      },
    );
  });
}

/** Derives `{ id, key }` for a bare LNS name using Node 24+ `node:crypto` Argon2id + SHA-256. */
export async function deriveName(name) {
  if (!isValidName(name)) throw new Error(`invalid name: ${name}`);
  const cached = deriveCache.get(name);
  if (cached) return cached;
  const master = await argon2idAsync(utf8.encode(name), utf8.encode(DERIVE_SALT));
  const derived = deriveFromMaster(master);
  deriveCache.set(name, derived);
  return derived;
}

function derivedAddress(program, domain, id) {
  if (!(id instanceof Uint8Array) || id.length !== 32) throw new Error("name ID must be 32 bytes");
  const seed = sha256Bytes(concat(utf8.encode(domain), id));
  return base58Encode(sha256Bytes(concat(PDA_PREFIX, accountIdBytes(program), seed)));
}

export function recordAddress(program, id) {
  return derivedAddress(program, NAME_SEED_DOMAIN, id);
}

export function pageAddress(program, id) {
  return derivedAddress(program, PAGE_SEED_DOMAIN, id);
}

/** Seals plaintext with AES-256-GCM using `node:crypto` (12-byte nonce || ciphertext || 16-byte tag). */
export function seal(key, plaintext, kind, nonce = null) {
  const associated = ASSOCIATED_DATA[kind];
  if (!associated) throw new Error(`unknown kind of sealed data: ${kind}`);
  const iv = nonce === null ? new Uint8Array(crypto.randomBytes(NONCE_LENGTH)) : new Uint8Array(nonce);
  if (iv.length !== NONCE_LENGTH) throw new Error(`nonce must be ${NONCE_LENGTH} bytes`);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(utf8.encode(associated));
  const ct1 = cipher.update(plaintext);
  const ct2 = cipher.final();
  const tag = cipher.getAuthTag();
  return concat(iv, ct1, ct2, tag);
}

/** Opens AES-256-GCM sealed bytes using `node:crypto`. Returns `Uint8Array` or `null` on failure. */
export function openSealed(key, sealed, kind) {
  const associated = ASSOCIATED_DATA[kind];
  if (!associated) throw new Error(`unknown kind of sealed data: ${kind}`);
  if (sealed.length < NONCE_LENGTH + TAG_LENGTH) return null;
  const iv = sealed.subarray(0, NONCE_LENGTH);
  const ciphertext = sealed.subarray(NONCE_LENGTH, sealed.length - TAG_LENGTH);
  const tag = sealed.subarray(sealed.length - TAG_LENGTH);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: TAG_LENGTH });
    decipher.setAAD(utf8.encode(associated));
    decipher.setAuthTag(tag);
    const pt1 = decipher.update(ciphertext);
    const pt2 = decipher.final();
    return concat(pt1, pt2);
  } catch {
    return null;
  }
}

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.offset = 0;
  }
  take(length) {
    if (this.offset + length > this.bytes.length) throw new Error("record is truncated");
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }
  u8() {
    return this.take(1)[0];
  }
  u32() {
    const [a, b, c, d] = this.take(4);
    return (a | (b << 8) | (c << 16) | (d << 24)) >>> 0;
  }
  u64() {
    const low = this.u32();
    const high = this.u32();
    return high * 2 ** 32 + low;
  }
  bool() {
    const value = this.u8();
    if (value > 1) throw new Error("not a boolean");
    return value === 1;
  }
  byteVec() {
    return this.take(this.u32());
  }
  string() {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.byteVec());
  }
  option(read) {
    return this.u8() === 0 ? null : read();
  }
}

const writeU32 = (value) => Uint8Array.of(value, value >>> 8, value >>> 16, value >>> 24);
const writeU64 = (value) => {
  const big = BigInt(value);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i += 1) out[i] = Number((big >> BigInt(i * 8)) & 0xffn);
  return out;
};
const writeByteVec = (bytes) => concat(writeU32(bytes.length), bytes);
const writeString = (text) => writeByteVec(utf8.encode(text));
const writeOption = (bytes) => (bytes === null ? Uint8Array.of(0) : concat(Uint8Array.of(1), bytes));

function fixed32(bytes, what) {
  if (bytes.length !== 32) throw new Error(`${what} must be 32 bytes`);
  return bytes;
}

export function decodeNameRecord(bytes) {
  const reader = new Reader(bytes);
  const version = reader.u8();
  return {
    version,
    ownerTag: toHex(reader.take(32)),
    expires: reader.u64(),
    sealed: reader.byteVec(),
    claimed: version >= 6 ? reader.bool() : false,
  };
}

export function encodeNameRecord({
  version = 6,
  ownerTag = new Uint8Array(32),
  expires = 0xffffffffffffffffn,
  sealed,
  claimed = false,
}) {
  const base = concat(
    Uint8Array.of(version),
    fixed32(ownerTag, "ownerTag"),
    writeU64(expires),
    writeByteVec(sealed),
  );
  return version >= 6 ? concat(base, Uint8Array.of(claimed ? 1 : 0)) : base;
}

export function decodePage(bytes) {
  const reader = new Reader(bytes);
  return { version: reader.u8(), sealed: reader.byteVec() };
}

export function encodePage(sealed, version = 1) {
  return concat(Uint8Array.of(version), writeByteVec(sealed));
}

export function decodeProfile(bytes) {
  const reader = new Reader(bytes);
  const profile = {
    name: reader.string(),
    account: reader.option(() => base58Encode(reader.take(32))),
    npk: reader.option(() => toHex(reader.take(32))),
    vpk: toHex(reader.byteVec()) || null,
    texts: {},
  };
  const count = reader.u32();
  for (let i = 0; i < count; i += 1) {
    const key = reader.string();
    profile.texts[key] = reader.string();
  }
  return profile;
}

export function encodeProfile({ name, account = null, npk = null, vpk = null, texts = {} }) {
  const entries = Object.entries(texts);
  const encoded = concat(
    writeString(name),
    writeOption(account === null ? null : accountIdBytes(account)),
    writeOption(npk === null ? null : fixed32(fromHex(npk), "npk")),
    writeByteVec(vpk === null ? new Uint8Array(0) : fromHex(vpk)),
    writeU32(entries.length),
    ...entries.flatMap(([k, v]) => [writeString(k), writeString(v)]),
  );
  const padded = new Uint8Array(Math.ceil(encoded.length / PROFILE_BLOCK) * PROFILE_BLOCK);
  padded.set(encoded);
  return padded;
}

export function decodePageContent(bytes) {
  const reader = new Reader(bytes);
  return { contentType: reader.string(), body: reader.byteVec() };
}

export function encodePageContent(contentType, bodyBytes) {
  return concat(writeString(contentType), writeByteVec(bodyBytes));
}

/** Reads `program`'s actor state on `accountId` (LEZ 0.4 `getAccountView`, with `shards` fallback). */
export async function readActorState(rpcUrl, program, accountId, fetchImpl = fetch) {
  const response = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getAccountView",
      params: [{ account_id: accountId, program_account_id: program }],
    }),
  });
  if (!response.ok) throw new Error(`sequencer returned HTTP ${response.status}`);
  const { result, error } = await response.json();
  if (error) throw new Error(`sequencer error: ${error.message}`);
  const data = result?.data;
  return Uint8Array.from(data?.actor_states?.[program] ?? data?.shards?.[program] ?? []);
}

function openAs(key, sealed, kind, decode) {
  if (sealed.length === 0) return null;
  const plaintext = openSealed(key, sealed, kind);
  if (plaintext === null) return null;
  try {
    return decode(plaintext);
  } catch {
    return null;
  }
}

async function readRecord(rpcUrl, program, id, now, fetchImpl) {
  const addr = recordAddress(program, id);
  const bytes = await readActorState(rpcUrl, program, addr, fetchImpl);
  if (bytes.length === 0) return { addr, record: null };
  const record = decodeNameRecord(bytes);
  if (now >= record.expires + GRACE_MS) return { addr, record: null };
  return { addr, record };
}

/** Resolves an LNS name on LEZ 0.4 and extracts its CID pointer metadata. */
export async function resolveName(
  rpcUrl,
  program,
  rawName,
  { now = Date.now(), fetchImpl = fetch } = {},
) {
  const name = normalizeName(rawName);
  if (!isValidName(name)) throw new Error(`invalid LNS name: ${rawName}`);
  const { id, key } = await deriveName(name);
  const { addr, record } = await readRecord(rpcUrl, program, id, now, fetchImpl);
  if (!record) return null;

  const expires = record.expires >= Number.MAX_SAFE_INTEGER ? null : record.expires;
  const held = {
    name,
    recordAddress: addr,
    version: record.version,
    expires,
    lapsed: expires !== null && expires <= now,
  };

  const profile = openAs(key, record.sealed, "record", decodeProfile);
  if (!profile || profile.name !== name) {
    return {
      ...held,
      account: null,
      payablePrivately: false,
      texts: {},
      cid: null,
      cidSha256: null,
      cidType: null,
    };
  }

  const texts = profile.texts ?? {};
  const site = extractSiteInfo({ name, texts });
  return {
    ...held,
    account: profile.account,
    payablePrivately: Boolean(profile.npk && profile.vpk),
    texts,
    cid: site.cid || null,
    cidSha256: site.sha256 || null,
    cidType: site.siteType || null,
  };
}

/** Resolves an LNS name's on-chain sealed page (`SetPage`). */
export async function resolveOnChainPage(
  rpcUrl,
  program,
  rawName,
  { now = Date.now(), fetchImpl = fetch } = {},
) {
  const name = normalizeName(rawName);
  if (!isValidName(name)) throw new Error(`invalid LNS name: ${rawName}`);
  const { id, key } = await deriveName(name);
  const { record } = await readRecord(rpcUrl, program, id, now, fetchImpl);
  if (!record) return null;
  const bytes = await readActorState(rpcUrl, program, pageAddress(program, id), fetchImpl);
  if (bytes.length === 0) return null;
  return openAs(key, decodePage(bytes).sealed, "page", decodePageContent);
}
