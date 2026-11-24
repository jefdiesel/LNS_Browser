// LNS (Logos Names) v5/v6 resolver and URL parser for LEZ 0.4 rc3 (with 0.3 fallback).
// Uses Argon2id (logos-names/v5) + AES-GCM sealed records matching logos-names-rc3/resolver/names.js.

import { argon2idAsync } from "@noble/hashes/argon2.js";

const utf8 = new TextEncoder();

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const PDA_PREFIX = pad32("/LEE/v0.2/AccountId/PDA/");
const DERIVE_SALT = "logos-names/v5";
const DERIVE_PARAMS = { t: 3, m: 65536, p: 1, dkLen: 32, version: 0x13, asyncTick: 50 };
const ID_DOMAIN = "logos-names/v5/id";
const KEY_DOMAIN = "logos-names/v5/key";
const NAME_SEED_DOMAIN = "logos-names/v5/name/";
const PAGE_SEED_DOMAIN = "logos-names/v5/page/";
const ASSOCIATED_DATA = { record: "logos-names/v5/record", page: "logos-names/v5/page" };
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const PROFILE_BLOCK = 256;
const NAME_PATTERN = /^(?!-)[a-z0-9-]{1,32}(?<!-)$/;
const CID_PATTERN = /^[A-Za-z0-9]{8,128}$/;

export const GRACE_MS = 2_592_000_000;

export const DEFAULT_CONFIG = Object.freeze({
  sequencer: "https://lez.nameswallet.app/",
  registry: "6Yxj5k8AiuBSuMAYVQFGrYKjJGUSSaWWgoB9D9XXN3gA",
  // Never default to port 8080 (Logos Blockchain node's port); user picks their real Logos Storage URL.
  storageApi: process.env.LOGOS_STORAGE_API || "",
  network: "lez-0.4-rc3",
});

// Cache Argon2id derivations in memory so browsing multiple assets on the same name is instant.
const deriveCache = new Map();

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

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
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

export function normalizeName(input) {
  const lowered = String(input)
    .trim()
    .replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  let bare = lowered.startsWith("lns://")
    ? lowered.slice(6)
    : lowered.startsWith("lns:")
      ? lowered.slice(4)
      : lowered;
  if (bare.startsWith("@")) bare = bare.slice(1);
  if (bare.endsWith(".lez")) bare = bare.slice(0, -4);
  return bare;
}

export function isValidName(name) {
  return typeof name === "string" && NAME_PATTERN.test(name);
}

export function isValidCid(cid) {
  return typeof cid === "string" && CID_PATTERN.test(cid);
}

/**
 * Parses an LNS or CID URL typed into the browser address bar.
 * Accepts:
 *   - `lns://jef`
 *   - `lns://jef/about.html?x=1#top`
 *   - `jef.lez/about.html`
 *   - `jef` or `@jef`
 *   - `cid://zDvZRwzm...`
 *
 * Returns `{ kind: "lns", name, path, canonical }` or `{ kind: "cid", cid, path, canonical }`.
 */
export function parseLnsUrl(raw) {
  const trimmed = String(raw ?? "").trim();
  if (!trimmed) throw new Error("enter an LNS name (e.g. lns://jef) or CID (cid://...)");

  if (/^cid:\/\//i.test(trimmed)) {
    const rest = trimmed.slice(6);
    const slash = rest.indexOf("/");
    const cid = slash === -1 ? rest : rest.slice(0, slash);
    const rawPath = slash === -1 ? "/" : rest.slice(slash);
    if (!isValidCid(cid)) throw new Error(`invalid CID: ${cid}`);
    const path = normalizeSitePath(rawPath);
    return { kind: "cid", cid, path, canonical: `cid://${cid}${path === "/" ? "" : path}` };
  }

  let body = trimmed;
  if (/^lns:\/\//i.test(body)) body = body.slice(6);
  else if (/^lns:/i.test(body)) body = body.slice(4);
  if (body.startsWith("@")) body = body.slice(1);

  // Split host/name from path, query, and fragment
  const match = body.match(/^([^/?#]+)(.*)$/);
  if (!match) throw new Error(`invalid LNS URL: ${trimmed}`);
  const host = match[1];
  const tail = match[2] || "/";
  const name = normalizeName(host);
  if (!isValidName(name)) {
    throw new Error(`invalid LNS name: "${host}" (use 1-32 lowercase letters, digits, or hyphens)`);
  }

  // Strip query/fragment from the path resolved against the site manifest
  const pathOnly = tail.split(/[?#]/)[0] || "/";
  const path = normalizeSitePath(pathOnly);
  return {
    kind: "lns",
    name,
    path,
    canonical: `lns://${name}${path === "/" ? "" : path}`,
  };
}

/** Normalizes a site-relative path, rejecting traversal (`..`) and null bytes. */
export function normalizeSitePath(rawPath) {
  let clean = String(rawPath ?? "/").split(/[?#]/)[0];
  if (clean.includes("\0")) throw new Error("invalid path");
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
  return "/" + parts.join("/");
}

export async function deriveName(name) {
  if (!isValidName(name)) throw new Error(`invalid name: ${name}`);
  const cached = deriveCache.get(name);
  if (cached) return cached;
  const master = await argon2idAsync(utf8.encode(name), utf8.encode(DERIVE_SALT), DERIVE_PARAMS);
  const derived = {
    id: await sha256(concat(utf8.encode(ID_DOMAIN), master)),
    key: await sha256(concat(utf8.encode(KEY_DOMAIN), master)),
  };
  deriveCache.set(name, derived);
  return derived;
}

async function derivedAddress(program, domain, id) {
  if (!(id instanceof Uint8Array) || id.length !== 32) throw new Error("name ID must be 32 bytes");
  const seed = await sha256(concat(utf8.encode(domain), id));
  return base58Encode(await sha256(concat(PDA_PREFIX, accountIdBytes(program), seed)));
}

export function recordAddress(program, id) {
  return derivedAddress(program, NAME_SEED_DOMAIN, id);
}

export function pageAddress(program, id) {
  return derivedAddress(program, PAGE_SEED_DOMAIN, id);
}

function sealingKey(key, usage) {
  return crypto.subtle.importKey("raw", key, "AES-GCM", false, [usage]);
}

function sealingParams(nonce, kind) {
  const associated = ASSOCIATED_DATA[kind];
  if (!associated) throw new Error(`unknown kind of sealed data: ${kind}`);
  return { name: "AES-GCM", iv: nonce, additionalData: utf8.encode(associated) };
}

export async function seal(key, plaintext, kind, nonce = null) {
  nonce ??= crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  if (nonce.length !== NONCE_LENGTH) throw new Error(`nonce must be ${NONCE_LENGTH} bytes`);
  const params = sealingParams(nonce, kind);
  const sealed = await crypto.subtle.encrypt(params, await sealingKey(key, "encrypt"), plaintext);
  return concat(nonce, new Uint8Array(sealed));
}

export async function openSealed(key, sealed, kind) {
  if (sealed.length < NONCE_LENGTH + TAG_LENGTH) return null;
  const params = sealingParams(sealed.subarray(0, NONCE_LENGTH), kind);
  try {
    const opening = await sealingKey(key, "decrypt");
    const ciphertext = sealed.subarray(NONCE_LENGTH);
    return new Uint8Array(await crypto.subtle.decrypt(params, opening, ciphertext));
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

export function encodeNameRecord({ version = 6, ownerTag = new Uint8Array(32), expires = 0xffffffffffffffffn, sealed, claimed = false }) {
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

async function openAs(key, sealed, kind, decode) {
  if (sealed.length === 0) return null;
  const plaintext = await openSealed(key, sealed, kind);
  if (plaintext === null) return null;
  try {
    return decode(plaintext);
  } catch {
    return null;
  }
}

async function readRecord(rpcUrl, program, id, now, fetchImpl) {
  const addr = await recordAddress(program, id);
  const bytes = await readActorState(rpcUrl, program, addr, fetchImpl);
  if (bytes.length === 0) return { addr, record: null };
  const record = decodeNameRecord(bytes);
  if (now >= record.expires + GRACE_MS) return { addr, record: null };
  return { addr, record };
}

/**
 * Resolves an LNS name on-chain and returns its profile, CID pointer metadata,
 * and optional on-chain fallback page info.
 */
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

  const profile = await openAs(key, record.sealed, "record", decodeProfile);
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
  const rawCid =
    typeof texts.cid === "string"
      ? texts.cid.trim().replace(/^cid\s*(?:=|:\/\/|:)\s*/i, "")
      : "";
  const cid = isValidCid(rawCid) ? rawCid : null;
  const cidSha256 =
    typeof texts["cid.sha256"] === "string" && /^[0-9a-f]{64}$/i.test(texts["cid.sha256"])
      ? texts["cid.sha256"].toLowerCase()
      : null;
  const cidType = typeof texts["cid.type"] === "string" ? texts["cid.type"] : null;

  return {
    ...held,
    account: profile.account,
    payablePrivately: Boolean(profile.npk && profile.vpk),
    texts,
    cid,
    cidSha256,
    cidType,
  };
}

/** Resolves an LNS name's on-chain sealed page (fallback when a name has no `cid` set). */
export async function resolveOnChainPage(
  rpcUrl,
  program,
  rawName,
  { now = Date.now(), fetchImpl = fetch } = {},
) {
  const name = normalizeName(rawName);
  const { id, key } = await deriveName(name);
  const { record } = await readRecord(rpcUrl, program, id, now, fetchImpl);
  if (!record) return null;
  const bytes = await readActorState(rpcUrl, program, await pageAddress(program, id), fetchImpl);
  if (bytes.length === 0) return null;
  return openAs(key, decodePage(bytes).sealed, "page", decodePageContent);
}
