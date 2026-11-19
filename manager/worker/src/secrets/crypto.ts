// AES-256-GCM at rest (05-manager.md section 6). EXP_MASTER_KEY = base64 of 32 bytes.
// Random 96-bit nonce per write. AAD binds the ciphertext to its identity so rows cannot be swapped.
import { ConfigError } from "../errors";
import { b64ToBytes, bytesToB64, fromUtf8, sha256Hex, utf8 } from "../util/encoding";

const keyCache = new Map<string, Promise<CryptoKey>>();

function parseKey(raw: string | undefined, name: string): { bytes: Uint8Array; text: string } {
  if (!raw || typeof raw !== "string") {
    throw new ConfigError("master_key_missing", `${name} is not set (wrangler secret put ${name})`);
  }
  let bytes: Uint8Array;
  try {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw.trim())) throw new Error("charset");
    bytes = b64ToBytes(raw.trim());
  } catch {
    throw new ConfigError("master_key_invalid", `${name} must be base64 of exactly 32 bytes`);
  }
  if (bytes.length !== 32) {
    throw new ConfigError("master_key_invalid", `${name} must be base64 of exactly 32 bytes`);
  }
  return { bytes, text: raw.trim() };
}

function importCached(text: string, bytes: Uint8Array): Promise<CryptoKey> {
  let p = keyCache.get(text);
  if (!p) {
    p = crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    keyCache.set(text, p);
    if (keyCache.size > 4) keyCache.delete(keyCache.keys().next().value as string);
  }
  return p;
}

/** Import EXP_MASTER_KEY; fails closed with a clear (secret-free) error when missing or malformed. */
export function masterKey(raw: string | undefined): Promise<CryptoKey> {
  const k = parseKey(raw, "EXP_MASTER_KEY");
  return importCached(k.text, k.bytes);
}

// ---- keyring: current + optional previous master key ------------------------------------------------------------
/** Public, non-secret identifier of a master key: first 16 hex of sha256("exp-key-id/v1|" + the base64 key text). */
export async function keyIdOf(rawKeyText: string): Promise<string> {
  return (await sha256Hex(`exp-key-id/v1|${rawKeyText.trim()}`)).slice(0, 16);
}

export interface RingKey {
  id: string;
  key: CryptoKey;
}

export interface KeyRing {
  current: RingKey;
  /** EXP_MASTER_KEY_PREVIOUS, only while a rotation is being re-encrypted */
  previous: RingKey | null;
}

export interface KeyEnv {
  EXP_MASTER_KEY?: string;
  EXP_MASTER_KEY_PREVIOUS?: string;
}

/** Build the keyring; fails closed (ConfigError) when the current key is missing/malformed or a configured previous key is malformed. */
export async function keyRing(env: KeyEnv): Promise<KeyRing> {
  const cur = parseKey(env.EXP_MASTER_KEY, "EXP_MASTER_KEY");
  const current: RingKey = { id: await keyIdOf(cur.text), key: await importCached(cur.text, cur.bytes) };
  let previous: RingKey | null = null;
  if (env.EXP_MASTER_KEY_PREVIOUS && env.EXP_MASTER_KEY_PREVIOUS.trim() !== "") {
    const prev = parseKey(env.EXP_MASTER_KEY_PREVIOUS, "EXP_MASTER_KEY_PREVIOUS");
    const id = await keyIdOf(prev.text);
    if (id !== current.id) previous = { id, key: await importCached(prev.text, prev.bytes) };
  }
  return { current, previous };
}

/**
 * Keys to try for a value stamped `keyId`. A known id selects exactly that key. Unknown id -> fail closed.
 * A missing id (legacy row, see migration 0003) means "the key current at migration time": current first, then the
 * previous key if one is configured. Nothing else is ever tried.
 */
export function candidateKeys(ring: KeyRing, keyId: string | null | undefined): RingKey[] {
  if (keyId === null || keyId === undefined || keyId === "") return ring.previous ? [ring.current, ring.previous] : [ring.current];
  if (keyId === ring.current.id) return [ring.current];
  if (ring.previous && keyId === ring.previous.id) return [ring.previous];
  throw new ConfigError(
    "unknown_key_id",
    `a stored value was sealed by master key ${keyId}, which is neither EXP_MASTER_KEY (${ring.current.id}) nor EXP_MASTER_KEY_PREVIOUS` +
      `${ring.previous ? ` (${ring.previous.id})` : " (not set)"}; set EXP_MASTER_KEY_PREVIOUS to that key`,
  );
}

/** Open with the key the value was sealed by; also reports the key that worked. */
export async function openWithRing(ring: KeyRing, sealed: Sealed, aad: string, keyId: string | null | undefined): Promise<{ plaintext: string; keyId: string }> {
  let last: unknown;
  for (const k of candidateKeys(ring, keyId)) {
    try {
      return { plaintext: await open(k.key, sealed, aad), keyId: k.id };
    } catch (e) {
      last = e;
    }
  }
  throw last;
}

export interface Sealed {
  nonce: string; // base64, 12 bytes
  ciphertext: string; // base64 (includes the GCM tag)
}

export async function seal(key: CryptoKey, plaintext: string, aad: string): Promise<Sealed> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: utf8(aad) },
    key,
    utf8(plaintext),
  );
  return { nonce: bytesToB64(nonce), ciphertext: bytesToB64(new Uint8Array(ct)) };
}

export async function open(key: CryptoKey, sealed: Sealed, aad: string): Promise<string> {
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(sealed.nonce), additionalData: utf8(aad) },
      key,
      b64ToBytes(sealed.ciphertext),
    );
    return fromUtf8(new Uint8Array(pt));
  } catch {
    throw new ConfigError("decrypt_failed", "stored secret could not be decrypted (wrong EXP_MASTER_KEY or tampered row)");
  }
}

/** AAD for a row in `secrets` (05-manager.md section 6): secret_id|kind|version. */
export const secretAad = (secretId: string, kind: string, version: number): string => `${secretId}|${kind}|${version}`;

// ---- encrypted credential values inside desired_docs ----------------------------------------
// enc2:<key_id>:<nonce>:<ciphertext>  (records the sealing key). enc1:<nonce>:<ciphertext> is the pre-rotation format:
// no key id, treated as legacy (see candidateKeys). New writes are always enc2 under the current key.
const ENC_PREFIX = "enc2:";
const ENC1_PREFIX = "enc1:";

export const isEncryptedCred = (v: unknown): v is string => typeof v === "string" && (v.startsWith(ENC_PREFIX) || v.startsWith(ENC1_PREFIX));

export async function sealCred(ring: KeyRing, value: string, aad: string): Promise<string> {
  const s = await seal(ring.current.key, value, aad);
  return `${ENC_PREFIX}${ring.current.id}:${s.nonce}:${s.ciphertext}`;
}

/** Key id recorded in the envelope (null for the legacy enc1 format). */
export function credKeyId(value: string): string | null {
  if (!value.startsWith(ENC_PREFIX)) return null;
  const i = value.indexOf(":", ENC_PREFIX.length);
  return i < 0 ? null : value.slice(ENC_PREFIX.length, i);
}

export async function openCred(ring: KeyRing, value: string, aad: string): Promise<string> {
  return (await openCredWithKey(ring, value, aad)).plaintext;
}

export async function openCredWithKey(ring: KeyRing, value: string, aad: string): Promise<{ plaintext: string; keyId: string }> {
  let keyId: string | null = null;
  let rest: string;
  if (value.startsWith(ENC_PREFIX)) {
    const r = value.slice(ENC_PREFIX.length);
    const i = r.indexOf(":");
    if (i < 0) throw new ConfigError("decrypt_failed", "malformed stored credential");
    keyId = r.slice(0, i);
    rest = r.slice(i + 1);
  } else {
    rest = value.slice(ENC1_PREFIX.length);
  }
  const i = rest.indexOf(":");
  if (i < 0) throw new ConfigError("decrypt_failed", "malformed stored credential");
  return openWithRing(ring, { nonce: rest.slice(0, i), ciphertext: rest.slice(i + 1) }, aad, keyId);
}

/** AAD for a credential inside a stored desired doc. */
export const credAad = (hostId: string, componentId: string, name: string): string =>
  `desired|${hostId}|${componentId}|${name}`;
