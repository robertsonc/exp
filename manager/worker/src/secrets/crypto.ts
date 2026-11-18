// AES-256-GCM at rest (05-manager.md section 6). EXP_MASTER_KEY = base64 of 32 bytes.
// Random 96-bit nonce per write. AAD binds the ciphertext to its identity so rows cannot be swapped.
import { ConfigError } from "../errors";
import { b64ToBytes, bytesToB64, fromUtf8, utf8 } from "../util/encoding";

const keyCache = new Map<string, Promise<CryptoKey>>();

/** Import EXP_MASTER_KEY; fails closed with a clear (secret-free) error when missing or malformed. */
export function masterKey(raw: string | undefined): Promise<CryptoKey> {
  if (!raw || typeof raw !== "string") {
    throw new ConfigError("master_key_missing", "EXP_MASTER_KEY is not set (wrangler secret put EXP_MASTER_KEY)");
  }
  let bytes: Uint8Array;
  try {
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw.trim())) throw new Error("charset");
    bytes = b64ToBytes(raw.trim());
  } catch {
    throw new ConfigError("master_key_invalid", "EXP_MASTER_KEY must be base64 of exactly 32 bytes");
  }
  if (bytes.length !== 32) {
    throw new ConfigError("master_key_invalid", "EXP_MASTER_KEY must be base64 of exactly 32 bytes");
  }
  const id = raw.trim();
  let p = keyCache.get(id);
  if (!p) {
    p = crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    keyCache.set(id, p);
    if (keyCache.size > 4) keyCache.delete(keyCache.keys().next().value as string);
  }
  return p;
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
const ENC_PREFIX = "enc1:";

export const isEncryptedCred = (v: unknown): v is string => typeof v === "string" && v.startsWith(ENC_PREFIX);

export async function sealCred(key: CryptoKey, value: string, aad: string): Promise<string> {
  const s = await seal(key, value, aad);
  return `${ENC_PREFIX}${s.nonce}:${s.ciphertext}`;
}

export async function openCred(key: CryptoKey, value: string, aad: string): Promise<string> {
  const rest = value.slice(ENC_PREFIX.length);
  const i = rest.indexOf(":");
  if (i < 0) throw new ConfigError("decrypt_failed", "malformed stored credential");
  return open(key, { nonce: rest.slice(0, i), ciphertext: rest.slice(i + 1) }, aad);
}

/** AAD for a credential inside a stored desired doc. */
export const credAad = (hostId: string, componentId: string, name: string): string =>
  `desired|${hostId}|${componentId}|${name}`;
