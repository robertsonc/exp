// Dashboard local-user passwords are hashed here, in the browser, with WebCrypto; only the resulting string is ever
// sent to the manager (05-manager.md section 6). Format, as the dashboard verifier expects it
// (01-contracts.md section 9.3, dashboard/exp_dashboard/auth.py): pbkdf2_sha256$<iterations>$<salt b64>$<hash b64>
// with standard padded base64, a 16-byte random salt and a 32-byte derived key.

export const PBKDF2_ITERATIONS = 600_000;
export const SALT_BYTES = 16;
export const KEY_BYTES = 32;
export const MIN_PASSWORD_CHARS = 10;
export const MAX_PASSWORD_CHARS = 256;

export function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export interface CryptoLike {
  subtle: SubtleCrypto;
  getRandomValues<T extends ArrayBufferView>(array: T): T;
}

export function passwordProblem(pw: string): string | null {
  if (pw.length < MIN_PASSWORD_CHARS) return `Use at least ${MIN_PASSWORD_CHARS} characters.`;
  if (pw.length > MAX_PASSWORD_CHARS) return `Use at most ${MAX_PASSWORD_CHARS} characters.`;
  return null;
}

/** `salt` is injectable for tests only; production always draws 16 random bytes. */
export async function hashPassword(password: string, c: CryptoLike = globalThis.crypto, salt?: Uint8Array): Promise<string> {
  const s: Uint8Array<ArrayBuffer> = salt ? new Uint8Array(salt) : c.getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await c.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await c.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: s, iterations: PBKDF2_ITERATIONS }, key, KEY_BYTES * 8);
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${toBase64(s)}$${toBase64(new Uint8Array(bits))}`;
}
