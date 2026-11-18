// Token generation and hashing (01-contracts.md section 1, 05-manager.md section 6).
// Token = prefix + base64url(32 random bytes) without padding (43 chars).
import { bytesToB64url, bytesToHex, sha256Hex, constantTimeEqual } from "../util/encoding";

export type TokenKind = "expe" | "expa" | "expi" | "expd" | "expn";

export const TOKEN_RE: Record<TokenKind, RegExp> = {
  expe: /^expe_[A-Za-z0-9_-]{43}$/,
  expa: /^expa_[A-Za-z0-9_-]{43}$/,
  expi: /^expi_[A-Za-z0-9_-]{43}$/,
  expd: /^expd_[A-Za-z0-9_-]{43}$/,
  expn: /^expn_[A-Za-z0-9_-]{43}$/,
};

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function newToken(kind: TokenKind): string {
  return `${kind}_${bytesToB64url(randomBytes(32))}`;
}

export function isToken(value: unknown, kind: TokenKind): value is string {
  return typeof value === "string" && TOKEN_RE[kind].test(value);
}

/** sha256 hex of the token string: the only form servers keep for enrol/agent/NOC tokens. */
export const tokenHash = (token: string): Promise<string> => sha256Hex(token);

export const hashesEqual = (a: string, b: string): boolean => constantTimeEqual(a, b);

/** 32 random bytes, standard base64 (the dashboard sso_secret format, 01-contracts.md section 9.3). */
export function newSsoSecret(): string {
  let s = "";
  for (const b of randomBytes(32)) s += String.fromCharCode(b);
  return btoa(s);
}

export function randomHex(n: number): string {
  return bytesToHex(randomBytes(n));
}
