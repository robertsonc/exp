import { pbkdf2Sync, webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { PBKDF2_ITERATIONS, hashPassword, passwordProblem, toBase64 } from '../src/lib/pbkdf2';

const crypto = webcrypto as unknown as Parameters<typeof hashPassword>[1];
// The pattern the admin API enforces on DashboardUserCreate.hash (admin.yaml).
const API_PATTERN = /^pbkdf2_sha256\$600000\$[A-Za-z0-9+/=_-]+\$[A-Za-z0-9+/=_-]+$/;

describe('browser password hashing', () => {
  it('produces exactly pbkdf2_sha256$600000$<salt>$<hash> that the dashboard verifier can check', async () => {
    const salt = new Uint8Array(16).map((_, i) => i * 7 + 1);
    const out = await hashPassword('correct horse battery', crypto, salt);
    const [scheme, iters, saltB64, hashB64] = out.split('$');
    expect(scheme).toBe('pbkdf2_sha256');
    expect(Number(iters)).toBe(600_000);
    expect(PBKDF2_ITERATIONS).toBe(600_000);
    expect(out).toMatch(API_PATTERN);
    // standard padded base64 of a 16-byte salt and a 32-byte key, as hashlib.pbkdf2_hmac in dashboard/auth.py produces
    expect(saltB64).toBe(Buffer.from(salt).toString('base64'));
    expect(Buffer.from(saltB64 ?? '', 'base64')).toHaveLength(16);
    expect(Buffer.from(hashB64 ?? '', 'base64')).toHaveLength(32);
    const expected = pbkdf2Sync('correct horse battery', Buffer.from(salt), 600_000, 32, 'sha256').toString('base64');
    expect(hashB64).toBe(expected);
  }, 30000);

  it('draws a fresh 16-byte salt every time and never embeds the password', async () => {
    const a = await hashPassword('another long passphrase', crypto);
    const b = await hashPassword('another long passphrase', crypto);
    expect(a).not.toBe(b);
    expect(a).not.toContain('another long passphrase');
    expect(Buffer.from(a.split('$')[2] ?? '', 'base64')).toHaveLength(16);
  }, 30000);

  it('base64 helper is standard base64', () => {
    expect(toBase64(new Uint8Array([251, 255, 254]))).toBe('+//+');
  });

  it('refuses short and huge passwords', () => {
    expect(passwordProblem('short')).toMatch(/at least 10/);
    expect(passwordProblem('x'.repeat(300))).toMatch(/at most/);
    expect(passwordProblem('long enough pw')).toBeNull();
  });
});
