import { describe, expect, it } from 'vitest';
import { EXPIRY_WARN_DAYS, MAX_CERT_PEM, MAX_KEY_PEM, certExpiry, fingerprintPending, tlsPemProblems } from '../src/lib/tls';

const CERT = '-----BEGIN CERTIFICATE-----\nAQIDBAUG\n-----END CERTIFICATE-----\n';
const KEY = '-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----\n';

describe('provided TLS: client-side PEM checks', () => {
  it('accepts a certificate and a PKCS#8, RSA or EC key', () => {
    expect(tlsPemProblems(CERT, KEY)).toEqual({});
    expect(tlsPemProblems(CERT + CERT, KEY.replace(/PRIVATE/g, 'RSA PRIVATE'))).toEqual({});
    expect(tlsPemProblems(CERT, KEY.replace(/PRIVATE/g, 'EC PRIVATE'))).toEqual({});
  });
  it('flags empty, wrong-kind, encrypted and oversize input', () => {
    expect(tlsPemProblems('', '')).toEqual({ cert: expect.any(String), key: expect.any(String) });
    expect(tlsPemProblems(KEY, CERT)).toEqual({ cert: expect.stringMatching(/BEGIN CERTIFICATE/), key: expect.stringMatching(/PRIVATE KEY/) });
    expect(tlsPemProblems(CERT, '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----').key).toMatch(/passphrase/);
    expect(tlsPemProblems(CERT + 'x'.repeat(MAX_CERT_PEM), KEY).cert).toMatch(/32 KiB/);
    expect(tlsPemProblems(CERT, KEY + 'x'.repeat(MAX_KEY_PEM)).key).toMatch(/8 KiB/);
  });
});

describe('provided TLS: expiry', () => {
  const now = Date.parse('2026-11-19T00:00:00Z');
  const at = (days: number) => new Date(now + days * 86_400_000).toISOString();
  it('warns below 30 days and flags expired', () => {
    expect(EXPIRY_WARN_DAYS).toBe(30);
    expect(certExpiry(at(90), now)).toMatchObject({ state: 'ok' });
    expect(certExpiry(at(30), now)).toMatchObject({ state: 'ok', days: 30 });
    expect(certExpiry(at(29.5), now)).toMatchObject({ state: 'soon', days: 29 });
    expect(certExpiry(at(1), now)).toMatchObject({ state: 'soon' });
    expect(certExpiry(at(-1), now)).toMatchObject({ state: 'expired' });
    expect(certExpiry('garbage', now).state).toBe('ok');
  });
  it('fingerprintPending ignores case and separators and is quiet when either side is unknown', () => {
    expect(fingerprintPending('AB:CD', 'abcd')).toBe(false);
    expect(fingerprintPending('AB:CD', 'AB:CE')).toBe(true);
    expect(fingerprintPending('AB:CD', null)).toBe(false);
    expect(fingerprintPending(null, 'AB:CD')).toBe(false);
  });
});
