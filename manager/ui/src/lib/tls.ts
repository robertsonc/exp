// Provided dashboard TLS (CR p2): client-side sanity checks before upload, and expiry classification.
// The Worker does the real validation (X.509, expiry, key possession); these only avoid obviously wrong uploads.

export const MAX_CERT_PEM = 32 * 1024;
export const MAX_KEY_PEM = 8 * 1024;
export const EXPIRY_WARN_DAYS = 30;

const CERT_RE = /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/;
const KEY_RE = /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END (?:RSA |EC )?PRIVATE KEY-----/;

export interface TlsProblems { cert?: string; key?: string }

export function tlsPemProblems(certPem: string, keyPem: string): TlsProblems {
  const p: TlsProblems = {};
  if (!certPem.trim()) p.cert = 'Paste or choose the certificate (PEM).';
  else if (certPem.length > MAX_CERT_PEM) p.cert = 'The certificate is larger than 32 KiB.';
  else if (!CERT_RE.test(certPem)) p.cert = 'This does not look like a PEM certificate (-----BEGIN CERTIFICATE-----).';
  if (!keyPem.trim()) p.key = 'Paste or choose the private key (PEM).';
  else if (keyPem.length > MAX_KEY_PEM) p.key = 'The key is larger than 8 KiB.';
  else if (/ENCRYPTED/.test(keyPem)) p.key = 'The key must not be passphrase-protected. Remove the passphrase first.';
  else if (!KEY_RE.test(keyPem)) p.key = 'This does not look like a PEM private key (-----BEGIN PRIVATE KEY-----).';
  return p;
}

export type ExpiryState = 'ok' | 'soon' | 'expired';

export function certExpiry(notAfter: string, now: number): { state: ExpiryState; days: number } {
  const ms = Date.parse(notAfter);
  if (!Number.isFinite(ms)) return { state: 'ok', days: Number.POSITIVE_INFINITY };
  const days = Math.floor((ms - now) / 86_400_000);
  if (ms <= now) return { state: 'expired', days };
  return { state: days < EXPIRY_WARN_DAYS ? 'soon' : 'ok', days };
}

const norm = (fp: string | null | undefined): string => (fp ?? '').replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
/** true when the dashboard reports a different certificate than the one stored (it has not applied it yet) */
export function fingerprintPending(stored: string | null | undefined, reported: string | null | undefined): boolean {
  return !!stored && !!reported && norm(stored) !== norm(reported);
}
