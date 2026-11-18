// Rendered configs never contain credentials (01-contracts.md section 9), but the UI redacts defensively:
// any key that looks like a secret is shown as [hidden]. TLS fingerprints are public and stay visible.
const SECRET = /(token|secret|password|passwd|credential|private|api[_-]?key|hash)/i;

export function redact(v: unknown, depth = 0): unknown {
  if (depth > 12) return '[truncated]';
  if (Array.isArray(v)) return v.map((x) => redact(x, depth + 1));
  if (v && typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      out[k] = SECRET.test(k) && !/fingerprint/i.test(k) ? '[hidden]' : redact(val, depth + 1);
    }
    return out;
  }
  return v;
}

/** Only https URLs from untrusted facts are ever used as link targets. */
export function safeHttpsUrl(u: unknown): string | null {
  if (typeof u !== 'string' || u.length > 2048) return null;
  try {
    const url = new URL(u);
    return url.protocol === 'https:' ? url.toString() : null;
  } catch {
    return null;
  }
}

export function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
