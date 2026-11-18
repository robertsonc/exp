// Client-side validation that mirrors shared/schemas/common.schema.json. The manager validates again; these checks
// only give the admin a reason before the request is sent.

export const RE = {
  slug: /^[a-z0-9][a-z0-9-]{0,63}$/,
  ipv4: /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$/,
  ipv4Cidr: /^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\/(3[0-2]|[12]?[0-9])$/,
  hostOrIp: /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/,
  httpsUrl: /^https:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(\/[^\s]*)?$/,
  httpUrl: /^https?:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(\/[^\s]*)?$/,
  semver: /^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$/,
  timezone: /^(UTC|[A-Za-z]+(\/[A-Za-z0-9_+-]+){1,2})$/,
  ident: /^[A-Za-z_][A-Za-z0-9_]{0,63}$/,
  username: /^[A-Za-z0-9._-]{1,64}$/,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
};

// eslint-disable-next-line no-control-regex
export const CTRL = /[\x00-\x1f\x7f]/;
export const RESERVED_LABELS = ['probe', 'site', 'outcome', 'target'];

export function slugProblem(v: string, what = 'Id'): string | null {
  return RE.slug.test(v) ? null : `${what} must be lowercase letters, digits and dashes, starting with a letter or digit (at most 64).`;
}

export function slugify(v: string, max = 64): string {
  return v.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, max).replace(/-+$/g, '');
}

export function httpsProblem(v: string): string | null {
  return v.length <= 512 && RE.httpsUrl.test(v) ? null : 'Enter an https:// URL.';
}

export function intIn(v: string | number, lo: number, hi: number): number | null {
  const n = typeof v === 'number' ? v : Number(v.trim());
  return (typeof v === 'number' || v.trim() !== '') && Number.isInteger(n) && n >= lo && n <= hi ? n : null;
}

export function numIn(v: string | number, lo: number, hi: number): number | null {
  const n = typeof v === 'number' ? v : Number(v.trim());
  return (typeof v === 'number' || v.trim() !== '') && Number.isFinite(n) && n >= lo && n <= hi ? n : null;
}

/** Split a free-text list (commas, spaces, newlines) into trimmed non-empty entries. */
export function splitList(v: string): string[] {
  return v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
}

/** True when `a` is a lower version than `b` (both semver, pre-release suffix ignored). */
export function versionLess(a: string, b: string): boolean {
  const pa = a.split('-')[0]?.split('.').map(Number) ?? [];
  const pb = b.split('-')[0]?.split('.').map(Number) ?? [];
  for (let i = 0; i < 3; i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y;
  }
  return false;
}
