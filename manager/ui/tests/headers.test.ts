// The admin SPA's Static Assets headers (public/_headers is copied into dist by vite): strict CSP, anti-framing, no sniffing.
import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (p: string): string => readFileSync(new URL(p, import.meta.url), 'utf8');

describe('_headers', () => {
  const src = read('../public/_headers');
  it('declares the required directives', () => {
    for (const d of ["default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'self'"]) expect(src).toContain(d);
    expect(src).not.toContain('unsafe-inline');
    expect(src).not.toContain('unsafe-eval');
    expect(src).toMatch(/^\/\*$/m);
    expect(src).toMatch(/X-Frame-Options: DENY/);
    expect(src).toMatch(/X-Content-Type-Options: nosniff/);
    expect(src).toMatch(/Referrer-Policy: no-referrer/);
    expect(src).toMatch(/Permissions-Policy: camera=\(\), microphone=\(\), geolocation=\(\)/);
  });
  it('index.html has no inline script or style (the CSP would block them)', () => {
    const html = read('../index.html');
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
    expect(html).not.toMatch(/<style\b/i);
    expect(html).not.toMatch(/\sstyle=/i);
    expect(html).not.toMatch(/\son[a-z]+=/i);
  });
  it('the build copies it to dist/_headers unchanged (skipped when dist is absent)', () => {
    const dist = new URL('../dist/_headers', import.meta.url);
    if (existsSync(dist)) expect(readFileSync(dist, 'utf8')).toBe(src);
  });
});
