import { describe, expect, it } from 'vitest';
import { isLaunchUrl, nocUrl } from '../src/lib/sso';

const N = '1760000000.' + 'A'.repeat(43);
describe('SSO launch URL', () => {
  it('accepts only the same-origin admin API launch path', () => {
    expect(isLaunchUrl(`/api/admin/v1/dashboards/dash-main/sso/page?n=${N}`)).toBe(true);
    for (const bad of [`https://evil.example/api/admin/v1/dashboards/d/sso/page?n=${N}`, `//evil.example/x`, `/api/admin/v1/dashboards/d/sso/page?n=${N}&x=1`, `/api/admin/v1/dashboards/../x/sso/page?n=${N}`, 'javascript:alert(1)', `/other?n=${N}`, null, 5]) expect(isLaunchUrl(bad), String(bad)).toBe(false);
  });
});

describe('NOC URL', () => {
  it('carries the token in the fragment only', () => {
    expect(nocUrl('https://10.32.98.30', 'expn_abc')).toBe('https://10.32.98.30/noc#t=expn_abc');
    expect(nocUrl('https://dash.example.com/some/path?x=1', 'expn_abc')).toBe('https://dash.example.com/noc#t=expn_abc');
  });
  it('needs an https dashboard address', () => {
    expect(nocUrl('http://10.32.98.30', 'expn_abc')).toBeNull();
    expect(nocUrl(null, 'expn_abc')).toBeNull();
    expect(nocUrl('garbage', 'expn_abc')).toBeNull();
  });
});
