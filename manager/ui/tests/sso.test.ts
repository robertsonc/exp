import { describe, expect, it } from 'vitest';
import { nocUrl, parseSsoForm } from '../src/lib/sso';

const TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhQGIuYyJ9.c2lnbmF0dXJl';
const page = (action: string, token = TOKEN, method = 'post') =>
  `<!doctype html><html><body onload="document.forms[0].submit()"><form method="${method}" action="${action}"><input type="hidden" name="token" value="${token}"></form></body></html>`;

describe('SSO handoff form', () => {
  it('reads action and token from the manager document', () => {
    expect(parseSsoForm(page('https://10.40.98.80/auth/sso'))).toEqual({ action: 'https://10.40.98.80/auth/sso', token: TOKEN });
    expect(parseSsoForm(page('https://dash.example.com:8443/auth/sso'))?.action).toBe('https://dash.example.com:8443/auth/sso');
  });
  it('refuses anything that could send the token somewhere unexpected', () => {
    expect(parseSsoForm(page('http://10.40.98.80/auth/sso'))).toBeNull(); // not https
    expect(parseSsoForm(page('https://10.40.98.80/other'))).toBeNull(); // wrong path
    expect(parseSsoForm(page('https://10.40.98.80/auth/sso?x=1'))).toBeNull();
    expect(parseSsoForm(page('https://u:p@10.40.98.80/auth/sso'))).toBeNull();
    expect(parseSsoForm(page('javascript:alert(1)'))).toBeNull();
    expect(parseSsoForm(page('https://10.40.98.80/auth/sso', 'not a jwt'))).toBeNull();
    expect(parseSsoForm(page('https://10.40.98.80/auth/sso', TOKEN, 'get'))).toBeNull();
    expect(parseSsoForm('<html>no form</html>')).toBeNull();
    expect(parseSsoForm('x'.repeat(20000))).toBeNull();
  });
  it('decodes attribute entities before validating', () => {
    expect(parseSsoForm(page('https://dash.example.com/auth/sso'.replace('/', '&#x2F;')))).toBeNull(); // unknown entity: not a valid URL
    expect(parseSsoForm(page('https://dash.example.com/auth/sso'))).not.toBeNull();
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
