// M6 speedtest settings UI: form <-> PUT body, validation, runner sources form, QR encoding, and the page itself.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { h, render } from 'preact';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SpeedtestSettings } from '../src/api/types';
import { DataStore } from '../src/data/store';
import { setStore } from '../src/data/hooks';
import { qrMatrix, qrPath } from '../src/lib/qr';
import { applyRunnerForm, runnerFormFrom, runnerProblems } from '../src/lib/runner';
import { contrastRatio, draftFrom, logoProblem, parseCopy, problems, safeColor, toBody } from '../src/lib/speedtest';
import { SpeedtestPage } from '../src/pages/SpeedtestPage';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(here, '../../../test/fixtures/configs/speedtest.json'), 'utf8')) as Record<string, any>;

/** the fixture's admin-owned part as the manager would return it from GET sites/{site}/speedtest */
function settings(over: Partial<SpeedtestSettings> = {}): SpeedtestSettings {
  const { schema: _a, speedtest_id: _b, site: _c, collector: _d, local_channel: _e, ...rest } = fixture;
  return { ...rest, branding: { ...rest['branding'], logo_artifact: null }, internet_leg: { ...rest['internet_leg'], paused: false }, device_key: { set: true, updated_at: '2026-11-18T10:00:00.000Z' }, updated_at: '2026-11-18T10:00:00.000Z', ...over } as SpeedtestSettings;
}

describe('settings form <-> PUT body', () => {
  it('the contract fixture has no problems and round-trips through the form', () => {
    const s = settings();
    const d = draftFrom(s);
    expect(problems(d)).toEqual({});
    const b = toBody(d, null) as Record<string, any>;
    expect(b.consent).toEqual({ text: s.consent.text });
    expect(b.zones).toEqual(s.zones);
    expect(b.zone_labels).toEqual(s.zone_labels);
    expect(b.serve).toEqual(s.serve);
    expect(b.tls).toEqual({ mode: 'none' });
    expect(b.branding.colors).toEqual(s.branding?.colors);
    expect(b.branding.languages).toEqual(['en', 'de']);
    expect(b.limits).toEqual(s.limits);
    expect(b.privacy).toEqual(s.privacy);
    expect(b.dns_leg).toEqual(s.dns_leg);
    expect(b.path).toEqual(s.path);
    expect(b.core_guard).toEqual(s.core_guard);
    expect('version' in b.consent).toBe(false);
    // the body is accepted by the same form again (stable)
    expect(toBody(draftFrom(b as SpeedtestSettings), null)).toEqual(b);
  });

  it('omits empty optional fields so the box keeps its defaults', () => {
    const d = draftFrom({ consent: { text: 'Hello' } });
    const b = toBody(d, null) as Record<string, any>;
    expect(Object.keys(b).sort()).toEqual(['consent', 'internet_leg', 'privacy', 'tls']);
    expect(b.privacy).toEqual({ scrub_after_diagnosis: false });
    expect(b.serve).toBeUndefined();
  });

  it('keeps the stored logo id and sends null when the admin removes it', () => {
    const d = draftFrom(settings());
    expect((toBody(d, 'art_01M7R3X9G0JPFS2FAGQ8ACHEYD') as any).branding.logo_artifact).toBe('art_01M7R3X9G0JPFS2FAGQ8ACHEYD');
    expect((toBody({ ...d, removeLogo: true }, 'art_01M7R3X9G0JPFS2FAGQ8ACHEYD') as any).branding.logo_artifact).toBeNull();
    expect((toBody(d, null) as any).branding.logo_artifact).toBeUndefined();
  });

  it('validates every field against the schema bounds', () => {
    const d = draftFrom(settings());
    const bad = (patch: Partial<typeof d>, key: string) => expect(problems({ ...d, ...patch })[key], key).toBeTruthy();
    bad({ consent: '  ' }, 'consent');
    bad({ consent: 'x'.repeat(2001) }, 'consent');
    bad({ consent: 'a\u0000b' }, 'consent');
    bad({ primary: 'red' }, 'primary');
    bad({ title: 'x'.repeat(81) }, 'title');
    bad({ languages: 'english' }, 'languages');
    bad({ languages: 'en, en' }, 'languages');
    bad({ copy: 'no equals sign' }, 'copy');
    bad({ copy: '1bad=x' }, 'copy');
    bad({ listenIp: '0.0.0.0' }, 'listenIp');
    bad({ listenIp: '127.0.0.1' }, 'listenIp');
    bad({ listenIp: '10.0.0' }, 'listenIp');
    bad({ hostname: 'has space' }, 'hostname');
    bad({ clientSubnets: '10.0.0.0/33' }, 'clientSubnets');
    bad({ translated: '999.1.1.1' }, 'translated');
    bad({ down: '0' }, 'down');
    bad({ limits: { ...d.limits, bytes_local: '5' } }, 'limit-bytes_local');
    bad({ limits: { ...d.limits, leg_token_ttl_s: '301' } }, 'limit-leg_token_ttl_s');
    bad({ retention: '400' }, 'retention');
    bad({ autoPause: '101' }, 'autoPause');
    bad({ zones: [{ id: 'A B', name: 'x' }] }, 'zone-id-0');
    bad({ zones: [{ id: 'a', name: 'x' }, { id: 'a', name: 'y' }] }, 'zone-id-1');
    bad({ subnets: [{ cidr: '10.1.0.0/16', zone: 'nope' }] }, 'subnet-zone-0');
    bad({ subnets: [{ cidr: 'x', zone: 'hall-a' }] }, 'subnet-cidr-0');
    bad({ dnsEnabled: true, dnsZone: '' }, 'dnsZone');
    bad({ gateway: 'x' }, 'gateway');
    bad({ guardIface: 'a/b' }, 'guardIface');
    bad({ hostname: '', listenIp: '10.0.0.9' }, 'serve');
    bad({ requireReal: true, clientSubnets: '', subnets: [] }, 'clientSubnets');
  });

  it('parses the page-text overrides', () => {
    expect(parseCopy('start_button=Start\n\nverdict_good = Great!')).toEqual({ entries: [['start_button', 'Start'], ['verdict_good', 'Great!']], error: null });
    expect(parseCopy('x').error).toBeTruthy();
    expect(parseCopy(`${'k'.repeat(65)}=1`).error).toBeTruthy();
    expect(parseCopy(Array.from({ length: 41 }, (_, i) => `k${i}=v`).join('\n')).error).toMatch(/40/);
  });

  it('only plain #rrggbb reaches the live preview', () => {
    expect(safeColor('#01a982', '#000')).toBe('#01a982');
    for (const x of ['red', 'url(javascript:1)', '#12', '#12345g', 'expression(1)']) expect(safeColor(x, '#000')).toBe('#000');
  });
});

describe('colour contrast hint', () => {
  it('computes the WCAG ratio and ignores anything that is not a plain hex colour', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBe(21);
    expect(contrastRatio('#ffffff', '#ffffff')).toBe(1);
    expect(contrastRatio('#7630ea', '#0b1320')).toBeLessThan(4.5);
    expect(contrastRatio('#f7f7f7', '#0b1320')).toBeGreaterThan(15);
    expect(contrastRatio('red', '#ffffff')).toBeNull();
  });
});

describe('logo checks', () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  it('enforces type, size and magic number', () => {
    expect(logoProblem('image/png', 100, png)).toBeNull();
    expect(logoProblem('image/gif', 100, png)).toMatch(/PNG, SVG or JPEG/);
    expect(logoProblem('image/png', 256 * 1024 + 1, png)).toMatch(/256 KiB/);
    expect(logoProblem('image/png', 256 * 1024, png)).toBeNull();
    expect(logoProblem('image/png', 0, png)).toMatch(/empty/);
    expect(logoProblem('image/png', 10, new Uint8Array([1, 2, 3, 4]))).toMatch(/not a PNG/);
    expect(logoProblem('image/jpeg', 10, new Uint8Array([0xff, 0xd8, 0xff, 0xe0]))).toBeNull();
    expect(logoProblem('image/jpeg', 10, png)).toMatch(/not a JPEG/);
    expect(logoProblem('image/svg+xml', 10, new TextEncoder().encode('<svg/>'))).toBeNull();
    expect(logoProblem('image/svg+xml', 10, new TextEncoder().encode('plain text'))).toMatch(/not an SVG/);
  });
});

describe('runner correlation sources', () => {
  const cfg = { drills_enabled: false, correlation: { window_before_s: 300, sources: { mist: { sites: [{ site_id: 'abc', name: 'Venue' }], zone_map: [{ zone: 'hall-b', ap_name_prefix: 'hallb-ap-' }], cache_ttl_s: 30 }, ec: { appliances: [{ ne_pk: '1.NE', wan_interfaces: ['wan0'] }], wan_util: { enabled: true, interval_s: 30 } }, syslog: { allow: ['10.0.0.0/8'], ring_minutes: 60 } } } };
  it('an untouched form leaves the config exactly as it was (unknown keys survive)', () => {
    const f = runnerFormFrom(cfg);
    expect(runnerProblems(f)).toEqual({});
    expect(applyRunnerForm(cfg, f)).toEqual(cfg);
  });
  it('edits only what was touched, drops emptied sections and never writes SSE', () => {
    const f = runnerFormFrom(cfg);
    const next = applyRunnerForm({ ...cfg, correlation: { ...cfg.correlation, sources: { ...cfg.correlation.sources, sse: { enabled: true } } } }, { ...f, mistSites: '', appliances: [], syslogAllow: '', wanUtil: false, enabled: false });
    const c = next['correlation'] as Record<string, any>;
    expect(c.enabled).toBe(false);
    expect(c.sources.mist.sites).toBeUndefined();
    expect(c.sources.mist.zone_map).toHaveLength(1);
    expect(c.sources.ec.appliances).toBeUndefined();
    expect(c.sources.ec.wan_util.enabled).toBe(false);
    expect(JSON.stringify(c)).not.toContain('sse');
  });
  it('validates ids, MACs, CIDRs and ranges', () => {
    const f = runnerFormFrom({});
    const p = (patch: Partial<typeof f>) => runnerProblems({ ...f, ...patch });
    expect(p({ zoneMap: [{ zone: 'Bad Zone', prefix: 'x', macs: '' }] })['zone-0']).toBeTruthy();
    expect(p({ zoneMap: [{ zone: 'ok', prefix: '', macs: '' }] })['zone-0']).toMatch(/prefix or AP MAC/);
    expect(p({ zoneMap: [{ zone: 'ok', prefix: '', macs: '5C:5B:35:00:01:A0' }] })['macs-0']).toBeTruthy();
    expect(p({ appliances: [{ nePk: '', wan: '' }] })['ne-0']).toBeTruthy();
    expect(p({ syslogAllow: '10.0.0.0/40' })['syslogAllow']).toBeTruthy();
    expect(p({ ringMinutes: '90' })['ringMinutes']).toBeTruthy();
    expect(p({ mistSites: 'x'.repeat(65) })['mistSites']).toBeTruthy();
  });
  it('an empty form on an empty config changes nothing', () => {
    expect(applyRunnerForm({}, runnerFormFrom({}))).toEqual({});
  });
});

describe('QR encoding (qrcode-generator, byte mode, level M)', () => {
  it('chooses the smallest version and draws the three finder patterns', () => {
    const m = qrMatrix('http://speed.summit.example/?z=hall-a');
    expect((m.size - 17) % 4).toBe(0);
    expect(m.size).toBe(29); // 37 bytes at level M fit version 3 (29 modules)
    const finder = (r0: number, c0: number) => {
      for (let r = 0; r < 7; r++) for (let c = 0; c < 7; c++) {
        const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3));
        expect(m.dark(r0 + r, c0 + c), `${r0 + r},${c0 + c}`).toBe(ring !== 2);
      }
    };
    finder(0, 0); finder(0, m.size - 7); finder(m.size - 7, 0);
    expect(m.dark(m.size - 8, 8)).toBe(true); // the always-dark module
    // timing pattern alternates between the finders
    for (let i = 8; i < m.size - 8; i++) expect(m.dark(6, i)).toBe(i % 2 === 0);
  });
  it('is deterministic, grows with the text and draws one path inside a quiet zone', () => {
    const a = qrPath('http://a.example/?z=x');
    expect(qrPath('http://a.example/?z=x')).toEqual(a);
    expect(qrPath('http://a.example/?z=x'.repeat(5)).side).toBeGreaterThan(a.side);
    expect(a.d.startsWith('M4 4')).toBe(true);
    expect(a.d).toMatch(/^(M\d+ \d+h\d+v1h-\d+z)+$/);
  });
  it('refuses text it cannot encode faithfully', () => {
    expect(() => qrMatrix('')).toThrow();
    expect(() => qrMatrix('café')).toThrow();
    expect(() => qrMatrix('x'.repeat(501))).toThrow();
  });
});

// ---- the page ----------------------------------------------------------------------------------------------------------

interface Call { method: string; url: string; body: string | null; ct: string | null }
let calls: Call[];
let st: SpeedtestSettings;
let root: HTMLElement;
let store: DataStore;

const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });
const tick = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const q = <T extends Element>(sel: string): T => root.querySelector(sel) as T;
const setValue = async (el: HTMLInputElement | HTMLTextAreaElement, v: string) => {
  el.value = v;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  await tick(2);
};
const byLabel = (text: string): HTMLInputElement | HTMLTextAreaElement => {
  const l = [...root.querySelectorAll('label')].find((x) => x.textContent?.trim() === text);
  if (!l) throw new Error(`no label ${text}`);
  return root.querySelector(`[id="${l.getAttribute('for') ?? ''}"]`) as HTMLInputElement;
};

beforeEach(() => {
  calls = [];
  st = settings();
  store = new DataStore({
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      const hdr = (init?.headers ?? {}) as Record<string, string>;
      calls.push({ method, url, body: typeof init?.body === 'string' ? init.body : init?.body ? '[binary]' : null, ct: hdr['Content-Type'] ?? null });
      if (method === 'PUT' && url.endsWith('/speedtest')) {
        const b = JSON.parse(String(init?.body)) as SpeedtestSettings;
        st = { ...st, ...b, consent: { text: b.consent.text, version: b.consent.text === st.consent.text ? (st.consent.version ?? 1) : (st.consent.version ?? 1) + 1 } };
        return json(st);
      }
      if (method === 'POST' && url.endsWith('/internet-pause')) {
        st = { ...st, internet_leg: { ...st.internet_leg, paused: JSON.parse(String(init?.body)).paused } };
        return json({ paused: st.internet_leg?.paused, updated_at: '2026-11-18T10:00:00.000Z' });
      }
      if (url.endsWith('/qr')) return json({ items: [{ zone: 'hall-a', name: 'Hall A <b>', url: 'http://speed.summit.example/?z=hall-a' }, { zone: 'hall-b', name: 'Hall B', url: 'http://speed.summit.example/?z=hall-b' }] });
      if (url.endsWith('/consent-history')) return json({ items: [{ version: 3, text: st.consent.text, changed_by: 'a@example.com', created_at: '2026-11-18T10:00:00.000Z' }, { version: 2, text: 'older text', changed_by: 'o@example.com', created_at: '2026-11-17T10:00:00.000Z' }] });
      if (url.includes('/integrations/')) return json({ kind: url.endsWith('mist') ? 'mist' : 'ec', config: {}, credentials: { set: false, updated_at: null }, allowlist: [], updated_at: null });
      if (url.endsWith('/speedtest')) return json(st);
      if (url.includes('/sites/hall-b')) return json({ site: 'hall-b', name: 'Hall B', timezone: 'UTC', edge_label: 'EC', release_version: '0.1.1', canary_host_id: null, canary_state: null, created_at: '', updated_at: '' });
      return json({}, 404);
    }) as typeof fetch,
    now: () => Date.now(),
    isVisible: () => true,
  });
  setStore(store);
  root = document.createElement('div');
  document.body.appendChild(root);
});
afterEach(() => {
  render(null, root);
  root.remove();
  store.dispose();
});

const waitFor = async (ok: () => boolean, what: string) => {
  for (let i = 0; i < 200; i++) {
    if (ok()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`timed out waiting for ${what}`);
};

const mount = async (role: 'owner' | 'admin' | 'operator' | 'viewer') => {
  render(h(SpeedtestPage, { slug: 'hall-b', me: { email: 'x@example.com', role } }), root);
  await waitFor(() => !!root.querySelector('form[aria-label="Speedtest settings"]') && !!root.querySelector('[data-testid=signage-ready], button'), 'the settings form');
  await waitFor(() => [...root.querySelectorAll('button')].some((b) => b.textContent?.startsWith('Open printable signage')), 'the signage panel');
};

describe('SpeedtestPage', () => {
  it('shows the settings, the consent version and the live preview', async () => {
    await mount('admin');
    expect(q('h1').textContent).toBe('Speedtest');
    expect((byLabel('Page title') as HTMLInputElement).value).toBe('Summit speed check');
    expect(q('[data-testid=st-preview-title]').textContent).toBe('Summit speed check');
    expect(q('[data-testid=consent-version]').textContent).toContain('Current version 3');
    await setValue(byLabel('Page title'), 'Another title');
    expect(q('[data-testid=st-preview-title]').textContent).toBe('Another title');
  });

  it('renders hostile text as text, never as markup', async () => {
    await mount('admin');
    await setValue(byLabel('Page title'), '<img src=x onerror=alert(1)>');
    expect(root.querySelector('[data-testid=st-preview] img[src="x"]')).toBeNull();
    expect(q('[data-testid=st-preview-title]').textContent).toBe('<img src=x onerror=alert(1)>');
    await setValue(byLabel('Primary colour'), 'url(javascript:alert(1))');
    expect((q('.st-preview-btn') as HTMLElement).getAttribute('style') ?? '').not.toContain('javascript');
  });

  it('warns when the chosen colours are hard to read', async () => {
    await mount('admin');
    expect(root.querySelector('[data-testid=contrast-warning]')).toBeNull();
    await setValue(byLabel('Text colour'), '#222222');
    expect(q('[data-testid=contrast-warning]').textContent).toMatch(/Text on background is/);
  });

  it('editing the consent text announces the next version and saves it', async () => {
    await mount('admin');
    await setValue(byLabel('Consent text'), 'A brand new wording.');
    expect(q('[data-testid=consent-version]').textContent).toContain('version 4');
    (q('button[type=submit]') as HTMLButtonElement).click();
    await tick(10);
    const put = calls.find((c) => c.method === 'PUT');
    expect(put?.url).toBe('/api/admin/v1/sites/hall-b/speedtest');
    expect(put?.ct).toBe('application/json');
    const body = JSON.parse(put?.body ?? '{}');
    expect(body.consent).toEqual({ text: 'A brand new wording.' });
    expect(body.serve.listen_ip).toBe('10.0.0.9');
    expect(q('[data-testid=consent-version]').textContent).toContain('Current version 4');
  });

  it('blocks saving while a field is invalid and says which', async () => {
    await mount('admin');
    await setValue(byLabel('Listen address'), '0.0.0.0');
    expect((q('button[type=submit]') as HTMLButtonElement).disabled).toBe(true);
    expect(root.textContent).toContain('A unicast address of the speedtest box');
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('a viewer sees the values but cannot change or save anything', async () => {
    await mount('viewer');
    expect((byLabel('Page title') as HTMLInputElement).disabled).toBe(true);
    expect((q('button[type=submit]') as HTMLButtonElement).disabled).toBe(true);
    expect(root.textContent).toContain('Your role does not allow changes');
    const pause = [...root.querySelectorAll('button')].find((b) => b.textContent?.includes('Pause internet leg')) as HTMLButtonElement;
    expect(pause.disabled).toBe(true);
    expect([...root.querySelectorAll('button')].some((b) => b.textContent?.includes('device key'))).toBe(true);
    expect(root.querySelector('[data-testid=consent-history]')).toBeNull();
  });

  it('an operator can pause the internet leg without being able to edit settings', async () => {
    await mount('operator');
    const pause = [...root.querySelectorAll('button')].find((b) => b.textContent === 'Pause internet leg') as HTMLButtonElement;
    expect(pause.disabled).toBe(false);
    pause.click();
    await tick(10);
    const c = calls.find((x) => x.url.endsWith('/internet-pause'));
    expect(c?.method).toBe('POST');
    expect(JSON.parse(c?.body ?? '{}')).toEqual({ paused: true });
    expect(root.textContent).toContain('paused');
    expect((q('button[type=submit]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('the device key is never displayed, only its state', async () => {
    await mount('owner');
    expect(root.textContent).toContain('Device key');
    expect(root.textContent).not.toMatch(/expk_/);
    expect([...root.querySelectorAll('button')].some((b) => b.textContent === 'Rotate device key…' && !b.disabled)).toBe(true);
  });

  it('printable signage: one QR per zone, names as text', async () => {
    await mount('admin');
    const open = [...root.querySelectorAll('button')].find((b) => b.textContent?.startsWith('Open printable signage')) as HTMLButtonElement;
    expect(open.textContent).toContain('2 zones');
    open.click();
    await tick(4);
    const sheet = q('[data-testid=signage]');
    expect(sheet.querySelectorAll('svg.qr')).toHaveLength(2);
    expect(sheet.textContent).toContain('Hall A <b>');
    expect(sheet.querySelector('b')).toBeNull();
    expect(sheet.textContent).toContain('http://speed.summit.example/?z=hall-b');
    expect(sheet.querySelector('svg.qr path')?.getAttribute('d')?.length).toBeGreaterThan(100);
  });

  it('the consent history is admin-only and lists every version', async () => {
    await mount('admin');
    const btn = [...root.querySelectorAll('button')].find((b) => b.textContent?.startsWith('Show history')) as HTMLButtonElement;
    btn.click();
    await waitFor(() => root.querySelectorAll('[data-testid=consent-history] li').length > 0, 'the history');
    const items = [...root.querySelectorAll('[data-testid=consent-history] li')].map((li) => li.textContent);
    expect(items).toHaveLength(2);
    expect(items[1]).toContain('older text');
  });
});

describe('no results or evidence in the manager UI (SR-20)', () => {
  it('the speedtest page and the api client reference only intent endpoints', () => {
    const src = readFileSync(join(here, '../src/pages/SpeedtestPage.tsx'), 'utf8') + readFileSync(join(here, '../src/api/endpoints.ts'), 'utf8');
    expect(src).not.toMatch(/\/speedtests|\/evidence|\/results|\/sessions/);
  });
});
