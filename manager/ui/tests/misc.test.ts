import { describe, expect, it } from 'vitest';
import { alignSeries, summarize, toSeconds } from '../src/charts/align';
import { visibleRange } from '../src/components/VirtualTable';
import { matchRoute } from '../src/router';
import { redact, safeHttpsUrl } from '../src/lib/redact';
import { searchIndex } from '../src/lib/search';
import { isSnoozed, issueScope, sortIssues } from '../src/lib/issues';
import { readJson, writeJson } from '../src/lib/storage';
import type { FleetHostRow, Issue, Overview } from '../src/api/types';
import { parsePorts } from '../src/pages/ComponentPage';

describe('chart alignment', () => {
  it('draws absent buckets as gaps and keeps real values', () => {
    const step = 300;
    const end = 3000;
    const pts = [{ t: 2100, avg: 5, max: 6 }, { t: 2700, avg: 7, max: 8 }];
    const a = alignSeries([pts], step, end, 1200);
    expect(a.xs).toEqual([1800, 2100, 2400, 2700, 3000]);
    expect(a.series[0]?.avg).toEqual([null, 5, null, 7, null]);
    expect(a.series[0]?.max).toEqual([null, 6, null, 8, null]);
  });
  it('accepts millisecond timestamps (mock admin) as well as seconds (contract)', () => {
    expect(toSeconds(1_794_893_700_000)).toBe(1_794_893_700);
    expect(toSeconds(1_794_893_700)).toBe(1_794_893_700);
    const end = 1_794_893_700;
    const a = alignSeries([[{ t: (end - 600) * 1000, avg: 5, max: 6 }]], 300, end, 1200);
    expect(a.series[0]?.avg).toEqual([null, null, 5, null, null]);
    const b = alignSeries([[{ t: end - 600, avg: 5, max: 6 }]], 300, end, 1200);
    expect(b.series[0]?.avg).toEqual([null, null, 5, null, null]);
  });
  it('summarises without counting the open bucket as a gap', () => {
    expect(summarize([null, 1, null, 3, null])).toEqual({ latest: 3, min: 1, max: 3, samples: 2, gaps: 1 });
    expect(summarize([null, null])).toEqual({ latest: null, min: null, max: null, samples: 0, gaps: 0 });
  });
});

describe('virtual window', () => {
  it('renders only the visible rows plus overscan', () => {
    expect(visibleRange(0, 400, 40, 500, 6)).toEqual([0, 16]);
    expect(visibleRange(4000, 400, 40, 500, 6)).toEqual([94, 116]);
    expect(visibleRange(1e9, 400, 40, 500, 6)[1]).toBe(500);
    expect(visibleRange(0, 400, 40, 0)).toEqual([0, 0]);
  });
});

describe('routes', () => {
  it('match real URLs', () => {
    expect(matchRoute('/').name).toBe('fleet');
    expect(matchRoute('/fleet').name).toBe('fleet');
    expect(matchRoute('/hosts').name).toBe('hosts');
    expect(matchRoute('/hosts/h_ABC123')).toEqual({ name: 'host', params: { id: 'h_ABC123' } });
    expect(matchRoute('/hosts/h_ABC123/components/cmp_XYZ9')).toEqual({ name: 'component', params: { id: 'h_ABC123', cid: 'cmp_XYZ9' } });
    expect(matchRoute('/sites/hall-b')).toEqual({ name: 'site', params: { site: 'hall-b' } });
    for (const n of ['issues', 'sites', 'releases', 'dashboards', 'drills', 'audit', 'settings']) expect(matchRoute(`/${n}`).name).toBe(n);
    expect(matchRoute('/hosts/../etc').name).toBe('notfound');
    expect(matchRoute('/nope').name).toBe('notfound');
  });
});

describe('untrusted data helpers', () => {
  it('redacts secret-looking keys but keeps fingerprints', () => {
    expect(redact({ a: 1, token: 'x', nested: { password_hash: 'y', tls_fingerprint_sha256: 'AB' }, list: [{ api_key: 'k' }] })).toEqual({
      a: 1, token: '[hidden]', nested: { password_hash: '[hidden]', tls_fingerprint_sha256: 'AB' }, list: [{ api_key: '[hidden]' }],
    });
  });
  it('only allows https links from facts', () => {
    expect(safeHttpsUrl('https://10.0.0.1/')).toBe('https://10.0.0.1/');
    expect(safeHttpsUrl('javascript:alert(1)')).toBeNull();
    expect(safeHttpsUrl('http://example.com')).toBeNull();
    expect(safeHttpsUrl(42)).toBeNull();
  });
  it('parses probe ports defensively', () => {
    const p = parsePorts([{ id: 'c01', link: 'up', leased: true, ip: '10.1.0.5', rx_pps: 5, last: { dns: 'fail', x: 3 } }, null, 'junk']);
    expect(p).toHaveLength(1);
    expect(p[0]?.last).toEqual([['dns', 'fail']]);
    expect(parsePorts('nope')).toEqual([]);
  });
});

describe('search', () => {
  const hosts = [{ host_id: 'h_A', name: 'hb-col-01', mgmt_ip: '10.32.98.25', site: 'hall-b' }, { host_id: 'h_B', name: 'hb-probe-01', mgmt_ip: '10.32.98.31', site: 'hall-b' }] as FleetHostRow[];
  const ov = { as_of: '', versions: {}, sites: [{ site: 'hall-b', name: 'Hall B' }], hosts: [{ host_id: 'h_A', name: 'hb-col-01', site: 'hall-b', state: 'enrolled', health: 'ok', components: [{ component_id: 'cmp_1', type: 'collector', id: 'col-hallb', health: 'ok' }] }] } as unknown as Overview;
  it('finds hosts by name, IP and id, sites and components', () => {
    expect(searchIndex('probe', hosts, ov)[0]?.to).toBe('/hosts/h_B');
    expect(searchIndex('10.32.98.25', hosts, ov)[0]?.label).toBe('hb-col-01');
    expect(searchIndex('h_a', hosts, ov)[0]?.to).toBe('/hosts/h_A');
    expect(searchIndex('hall b', hosts, ov).some((h) => h.kind === 'site')).toBe(true);
    expect(searchIndex('hall', hosts, ov).some((h) => h.to === '/sites/hall-b')).toBe(true);
    expect(searchIndex('col-hallb', hosts, ov)[0]?.to).toBe('/hosts/h_A/components/cmp_1');
    expect(searchIndex('', hosts, ov)).toEqual([]);
  });
});

describe('issues', () => {
  const base = { issue_id: 'iss_1', kind: 'disk_high', severity: 'warn', host_id: 'h', component_id: null, site: 's', opened_at: '2026-11-18T10:00:00Z', resolved_at: null, last_value: 90, detail: '', snoozed_until: null } as Issue;
  it('snooze state', () => {
    const now = Date.parse('2026-11-18T12:00:00Z');
    expect(isSnoozed(base, now)).toBe(false);
    expect(isSnoozed({ ...base, snoozed_until: '2026-11-18T13:00:00Z' }, now)).toBe(true);
    expect(isSnoozed({ ...base, snoozed_until: '2026-11-18T11:00:00Z' }, now)).toBe(false);
    expect(isSnoozed({ ...base, snoozed_until: 'resolved' }, now)).toBe(true);
  });
  it('sorts crit first then newest', () => {
    const l = sortIssues([base, { ...base, issue_id: 'iss_2', severity: 'crit' }, { ...base, issue_id: 'iss_3', opened_at: '2026-11-18T11:00:00Z' }]);
    expect(l.map((i) => i.issue_id)).toEqual(['iss_2', 'iss_3', 'iss_1']);
    expect(issueScope('probe_spool')).toBe('probe');
    expect(issueScope('storage_runway')).toBe('collector');
    expect(issueScope('disk_high')).toBe('host');
  });
});

describe('storage wrapper', () => {
  it('works without localStorage (blocked or private mode)', () => {
    const real = Object.getOwnPropertyDescriptor(window, 'localStorage');
    Object.defineProperty(window, 'localStorage', { configurable: true, get() { throw new Error('blocked'); } });
    try {
      expect(readJson('k', [1])).toEqual([1]);
      expect(writeJson('k', { a: 1 })).toBe(false);
    } finally {
      if (real) Object.defineProperty(window, 'localStorage', real);
    }
  });
  it('round-trips and tolerates corrupt values', () => {
    expect(writeJson('exp.test', { a: 1 })).toBe(true);
    expect(readJson('exp.test', null)).toEqual({ a: 1 });
    window.localStorage.setItem('exp.test', '{not json');
    expect(readJson('exp.test', 'fallback')).toBe('fallback');
  });
});
