import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Iface } from '../src/api/types';
import {
  applyCollectorForm, applyDashboardForm, applyProbeForm, buildPorts, draftsFromPorts, collectorFormFrom, dashboardFormFrom, defaultComponentId, defaultIntent,
  emptyDraft, ifaceBlockReason, probeFormFrom, sameConfig, type Cfg,
} from '../src/lib/intent';
import { slugify, versionLess } from '../src/lib/validate';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (n: string): Cfg => JSON.parse(readFileSync(join(here, '..', '..', '..', 'test', 'fixtures', 'configs', `${n}.json`), 'utf8')) as Cfg;

const ifaces: Iface[] = [
  { name: 'eno1', mac: 'aa:bb:cc:00:00:01', state: 'up', speed_mbps: 1000, addrs: ['10.0.0.5/24'], default_route: true, in_use_by: 'mgmt' },
  { name: 'enp1', mac: 'aa:bb:cc:00:00:02', state: 'up', speed_mbps: 1000, addrs: [], default_route: false, in_use_by: 'none' },
  { name: 'enp2', mac: 'aa:bb:cc:00:00:03', state: 'down', addrs: [], default_route: false, in_use_by: 'none' },
  { name: 'enp3', mac: 'aa:bb:cc:00:00:04', state: 'up', addrs: [], default_route: false, in_use_by: 'probe:other' },
];

describe('probe interface picker', () => {
  it('never allows the management interface and says why', () => {
    expect(ifaceBlockReason(ifaces[0] as Iface)).toMatch(/Management interface/);
    expect(ifaceBlockReason({ ...(ifaces[1] as Iface), default_route: true })).toMatch(/default route/);
    expect(ifaceBlockReason(ifaces[3] as Iface)).toMatch(/Already used/);
    expect(ifaceBlockReason(ifaces[1] as Iface)).toBeNull();
    const r = buildPorts(ifaces, { eno1: { ...emptyDraft(), role: 'client' } });
    expect(r.ports).toEqual([]);
    expect(r.errors['eno1']).toMatch(/Management interface/);
  });
  it('prefills the picker from a probe\'s current ports, and saving them unchanged gives the same list', () => {
    const current = [{ id: 'c01', iface: 'enp1', role: 'client' }, { id: 's01', iface: 'enp2', role: 'target', address: '10.1.0.250/24', gateway: '10.1.0.1' }];
    const drafts = draftsFromPorts(current);
    expect(drafts['enp1']).toEqual({ ...emptyDraft(), role: 'client' });
    expect(buildPorts(ifaces, drafts).ports).toEqual(current);
    expect(draftsFromPorts(undefined)).toEqual({});
    expect(draftsFromPorts([{ iface: 'x', role: 'mgmt' }, null, 'junk'])).toEqual({});
  });
  it('numbers ports per role and validates target addresses', () => {
    const r = buildPorts(ifaces, {
      enp1: { ...emptyDraft(), role: 'client' },
      enp2: { ...emptyDraft(), role: 'target', address: '10.1.0.250/24', gateway: '10.1.0.1' },
    });
    expect(r.errors).toEqual({});
    expect(r.ports).toEqual([{ id: 'c01', iface: 'enp1', role: 'client' }, { id: 's01', iface: 'enp2', role: 'target', address: '10.1.0.250/24', gateway: '10.1.0.1' }]);
    const bad = buildPorts(ifaces, { enp2: { ...emptyDraft(), role: 'target', address: '10.1.0.250', gateway: '10.1.0.1' } });
    expect(bad.ports).toEqual([]);
    expect(bad.errors['enp2']).toMatch(/a\.b\.c\.d\/len/);
    expect(buildPorts(ifaces, { enp2: { ...emptyDraft(), role: 'target', address: '10.1.0.250/24', gateway: 'nope' } }).errors['enp2']).toMatch(/gateway/);
  });
});

describe('new component defaults', () => {
  it('derives slugs and never puts secrets or wiring in the intent', () => {
    expect(defaultComponentId('probe', slugify('Hall B / Probe 5'))).toBe('probe-hall-b-probe-5');
    expect(defaultComponentId('collector', 'a'.repeat(80)).length).toBeLessThanOrEqual(64);
    for (const s of ['probe', 'collector', 'dashboard', 'runner'] as const) {
      const text = JSON.stringify(defaultIntent(s, 'hb-1'));
      expect(text).not.toMatch(/exp[aeidn]_|secret|password|hash/i);
    }
  });
});

describe('probe editor model', () => {
  it('an untouched form leaves the config unchanged (fixture round trip)', () => {
    const cfg = fixture('probe');
    const r = applyProbeForm(cfg, probeFormFrom(cfg));
    expect(r.problems).toEqual({});
    expect(sameConfig(r.config, cfg)).toBe(true);
    // a minimal intent without defaults stays minimal too
    const min = defaultIntent('probe', 'x');
    expect(sameConfig(applyProbeForm(min, probeFormFrom(min)).config, min)).toBe(true);
    expect(sameConfig(applyProbeForm({}, probeFormFrom({})).config, {})).toBe(true);
  });
  it('applies edits, keeps unknown keys and validates', () => {
    const cfg = { ...fixture('probe'), future_key: { a: 1 } } as Cfg;
    const f = probeFormFrom(cfg);
    f.hbInterval = '15';
    f.ping = '9.9.9.9\n1.1.1.1';
    f.app.targets = [...f.app.targets, { app: 'teams', url: 'https://teams.microsoft.com/', apdex: '800' }];
    f.labels = [{ key: 'area', value: 'keynote' }];
    f.wifi = { on: false, interval: '300' };
    const r = applyProbeForm(cfg, f);
    expect(r.problems).toEqual({});
    const hb = r.config['heartbeat'] as Cfg;
    expect(hb['interval_s']).toBe(15);
    expect(hb['ping']).toEqual(['9.9.9.9', '1.1.1.1']);
    expect(((r.config['tests'] as Cfg)['app'] as Cfg)['targets']).toHaveLength(2);
    expect(r.config['labels']).toEqual({ area: 'keynote' });
    expect(r.config['future_key']).toEqual({ a: 1 });
    expect(sameConfig(r.config, cfg)).toBe(false);
  });
  it('reports a problem per bad field and refuses reserved labels', () => {
    const f = probeFormFrom(fixture('probe'));
    f.hbInterval = '2';
    f.ping = 'bad host!';
    f.app.targets = [{ app: 'Bad Name', url: 'ftp://x', apdex: '0' }];
    f.path.peers = [{ peer: 'p1', address: 'x', port: '70000', udp: true, tcp: false, duration: '10', rate: '256' }];
    f.labels = [{ key: 'probe', value: 'x' }, { key: '__x', value: 'y' }, { key: 'ok', value: 'a\u0001' }];
    const p = applyProbeForm(fixture('probe'), f).problems;
    expect(Object.keys(p)).toEqual(expect.arrayContaining(['hbInterval', 'ping', 'app0', 'peer0', 'label0', 'label1', 'label2']));
  });
});

describe('collector and dashboard editor models', () => {
  it('round-trips the fixtures and edits retention and alerts', () => {
    const c = fixture('collector');
    expect(sameConfig(applyCollectorForm(c, collectorFormFrom(c)).config, c)).toBe(true);
    const f = collectorFormFrom(c);
    f.recordsDays = '14';
    f.voice = 'plain';
    f.boardUrl = 'https://board.example.com/';
    const r = applyCollectorForm(c, f);
    expect((r.config['retention'] as Cfg)['records_days']).toBe(14);
    expect((r.config['alerts'] as Cfg)['voice']).toBe('plain');
    f.metricsDays = '0';
    f.boardUrl = 'http://nope';
    expect(Object.keys(applyCollectorForm(c, f).problems)).toEqual(expect.arrayContaining(['metricsDays', 'boardUrl']));
  });
  it('dashboard: title and collectors; config.tls is not edited here (own endpoint)', () => {
    const d = fixture('dashboard');
    expect(sameConfig(applyDashboardForm(d, dashboardFormFrom(d)).config, d)).toBe(true);
    const f = dashboardFormFrom(d);
    f.title = 'Hall B wall';
    f.collectorIds = [];
    const r = applyDashboardForm(d, f);
    expect(r.config['title']).toBe('Hall B wall');
    expect(r.config['tls']).toEqual(d['tls']);
    expect(r.config['collector_ids']).toEqual([]);
    expect(r.config['collectors']).toEqual([]);
    f.title = '';
    f.url = 'http://insecure';
    expect(Object.keys(applyDashboardForm(d, f).problems)).toEqual(expect.arrayContaining(['title', 'url']));
  });
});

describe('versions', () => {
  it('orders semver for rollback targets', () => {
    expect(versionLess('0.1.0', '0.1.1')).toBe(true);
    expect(versionLess('0.2.0', '0.1.9')).toBe(false);
    expect(versionLess('1.0.0', '1.0.0')).toBe(false);
    expect(versionLess('0.1.9', '0.1.10')).toBe(true);
  });
});
