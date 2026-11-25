// Component intent: defaults for new components, the probe port picker, and the editors' form models.
// Everything here is pure (no DOM, no network) so it is unit-tested. A component's `config` is admin intent with no
// secrets (admin.yaml Component.config); editors merge their fields into a copy of it and keep every key they do not
// know about, so a config written by a newer manager survives a round trip through this UI.
import type { Iface, Shape } from '../api/types';
import { CTRL, RE, RESERVED_LABELS, intIn, numIn, splitList } from './validate';

export type Cfg = Record<string, unknown>;

const isObj = (v: unknown): v is Cfg => typeof v === 'object' && v !== null && !Array.isArray(v);
export const obj = (v: unknown): Cfg => (isObj(v) ? v : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : d);
const numStr = (v: unknown, d = ''): string => (typeof v === 'number' && Number.isFinite(v) ? String(v) : d);

/** Write `v` unless it is the default and the key was absent, so an untouched form never makes a config look edited. */
function setDef(o: Cfg, k: string, v: unknown, def: unknown): void {
  if (k in o || JSON.stringify(v) !== JSON.stringify(def)) o[k] = v;
}

/** Canonical form for comparing intents: absent, null, empty list and empty object are all "nothing". */
function canon(v: unknown): unknown {
  if (Array.isArray(v)) {
    const a = v.map(canon);
    return a.length ? a : undefined;
  }
  if (isObj(v)) {
    const o: Cfg = {};
    for (const k of Object.keys(v).sort()) {
      const c = canon(v[k]);
      if (c !== undefined && c !== null) o[k] = c;
    }
    return Object.keys(o).length ? o : undefined;
  }
  return v;
}

export function sameConfig(a: unknown, b: unknown): boolean {
  return JSON.stringify(canon(a) ?? null) === JSON.stringify(canon(b) ?? null);
}

// ---- new components (add-host wizard) -----------------------------------------------------------------------------

const PREFIX: Record<Shape, string> = { probe: 'probe', collector: 'col', dashboard: 'dash', runner: 'runner', speedtest: 'spd' };

export function defaultComponentId(shape: Shape, hostSlug: string): string {
  const base = `${PREFIX[shape]}-${hostSlug}`.replace(/-+/g, '-').replace(/-$/, '');
  return base.slice(0, 64).replace(/-$/, '');
}

/** Starting intent for a new component. No secrets, no wiring: the manager compiles those. */
export function defaultIntent(shape: Shape, hostName: string): Cfg {
  switch (shape) {
    case 'probe':
      return {
        mode: 'netns',
        heartbeat: { interval_s: 10, gateway: true, dhcp: true, dns: true, ping: ['1.1.1.1', '8.8.8.8'], dns_names: ['www.google.com', 'www.microsoft.com'] },
        tests: { dhcp: { interval_s: 300 }, dns: { interval_s: 300, names: ['www.google.com', 'teams.microsoft.com'] }, app: null, throughput: null, path: null, wifi: null },
      };
    case 'collector':
      return {
        retention: { metrics_days: 30, records_days: 7 },
        alerts: { enabled: true, voice: 'sysadmin', hold_down_s: 20, hold_back_s: 60, reopen_s: 300, calm_s: 600 },
      };
    case 'dashboard':
      return { title: `HPE EXP - ${hostName}`.slice(0, 128), auth: { session_hours: 12, local_users: true, noc_tokens: true }, tls: { mode: 'self_signed' } };
    case 'runner':
      return {};
    default:
      return {};
  }
}

// ---- probe port picker -----------------------------------------------------------------------------------------

export type PortRole = 'none' | 'client' | 'target' | 'wifi';
export interface PortDraft { role: PortRole; address: string; gateway: string; ssid: string; network: string; reference: boolean }
export const emptyDraft = (): PortDraft => ({ role: 'none', address: '', gateway: '', ssid: '', network: '', reference: false });
const NETWORK_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;

/** Why an interface cannot carry tests, or null when it can. The management interface is never selectable. */
export function ifaceBlockReason(i: Iface, ownProbe?: string): string | null {
  if (i.in_use_by === 'mgmt' || i.default_route) return 'Management interface: it carries the default route and is never used for tests.';
  if (i.in_use_by.startsWith('probe:') && i.in_use_by !== `probe:${ownProbe ?? ''}`) return `Already used by ${i.in_use_by.replace('probe:', 'probe port ')}.`;
  return null;
}

/** The picker rows for a probe's current ports (so the component page edits what is configured, not a blank slate). */
export function draftsFromPorts(ports: unknown): Record<string, PortDraft> {
  const out: Record<string, PortDraft> = {};
  if (!Array.isArray(ports)) return out;
  for (const p of ports) {
    if (!p || typeof p !== 'object') continue;
    const c = p as Cfg;
    const iface = typeof c['iface'] === 'string' ? c['iface'] : null;
    const role = c['role'];
    if (!iface || (role !== 'client' && role !== 'target' && role !== 'wifi')) continue;
    out[iface] = { role, address: typeof c['address'] === 'string' ? c['address'] : '', gateway: typeof c['gateway'] === 'string' ? c['gateway'] : '', ssid: typeof c['ssid'] === 'string' ? c['ssid'] : '',
      network: typeof c['network'] === 'string' ? c['network'] : '', reference: c['reference'] === true };
  }
  return out;
}

export interface PortsResult { ports: Cfg[]; errors: Record<string, string> }

/** Turn the picker's choices into the `ports` array of PUT components/{id}/ports. Ids are c01.., s01.., w01... */
export function buildPorts(ifaces: Iface[], drafts: Record<string, PortDraft>, ownProbe?: string): PortsResult {
  const ports: Cfg[] = [];
  const errors: Record<string, string> = {};
  const n = { client: 0, target: 0, wifi: 0 };
  const targetNets = new Set<string>();
  for (const i of ifaces) {
    const d = drafts[i.name];
    if (!d || d.role === 'none') continue;
    const block = ifaceBlockReason(i, ownProbe);
    if (block) {
      errors[i.name] = block;
      continue;
    }
    n[d.role] += 1;
    const id = `${d.role === 'client' ? 'c' : d.role === 'target' ? 's' : 'w'}${String(n[d.role]).padStart(2, '0')}`;
    // the site lines board (CR-site-lines-board): which network an attendee port measures; manager-only
    const board: Cfg = {};
    if (d.role === 'client' || d.role === 'wifi') {
      const net = d.network.trim().toLowerCase();
      if (net && !NETWORK_RE.test(net)) errors[i.name] = 'Network: lower-case letters, digits and dashes, for example hall-a.';
      else if (net) {
        board['network'] = net;
        if (d.reference) board['reference'] = true;
      } else if (d.reference) errors[i.name] = 'Give the reference port a network name.';
    }
    if (d.role === 'client') ports.push({ id, iface: i.name, role: 'client', ...board });
    else if (d.role === 'wifi') {
      const p: Cfg = { id, iface: i.name, role: 'wifi', ...board };
      if (d.ssid.trim()) {
        if (d.ssid.length > 32 || CTRL.test(d.ssid)) errors[i.name] = 'SSID must be at most 32 characters without control characters.';
        else p['ssid'] = d.ssid.trim();
      }
      ports.push(p);
    } else {
      if (!RE.ipv4Cidr.test(d.address.trim())) errors[i.name] = 'Enter the target address as a.b.c.d/len, for example 10.1.0.250/24.';
      else if (!RE.ipv4.test(d.gateway.trim())) errors[i.name] = 'Enter the gateway as an IPv4 address.';
      else if (targetNets.has(d.address.trim())) errors[i.name] = 'Another target port already uses this address.';
      else {
        targetNets.add(d.address.trim());
        ports.push({ id, iface: i.name, role: 'target', address: d.address.trim(), gateway: d.gateway.trim() });
      }
    }
  }
  return { ports, errors };
}

// ---- probe editor -----------------------------------------------------------------------------------------------

export interface AppRow { app: string; url: string; apdex: string }
export interface PeerRow { peer: string; address: string; port: string; udp: boolean; tcp: boolean; duration: string; rate: string }
export interface LabelRow { key: string; value: string }
export interface TestForm { on: boolean; interval: string }
export interface ProbeForm {
  hbInterval: string; hbGateway: boolean; hbDhcp: boolean; hbDns: boolean; ping: string; dnsNames: string; altResolver: string; traceTarget: string;
  dhcp: TestForm;
  dns: TestForm & { names: string };
  app: TestForm & { targets: AppRow[] };
  throughput: TestForm & { cloudflare: boolean; iperf3: boolean };
  path: TestForm & { peers: PeerRow[] };
  wifi: TestForm;
  labels: LabelRow[];
}

const testOn = (v: unknown): boolean => isObj(v);

export function probeFormFrom(config: Cfg): ProbeForm {
  const hb = obj(config['heartbeat']);
  const tests = obj(config['tests']);
  const t = (k: string): Cfg => obj(tests[k]);
  const providers = arr(t('throughput')['providers']);
  return {
    hbInterval: numStr(hb['interval_s'], '10'), hbGateway: hb['gateway'] !== false, hbDhcp: hb['dhcp'] !== false, hbDns: hb['dns'] !== false,
    ping: arr(hb['ping']).map(String).join('\n'), dnsNames: arr(hb['dns_names']).map(String).join('\n'),
    altResolver: str(hb['alternate_resolver']), traceTarget: str(obj(hb['trace'])['target']),
    dhcp: { on: testOn(tests['dhcp']), interval: numStr(t('dhcp')['interval_s'], '300') },
    dns: { on: testOn(tests['dns']), interval: numStr(t('dns')['interval_s'], '300'), names: arr(t('dns')['names']).map(String).join('\n') },
    app: {
      on: testOn(tests['app']), interval: numStr(t('app')['interval_s'], '300'),
      targets: arr(t('app')['targets']).map((x) => ({ app: str(obj(x)['app']), url: str(obj(x)['url']), apdex: numStr(obj(x)['apdex_t_ms'], '500') })),
    },
    throughput: { on: testOn(tests['throughput']), interval: numStr(t('throughput')['interval_s'], '600'), cloudflare: providers.includes('cloudflare'), iperf3: providers.includes('iperf3') },
    path: {
      on: testOn(tests['path']), interval: numStr(t('path')['interval_s'], '60'),
      peers: arr(t('path')['peers']).map((x) => {
        const p = obj(x);
        const proto = arr(p['proto']);
        return { peer: str(p['peer']), address: str(p['address']), port: numStr(p['port']), udp: proto.includes('udp'), tcp: proto.includes('tcp'), duration: numStr(p['duration_s'], '10'), rate: numStr(p['rate_kbps'], '256') };
      }),
    },
    wifi: { on: testOn(tests['wifi']), interval: numStr(t('wifi')['interval_s'], '300') },
    labels: Object.entries(obj(config['labels'])).map(([key, value]) => ({ key, value: str(value) })),
  };
}

export type Problems = Record<string, string>;

function setOrDelete(o: Cfg, k: string, v: unknown): void {
  if (v === undefined || v === '' || (Array.isArray(v) && v.length === 0)) delete o[k];
  else o[k] = v;
}

/** Merge the form into a copy of `config`. Returns the problems per field name (empty = valid). */
export function applyProbeForm(config: Cfg, f: ProbeForm): { config: Cfg; problems: Problems } {
  const out: Cfg = JSON.parse(JSON.stringify(config)) as Cfg;
  const p: Problems = {};

  const hb = obj(out['heartbeat']);
  const hbi = intIn(f.hbInterval, 5, 60);
  if (hbi === null) p['hbInterval'] = 'Heartbeat interval is 5 to 60 seconds.';
  else setDef(hb, 'interval_s', hbi, 10);
  setDef(hb, 'gateway', f.hbGateway, true);
  setDef(hb, 'dhcp', f.hbDhcp, true);
  setDef(hb, 'dns', f.hbDns, true);
  const ping = splitList(f.ping);
  if (ping.length > 16) p['ping'] = 'At most 16 ping targets.';
  else if (ping.some((x) => !RE.hostOrIp.test(x))) p['ping'] = 'Ping targets must be host names or IPv4 addresses.';
  else setDef(hb, 'ping', ping, []);
  const names = splitList(f.dnsNames);
  if (names.length > 32) p['dnsNames'] = 'At most 32 heartbeat DNS names.';
  else if (names.some((x) => !RE.hostOrIp.test(x))) p['dnsNames'] = 'DNS names may contain letters, digits, dots and dashes only.';
  else setDef(hb, 'dns_names', names, []);
  if (f.altResolver.trim()) {
    if (!RE.hostOrIp.test(f.altResolver.trim())) p['altResolver'] = 'Enter a host name or IPv4 address.';
    else hb['alternate_resolver'] = f.altResolver.trim();
  } else delete hb['alternate_resolver'];
  if (f.traceTarget.trim()) {
    if (!RE.hostOrIp.test(f.traceTarget.trim())) p['traceTarget'] = 'Enter a host name or IPv4 address.';
    else hb['trace'] = { ...obj(hb['trace']), target: f.traceTarget.trim() };
  } else delete hb['trace'];
  if (Object.keys(hb).length || 'heartbeat' in out) out['heartbeat'] = hb;

  const tests = obj(out['tests']);
  const interval = (key: string, tf: TestForm): number | null => {
    const v = intIn(tf.interval, 10, 86400);
    if (v === null && tf.on) p[`${key}Interval`] = 'Interval is 10 to 86400 seconds.';
    return v;
  };
  const DEFAULT_INTERVAL: Record<string, number> = { dhcp: 300, dns: 300, app: 300, throughput: 600, path: 60, wifi: 300 };
  const put = (key: string, tf: TestForm, extra: (o: Cfg) => void): void => {
    if (!tf.on) {
      if (tests[key] != null) tests[key] = null;
      return;
    }
    const o = obj(tests[key]);
    const iv = interval(key, tf);
    if (iv !== null) setDef(o, 'interval_s', iv, DEFAULT_INTERVAL[key]);
    extra(o);
    tests[key] = o;
  };
  put('dhcp', f.dhcp, () => undefined);
  put('dns', f.dns, (o) => {
    const ns = splitList(f.dns.names);
    if (ns.length > 64) p['dnsTestNames'] = 'At most 64 names.';
    else if (ns.some((x) => !RE.hostOrIp.test(x))) p['dnsTestNames'] = 'DNS names may contain letters, digits, dots and dashes only.';
    else setDef(o, 'names', ns, []);
  });
  put('app', f.app, (o) => {
    if (f.app.targets.length > 64) p['appTargets'] = 'At most 64 app targets.';
    const seen = new Set<string>();
    const targets: Cfg[] = [];
    f.app.targets.forEach((r, i) => {
      if (!RE.slug.test(r.app.trim())) p[`app${i}`] = 'App name: lowercase letters, digits and dashes.';
      else if (seen.has(r.app.trim())) p[`app${i}`] = 'App names must be unique.';
      else if (!RE.httpUrl.test(r.url.trim()) || r.url.length > 512) p[`app${i}`] = 'URL must start with http:// or https://.';
      else {
        const a = numIn(r.apdex, 1, 60000);
        if (a === null) p[`app${i}`] = 'Apdex T is 1 to 60000 ms.';
        else targets.push({ app: r.app.trim(), url: r.url.trim(), apdex_t_ms: a });
      }
      seen.add(r.app.trim());
    });
    setDef(o, 'targets', targets, []);
  });
  put('throughput', f.throughput, (o) => {
    const prov = [f.throughput.cloudflare ? 'cloudflare' : null, f.throughput.iperf3 ? 'iperf3' : null].filter(Boolean);
    if (prov.length === 0) p['throughputProviders'] = 'Pick at least one provider.';
    else setDef(o, 'providers', prov, ['cloudflare']);
  });
  put('path', f.path, (o) => {
    if (f.path.peers.length > 16) p['pathPeers'] = 'At most 16 path peers.';
    const peers: Cfg[] = [];
    f.path.peers.forEach((r, i) => {
      const port = intIn(r.port, 1, 65535);
      const dur = numIn(r.duration, 1, 60);
      const rate = intIn(r.rate, 1, 1000000);
      const proto = [r.udp ? 'udp' : null, r.tcp ? 'tcp' : null].filter(Boolean);
      if (!RE.slug.test(r.peer.trim())) p[`peer${i}`] = 'Peer name: lowercase letters, digits and dashes.';
      else if (!RE.hostOrIp.test(r.address.trim())) p[`peer${i}`] = 'Address must be a host name or IPv4 address.';
      else if (port === null) p[`peer${i}`] = 'Port is 1 to 65535.';
      else if (proto.length === 0) p[`peer${i}`] = 'Pick udp, tcp or both.';
      else if (dur === null) p[`peer${i}`] = 'Duration is 1 to 60 seconds.';
      else if (rate === null) p[`peer${i}`] = 'Rate is 1 to 1000000 kbit/s.';
      else peers.push({ peer: r.peer.trim(), address: r.address.trim(), port, proto, duration_s: dur, rate_kbps: rate });
    });
    setDef(o, 'peers', peers, []);
  });
  put('wifi', f.wifi, () => undefined);
  if (Object.keys(tests).length || 'tests' in out) out['tests'] = tests;

  const labels: Cfg = {};
  if (f.labels.length > 20) p['labels'] = 'At most 20 labels.';
  f.labels.forEach((l, i) => {
    const k = l.key.trim();
    if (!RE.ident.test(k) || k.startsWith('__') || RESERVED_LABELS.includes(k)) p[`label${i}`] = 'Label names are identifiers (letters, digits, underscore), not probe, site, outcome, target.';
    else if (l.value.length > 128 || CTRL.test(l.value)) p[`label${i}`] = 'Label values are at most 128 characters without control characters.';
    else if (k in labels) p[`label${i}`] = 'Label names must be unique.';
    else labels[k] = l.value;
  });
  setOrDelete(out, 'labels', Object.keys(labels).length ? labels : undefined);
  return { config: out, problems: p };
}

// ---- collector editor -------------------------------------------------------------------------------------------

export interface CollectorForm {
  metricsDays: string; recordsDays: string;
  alertsOn: boolean; boardUrl: string; timezone: string; voice: 'plain' | 'sysadmin'; holdDown: string; holdBack: string; reopen: string; calm: string;
}

export function collectorFormFrom(c: Cfg): CollectorForm {
  const r = obj(c['retention']);
  const a = obj(c['alerts']);
  return {
    metricsDays: numStr(r['metrics_days'], '30'), recordsDays: numStr(r['records_days'], '7'),
    alertsOn: a['enabled'] !== false, boardUrl: str(a['board_url']), timezone: str(a['timezone']), voice: a['voice'] === 'plain' ? 'plain' : 'sysadmin',
    holdDown: numStr(a['hold_down_s'], '20'), holdBack: numStr(a['hold_back_s'], '60'), reopen: numStr(a['reopen_s'], '300'), calm: numStr(a['calm_s'], '600'),
  };
}

export function applyCollectorForm(config: Cfg, f: CollectorForm): { config: Cfg; problems: Problems } {
  const out: Cfg = JSON.parse(JSON.stringify(config)) as Cfg;
  const p: Problems = {};
  const ret = obj(out['retention']);
  const md = intIn(f.metricsDays, 1, 3650);
  const rd = intIn(f.recordsDays, 1, 3650);
  if (md === null) p['metricsDays'] = 'Metrics retention is 1 to 3650 days.'; else setDef(ret, 'metrics_days', md, 30);
  if (rd === null) p['recordsDays'] = 'Records retention is 1 to 3650 days.'; else setDef(ret, 'records_days', rd, 7);
  if (Object.keys(ret).length || 'retention' in out) out['retention'] = ret;
  const al = obj(out['alerts']);
  setDef(al, 'enabled', f.alertsOn, true);
  if (f.boardUrl.trim()) {
    if (f.boardUrl.length > 512 || !RE.httpsUrl.test(f.boardUrl.trim())) p['boardUrl'] = 'Board URL must be an https:// URL.';
    else al['board_url'] = f.boardUrl.trim();
  } else delete al['board_url'];
  if (f.timezone.trim()) {
    if (!RE.timezone.test(f.timezone.trim())) p['timezone'] = 'Use an IANA zone such as America/Chicago, or UTC.';
    else al['timezone'] = f.timezone.trim();
  } else delete al['timezone'];
  setDef(al, 'voice', f.voice, 'sysadmin');
  const hold: [string, string, string, number][] = [['holdDown', 'hold_down_s', f.holdDown, 20], ['holdBack', 'hold_back_s', f.holdBack, 60], ['reopen', 'reopen_s', f.reopen, 300], ['calm', 'calm_s', f.calm, 600]];
  for (const [key, field, v, def] of hold) {
    const n = intIn(v, 0, 86400);
    if (n === null) p[key] = 'Enter 0 to 86400 seconds.'; else setDef(al, field, n, def);
  }
  if (Object.keys(al).length || 'alerts' in out) out['alerts'] = al;
  return { config: out, problems: p };
}

// ---- dashboard editor -------------------------------------------------------------------------------------------

export interface DashboardForm { title: string; url: string; sessionHours: string; localUsers: boolean; nocTokens: boolean; collectorIds: string[] }

export function dashboardFormFrom(c: Cfg): DashboardForm {
  const auth = obj(c['auth']);
  const ids = Array.isArray(c['collector_ids']) ? arr(c['collector_ids']).map(String) : arr(c['collectors']).map((x) => str(obj(x)['collector_id'])).filter(Boolean);
  return {
    title: str(c['title']), url: str(c['url']),
    sessionHours: numStr(auth['session_hours'], '12'), localUsers: auth['local_users'] !== false, nocTokens: auth['noc_tokens'] !== false, collectorIds: ids,
  };
}

export function applyDashboardForm(config: Cfg, f: DashboardForm): { config: Cfg; problems: Problems } {
  const out: Cfg = JSON.parse(JSON.stringify(config)) as Cfg;
  const p: Problems = {};
  const title = f.title.trim();
  if (title.length < 1 || title.length > 128 || CTRL.test(title)) p['title'] = 'Title is 1 to 128 characters without control characters.'; else out['title'] = title;
  if (f.url.trim()) {
    if (f.url.length > 512 || !RE.httpsUrl.test(f.url.trim())) p['url'] = 'The dashboard address must be an https:// URL.'; else out['url'] = f.url.trim().replace(/\/+$/, '');
  } else delete out['url'];
  const auth = obj(out['auth']);
  const sh = intIn(f.sessionHours, 1, 168);
  if (sh === null) p['sessionHours'] = 'Session length is 1 to 168 hours.'; else setDef(auth, 'session_hours', sh, 12);
  setDef(auth, 'local_users', f.localUsers, true);
  setDef(auth, 'noc_tokens', f.nocTokens, true);
  if (Object.keys(auth).length || 'auth' in out) out['auth'] = auth;
  // The certificate (mode + provided pair) has its own write-only endpoint (PUT dashboards/{id}/tls); config.tls is left as is.
  // Intent lists collector ids; the manager fills URL, pin and token when each collector has reported (05-manager.md section 7).
  const derived = dashboardFormFrom(config).collectorIds;
  if ('collector_ids' in out || JSON.stringify(derived) !== JSON.stringify(f.collectorIds)) out['collector_ids'] = [...f.collectorIds];
  if (Array.isArray(out['collectors'])) out['collectors'] = (out['collectors'] as unknown[]).filter((x) => f.collectorIds.includes(str(obj(x)['collector_id'])));
  return { config: out, problems: p };
}

/** Probe features the 0.2.0 probe does not have yet (milestone M4, probe/README.md): the probe skips a configured one
 * and logs "not available in this build". The UI says so and does not offer to switch them on. */
export const PROBE_M4_NOTE = 'Not in the 0.2.0 probe yet (milestone M4): the probe would skip it. You can still switch an existing one off.';
export const PROBE_M4_ROLE_NOTE = 'not in 0.2.0 probes (M4)';
