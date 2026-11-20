// Runner correlation sources <-> the runner component's `correlation` intent (runner.config.schema.json, M6). The manager
// compiles the privacy setting, the localhost channel and SSE (always off: no vendor documentation) itself; this form
// edits only the connector sources. Pure and unit-tested.
import { RE, intIn, splitList } from './validate';

type Cfg = Record<string, unknown>;
const isObj = (v: unknown): v is Cfg => v !== null && typeof v === 'object' && !Array.isArray(v);
const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
// eslint-disable-next-line no-control-regex
const CTRL = /[\x00-\x1f\x7f]/;

export interface RunnerForm {
  enabled: boolean;
  mistSites: string;                       // one Mist site id per line
  zoneMap: { zone: string; prefix: string; macs: string }[];
  appliances: { nePk: string; wan: string }[];
  wanUtil: boolean;
  syslogAllow: string;                     // CIDRs, comma or space separated
  ringMinutes: string;
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '');

export function runnerFormFrom(config: Cfg): RunnerForm {
  const c = isObj(config['correlation']) ? config['correlation'] : {};
  const src = isObj(c['sources']) ? c['sources'] : {};
  const mist = isObj(src['mist']) ? src['mist'] : {};
  const ec = isObj(src['ec']) ? src['ec'] : {};
  const sys = isObj(src['syslog']) ? src['syslog'] : {};
  return {
    enabled: c['enabled'] !== false,
    mistSites: (Array.isArray(mist['sites']) ? mist['sites'] : []).filter(isObj).map((s) => str(s['site_id'])).filter(Boolean).join('\n'),
    zoneMap: (Array.isArray(mist['zone_map']) ? mist['zone_map'] : []).filter(isObj).map((z) => ({ zone: str(z['zone']), prefix: str(z['ap_name_prefix']), macs: (Array.isArray(z['ap_macs']) ? z['ap_macs'] : []).join(', ') })),
    appliances: (Array.isArray(ec['appliances']) ? ec['appliances'] : []).filter(isObj).map((a) => ({ nePk: str(a['ne_pk']), wan: (Array.isArray(a['wan_interfaces']) ? a['wan_interfaces'] : []).join(', ') })),
    wanUtil: isObj(ec['wan_util']) ? ec['wan_util']['enabled'] === true : false,
    syslogAllow: (Array.isArray(sys['allow']) ? sys['allow'] : []).join(', '),
    ringMinutes: typeof sys['ring_minutes'] === 'number' ? String(sys['ring_minutes']) : '',
  };
}

export function runnerProblems(f: RunnerForm): Record<string, string> {
  const p: Record<string, string> = {};
  const sites = f.mistSites.split('\n').map((x) => x.trim()).filter(Boolean);
  if (sites.length > 64) p['mistSites'] = 'At most 64 sites.';
  else if (sites.some((x) => x.length > 64 || CTRL.test(x))) p['mistSites'] = 'Each id is at most 64 characters.';
  f.zoneMap.forEach((z, i) => {
    if (!RE.slug.test(z.zone)) p[`zone-${i}`] = 'A zone id (lowercase letters, digits, dashes).';
    else if (!z.prefix.trim() && splitList(z.macs).length === 0) p[`zone-${i}`] = 'Give an AP name prefix or AP MAC addresses.';
    if (z.prefix.length > 64 || CTRL.test(z.prefix)) p[`prefix-${i}`] = 'At most 64 characters.';
    if (splitList(z.macs).some((m) => !MAC.test(m))) p[`macs-${i}`] = 'Lower-case colon MACs such as 5c:5b:35:00:01:a0.';
  });
  if (f.zoneMap.length > 256) p['zoneMap'] = 'At most 256 zone rules.';
  f.appliances.forEach((a, i) => {
    if (!a.nePk.trim() || a.nePk.length > 128 || CTRL.test(a.nePk)) p[`ne-${i}`] = 'The appliance id (nePk), at most 128 characters.';
    if (splitList(a.wan).length > 16 || splitList(a.wan).some((w) => w.length > 32)) p[`wan-${i}`] = 'At most 16 interfaces of 32 characters.';
  });
  if (f.appliances.length > 8) p['appliances'] = 'At most 8 appliances.';
  const allow = splitList(f.syslogAllow);
  if (allow.length > 64 || allow.some((a) => !RE.ipv4Cidr.test(a))) p['syslogAllow'] = 'CIDRs such as 10.0.0.0/8, at most 64.';
  if (f.ringMinutes && intIn(f.ringMinutes, 1, 60) === null) p['ringMinutes'] = '1 to 60 minutes.';
  return p;
}

/** The new component config: untouched keys of the old one stay; `correlation` is rebuilt from the form. */
export function applyRunnerForm(old: Cfg, f: RunnerForm): Cfg {
  const prev = isObj(old['correlation']) ? old['correlation'] : {};
  const prevSrc = isObj(prev['sources']) ? prev['sources'] : {};
  const mist: Cfg = { ...(isObj(prevSrc['mist']) ? prevSrc['mist'] : {}) };
  const ec: Cfg = { ...(isObj(prevSrc['ec']) ? prevSrc['ec'] : {}) };
  const sys: Cfg = { ...(isObj(prevSrc['syslog']) ? prevSrc['syslog'] : {}) };
  const sites = f.mistSites.split('\n').map((x) => x.trim()).filter(Boolean);
  const keepName = new Map((Array.isArray(mist['sites']) ? mist['sites'] : []).filter(isObj).map((s) => [str(s['site_id']), s['name']]));
  if (sites.length) mist['sites'] = sites.map((id) => ({ site_id: id, ...(keepName.get(id) ? { name: keepName.get(id) } : {}) }));
  else delete mist['sites'];
  if (f.zoneMap.length) mist['zone_map'] = f.zoneMap.map((z) => ({ zone: z.zone, ...(z.prefix.trim() ? { ap_name_prefix: z.prefix.trim() } : {}), ...(splitList(z.macs).length ? { ap_macs: splitList(z.macs) } : {}) }));
  else delete mist['zone_map'];
  if (f.appliances.length) ec['appliances'] = f.appliances.map((a) => ({ ne_pk: a.nePk.trim(), ...(splitList(a.wan).length ? { wan_interfaces: splitList(a.wan) } : {}) }));
  else delete ec['appliances'];
  const prevWan = isObj(ec['wan_util']) ? ec['wan_util'] : {};
  if (f.wanUtil || Object.keys(prevWan).length) ec['wan_util'] = { ...prevWan, enabled: f.wanUtil };
  const allow = splitList(f.syslogAllow);
  if (allow.length) sys['allow'] = allow;
  else delete sys['allow'];
  if (f.ringMinutes) sys['ring_minutes'] = Number(f.ringMinutes);
  else delete sys['ring_minutes'];
  const sources: Cfg = {};
  for (const [k, v] of [['mist', mist], ['ec', ec], ['syslog', sys]] as const) if (Object.keys(v).length) sources[k] = v;
  const corr: Cfg = { ...prev, sources };
  if (!Object.keys(sources).length) delete corr['sources'];
  delete corr['sse']; // never part of the intent
  if (f.enabled) delete corr['enabled'];
  else corr['enabled'] = false;
  const next: Cfg = { ...old };
  if (Object.keys(corr).length) next['correlation'] = corr;
  else delete next['correlation'];
  return next;
}
