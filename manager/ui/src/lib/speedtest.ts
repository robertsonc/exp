// Speedtest settings form <-> PUT body (admin.yaml SpeedtestSettingsPut). Pure and unit-tested. Everything typed by the
// admin is a string in the draft; `problems()` mirrors the schema bounds so the admin sees a reason before saving, and
// `toBody()` emits only what was filled in (an empty optional field is omitted, so the box keeps its default).
import type { SpeedtestSettings } from '../api/types';
import { CTRL, RE, intIn, numIn, splitList } from './validate';

export const HEX = /^#[0-9A-Fa-f]{6}$/;
const BCP47 = /^[a-z]{2}(-[A-Za-z]{2,4})?$/;
const COPY_KEY = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
// eslint-disable-next-line no-control-regex
const TEXT_CTRL = /[\x00-\x08\x0b-\x1f\x7f]/;

export const LOGO_MAX_BYTES = 256 * 1024;
export const LOGO_TYPES = ['image/png', 'image/svg+xml', 'image/jpeg'] as const;
export type LogoType = (typeof LOGO_TYPES)[number];

export const LIMIT_KEYS = ['tests_per_10min_per_ip', 'max_concurrent_per_ip', 'max_concurrent_tests', 'max_concurrent_internet', 'bytes_local', 'bytes_internet', 'leg_token_ttl_s', 'result_deadline_s'] as const;
export type LimitKey = (typeof LIMIT_KEYS)[number];
/** Bounds from speedtest.config.schema.json, with the defaults of CR-m6-spec-resolutions as placeholders. */
export const LIMIT_META: Record<LimitKey, { label: string; min: number; max: number; def: number }> = {
  tests_per_10min_per_ip: { label: 'Tests per 10 min per client', min: 1, max: 1000, def: 6 },
  max_concurrent_per_ip: { label: 'Concurrent tests per client', min: 1, max: 100, def: 1 },
  max_concurrent_tests: { label: 'Concurrent tests on the box', min: 1, max: 1000, def: 20 },
  max_concurrent_internet: { label: 'Internet-leg slots', min: 1, max: 1000, def: 10 },
  bytes_local: { label: 'On-network bytes per test', min: 1_000_000, max: 10_000_000_000, def: 200_000_000 },
  bytes_internet: { label: 'Internet bytes per test', min: 1_000_000, max: 10_000_000_000, def: 200_000_000 },
  leg_token_ttl_s: { label: 'Leg token lifetime (s)', min: 10, max: 300, def: 60 },
  result_deadline_s: { label: 'Result deadline (s)', min: 30, max: 900, def: 180 },
};

export interface Draft {
  title: string;
  primary: string; accent: string; background: string; text: string;
  languages: string;
  copy: string;
  removeLogo: boolean;
  consent: string;
  zones: { id: string; name: string }[];
  subnets: { cidr: string; zone: string }[];
  down: string; up: string;
  limits: Record<LimitKey, string>;
  internetEnabled: boolean; autoPause: string;
  retention: string; scrub: boolean;
  showNetwork: boolean;
  placement: '' | 'core' | 'dc' | 'other';
  hostname: string; listenIp: string; requireReal: boolean; clientSubnets: string; translated: string;
  tlsMode: 'none' | 'provided';
  dnsEnabled: boolean; dnsZone: string;
  gateway: string; edge: string; edge1: string; pathNote: string;
  guardIface: string; guardUtil: string; guardMin: string;
}

const s = (v: unknown): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '');

export function draftFrom(x: SpeedtestSettings): Draft {
  const c = x.branding?.colors ?? {};
  const l = x.limits ?? {};
  return {
    title: x.branding?.title ?? '',
    primary: c.primary ?? '', accent: c.accent ?? '', background: c.background ?? '', text: c.text ?? '',
    languages: (x.branding?.languages ?? []).join(', '),
    copy: Object.entries(x.branding?.copy ?? {}).map(([k, v]) => `${k}=${v}`).join('\n'),
    removeLogo: false,
    consent: x.consent.text,
    zones: (x.zones ?? []).map((z) => ({ ...z })),
    subnets: (x.zone_labels?.subnets ?? []).map((z) => ({ ...z })),
    down: s(x.targets?.down_mbps), up: s(x.targets?.up_mbps),
    limits: Object.fromEntries(LIMIT_KEYS.map((k) => [k, s(l[k])])) as Record<LimitKey, string>,
    internetEnabled: x.internet_leg?.enabled ?? true, autoPause: s(x.internet_leg?.auto_pause_wan_util_pct),
    retention: s(x.privacy?.retention_days), scrub: x.privacy?.scrub_after_diagnosis === true,
    showNetwork: x.display?.show_network_details === true,
    placement: x.serve?.placement ?? '',
    hostname: x.serve?.hostname ?? '', listenIp: x.serve?.listen_ip ?? '', requireReal: x.serve?.require_real_client_ip ?? true,
    clientSubnets: (x.serve?.client_subnets ?? []).join(', '), translated: (x.serve?.translated_addresses ?? []).join(', '),
    tlsMode: x.tls?.mode ?? 'none',
    dnsEnabled: x.dns_leg?.enabled === true, dnsZone: x.dns_leg?.zone ?? '',
    gateway: x.path?.gateway ?? '', edge: x.path?.edge ?? '', edge1: x.path?.edge1 ?? '', pathNote: x.path?.note ?? '',
    guardIface: x.core_guard?.iface ?? '', guardUtil: s(x.core_guard?.util_pct), guardMin: s(x.core_guard?.min_bytes),
  };
}

export function parseCopy(text: string): { entries: [string, string][]; error: string | null } {
  const entries: [string, string][] = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const i = line.indexOf('=');
    if (i < 1) return { entries, error: `"${line.slice(0, 40)}" needs the form key=text.` };
    const k = line.slice(0, i).trim();
    const v = line.slice(i + 1).trim();
    if (!COPY_KEY.test(k)) return { entries, error: `"${k.slice(0, 40)}" is not a valid key (letters, digits and underscores).` };
    if (v.length > 280 || CTRL.test(v)) return { entries, error: `The text of ${k} must be at most 280 characters without control characters.` };
    entries.push([k, v]);
  }
  if (entries.length > 40) return { entries, error: 'At most 40 copy entries.' };
  return { entries, error: null };
}

const ip = (v: string): boolean => RE.ipv4.test(v);
const listIssue = (v: string, ok: (x: string) => boolean, max: number, what: string): string | null => {
  const l = splitList(v);
  if (l.length > max) return `At most ${max} entries.`;
  const bad = l.find((x) => !ok(x));
  return bad ? `"${bad.slice(0, 40)}" is not ${what}.` : null;
};

export function problems(d: Draft): Record<string, string> {
  const p: Record<string, string> = {};
  const set = (k: string, m: string | null) => { if (m) p[k] = m; };
  set('title', d.title.length > 80 || CTRL.test(d.title) ? 'At most 80 characters, no control characters.' : null);
  for (const k of ['primary', 'accent', 'background', 'text'] as const) set(k, d[k] && !HEX.test(d[k]) ? 'Use a colour like #01a982.' : null);
  const langs = splitList(d.languages);
  set('languages', langs.length > 8 ? 'At most 8 languages.' : langs.find((l) => !BCP47.test(l)) ? 'Use language tags such as en or de-CH.' : new Set(langs).size !== langs.length ? 'Each language once.' : null);
  set('copy', parseCopy(d.copy).error);
  set('consent', d.consent.trim() === '' ? 'The consent text is required.' : d.consent.length > 2000 ? 'At most 2000 characters.' : TEXT_CTRL.test(d.consent) ? 'No control characters.' : null);
  const ids = d.zones.map((z) => z.id);
  d.zones.forEach((z, i) => {
    set(`zone-id-${i}`, !RE.slug.test(z.id) ? 'Lowercase letters, digits and dashes.' : ids.indexOf(z.id) !== i ? 'Each zone id once.' : null);
    set(`zone-name-${i}`, z.name.length > 64 || CTRL.test(z.name) ? 'At most 64 characters.' : null);
  });
  if (d.zones.length > 256) p['zones'] = 'At most 256 zones.';
  const known = new Set(ids);
  d.subnets.forEach((n, i) => {
    set(`subnet-cidr-${i}`, !RE.ipv4Cidr.test(n.cidr) ? 'Use a CIDR such as 10.60.0.0/16.' : d.subnets.findIndex((x) => x.cidr === n.cidr) !== i ? 'Each subnet once.' : null);
    set(`subnet-zone-${i}`, !RE.slug.test(n.zone) ? 'Choose a zone.' : known.size > 0 && !known.has(n.zone) ? 'Not one of the zones above.' : null);
  });
  if (d.subnets.length > 256) p['subnets'] = 'At most 256 subnets.';
  set('down', d.down && numIn(d.down, 0.1, 100000) === null ? '0.1 to 100000 Mb/s.' : null);
  set('up', d.up && numIn(d.up, 0.1, 100000) === null ? '0.1 to 100000 Mb/s.' : null);
  for (const k of LIMIT_KEYS) { const m = LIMIT_META[k]; set(`limit-${k}`, d.limits[k] && intIn(d.limits[k], m.min, m.max) === null ? `${m.min} to ${m.max}.` : null); }
  set('autoPause', d.autoPause && intIn(d.autoPause, 1, 100) === null ? '1 to 100 percent.' : null);
  set('retention', d.retention && intIn(d.retention, 1, 365) === null ? '1 to 365 days.' : null);
  const listen = d.listenIp.trim();
  set('listenIp', listen && (!ip(listen) || listen === '0.0.0.0' || listen.startsWith('127.') || Number(listen.split('.')[0]) >= 224) ? 'A unicast address of the speedtest box (not 0.0.0.0 or loopback).' : null);
  set('hostname', d.hostname && !RE.hostOrIp.test(d.hostname) ? 'A host name or address without spaces.' : null);
  set('clientSubnets', listIssue(d.clientSubnets, (x) => RE.ipv4Cidr.test(x), 64, 'a CIDR'));
  set('translated', listIssue(d.translated, ip, 64, 'an IPv4 address'));
  const serving = d.hostname.trim() !== '' || listen !== '';
  if (serving && (d.hostname.trim() === '' || listen === '')) p['serve'] = 'Give both the host name and the listen address, or neither.';
  if (d.requireReal && serving && splitList(d.clientSubnets).length === 0 && d.subnets.length === 0) p['clientSubnets'] = 'Requiring the real client IP needs the attendee subnets (here or in the zone labels).';
  if (d.dnsEnabled && !d.dnsZone.trim()) p['dnsZone'] = 'Give the zone the box answers for, for example t.speed.example.';
  else set('dnsZone', d.dnsZone && !RE.hostOrIp.test(d.dnsZone) ? 'A DNS name without spaces.' : null);
  set('gateway', d.gateway && d.gateway !== 'auto' && !ip(d.gateway) ? 'auto or an IPv4 address.' : null);
  set('edge', d.edge && !ip(d.edge) ? 'An IPv4 address or empty.' : null);
  set('edge1', d.edge1 && d.edge1 !== 'auto' && !ip(d.edge1) ? 'auto, an IPv4 address or empty.' : null);
  set('pathNote', d.pathNote.length > 200 || CTRL.test(d.pathNote) ? 'At most 200 characters.' : null);
  set('guardIface', d.guardIface && !/^[A-Za-z0-9_.:-]{1,15}$/.test(d.guardIface) ? 'An interface name (at most 15 characters).' : null);
  set('guardUtil', d.guardUtil && intIn(d.guardUtil, 1, 100) === null ? '1 to 100 percent.' : null);
  set('guardMin', d.guardMin && intIn(d.guardMin, 100000, 1_000_000_000) === null ? '100000 to 1000000000 bytes.' : null);
  return p;
}

const num = (v: string): number => Number(v.trim());
const obj = (o: Record<string, unknown>): Record<string, unknown> | undefined => (Object.keys(o).length ? o : undefined);

/** The PUT body. Call only when `problems(d)` is empty. `logo` is the stored logo artifact id (kept unless removed). */
export function toBody(d: Draft, logo: string | null | undefined): SpeedtestSettings {
  const body: Record<string, unknown> = { consent: { text: d.consent } };
  const set = (k: string, v: unknown) => { if (v !== undefined) body[k] = v; };
  const colors = obj({ ...(d.primary ? { primary: d.primary } : {}), ...(d.accent ? { accent: d.accent } : {}), ...(d.background ? { background: d.background } : {}), ...(d.text ? { text: d.text } : {}) });
  const langs = splitList(d.languages);
  const copy = Object.fromEntries(parseCopy(d.copy).entries);
  const branding = obj({
    ...(d.title ? { title: d.title } : {}), ...(colors ? { colors } : {}), ...(langs.length ? { languages: langs } : {}), ...(Object.keys(copy).length ? { copy } : {}),
    ...(d.removeLogo ? { logo_artifact: null } : logo ? { logo_artifact: logo } : {}),
  });
  set('branding', branding);
  if (d.zones.length) set('zones', d.zones.map((z) => ({ id: z.id, name: z.name })));
  if (d.subnets.length) set('zone_labels', { subnets: d.subnets.map((n) => ({ cidr: n.cidr, zone: n.zone })) });
  set('display', d.showNetwork ? { show_network_details: true } : undefined);
  set('targets', obj({ ...(d.down ? { down_mbps: num(d.down) } : {}), ...(d.up ? { up_mbps: num(d.up) } : {}) }));
  set('limits', obj(Object.fromEntries(LIMIT_KEYS.filter((k) => d.limits[k].trim() !== '').map((k) => [k, num(d.limits[k])]))));
  set('internet_leg', { enabled: d.internetEnabled, provider: 'cloudflare', ...(d.autoPause ? { auto_pause_wan_util_pct: num(d.autoPause) } : {}) });
  set('privacy', { ...(d.retention ? { retention_days: num(d.retention) } : {}), scrub_after_diagnosis: d.scrub });
  const cg = obj({ ...(d.guardIface ? { iface: d.guardIface } : {}), ...(d.guardUtil ? { util_pct: num(d.guardUtil) } : {}), ...(d.guardMin ? { min_bytes: num(d.guardMin) } : {}) });
  set('core_guard', cg);
  if (d.hostname.trim() && d.listenIp.trim()) {
    const cs = splitList(d.clientSubnets);
    const tr = splitList(d.translated);
    set('serve', {
      ...(d.placement ? { placement: d.placement } : {}), hostname: d.hostname.trim(), listen_ip: d.listenIp.trim(), require_real_client_ip: d.requireReal,
      ...(cs.length ? { client_subnets: cs } : {}), ...(tr.length ? { translated_addresses: tr } : {}),
    });
  }
  set('tls', { mode: d.tlsMode });
  if (d.dnsEnabled || d.dnsZone) set('dns_leg', { enabled: d.dnsEnabled, ...(d.dnsZone ? { zone: d.dnsZone } : {}) });
  set('path', obj({ ...(d.gateway ? { gateway: d.gateway } : {}), ...(d.edge ? { edge: d.edge } : {}), ...(d.edge1 ? { edge1: d.edge1 } : {}), ...(d.pathNote ? { note: d.pathNote } : {}) }));
  return body as unknown as SpeedtestSettings;
}

// ---- logo --------------------------------------------------------------------------------------------------------

/** Why a chosen file cannot be the logo (type and size bounds the Worker enforces again, plus the magic number). */
export function logoProblem(type: string, size: number, head: Uint8Array): string | null {
  if (!(LOGO_TYPES as readonly string[]).includes(type)) return 'Use a PNG, SVG or JPEG image.';
  if (size === 0) return 'The file is empty.';
  if (size > LOGO_MAX_BYTES) return 'The logo can be at most 256 KiB.';
  if (type === 'image/png' && !(head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47)) return 'This file is not a PNG image.';
  if (type === 'image/jpeg' && !(head[0] === 0xff && head[1] === 0xd8 && head[2] === 0xff)) return 'This file is not a JPEG image.';
  if (type === 'image/svg+xml' && !new TextDecoder().decode(head).includes('<')) return 'This file is not an SVG image.';
  return null;
}

/** CSS colour only if it is a plain #rrggbb value: anything else is ignored in the live preview. */
export const safeColor = (v: string, fallback: string): string => (HEX.test(v) ? v : fallback);
