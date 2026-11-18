import type { FleetHostRow, Health } from '../api/types';
import { collate } from './format';
import { healthRank, hostPresence, type Presence } from './state';
import { toCsv } from './csv';
import { own } from './own';

export interface HostFilters {
  site: string;
  shape: string;
  health: string;
  version: string;
  state: string;
  q: string;
  drift: boolean;
}

export const FILTER_KEYS = ['site', 'shape', 'health', 'version', 'state', 'q', 'drift'] as const;

export function parseFilters(p: URLSearchParams): HostFilters {
  return {
    site: p.get('site') ?? '', shape: p.get('shape') ?? '', health: p.get('health') ?? '', version: p.get('version') ?? '',
    state: p.get('state') ?? '', q: p.get('q') ?? '', drift: p.get('drift') === '1',
  };
}

export interface HostView {
  row: FleetHostRow;
  presence: Presence;
  /** True when values must be labelled "as of" (stale) or hidden (offline). */
  asOf: boolean;
}

export function toViews(rows: readonly FleetHostRow[], nowMs: number, dataAgeMs: number | null): HostView[] {
  return rows.map((row) => {
    const presence = hostPresence(row, nowMs, dataAgeMs);
    return { row, presence, asOf: presence === 'stale' };
  });
}

export function isDrift(r: FleetHostRow): boolean {
  return r.desired_version != null && r.applied_version != null && r.desired_version !== r.applied_version;
}

export function applyFilters(views: readonly HostView[], f: HostFilters): HostView[] {
  const q = f.q.trim().toLowerCase();
  return views.filter(({ row: r, presence }) => {
    if (f.site && r.site !== f.site) return false;
    if (f.shape && !r.shapes.includes(f.shape as never)) return false;
    if (f.health && r.health !== (f.health as Health)) return false;
    if (f.version && r.agent_version !== f.version) return false;
    if (f.state && presence !== f.state) return false;
    if (f.drift && !isDrift(r)) return false;
    if (q && !(r.name.toLowerCase().includes(q) || (r.mgmt_ip ?? '').includes(q) || r.host_id.toLowerCase().includes(q) || r.site.includes(q))) return false;
    return true;
  });
}

export function workValue(r: FleetHostRow): number | null {
  const w = r.work;
  if (!w) return null;
  const vals = [w.measurements_per_min, w.ingest_records_per_s, w.sessions_active, w.drills_active].filter((v): v is number => typeof v === 'number');
  return vals.length ? vals.reduce((a, b) => a + b, 0) : null;
}

export function netValue(r: FleetHostRow): number | null {
  const n = r.net;
  if (!n) return null;
  const v = [n.rx_bps, n.tx_bps].filter((x): x is number => typeof x === 'number');
  return v.length ? v.reduce((a, b) => a + b, 0) : null;
}

type SortVal = string | number | null;
const SORTERS: Record<string, (v: HostView) => SortVal> = {
  name: (v) => v.row.name,
  site: (v) => v.row.site,
  health: (v) => healthRank(v.row.health) * 1000 + v.row.open_issues,
  cpu: (v) => v.row.cpu_pct ?? null,
  mem: (v) => v.row.mem_pct ?? null,
  disk: (v) => v.row.disk_pct_max ?? null,
  uptime: (v) => v.row.uptime_s ?? null,
  net: (v) => netValue(v.row),
  work: (v) => workValue(v.row),
  version: (v) => v.row.applied_version ?? null,
  last_seen: (v) => (v.row.last_seen ? Date.parse(v.row.last_seen) : null),
  shapes: (v) => v.row.shapes.join(','),
};

export const SORT_KEYS = Object.keys(SORTERS);

export function parseSort(s: string | null): { key: string; dir: 'asc' | 'desc' } {
  const raw = s ?? '';
  const dir = raw.startsWith('-') ? 'desc' : 'asc';
  const key = raw.replace(/^-/, '');
  return own(SORTERS, key) ? { key, dir } : { key: 'name', dir: 'asc' };
}

export function sortViews(views: readonly HostView[], key: string, dir: 'asc' | 'desc'): HostView[] {
  const get = own(SORTERS, key) ?? SORTERS['name']!;
  const m = dir === 'asc' ? 1 : -1;
  const keyed = views.map((v) => ({ v, k: get(v) }));
  keyed.sort((a, b) => {
    // Missing values always sort last, whatever the direction.
    if (a.k === null && b.k === null) return collate(a.v.row.name, b.v.row.name);
    if (a.k === null) return 1;
    if (b.k === null) return -1;
    const c = typeof a.k === 'number' && typeof b.k === 'number' ? a.k - b.k : collate(String(a.k), String(b.k));
    return c !== 0 ? c * m : collate(a.v.row.name, b.v.row.name);
  });
  return keyed.map((x) => x.v);
}

export function hostsCsv(views: readonly HostView[]): string {
  const header = ['name', 'host_id', 'mgmt_ip', 'site', 'shapes', 'state', 'health', 'open_issues', 'cpu_pct', 'mem_pct', 'disk_pct_max',
    'uptime_s', 'rx_pps', 'tx_pps', 'rx_bps', 'tx_bps', 'measurements_per_min', 'ingest_records_per_s', 'sessions_active', 'drills_active',
    'agent_version', 'desired_version', 'applied_version', 'last_seen'];
  const rows = views.map(({ row: r, presence }) => [
    r.name, r.host_id, r.mgmt_ip, r.site, r.shapes.join(' '), presence, r.health, r.open_issues, r.cpu_pct, r.mem_pct, r.disk_pct_max,
    r.uptime_s, r.net?.rx_pps, r.net?.tx_pps, r.net?.rx_bps, r.net?.tx_bps, r.work?.measurements_per_min, r.work?.ingest_records_per_s,
    r.work?.sessions_active, r.work?.drills_active, r.agent_version, r.desired_version, r.applied_version, r.last_seen,
  ]);
  return toCsv(header, rows);
}
