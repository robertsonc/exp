import type { Issue } from '../api/types';

import { own } from './own';

export const KIND_LABEL: Record<string, string> = {
  host_stale: 'Host stale', host_offline: 'Host offline', disk_high: 'Disk high', storage_runway: 'Storage runway',
  mem_low: 'Memory low', cpu_high: 'CPU high', clock: 'Clock offset', component_unhealthy: 'Component unhealthy',
  crash_loop: 'Crash loop', reconcile_failed: 'Reconcile failed', version_drift: 'Version drift', probe_ports: 'Probe ports',
  probe_push_lag: 'Push lag', probe_spool: 'Spool filling', probe_collector: 'Collector unreachable',
  collector_rejects: 'Ingest rejects', collector_vm: 'VictoriaMetrics', collector_probes: 'Probes missing',
  dashboard_collectors: 'Collectors unreachable', iface_errors: 'Interface errors',
};

/** Coarse "type" of an issue for the filter: where it lives. */
export function issueScope(kind: string): string {
  if (kind.startsWith('probe_')) return 'probe';
  if (kind.startsWith('collector_') || kind === 'storage_runway') return 'collector';
  if (kind.startsWith('dashboard_')) return 'dashboard';
  if (kind === 'component_unhealthy' || kind === 'crash_loop') return 'component';
  return 'host';
}

/** Issue type for the filter: the component type the API reports, `host` for host-level issues; an API that predates
 *  `component_type` (CR-wp5-fleet-api-gaps item 6) falls back to the kind-derived scope. */
export function issueType(i: Pick<Issue, 'kind' | 'component_type'>): string {
  if (i.component_type === undefined) return issueScope(i.kind);
  return i.component_type ?? 'host';
}

export const SCOPES = ['host', 'probe', 'collector', 'dashboard', 'runner'] as const;

export function kindLabel(kind: string): string {
  return own(KIND_LABEL, kind) ?? kind;
}

export function isSnoozed(i: Issue, nowMs: number): boolean {
  const s = i.snoozed_until;
  if (!s) return false;
  if (s === 'resolved') return true;
  const t = Date.parse(s);
  return !Number.isNaN(t) && t > nowMs;
}

/** Crit first, then most recent. */
export function sortIssues(list: readonly Issue[]): Issue[] {
  return [...list].sort((a, b) => (a.severity === b.severity ? Date.parse(b.opened_at) - Date.parse(a.opened_at) : a.severity === 'crit' ? -1 : 1));
}

/** Format the issue's last value according to its kind. */
export function issueValue(i: Issue): string {
  const v = i.last_value;
  if (v === null || v === undefined || !Number.isFinite(v)) return '';
  switch (i.kind) {
    case 'disk_high': case 'cpu_high': case 'probe_spool': case 'mem_low': return `${Math.round(v)}%`;
    case 'storage_runway': return `${Math.round(v * 10) / 10} d`;
    default: return '';
  }
}
