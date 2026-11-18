import { ep } from '../api/endpoints';
import type { Component, Host, HostStatus, Page, Site } from '../api/types';
import { getStore, useNow, useResource } from './hooks';
import { hostPresence, type Presence } from '../lib/state';

function dataAge(fetchedAt: number): number | null {
  return Number.isFinite(fetchedAt) ? getStore().clientNow() - fetchedAt : null;
}

export interface HostData {
  host: ReturnType<typeof useResource<Host>>;
  status: ReturnType<typeof useResource<HostStatus>>;
  comps: ReturnType<typeof useResource<Page<Component>>>;
  site: Site | undefined;
  tz: string | null;
  presence: Presence | null;
  /** Time of the last status report (the report itself, falling back to the host row). */
  lastReport: string | null;
  intervalS: number;
  now: number;
}

/** Everything the host and component pages need about one host. */
export function useHostData(id: string): HostData {
  const now = useNow();
  const host = useResource<Host>(ep.host(id));
  const status = useResource<HostStatus>(ep.hostStatus(id));
  const comps = useResource<Page<Component>>(ep.hostComponents(id), { paged: true });
  const siteSlug = host.data?.site;
  const site = useResource<Site>(siteSlug ? ep.site(siteSlug) : null);
  const intervalS = status.data?.report.metrics.interval_s ?? 60;
  const lastReport = status.data?.received_at ?? host.data?.last_seen ?? null;
  const presence = host.data
    ? hostPresence({ state: host.data.state, last_seen: lastReport }, now, dataAge(Math.min(host.fetchedAt ?? Infinity, status.fetchedAt ?? Infinity)), intervalS)
    : null;
  return { host, status, comps, site: site.data, tz: site.data?.timezone ?? null, presence, lastReport, intervalS, now };
}
