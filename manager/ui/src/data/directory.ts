import { useMemo } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { FleetHostRow, Overview } from '../api/types';
import { useResource } from './hooks';

export interface Directory {
  hosts: FleetHostRow[];
  byId: Map<string, FleetHostRow>;
  comps: Map<string, { id: string; type: string; host_id: string }>;
  hostsFetchedAt: number | null;
  loading: boolean;
  error: ReturnType<typeof useResource>['error'];
}

/** Host rows (and optionally component names) for resolving ids in issue lists, search, etc. */
export function useDirectory(withComponents = false): Directory {
  const hosts = useResource<{ items: FleetHostRow[] }>(ep.hosts, { paged: true });
  const ov = useResource<Overview>(withComponents ? ep.overview : null);
  const list = hosts.data?.items;
  const byId = useMemo(() => new Map((list ?? []).map((h) => [h.host_id, h])), [list]);
  const comps = useMemo(() => {
    const m = new Map<string, { id: string; type: string; host_id: string }>();
    for (const h of ov.data?.hosts ?? []) for (const c of h.components) m.set(c.component_id, { id: c.id, type: c.type, host_id: h.host_id });
    return m;
  }, [ov.data]);
  return { hosts: list ?? [], byId, comps, hostsFetchedAt: hosts.fetchedAt, loading: hosts.loading, error: hosts.error };
}
