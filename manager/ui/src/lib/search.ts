import type { FleetHostRow, Overview } from '../api/types';

export interface SearchHit { kind: 'host' | 'site' | 'component'; label: string; detail: string; to: string }

/** Global search across hosts (name, IP, id), sites (slug, name) and components (id, type, id). */
export function searchIndex(query: string, hosts: readonly FleetHostRow[] | undefined, overview: Overview | undefined, limit = 12): SearchHit[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];
  const scored: { score: number; hit: SearchHit }[] = [];
  const rank = (fields: (string | null | undefined)[]): number => {
    let best = 0;
    for (const f of fields) {
      if (!f) continue;
      const l = f.toLowerCase();
      if (l === needle) best = Math.max(best, 4);
      else if (l.startsWith(needle)) best = Math.max(best, 3);
      else if (l.includes(needle)) best = Math.max(best, 1);
    }
    return best;
  };
  for (const h of hosts ?? []) {
    const s = rank([h.name, h.mgmt_ip, h.host_id]);
    if (s) scored.push({ score: s + 0.5, hit: { kind: 'host', label: h.name, detail: `${h.mgmt_ip ?? 'no IP'} · ${h.site}`, to: `/hosts/${h.host_id}` } });
  }
  for (const s of overview?.sites ?? []) {
    const sc = rank([s.site, s.name]);
    if (sc) scored.push({ score: sc + 0.3, hit: { kind: 'site', label: s.name, detail: `site ${s.site}`, to: `/sites/${s.site}` } });
  }
  for (const h of overview?.hosts ?? []) {
    for (const c of h.components) {
      const sc = rank([c.id, c.component_id]);
      if (sc) scored.push({ score: sc, hit: { kind: 'component', label: c.id, detail: `${c.type} on ${h.name}`, to: `/hosts/${h.host_id}/components/${c.component_id}` } });
    }
  }
  scored.sort((a, b) => b.score - a.score || a.hit.label.localeCompare(b.hit.label));
  return scored.slice(0, limit).map((s) => s.hit);
}
