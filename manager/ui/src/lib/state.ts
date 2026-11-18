// State logic: staleness, freshness levels, thresholds, backoff. Pure and unit tested.
import type { Health, HostState } from '../api/types';

export const POLL_MS = 30_000;
export const FRESH_AMBER_S = 90;
export const FRESH_RED_S = 300;
export const DEFAULT_STATUS_INTERVAL_S = 60;
export const OFFLINE_AFTER_S = 600;

export type FreshLevel = 'ok' | 'amber' | 'red';

/** "Updated N s ago" colour: amber after 90 s, red after 5 min without a successful refresh. */
export function freshnessLevel(ageS: number | null): FreshLevel {
  if (ageS === null) return 'red';
  if (ageS >= FRESH_RED_S) return 'red';
  if (ageS >= FRESH_AMBER_S) return 'amber';
  return 'ok';
}

/** Exponential backoff for failed polls: 30 s, 60 s, 120 s ... capped at 5 min. */
export function backoffMs(failures: number, base = POLL_MS, cap = 300_000): number {
  if (failures <= 0) return base;
  return Math.min(cap, base * 2 ** Math.min(failures, 10));
}

export type Presence = 'online' | 'stale' | 'offline' | 'pending' | 'decommissioning' | 'removed';

export interface PresenceInput {
  state: HostState;
  stale?: boolean;
  last_seen: string | null;
}

/**
 * Effective presence of a host. The server state is authoritative while our copy is fresh. When our
 * copy is older than 90 s (polling is failing) we extrapolate the report age so a host is never shown
 * as current from old data: stale after 3 x interval, offline after 10 min (spec section 6).
 */
export function hostPresence(h: PresenceInput, nowMs: number, dataAgeMs: number | null, intervalS = DEFAULT_STATUS_INTERVAL_S): Presence {
  if (h.state === 'pending' || h.state === 'decommissioning' || h.state === 'removed') return h.state;
  let p: Presence = h.state === 'offline' ? 'offline' : h.state === 'stale' || h.stale ? 'stale' : 'online';
  if (dataAgeMs !== null && dataAgeMs > 90_000 && h.last_seen) {
    const age = (nowMs - Date.parse(h.last_seen)) / 1000;
    if (age > OFFLINE_AFTER_S) p = 'offline';
    else if (age > 3 * intervalS && p === 'online') p = 'stale';
  }
  return p;
}

const HEALTH_RANK: Record<Health, number> = { ok: 0, unknown: 1, degraded: 2, fail: 3 };
export function healthRank(h: Health): number {
  return HEALTH_RANK[h] ?? 1;
}
export function worstHealth(list: Health[]): Health {
  let w: Health = 'ok';
  for (const h of list) if (healthRank(h) > healthRank(w)) w = h;
  return list.length ? w : 'unknown';
}

export type Sev = 'ok' | 'warn' | 'fail' | 'unknown';
/** Disk: amber >= 85, red >= 95 (spec 4.3). */
export function diskSeverity(pct: number | null | undefined): Sev {
  if (pct === null || pct === undefined || !Number.isFinite(pct)) return 'unknown';
  if (pct >= 95) return 'fail';
  if (pct >= 85) return 'warn';
  return 'ok';
}
export function pctSeverity(pct: number | null | undefined, warn = 85, fail = 95): Sev {
  return diskSeverity(pct === null || pct === undefined ? pct : pct >= fail ? 100 : pct >= warn ? 90 : 0);
}

/** Days-to-full colour: warn < 7 d, crit < 2 d (05-manager.md section 14). */
export function runwaySeverity(days: number | null | undefined): Sev {
  if (days === null || days === undefined || !Number.isFinite(days)) return 'ok';
  if (days < 2) return 'fail';
  if (days < 7) return 'warn';
  return 'ok';
}

export function healthToSev(h: Health): Sev {
  return h === 'ok' ? 'ok' : h === 'degraded' ? 'warn' : h === 'fail' ? 'fail' : 'unknown';
}
