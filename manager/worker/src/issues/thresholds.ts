// Fleet thresholds (05-manager.md section 14): defaults, merge, validation. Stored in settings.fleet_thresholds_json.
import { z } from "zod";
import type { Env } from "../env";
import { DEFAULT_ORG } from "../env";
import { parseJson } from "../compile/load";

export interface Thresholds {
  disk_high: { warn_pct: number; crit_pct: number };
  storage_runway: { warn_days: number; crit_days: number };
  mem_low: { available_pct: number; for_min: number };
  cpu_high: { pct: number; avg_min: number };
  probe_push_lag: { warn_s: number; crit_s: number };
  probe_spool: { pct: number };
  crash_loop: { restarts: number; window_min: number };
  version_drift: { minutes: number };
  clock: { offset_ms: number };
  iface_errors: { pct: number; window_min: number };
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  disk_high: { warn_pct: 85, crit_pct: 95 },
  storage_runway: { warn_days: 7, crit_days: 2 },
  mem_low: { available_pct: 10, for_min: 10 },
  cpu_high: { pct: 90, avg_min: 15 },
  probe_push_lag: { warn_s: 120, crit_s: 600 },
  probe_spool: { pct: 50 },
  crash_loop: { restarts: 3, window_min: 15 },
  version_drift: { minutes: 10 },
  clock: { offset_ms: 1000 },
  iface_errors: { pct: 0.1, window_min: 15 },
};

const pct = z.number().min(0).max(100);
const nonneg = z.number().min(0);
const pos = z.number().int().min(1).max(1440);
export const ThresholdsSchema = z
  .object({
    disk_high: z.object({ warn_pct: pct, crit_pct: pct }).partial().strict(),
    storage_runway: z.object({ warn_days: nonneg, crit_days: nonneg }).partial().strict(),
    mem_low: z.object({ available_pct: pct, for_min: pos }).partial().strict(),
    cpu_high: z.object({ pct, avg_min: pos }).partial().strict(),
    probe_push_lag: z.object({ warn_s: nonneg, crit_s: nonneg }).partial().strict(),
    probe_spool: z.object({ pct }).partial().strict(),
    crash_loop: z.object({ restarts: z.number().int().min(1).max(1000), window_min: pos }).partial().strict(),
    version_drift: z.object({ minutes: pos }).partial().strict(),
    clock: z.object({ offset_ms: nonneg }).partial().strict(),
    iface_errors: z.object({ pct: nonneg, window_min: pos }).partial().strict(),
  })
  .partial()
  .strict();

export function mergeThresholds(stored: unknown, clamp = true): Thresholds {
  const out = structuredClone(DEFAULT_THRESHOLDS) as unknown as Record<string, Record<string, number>>;
  const parsed = ThresholdsSchema.safeParse(stored);
  if (parsed.success) {
    for (const [group, vals] of Object.entries(parsed.data)) Object.assign(out[group] as Record<string, number>, vals);
  }
  const t = out as unknown as Thresholds;
  // keep warn <= crit coherent even when only one side was edited
  if (clamp && t.disk_high.warn_pct > t.disk_high.crit_pct) t.disk_high.warn_pct = t.disk_high.crit_pct;
  return t;
}

export async function loadThresholds(env: Env): Promise<Thresholds> {
  const r = await env.DB.prepare("SELECT fleet_thresholds_json FROM settings WHERE org_id = ?1").bind(DEFAULT_ORG).first<{ fleet_thresholds_json: string }>();
  return mergeThresholds(parseJson(r?.fleet_thresholds_json, {}));
}
