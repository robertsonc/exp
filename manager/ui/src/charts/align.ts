import type { MetricPoint } from '../api/types';

export const RANGES = ['1h', '6h', '24h', '7d', '30d'] as const;
export type RangeKey = (typeof RANGES)[number];
export const RANGE_SECONDS: Record<RangeKey, number> = { '1h': 3600, '6h': 21_600, '24h': 86_400, '7d': 604_800, '30d': 2_592_000 };

export function isRange(v: string | null | undefined): v is RangeKey {
  return !!v && (RANGES as readonly string[]).includes(v);
}

/** The contract says epoch seconds; the mock admin API sends milliseconds. Accept both (see CR-wp5-metric-t-units). */
export function toSeconds(t: number): number {
  return t > 1e11 ? Math.round(t / 1000) : t;
}

export interface AlignedSeries { avg: (number | null)[]; max: (number | null)[] }
export interface Aligned { xs: number[]; series: AlignedSeries[] }

/**
 * Put every series on one regular time grid. Buckets without a sample become null so charts draw gaps
 * (docs/spec/05-manager.md section 13: "a bucket with no samples is absent and drawn as a gap").
 */
export function alignSeries(inputs: readonly (readonly MetricPoint[])[], stepS: number, endSec: number, rangeSec: number): Aligned {
  const step = Math.max(1, stepS);
  const end = Math.floor(endSec / step) * step;
  const start = end - Math.floor(rangeSec / step) * step;
  const n = Math.floor((end - start) / step) + 1;
  const xs = Array.from({ length: n }, (_, i) => start + i * step);
  const series = inputs.map((pts) => {
    const avg: (number | null)[] = new Array(n).fill(null);
    const max: (number | null)[] = new Array(n).fill(null);
    for (const p of pts) {
      if (typeof p.t !== 'number') continue;
      const idx = Math.round((toSeconds(p.t) - start) / step);
      if (idx < 0 || idx >= n) continue;
      const a = typeof p.avg === 'number' && Number.isFinite(p.avg) ? p.avg : null;
      const m = typeof p.max === 'number' && Number.isFinite(p.max) ? p.max : null;
      avg[idx] = a;
      max[idx] = m ?? a;
    }
    return { avg, max };
  });
  return { xs, series };
}

export interface Summary { latest: number | null; min: number | null; max: number | null; samples: number; gaps: number }

export function summarize(values: readonly (number | null)[]): Summary {
  let latest: number | null = null;
  let min: number | null = null;
  let max: number | null = null;
  let samples = 0;
  let firstIdx = -1;
  let lastIdx = -1;
  values.forEach((v, i) => {
    if (v === null) return;
    samples += 1;
    latest = v;
    if (firstIdx < 0) firstIdx = i;
    lastIdx = i;
    if (min === null || v < min) min = v;
    if (max === null || v > max) max = v;
  });
  // Only gaps between the first and last sample count (the open current bucket is not a gap).
  let gaps = 0;
  for (let i = firstIdx; i >= 0 && i <= lastIdx; i += 1) if (values[i] === null) gaps += 1;
  return { latest, min, max, samples, gaps };
}
