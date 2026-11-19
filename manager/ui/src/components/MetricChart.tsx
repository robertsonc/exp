import type { JSX } from 'preact';
import { ep } from '../api/endpoints';
import type { MetricSeries } from '../api/types';
import { useResource } from '../data/hooks';
import { TimeSeriesChart, type ChartSeries } from '../charts/TimeSeriesChart';
import { RANGES, isRange, type RangeKey } from '../charts/align';
import { ErrorBanner, SkeletonBlock } from './atoms';
import { setQuery } from '../router';

export function useMetrics(kind: 'host' | 'component', id: string, range: RangeKey, keys?: readonly string[]) {
  return useResource<MetricSeries>(kind === 'host' ? ep.hostMetrics(id, range) : ep.compMetrics(id, range, keys));
}

/** Interface roll-ups are 5-minute buckets kept 48 h: longer page ranges show the 48 h available. */
export function ifaceRange(r: RangeKey): string {
  return r === '7d' || r === '30d' ? '48h' : r;
}

/** Per-interface history of a host (CR-wp5-fleet-api-gaps item 3). `null` disables the subscription. */
export function useIfaceMetrics(hostId: string, iface: string | null, range: RangeKey) {
  return useResource<MetricSeries>(iface === null ? null : ep.ifaceMetrics(hostId, iface, ifaceRange(range)));
}

export function RangePicker({ value }: { value: RangeKey }): JSX.Element {
  return (
    <div class="range" role="group" aria-label="Time range">
      {RANGES.map((r) => (
        <button key={r} type="button" class={`btn btn-sm${r === value ? ' btn-active' : ''}`} aria-pressed={r === value} onClick={() => setQuery({ range: r === '24h' ? null : r })}>
          {r === '1h' ? '1 h' : r === '6h' ? '6 h' : r === '24h' ? '24 h' : r === '7d' ? '7 d' : '30 d'}
        </button>
      ))}
    </div>
  );
}

export function rangeFrom(q: URLSearchParams): RangeKey {
  const r = q.get('range');
  return isRange(r) ? r : '24h';
}

export interface KeyDef { key: string; label: string; color: string }

/** One chart from a shared metrics resource; keys the API does not return are simply omitted. */
export function MetricChart({ m, title, keys, fmt, range, tz, yMax, band, skipEmpty }: {
  m: ReturnType<typeof useMetrics>; title: string; keys: KeyDef[]; fmt: (v: number | null) => string; range: RangeKey; tz?: string | null; yMax?: number; band?: boolean;
  /** Leave out series that came back without any point (e.g. a test the probe never ran). */
  skipEmpty?: boolean;
}): JSX.Element {
  if (m.loading) return <SkeletonBlock rows={3} label={`Loading ${title}`} />;
  if (!m.data) return <ErrorBanner what={`Could not load ${title}.`} message={m.error?.message} onRetry={m.refresh} />;
  const series: ChartSeries[] = [];
  for (const k of keys) {
    const pts = m.data.series[k.key];
    if (pts && !(skipEmpty && pts.length === 0)) series.push({ key: k.key, label: k.label, points: pts, color: k.color });
  }
  if (series.length === 0) {
    return <figure class="chart"><figcaption class="chart-head"><h3>{title}</h3></figcaption><div class="chart-empty" role="status">This metric is not reported for this {m.data.component_id ? 'component' : 'host'}.</div></figure>;
  }
  const asOf = Date.parse(m.data.as_of);
  const rangeSeconds = m.data.range === '48h' ? 48 * 3600 : undefined;
  return <TimeSeriesChart title={title} series={series} stepS={m.data.step_s} asOfMs={Number.isNaN(asOf) ? Date.now() : asOf} range={range} rangeSeconds={rangeSeconds} tz={tz} fmt={fmt} yMax={yMax} band={band} />;
}
