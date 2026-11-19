import type { JSX } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';
import type { MetricPoint } from '../api/types';
import { alignSeries, RANGE_SECONDS, summarize, type RangeKey } from './align';
import { DASH, formatAbsolute, formatClock } from '../lib/format';
import { useTheme } from '../lib/theme';
import { Glyph } from '../components/Icon';

export interface ChartSeries {
  key: string;
  label: string;
  points: readonly MetricPoint[];
  /** CSS custom property name, e.g. `--exp-line-network`. */
  color: string;
}

export interface ChartProps {
  title: string;
  series: ChartSeries[];
  stepS: number;
  asOfMs: number;
  range: RangeKey;
  /** Overrides the span of `range` (per-interface history spans 48 h, which is not a page range). */
  rangeSeconds?: number;
  tz?: string | null;
  fmt: (v: number | null) => string;
  /** Draw the max band (single-series charts only by default). */
  band?: boolean;
  yMax?: number;
  height?: number;
}

function validTz(tz: string | null | undefined): string | undefined {
  if (!tz) return undefined;
  try {
    new Intl.DateTimeFormat('en', { timeZone: tz });
    return tz;
  } catch {
    return undefined;
  }
}

function cssVar(name: string, fallback: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function withAlpha(color: string, a: number): string {
  const m = /^#([0-9a-f]{6})$/i.exec(color);
  if (!m || !m[1]) return color;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

/** uPlot time series: avg line + max band, gaps drawn as gaps, tooltip in site timezone and UTC, table view. */
export function TimeSeriesChart(props: ChartProps): JSX.Element {
  const { title, series, stepS, asOfMs, range, fmt, yMax, height = 190 } = props;
  const spanS = props.rangeSeconds ?? RANGE_SECONDS[range];
  const tz = validTz(props.tz);
  const band = props.band ?? series.length === 1;
  const theme = useTheme();
  const [table, setTable] = useState(false);
  const host = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);

  const aligned = useMemo(
    () => alignSeries(series.map((s) => s.points), stepS, Math.floor(asOfMs / 1000), spanS),
    [series, stepS, asOfMs, spanS],
  );

  const summaries = useMemo(() => series.map((s, i) => ({ s, sum: summarize(aligned.series[i]?.avg ?? []) })), [series, aligned]);
  const anyData = summaries.some((x) => x.sum.samples > 0);

  useEffect(() => {
    const el = host.current;
    if (!el || table || !anyData) return undefined;
    const text = cssVar('--exp-text-dim', '#888');
    const grid = cssVar('--exp-stroke', '#333');
    const colors = series.map((s) => cssVar(s.color, '#2f7fb8'));
    const data: uPlot.AlignedData = [aligned.xs, ...aligned.series.flatMap((a) => (band ? [a.avg, a.max] : [a.avg]))] as uPlot.AlignedData;
    const uSeries: uPlot.Series[] = [{}];
    const bands: uPlot.Band[] = [];
    series.forEach((s, i) => {
      const c = colors[i] ?? '#2f7fb8';
      uSeries.push({ label: s.label, stroke: c, width: 1.6, spanGaps: false, points: { show: false }, value: (_u, v) => fmt(v ?? null) });
      if (band) {
        uSeries.push({ label: `${s.label} max`, stroke: withAlpha(c, 0.45), width: 1, spanGaps: false, points: { show: false }, value: (_u, v) => fmt(v ?? null) });
        bands.push({ series: [uSeries.length - 1, uSeries.length - 2], fill: withAlpha(c, 0.14) });
      }
    });
    const opts: uPlot.Options = {
      width: Math.max(220, el.clientWidth),
      height,
      padding: [8, 8, 0, 0],
      legend: { show: false },
      cursor: { drag: { x: false, y: false }, points: { size: 6 } },
      ...(tz ? { tzDate: (ts: number) => uPlot.tzDate(new Date(ts * 1000), tz) } : {}),
      scales: { x: { time: true }, y: { range: (_u, lo, hi) => [Math.min(0, lo ?? 0), yMax ?? Math.max(hi ?? 1, 1) * 1.1] } },
      axes: [
        { stroke: text, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid }, font: '11px system-ui, sans-serif' },
        { stroke: text, grid: { stroke: grid, width: 1 }, ticks: { stroke: grid }, size: 62, font: '11px system-ui, sans-serif', values: (_u, ticks) => ticks.map((t) => fmt(t)) },
      ],
      series: uSeries,
      bands,
      hooks: {
        setCursor: [
          (u) => {
            const t = tip.current;
            if (!t) return;
            const idx = u.cursor.idx;
            if (idx === null || idx === undefined) {
              t.textContent = '';
              t.hidden = true;
              return;
            }
            const x = aligned.xs[idx];
            if (x === undefined) return;
            const parts = series.map((s, i) => `${s.label}: ${fmt(aligned.series[i]?.avg[idx] ?? null)}`);
            t.textContent = `${formatAbsolute(x * 1000, props.tz)}  |  ${parts.join('  ')}`;
            t.hidden = false;
          },
        ],
      },
    };
    const u = new uPlot(opts, data, el);
    const ro = new ResizeObserver(() => u.setSize({ width: Math.max(220, el.clientWidth), height }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      u.destroy();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aligned, series, theme, table, anyData, band, height, tz]);

  const tzLabel = tz ?? 'UTC';
  return (
    <figure class="chart">
      <figcaption class="chart-head">
        <h3>{title}</h3>
        <span class="chart-tz">times in {tzLabel}</span>
        <button type="button" class="btn btn-sm" aria-pressed={table} onClick={() => setTable(!table)}>
          <Glyph name="columns" size={13} /> {table ? 'Chart view' : 'Table view'}
        </button>
      </figcaption>
      <p class="chart-summary">
        {summaries.map(({ s, sum }) => (
          <span key={s.key}>
            <strong>{s.label}</strong>{' '}
            {sum.samples ? `latest ${fmt(sum.latest)}, range ${fmt(sum.min)} to ${fmt(sum.max)}` : 'no data'}
            {sum.gaps && sum.samples ? `, ${sum.gaps} gap${sum.gaps === 1 ? '' : 's'}` : ''}
            {' '}
          </span>
        ))}
      </p>
      {!anyData ? <div class="chart-empty" role="status">No data in this range</div> : table ? (
        <div class="table-scroll chart-table">
          <table>
            <caption class="sr-only">{title} values</caption>
            <thead>
              <tr><th scope="col">Time ({tzLabel})</th>{series.map((s) => <th key={s.key} scope="col">{s.label}</th>)}</tr>
            </thead>
            <tbody>
              {aligned.xs.map((x, i) => (
                <tr key={x}>
                  <th scope="row">{formatClock(x * 1000, tz, range === '7d' || range === '30d')}</th>
                  {series.map((s, j) => <td key={s.key}>{aligned.series[j]?.avg[i] == null ? <span class="missing" title="no data in this bucket">{DASH}</span> : fmt(aligned.series[j]?.avg[i] ?? null)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <div ref={host} class="chart-host" style={{ height: `${height}px` }} />
          <div ref={tip} class="chart-tip" hidden aria-hidden="true" />
        </>
      )}
      {series.length > 1 && anyData && !table ? (
        <ul class="chart-legend">
          {series.map((s) => <li key={s.key}><span class="swatch" style={{ background: `var(${s.color})` }} />{s.label}</li>)}
        </ul>
      ) : null}
    </figure>
  );
}
