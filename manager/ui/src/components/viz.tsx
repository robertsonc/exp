import type { ComponentChildren, JSX } from 'preact';
import { navigate } from '../router';
import { DASH } from '../lib/format';

/** Hand-rolled SVG sparkline; null values are drawn as gaps. */
export function Sparkline({ values, width = 80, height = 22, label, tone = 'accent' }: {
  values: readonly (number | null | undefined)[] | undefined; width?: number; height?: number; label?: string; tone?: 'accent' | 'warn' | 'fail' | 'dim';
}): JSX.Element {
  const vals = (values ?? []).map((v) => (typeof v === 'number' && Number.isFinite(v) ? v : null));
  const nums = vals.filter((v): v is number => v !== null);
  if (nums.length < 2) return <span class="spark-empty" title="no history" aria-label="no history">{DASH}</span>;
  const lo = Math.min(...nums);
  const hi = Math.max(...nums);
  const span = hi - lo || 1;
  const pad = 2;
  const x = (i: number) => pad + (i / (vals.length - 1)) * (width - 2 * pad);
  const y = (v: number) => height - pad - ((v - lo) / span) * (height - 2 * pad);
  const segs: string[] = [];
  let cur: string[] = [];
  vals.forEach((v, i) => {
    if (v === null) {
      if (cur.length) segs.push(cur.join(' '));
      cur = [];
    } else cur.push(`${x(i).toFixed(1)},${y(v).toFixed(1)}`);
  });
  if (cur.length) segs.push(cur.join(' '));
  const last = nums[nums.length - 1] ?? 0;
  return (
    <svg class={`spark spark-${tone}`} width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img"
      aria-label={label ?? `trend, latest ${Math.round(last * 10) / 10}, min ${Math.round(lo * 10) / 10}, max ${Math.round(hi * 10) / 10}`}>
      {segs.map((p, i) => (p.includes(' ') ? <polyline key={i} points={p} fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" /> : <circle key={i} cx={p.split(',')[0]} cy={p.split(',')[1]} r="1.2" fill="currentColor" />))}
    </svg>
  );
}

export interface HealthCounts { ok: number; warn: number; fail: number; offline: number }

/** Stacked health bar (ok / warn / fail / offline) plus a text legend. */
export function HealthBar({ counts, width = 160, showLegend = true }: { counts: HealthCounts; width?: number; showLegend?: boolean }): JSX.Element {
  const total = counts.ok + counts.warn + counts.fail + counts.offline;
  const parts: [keyof HealthCounts, number][] = [['ok', counts.ok], ['warn', counts.warn], ['fail', counts.fail], ['offline', counts.offline]];
  let off = 0;
  const desc = parts.filter(([, n]) => n > 0).map(([k, n]) => `${n} ${k}`).join(', ') || 'no hosts';
  return (
    <span class="healthbar">
      <svg width={width} height="10" viewBox={`0 0 ${width} 10`} role="img" aria-label={`Host health: ${desc}`} preserveAspectRatio="none">
        <rect x="0" y="0" width={width} height="10" rx="3" class="hb-empty" />
        {total > 0 ? parts.map(([k, n]) => {
          if (n <= 0) return null;
          const w = (n / total) * width;
          const r = <rect key={k} x={off} y="0" width={w} height="10" class={`hb-${k}`} />;
          off += w;
          return r;
        }) : null}
      </svg>
      {showLegend ? <span class="hb-legend">{desc}</span> : null}
    </span>
  );
}

/** Horizontal usage bar (disk %), colour from severity. */
export function UsageBar({ pct, sev, width = 160 }: { pct: number; sev: 'ok' | 'warn' | 'fail' | 'unknown'; width?: number }): JSX.Element {
  const w = Math.max(0, Math.min(100, pct)) / 100 * width;
  return (
    <svg class={`usage usage-${sev}`} width={width} height="8" viewBox={`0 0 ${width} 8`} role="img" aria-label={`${Math.round(pct)} percent used`}>
      <rect x="0" y="0" width={width} height="8" rx="3" class="u-track" />
      <rect x="0" y="0" width={w} height="8" rx="3" class="u-fill" />
    </svg>
  );
}

/** KPI tile; links to a pre-filtered view when `to` is given. */
export function KpiTile({ label, value, sub, to, tone, asOf }: {
  label: string; value: ComponentChildren; sub?: ComponentChildren; to?: string; tone?: 'ok' | 'warn' | 'fail'; asOf?: string;
}): JSX.Element {
  const body = (
    <>
      <span class="kpi-label">{label}</span>
      <span class={`kpi-value${tone ? ` kpi-${tone}` : ''}`}>{value}</span>
      {sub ? <span class="kpi-sub">{sub}</span> : null}
    </>
  );
  if (!to) return <div class="kpi" title={asOf}>{body}</div>;
  return (
    <a class="kpi kpi-link" href={to} title={asOf} onClick={(e) => linkClick(e, to)}>{body}</a>
  );
}

/** Metric value with unit and optional sparkline. */
export function MetricTile({ label, value, sub, spark, sev, title }: {
  label: string; value: ComponentChildren; sub?: ComponentChildren; spark?: readonly (number | null)[]; sev?: 'ok' | 'warn' | 'fail' | 'unknown'; title?: string;
}): JSX.Element {
  return (
    <div class={`metric${sev && sev !== 'ok' && sev !== 'unknown' ? ` metric-${sev}` : ''}`} title={title}>
      <span class="metric-label">{label}</span>
      <span class="metric-value">{value}</span>
      {sub ? <span class="metric-sub">{sub}</span> : null}
      {spark ? <Sparkline values={spark} width={96} height={20} tone={sev === 'fail' ? 'fail' : sev === 'warn' ? 'warn' : 'accent'} /> : null}
    </div>
  );
}

/** Same-origin SPA link: plain click navigates client-side, modified clicks keep default behaviour. */
export function linkClick(e: MouseEvent, to: string): void {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  navigate(to);
}

export function Link({ to, children, class: cls, title, ...rest }: { to: string; children: ComponentChildren; class?: string; title?: string; 'aria-label'?: string; 'aria-current'?: 'page' | undefined }): JSX.Element {
  return <a href={to} class={cls} title={title} {...rest} onClick={(e) => linkClick(e as unknown as MouseEvent, to)}>{children}</a>;
}
