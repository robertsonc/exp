import type { JSX } from 'preact';
import { useMemo, useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { FleetHostRow, Me, Site } from '../api/types';
import { getStore, useNow, useResource } from '../data/hooks';
import { Glyph, Icon } from '../components/Icon';
import { Badge, Button, EmptyState, Missing, ShapeBadges, StatusPill, healthPill } from '../components/atoms';
import { FilterBar } from '../components/FilterBar';
import { canAdmin } from '../components/Issues';
import { Sparkline, Link } from '../components/viz';
import { VirtualTable, type Column } from '../components/VirtualTable';
import { Loadable, PageHeader } from './common';
import { downloadText } from '../lib/csv';
import { DASH, formatAbsolute, formatAgo, formatCount, formatDuration, formatMbps, formatPct, formatPps } from '../lib/format';
import { applyFilters, FILTER_KEYS, hostsCsv, isDrift, parseFilters, parseSort, sortViews, toViews, type HostView } from '../lib/hosts';
import { diskSeverity, type Sev } from '../lib/state';
import { readJson, writeJson } from '../lib/storage';
import { setQuery, useLocation } from '../router';

const COL_KEY = 'exp.ui.hostCols';
const VIEWS_KEY = 'exp.ui.hostViews';
interface SavedView { name: string; query: string }

const ALL_COLS: { id: string; label: string }[] = [
  { id: 'name', label: 'Host' }, { id: 'site', label: 'Site' }, { id: 'shapes', label: 'Shapes' }, { id: 'health', label: 'Health' },
  { id: 'cpu', label: 'CPU' }, { id: 'mem', label: 'Memory' }, { id: 'disk', label: 'Disk' }, { id: 'uptime', label: 'Uptime' },
  { id: 'net', label: 'Net' }, { id: 'work', label: 'Work' }, { id: 'version', label: 'Version' }, { id: 'last_seen', label: 'Last report' },
];

function Metric({ v, children, why }: { v: HostView; children: JSX.Element | string; why?: string }): JSX.Element {
  if (v.presence === 'offline') return <Missing why="offline: last values are on the host page" />;
  if (v.presence === 'pending') return <Missing why="no report yet" />;
  if (why) return <Missing why={why} />;
  return <span class={v.asOf ? 'asof-val' : ''} title={v.asOf ? `as of ${formatAgo(v.row.last_seen, Date.now())}` : undefined}>{children}</span>;
}

function SevText({ sev, children }: { sev: Sev; children: string }): JSX.Element {
  if (sev === 'fail') return <span class="sev-fail"><Icon name="x" size={12} /> {children}</span>;
  if (sev === 'warn') return <span class="sev-warn"><Icon name="alert" size={12} /> {children}</span>;
  return <span>{children}</span>;
}

export function workText(r: FleetHostRow): string {
  const w = r.work;
  if (!w) return DASH;
  const parts: string[] = [];
  if (r.shapes.includes('probe') && w.measurements_per_min != null) parts.push(`${formatCount(w.measurements_per_min)} meas/min`);
  if (r.shapes.includes('collector') && w.ingest_records_per_s != null) parts.push(`${formatCount(w.ingest_records_per_s)} rec/s`);
  if (r.shapes.includes('dashboard') && w.sessions_active != null) parts.push(`${w.sessions_active} sessions`);
  if (r.shapes.includes('runner') && w.drills_active != null) parts.push(`${w.drills_active} drills`);
  return parts.length ? parts.join(' · ') : DASH;
}

function HostCell({ v, now }: { v: HostView; now: number }): JSX.Element {
  const r = v.row;
  return (
    <span class="host-cell">
      <Link to={`/hosts/${r.host_id}`} class="host-link">{r.name}</Link>
      {v.presence === 'stale' ? <Badge tone="warn" title={`Last report ${formatAbsolute(r.last_seen)}`}>stale</Badge> : null}
      {v.presence === 'offline' ? <Badge tone="fail" title={`Last report ${formatAbsolute(r.last_seen)}`}>offline</Badge> : null}
      {v.presence === 'pending' ? <Badge>pending</Badge> : null}
      {v.presence === 'decommissioning' ? <Badge tone="warn">decommissioning</Badge> : null}
      <span class="dim host-ip">{r.mgmt_ip ?? 'no IP yet'}{v.presence === 'stale' ? ` · as of ${formatAgo(r.last_seen, now)}` : ''}</span>
    </span>
  );
}

function HealthCell({ v }: { v: HostView }): JSX.Element {
  const r = v.row;
  if (v.presence === 'stale') return <StatusPill state="stale" title={`Last known health: ${r.health}`} />;
  if (v.presence === 'offline') return <StatusPill state="offline" title={`Last known health: ${r.health}`} />;
  if (v.presence === 'pending') return <StatusPill state="unknown" label="pending" />;
  return (
    <span class="health-cell">
      <StatusPill state={healthPill(r.health)} label={r.health === 'degraded' ? 'warn' : r.health} />
      {r.open_issues > 0 ? <Link to={`/issues?site=${r.site}`} class="issue-count" title="open issues">{r.open_issues} issue{r.open_issues === 1 ? '' : 's'}</Link> : null}
    </span>
  );
}

function versionCell(v: HostView): JSX.Element {
  const r = v.row;
  const a = r.applied_version;
  const d = r.desired_version;
  if (a == null && d == null) return <Missing why="no version reported" />;
  const drift = isDrift(r);
  return (
    <span class={drift ? 'sev-warn' : ''} title={`agent ${r.agent_version ?? DASH}; applied v${a ?? DASH}, desired v${d ?? DASH}`}>
      {drift ? <Icon name="alert" size={12} /> : null} {drift ? `v${a}→v${d}` : `v${a ?? d}`}
      <span class="dim"> {r.agent_version ?? ''}</span>
    </span>
  );
}

function buildColumns(now: number): Column<HostView>[] {
  return [
    { id: 'name', header: 'Host', sortable: true, width: '13rem', cell: (v) => <HostCell v={v} now={now} /> },
    { id: 'site', header: 'Site', sortable: true, width: '5.5rem', cell: (v) => v.row.site },
    { id: 'shapes', header: 'Shapes', width: '4.5rem', cell: (v) => <ShapeBadges shapes={v.row.shapes} /> },
    { id: 'health', header: 'Health', sortable: true, width: '8.5rem', cell: (v) => <HealthCell v={v} /> },
    { id: 'cpu', header: 'CPU', sortable: true, width: '7.5rem', cell: (v) => (
      <Metric v={v} why={v.row.cpu_pct == null ? 'not reported' : undefined}><span class="with-spark">{formatPct(v.row.cpu_pct)} <Sparkline values={v.row.cpu_spark} width={56} height={18} tone={v.asOf ? 'dim' : 'accent'} /></span></Metric>) },
    { id: 'mem', header: 'Memory', sortable: true, width: '5.5rem', align: 'right', cell: (v) => <Metric v={v} why={v.row.mem_pct == null ? 'not reported' : undefined}>{formatPct(v.row.mem_pct)}</Metric> },
    { id: 'disk', header: 'Disk', sortable: true, width: '5.5rem', align: 'right', cell: (v) => (
      <Metric v={v} why={v.row.disk_pct_max == null ? 'not reported' : undefined}><SevText sev={diskSeverity(v.row.disk_pct_max)}>{formatPct(v.row.disk_pct_max)}</SevText></Metric>) },
    { id: 'uptime', header: 'Uptime', sortable: true, width: '5.5rem', align: 'right', cell: (v) => <Metric v={v} why={v.row.uptime_s == null ? 'not reported' : undefined}>{formatDuration(v.row.uptime_s)}</Metric> },
    { id: 'net', header: 'Net in / out', sortable: true, width: '12rem', cell: (v) => (
      <Metric v={v} why={v.row.net == null ? 'not reported' : undefined}>
        <span class="with-spark net-cell">
          <span class="net-txt">{formatPps(v.row.net?.rx_pps)} · {formatMbps(v.row.net?.rx_bps)}<br />{formatPps(v.row.net?.tx_pps)} · {formatMbps(v.row.net?.tx_bps)}</span>
          <Sparkline values={v.row.net_spark} width={48} height={18} tone={v.asOf ? 'dim' : 'accent'} />
        </span>
      </Metric>) },
    { id: 'work', header: 'Work', sortable: true, width: '8.5rem', cell: (v) => <Metric v={v} why={workText(v.row) === DASH ? 'not applicable' : undefined}>{workText(v.row)}</Metric> },
    { id: 'version', header: 'Version', sortable: true, width: '7rem', cell: (v) => versionCell(v) },
    { id: 'last_seen', header: 'Last report', sortable: true, width: '7.5rem', cell: (v) => (
      <span title={formatAbsolute(v.row.last_seen)} class={v.presence === 'online' ? '' : 'sev-warn'}>
        {v.row.last_seen ? `${v.presence === 'stale' || v.presence === 'offline' ? 'as of ' : ''}${formatAgo(v.row.last_seen, now)}` : <Missing why="no report yet" />}
      </span>) },
  ];
}

function HostCard({ v, now }: { v: HostView; now: number }): JSX.Element {
  const r = v.row;
  return (
    <div class="host-card">
      <div class="row-top"><HostCell v={v} now={now} /><HealthCell v={v} /></div>
      <div class="row-meta"><span>{r.site}</span><ShapeBadges shapes={r.shapes} /><span>{workText(r)}</span></div>
      <div class="row-meta">
        <span>CPU <Metric v={v}>{formatPct(r.cpu_pct)}</Metric></span>
        <span>Mem <Metric v={v}>{formatPct(r.mem_pct)}</Metric></span>
        <span>Disk <Metric v={v}><SevText sev={diskSeverity(r.disk_pct_max)}>{formatPct(r.disk_pct_max)}</SevText></Metric></span>
      </div>
    </div>
  );
}

export function HostsPage({ site: lockSite, me }: { site?: string; me?: Me | undefined } = {}): JSX.Element {
  const { query } = useLocation();
  const now = useNow(10_000);
  const res = useResource<{ items: FleetHostRow[] }>(ep.hosts, { paged: true });
  const sitesRes = useResource<{ items: Site[] }>(ep.sites);
  const filters = { ...parseFilters(query), ...(lockSite ? { site: lockSite } : {}) };
  const sort = parseSort(query.get('sort'));
  const [hidden, setHidden] = useState<string[]>(() => readJson<string[]>(COL_KEY, []));
  const [views, setViews] = useState<SavedView[]>(() => readJson<SavedView[]>(VIEWS_KEY, []));
  const [viewName, setViewName] = useState('');

  const rows = res.data?.items;
  const age = res.fetchedAt === null ? null : getStore().clientNow() - res.fetchedAt;
  const all = useMemo(() => toViews(rows ?? [], now, age === null ? null : Math.floor(age / 15_000) * 15_000), [rows, now, age]);
  const shown = useMemo(() => sortViews(applyFilters(all, filters), sort.key, sort.dir),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [all, query.toString()]);

  const sites = sitesRes.data?.items.map((s) => ({ value: s.site, label: s.name })) ?? [...new Set((rows ?? []).map((r) => r.site))].map((s) => ({ value: s, label: s }));
  const versions = [...new Set((rows ?? []).map((r) => r.agent_version).filter((v): v is string => !!v))].sort();

  const cols = buildColumns(now).filter((c) => !hidden.includes(c.id));
  const setFilter = (id: string, v: string) => setQuery({ [id]: v });
  const toggleSort = (key: string) => {
    const next = sort.key === key ? (sort.dir === 'asc' ? `-${key}` : null) : key;
    setQuery({ sort: next });
  };
  const toggleCol = (id: string) => {
    const next = hidden.includes(id) ? hidden.filter((h) => h !== id) : [...hidden, id];
    setHidden(next);
    writeJson(COL_KEY, next);
  };
  const saveView = () => {
    const name = viewName.trim().slice(0, 40);
    if (!name) return;
    const q = new URLSearchParams(window.location.search);
    const keep = new URLSearchParams();
    for (const k of [...FILTER_KEYS, 'sort']) if (q.get(k)) keep.set(k, q.get(k) as string);
    const next = [...views.filter((v) => v.name !== name), { name, query: keep.toString() }];
    setViews(next);
    writeJson(VIEWS_KEY, next);
    setViewName('');
  };
  const applyView = (name: string) => {
    const v = views.find((x) => x.name === name);
    if (!v) return;
    const target = new URLSearchParams(v.query);
    const patch: Record<string, string | null> = { sort: target.get('sort') };
    for (const k of FILTER_KEYS) patch[k] = target.get(k);
    setQuery(patch);
  };
  const deleteView = (name: string) => {
    const next = views.filter((v) => v.name !== name);
    setViews(next);
    writeJson(VIEWS_KEY, next);
  };
  const exportCsv = () => downloadText(`exp-hosts-${new Date().toISOString().slice(0, 10)}.csv`, hostsCsv(shown));

  return (
    <>
      {lockSite ? <h2 class="h2">Hosts</h2> : <PageHeader title="Hosts" sub="Every host in the fleet. Stale hosts are greyed and labelled with the time of their last report."
        actions={canAdmin(me) ? <Link to="/hosts/new" class="btn btn-primary">Add host</Link> : undefined} />}
      <Loadable loading={res.loading} error={res.data ? null : res.error} onRetry={res.refresh} what="hosts" rows={8}>
        <FilterBar
          filters={[
            ...(lockSite ? [] : [{ id: 'site', label: 'Site', value: filters.site, options: sites }]),
            { id: 'shape', label: 'Shape', value: filters.shape, options: ['probe', 'collector', 'dashboard', 'runner'].map((s) => ({ value: s, label: s })) },
            { id: 'health', label: 'Health', value: filters.health, options: [{ value: 'ok', label: 'ok' }, { value: 'degraded', label: 'warn' }, { value: 'fail', label: 'fail' }, { value: 'unknown', label: 'unknown' }] },
            { id: 'version', label: 'Version', value: filters.version, options: versions.map((v) => ({ value: v, label: v })) },
            { id: 'state', label: 'State', value: filters.state, options: ['online', 'stale', 'offline', 'pending'].map((s) => ({ value: s, label: s })) },
          ]}
          onChange={setFilter}
          onClear={() => setQuery({ site: null, shape: null, health: null, version: null, state: null, q: null, drift: null })}
        >
          <label class="chip chip-search">
            <span class="chip-label">Filter</span>
            <input type="search" placeholder="name, IP or id" aria-label="Filter hosts by name, IP or id" value={filters.q} onInput={(e) => setFilter('q', (e.currentTarget as HTMLInputElement).value)} />
          </label>
          {filters.drift ? <button type="button" class="chip chip-on" onClick={() => setFilter('drift', '')}>version drift only &times;</button> : null}
        </FilterBar>

        <div class="toolbar">
          <span class="result-count" role="status" data-testid="host-count">{shown.length} of {all.length} hosts</span>
          <details class="popover">
            <summary class="btn btn-sm"><Glyph name="columns" size={14} /> Columns</summary>
            <div class="popover-body" role="group" aria-label="Visible columns">
              {ALL_COLS.map((c) => (
                <label key={c.id} class="check"><input type="checkbox" checked={!hidden.includes(c.id)} disabled={c.id === 'name'} onChange={() => toggleCol(c.id)} /> {c.label}</label>
              ))}
            </div>
          </details>
          <details class="popover">
            <summary class="btn btn-sm"><Glyph name="bookmark" size={14} /> Views{views.length ? ` (${views.length})` : ''}</summary>
            <div class="popover-body">
              {views.length === 0 ? <p class="dim">No saved views yet.</p> : (
                <ul class="view-list">
                  {views.map((v) => (
                    <li key={v.name}>
                      <button type="button" class="btn btn-sm" onClick={() => applyView(v.name)}>{v.name}</button>
                      <button type="button" class="btn btn-sm btn-ghost" aria-label={`Delete view ${v.name}`} onClick={() => deleteView(v.name)}>&times;</button>
                    </li>
                  ))}
                </ul>
              )}
              <label class="field"><span>Save current filters and sort as</span>
                <input type="text" value={viewName} maxLength={40} aria-label="Saved view name" onInput={(e) => setViewName((e.currentTarget as HTMLInputElement).value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') saveView(); }} />
              </label>
              <Button small variant="primary" disabled={!viewName.trim()} onClick={saveView}>Save view</Button>
            </div>
          </details>
          <Button small onClick={exportCsv}><Glyph name="download" size={14} /> Export CSV</Button>
        </div>

        <VirtualTable
          rows={shown} columns={cols} rowKey={(v) => v.row.host_id} label="Hosts" sort={sort} onSort={toggleSort}
          rowClass={(v) => `host-row host-${v.presence}`} rowHeight={52} cardHeight={132} viewHeight={640}
          onActivate={(v) => { window.history.pushState(null, '', `/hosts/${v.row.host_id}`); window.dispatchEvent(new PopStateEvent('popstate')); }}
          card={(v) => <HostCard v={v} now={now} />}
          empty={<EmptyState title={all.length ? 'No host matches these filters' : 'No hosts yet'}>{all.length ? 'Clear a filter to see more hosts.' : <>Add your first host to start collecting fleet health. <Link to="/hosts/new">Add a host</Link></>}</EmptyState>}
        />
      </Loadable>
    </>
  );
}
