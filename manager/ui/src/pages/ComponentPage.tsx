import type { JSX } from 'preact';
import type { Component, Me, StatusComponent } from '../api/types';
import { useHostData } from '../data/hostData';
import { Badge, EmptyState, ErrorBanner, Missing, Panel, SkeletonBlock, StatusPill, Tabs, healthPill } from '../components/atoms';
import { OpenDashboardButton } from '../components/OpenDashboard';
import { CollectorEditor, DashboardEditor, ProbeEditor } from './ComponentEditors';
import { MetricChart, RangePicker, rangeFrom, useMetrics } from '../components/MetricChart';
import { Link, MetricTile, UsageBar } from '../components/viz';
import { PageHeader } from './common';
import { DASH, formatAbsolute, formatAgo, formatBps, formatCount, formatDaysToFull, formatDuration, formatGiB, formatMiB, formatPct, formatPps, formatRate } from '../lib/format';
import { num, safeHttpsUrl } from '../lib/redact';
import { runwaySeverity } from '../lib/state';
import { setQuery, useLocation } from '../router';

const f1 = (v: number | null) => (v === null ? DASH : String(Math.round(v * 10) / 10));
const perS = (v: number | null) => (v === null ? DASH : `${f1(v)}/s`);
const perMin = (v: number | null) => (v === null ? DASH : `${f1(v)}/min`);

function metric(sc: StatusComponent | undefined, k: string): number | null {
  return num(sc?.metrics?.[k]);
}

// ---- Collector -----------------------------------------------------------------------------------

function StorageRunway({ sc }: { sc: StatusComponent | undefined }): JSX.Element {
  const vm = metric(sc, 'vm_storage_gb');
  const rec = metric(sc, 'records_db_gb');
  const free = metric(sc, 'storage_free_gb');
  const hasDays = sc?.metrics && 'days_to_full' in sc.metrics;
  const days = hasDays ? num(sc?.metrics?.['days_to_full']) : undefined;
  const used = (vm ?? 0) + (rec ?? 0);
  const total = free !== null ? used + free : null;
  const sev = days === undefined ? 'unknown' : runwaySeverity(days);
  return (
    <Panel title="Storage" id="storage">
      <div class="metric-row">
        <MetricTile label="VictoriaMetrics" value={vm === null ? <Missing why="not reported" /> : formatGiB(vm)} />
        <MetricTile label="Records database" value={rec === null ? <Missing why="not reported" /> : formatGiB(rec)} />
        <MetricTile label="Free" value={free === null ? <Missing why="not reported" /> : formatGiB(free)} />
        <MetricTile label="Days to full" sev={sev} title="Free storage divided by the 24-hour average growth rate"
          value={days === undefined ? <Missing why="not reported by this collector version" /> : <span data-testid="days-to-full">{formatDaysToFull(days)}</span>} />
      </div>
      {total ? <p class="usage-line"><UsageBar pct={(used / total) * 100} sev={sev === 'unknown' ? 'ok' : sev} width={260} /> <span class="dim">{formatGiB(used)} used of {formatGiB(total)}</span></p> : null}
    </Panel>
  );
}

function ProbesTable({ comp, sc }: { comp: Component | undefined; sc: StatusComponent | undefined }): JSX.Element {
  const reported = Array.isArray(sc?.metrics?.['probes']) ? (sc?.metrics?.['probes'] as Record<string, unknown>[]) : null;
  const cfgProbes = Array.isArray(comp?.config['probes']) ? (comp?.config['probes'] as { probe_id?: unknown; label?: unknown }[]) : [];
  const rows = reported
    ? reported.map((p) => ({ id: String(p['probe_id'] ?? ''), seen: typeof p['last_seen'] === 'string' ? p['last_seen'] : null, rpm: num(p['records_per_min']), clk: num(p['clock_offset_ms']) }))
    : cfgProbes.map((p) => ({ id: String(p.probe_id ?? ''), seen: null, rpm: null, clk: null }));
  const total = metric(sc, 'probes_total');
  const reporting = metric(sc, 'probes_reporting');
  return (
    <Panel title={`Probes reporting${total !== null ? `: ${reporting ?? DASH} of ${total}` : ''}`} id="probes">
      {rows.length === 0 ? <EmptyState title="No probes assigned to this collector" /> : (
        <div class="table-scroll">
          <table class="plain">
            <caption class="sr-only">Probes of this collector</caption>
            <thead><tr><th scope="col">Probe</th><th scope="col">Last seen</th><th scope="col">Records/min</th><th scope="col">Clock offset</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <th scope="row">{r.id}</th>
                  <td>{r.seen ? <span title={formatAbsolute(r.seen)}>{formatAgo(r.seen, Date.now())}</span> : <Missing why="per-probe detail is not part of the collector health report" />}</td>
                  <td>{r.rpm !== null ? formatCount(r.rpm) : DASH}</td>
                  <td>{r.clk !== null ? `${r.clk} ms` : DASH}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function CollectorView({ sc, comp, m, range, tz }: { sc: StatusComponent | undefined; comp: Component | undefined; m: ReturnType<typeof useMetrics>; range: ReturnType<typeof rangeFrom>; tz: string | null }): JSX.Element {
  const rejByReason = sc?.metrics?.['rejects_by_reason'];
  const reasons = rejByReason && typeof rejByReason === 'object' ? Object.entries(rejByReason as Record<string, unknown>).filter(([, v]) => typeof v === 'number') : [];
  return (
    <>
      <div class="metric-row">
        <MetricTile label="Ingest" value={formatRate(metric(sc, 'ingest_records_per_s'), 's')} />
        <MetricTile label="Rejected" value={formatRate(metric(sc, 'ingest_rejected_per_min'), 'min')} sev={(metric(sc, 'ingest_rejected_per_min') ?? 0) > 0 ? 'warn' : 'ok'} />
        <MetricTile label="Duplicates" value={formatRate(metric(sc, 'ingest_duplicates_per_min'), 'min')} />
        <MetricTile label="VM backlog" value={metric(sc, 'vm_backlog_points') === null ? <Missing why="not reported" /> : `${formatCount(metric(sc, 'vm_backlog_points'))} pts`} />
        <MetricTile label="VictoriaMetrics" value={metric(sc, 'vm_up') === null ? <Missing why="not reported" /> : metric(sc, 'vm_up') === 1 ? 'up' : 'DOWN'} sev={metric(sc, 'vm_up') === 0 ? 'fail' : 'ok'} />
        <MetricTile label="SSE clients" value={metric(sc, 'sse_clients') ?? <Missing why="not reported" />} />
        <MetricTile label="Open incidents" value={metric(sc, 'open_incidents') ?? <Missing why="not reported" />} sub={<Link to="/dashboards">Open board</Link>} />
        <MetricTile label="Webhook failures (1 h)" value={metric(sc, 'webhook_failures_1h') ?? <Missing why="not reported" />} sev={(metric(sc, 'webhook_failures_1h') ?? 0) > 0 ? 'warn' : 'ok'} />
        <MetricTile label="Rules eval p95" value={metric(sc, 'rules_eval_ms_p95') === null ? <Missing why="not reported" /> : `${f1(metric(sc, 'rules_eval_ms_p95'))} ms`} />
      </div>
      <div class="range-bar"><h2 class="h2">Trends</h2><RangePicker value={range} /></div>
      <div class="charts">
        <MetricChart m={m} title="Ingest records/s" range={range} tz={tz} fmt={perS} keys={[{ key: 'ingest_records_per_s', label: 'accepted', color: '--exp-line-network' }, { key: 'ingest_duplicates_per_s', label: 'duplicate', color: '--exp-line-dhcp' }]} />
        <MetricChart m={m} title="Rejected per minute" range={range} tz={tz} fmt={perMin} keys={[{ key: 'ingest_rejected_per_min', label: 'rejected', color: '--exp-line-apps' }, { key: 'rejects_per_min', label: 'rejected', color: '--exp-line-apps' }]} />
        <MetricChart m={m} title="Probes reporting" range={range} tz={tz} fmt={f1} keys={[{ key: 'probes_reporting', label: 'probes', color: '--exp-line-wifi' }]} />
        <MetricChart m={m} title="VictoriaMetrics backlog" range={range} tz={tz} fmt={f1} keys={[{ key: 'vm_backlog_points', label: 'points', color: '--exp-line-internet' }, { key: 'vm_lag_s', label: 'lag s', color: '--exp-line-internet' }]} />
        <MetricChart m={m} title="Storage (GiB)" range={range} tz={tz} fmt={f1} keys={[{ key: 'vm_storage_gb', label: 'VictoriaMetrics', color: '--exp-line-network' }, { key: 'records_db_gb', label: 'records', color: '--exp-line-dns' }]} />
      </div>
      <StorageRunway sc={sc} />
      <div class="grid-2">
        <ProbesTable comp={comp} sc={sc} />
        <Panel title="Rejects by reason" id="rej">
          {reasons.length === 0 ? <EmptyState title="No rejects reported" /> : (
            <ul class="events">{reasons.map(([k, v]) => <li key={k}><strong>{k}</strong>: {String(v)}</li>)}</ul>
          )}
        </Panel>
      </div>
    </>
  );
}

// ---- Probe ---------------------------------------------------------------------------------------

interface Port {
  id: string; iface: string; role: string; link: string; leased: boolean | null; ip: string | null; gateway: string | null;
  rx_pps: number | null; tx_pps: number | null; rx_bps: number | null; tx_bps: number | null;
  errors: number | null; drops: number | null; last: [string, string][];
}

export function parsePorts(raw: unknown): Port[] {
  if (!Array.isArray(raw)) return [];
  const s = (v: unknown) => (typeof v === 'string' ? v : null);
  return raw.filter((p): p is Record<string, unknown> => !!p && typeof p === 'object').slice(0, 64).map((p) => {
    const last = p['last'] && typeof p['last'] === 'object' ? Object.entries(p['last'] as Record<string, unknown>).filter(([, v]) => typeof v === 'string').slice(0, 12) as [string, string][] : [];
    const e = (num(p['rx_errors']) ?? 0) + (num(p['tx_errors']) ?? 0);
    const d = (num(p['rx_drops']) ?? 0) + (num(p['tx_drops']) ?? 0);
    return {
      id: s(p['id']) ?? '?', iface: s(p['iface']) ?? '', role: s(p['role']) ?? '', link: s(p['link']) ?? 'unknown',
      leased: typeof p['leased'] === 'boolean' ? p['leased'] : null, ip: s(p['ip']), gateway: s(p['gateway']),
      rx_pps: num(p['rx_pps']), tx_pps: num(p['tx_pps']), rx_bps: num(p['rx_bps']), tx_bps: num(p['tx_bps']),
      errors: p['rx_errors'] === undefined && p['tx_errors'] === undefined ? null : e, drops: p['rx_drops'] === undefined && p['tx_drops'] === undefined ? null : d, last,
    };
  });
}

export function PortTile({ p }: { p: Port }): JSX.Element {
  const linkState = p.link === 'up' ? 'ok' : p.link === 'down' ? 'fail' : 'unknown';
  return (
    <li class="port" data-testid="port-tile" data-port={p.id}>
      <div class="port-head">
        <strong>{p.id}</strong>
        <span class="dim">{p.role || DASH} · {p.iface}</span>
        <StatusPill state={linkState} label={`link ${p.link}`} />
      </div>
      <dl class="facts facts-compact">
        <div><dt>Lease</dt><dd>{p.role === 'client' ? (p.leased ? `${p.ip ?? DASH}` : <span class="sev-warn">no lease</span>) : (p.ip ?? DASH)}</dd></div>
        <div><dt>Gateway</dt><dd>{p.gateway ?? DASH}</dd></div>
        <div><dt>In</dt><dd>{formatPps(p.rx_pps)} · {formatBps(p.rx_bps)}</dd></div>
        <div><dt>Out</dt><dd>{formatPps(p.tx_pps)} · {formatBps(p.tx_bps)}</dd></div>
        <div><dt>Errors / drops</dt><dd class={(p.errors ?? 0) + (p.drops ?? 0) > 0 ? 'sev-warn' : ''}>{p.errors ?? DASH} / {p.drops ?? DASH}</dd></div>
      </dl>
      {p.last.length ? (
        <ul class="outcomes" aria-label={`Last heartbeat per line on ${p.id}`}>
          {p.last.map(([line, out]) => <li key={line}><StatusPill state={out === 'ok' ? 'ok' : out === 'fail' ? 'fail' : out === 'warn' ? 'warn' : 'unknown'} label={`${line} ${out}`} /></li>)}
        </ul>
      ) : null}
    </li>
  );
}

function ProbeView({ sc, m, range, tz }: { sc: StatusComponent | undefined; m: ReturnType<typeof useMetrics>; range: ReturnType<typeof rangeFrom>; tz: string | null }): JSX.Element {
  const ports = parsePorts(sc?.metrics?.['ports']);
  const byTest = sc?.metrics?.['by_test_per_min'];
  const tests = byTest && typeof byTest === 'object' ? Object.entries(byTest as Record<string, unknown>).filter(([, v]) => typeof v === 'number') as [string, number][] : [];
  const reach = sc?.facts?.['collector_reachable'];
  return (
    <>
      <div class="metric-row">
        <MetricTile label="Measurements" value={formatRate(metric(sc, 'measurements_per_min'), 'min')} />
        <MetricTile label="Failures" value={formatRate(metric(sc, 'fail_per_min'), 'min')} sev={(metric(sc, 'fail_per_min') ?? 0) > 0 ? 'warn' : 'ok'} />
        <MetricTile label="Spool depth" value={metric(sc, 'spool_depth') ?? <Missing why="not reported" />} />
        <MetricTile label="Push lag" value={metric(sc, 'push_lag_s') === null ? <Missing why="not reported" /> : formatDuration(metric(sc, 'push_lag_s'))} />
        <MetricTile label="Clock offset" value={metric(sc, 'clock_offset_ms') === null ? <Missing why="not reported" /> : `${f1(metric(sc, 'clock_offset_ms'))} ms`} />
        <MetricTile label="Collector" value={reach === true ? 'reachable' : reach === false ? 'UNREACHABLE' : <Missing why="not reported" />} sev={reach === false ? 'fail' : 'ok'} />
      </div>
      <Panel title={`Ports (${ports.length})`} id="ports" actions={<Link to="/dashboards" class="btn btn-sm">Open board</Link>}>
        {ports.length === 0 ? <EmptyState title="No port data yet">This probe has not reported any ports.</EmptyState> : <ul class="port-grid" data-testid="ports-grid">{ports.map((p) => <PortTile key={p.id} p={p} />)}</ul>}
      </Panel>
      <div class="range-bar"><h2 class="h2">Trends</h2><RangePicker value={range} /></div>
      <div class="charts">
        <MetricChart m={m} title="Measurements per minute" range={range} tz={tz} fmt={f1} keys={[{ key: 'measurements_per_min', label: 'measurements', color: '--exp-line-network' }]} />
        <MetricChart m={m} title="Failures per minute" range={range} tz={tz} fmt={f1} keys={[{ key: 'fail_per_min', label: 'failures', color: '--exp-line-apps' }]} />
        <MetricChart m={m} title="Spool depth" range={range} tz={tz} fmt={f1} keys={[{ key: 'spool_depth', label: 'records', color: '--exp-line-dhcp' }]} />
        <MetricChart m={m} title="Push lag" range={range} tz={tz} fmt={f1} keys={[{ key: 'push_lag_s', label: 'seconds', color: '--exp-line-internet' }]} />
      </div>
      <Panel title="Measurements per minute by test" id="bytest">
        {tests.length === 0 ? <EmptyState title="No per-test counts reported" /> : (
          <ul class="bars">{tests.map(([k, v]) => <li key={k}><span class="bar-label">{k}</span><span class="bar" style={{ width: `${Math.min(100, (v / Math.max(...tests.map((t) => t[1]), 1)) * 100)}%` }} /><span class="bar-val">{v}</span></li>)}</ul>
        )}
      </Panel>
    </>
  );
}

// ---- Dashboard and runner ------------------------------------------------------------------------

function DashboardView({ sc, comp, m, range, tz }: { sc: StatusComponent | undefined; comp: Component | undefined; m: ReturnType<typeof useMetrics>; range: ReturnType<typeof rangeFrom>; tz: string | null }): JSX.Element {
  const total = metric(sc, 'collectors_total');
  const reach = metric(sc, 'collectors_reachable');
  const url = safeHttpsUrl(sc?.facts?.['url'] ?? comp?.config['url']);
  const fp = typeof sc?.facts?.['tls_fingerprint_sha256'] === 'string' ? (sc.facts['tls_fingerprint_sha256'] as string) : null;
  return (
    <>
      <div class="metric-row">
        <MetricTile label="Collectors reachable" value={total === null && reach === null ? <Missing why="not reported" /> : `${reach ?? DASH} of ${total ?? DASH}`} sev={total !== null && reach !== null && reach < total ? 'warn' : 'ok'} />
        <MetricTile label="Active sessions" value={metric(sc, 'sessions_active') ?? <Missing why="not reported" />} />
        <MetricTile label="Requests" value={formatRate(metric(sc, 'requests_per_min'), 'min')} />
        <MetricTile label="SSE clients" value={metric(sc, 'sse_clients') ?? <Missing why="not reported" />} />
        <MetricTile label="Login failures (1 h)" value={metric(sc, 'login_failures_1h') ?? <Missing why="not reported" />} sev={(metric(sc, 'login_failures_1h') ?? 0) > 10 ? 'warn' : 'ok'} />
      </div>
      <Panel title="Endpoint" id="dep">
        <dl class="facts"><div><dt>URL</dt><dd>{url ?? DASH}</dd></div><div><dt>TLS fingerprint (SHA-256)</dt><dd class="mono">{fp ?? DASH}</dd></div></dl>
        {comp ? <OpenDashboardButton dashId={comp.id} primary /> : null}
        <p class="dim">Opens the dashboard in a new window, signed in as you through the manager's single sign-on.</p>
      </Panel>
      <div class="range-bar"><h2 class="h2">Trends</h2><RangePicker value={range} /></div>
      <div class="charts">
        <MetricChart m={m} title="Active sessions" range={range} tz={tz} fmt={f1} keys={[{ key: 'sessions_active', label: 'sessions', color: '--exp-line-network' }]} />
        <MetricChart m={m} title="Requests per minute" range={range} tz={tz} fmt={f1} keys={[{ key: 'requests_per_min', label: 'requests', color: '--exp-line-internet' }]} />
      </div>
    </>
  );
}

function RunnerView({ sc, comp, m, range, tz }: { sc: StatusComponent | undefined; comp: Component | undefined; m: ReturnType<typeof useMetrics>; range: ReturnType<typeof rangeFrom>; tz: string | null }): JSX.Element {
  const pullers = Array.isArray(sc?.metrics?.['pullers']) ? (sc?.metrics?.['pullers'] as Record<string, unknown>[]) : [];
  const allow = comp?.config['allowlist'];
  const allowN = Array.isArray(allow) ? allow.length : null;
  return (
    <>
      <div class="metric-row">
        <MetricTile label="Active drills" value={metric(sc, 'drills_active') ?? <Missing why="not reported" />} />
        <MetricTile label="Allowlist size" value={allowN ?? <Missing why="not in the component configuration" />} />
      </div>
      <Panel title="Pullers" id="pullers">
        {pullers.length === 0 ? <EmptyState title="No pullers reported" /> : (
          <div class="table-scroll"><table class="plain">
            <caption class="sr-only">Pullers</caption>
            <thead><tr><th scope="col">Source</th><th scope="col">Last success</th><th scope="col">Errors (1 h)</th></tr></thead>
            <tbody>{pullers.map((p, i) => (
              <tr key={i}><th scope="row">{String(p['source'] ?? '?')}</th><td>{typeof p['last_ok'] === 'string' ? formatAgo(p['last_ok'], Date.now()) : DASH}</td><td class={(num(p['errors_1h']) ?? 0) > 0 ? 'sev-warn' : ''}>{num(p['errors_1h']) ?? DASH}</td></tr>
            ))}</tbody>
          </table></div>
        )}
      </Panel>
      <div class="range-bar"><h2 class="h2">Trends</h2><RangePicker value={range} /></div>
      <div class="charts"><MetricChart m={m} title="Active drills" range={range} tz={tz} fmt={f1} keys={[{ key: 'drills_active', label: 'drills', color: '--exp-line-apps' }]} /></div>
    </>
  );
}

export function ComponentPage({ id, cid, me }: { id: string; cid: string; me?: Me | undefined }): JSX.Element {
  const { query } = useLocation();
  const range = rangeFrom(query);
  const d = useHostData(id);
  const m = useMetrics('component', cid, range);
  const comps = d.comps.data?.items;
  const comp = comps?.find((c) => c.component_id === cid);
  const sc = comp ? d.status.data?.report.components.find((c) => c.type === comp.type && c.id === comp.id) : undefined;
  const presence = d.presence ?? 'online';

  if (d.comps.loading || d.host.loading) return <><PageHeader title="Component" /><SkeletonBlock rows={6} label="Loading component" /></>;
  if (!comp) {
    return (
      <>
        <PageHeader title="Component" crumbs={[{ to: '/hosts', label: 'Hosts' }, { to: `/hosts/${id}`, label: d.host.data?.name ?? id }]} />
        {d.comps.error ? <ErrorBanner what="Could not load components." message={d.comps.error.message} onRetry={d.comps.refresh} /> : <EmptyState title="Component not found" action={<Link to={`/hosts/${id}`} class="btn">Back to host</Link>}>It may have been removed from this host.</EmptyState>}
      </>
    );
  }
  const health = presence === 'online' ? (sc?.health ?? comp.health) : null;
  const editable = comp.type === 'probe' || comp.type === 'collector' || comp.type === 'dashboard';
  const tab = editable && query.get('view') === 'configure' ? 'configure' : 'status';
  return (
    <>
      <PageHeader
        title={comp.id}
        crumbs={[{ to: '/hosts', label: 'Hosts' }, { to: `/hosts/${id}`, label: d.host.data?.name ?? id }]}
        sub={<>{comp.type} · version {sc?.version ?? comp.version ?? DASH} · {sc?.state ?? 'no report'} · restarts {sc?.process?.restarts ?? DASH} · uptime {formatDuration(sc?.process?.uptime_s)} · CPU {formatPct(sc?.process?.cpu_pct)} · memory {sc?.process?.rss_mb != null ? formatMiB(sc.process.rss_mb) : DASH}</>}
        actions={health ? <StatusPill state={healthPill(health)} label={health === 'degraded' ? 'warn' : health} /> : <StatusPill state={presence === 'offline' ? 'offline' : 'stale'} />}
      />
      {presence !== 'online' ? <div class="banner banner-warn" role="status" data-testid="stale-banner"><Badge tone="warn">{presence}</Badge><span>The host last reported {formatAgo(d.lastReport, d.now)}. Values are as of {formatAbsolute(d.lastReport, d.tz)}.</span></div> : null}
      {sc?.detail ? <p class="comp-detail">{sc.detail}</p> : null}
      {editable ? <Tabs label="Component sections" tabs={[{ id: 'status', label: 'Status' }, { id: 'configure', label: 'Configure' }]} active={tab} onChange={(t) => setQuery({ view: t === 'status' ? null : t })} /> : null}
      {tab === 'configure' ? (
        <div role="tabpanel" id="panel-configure" aria-labelledby="tab-configure">
          {comp.type === 'probe' ? <ProbeEditor key={`${comp.component_id}:${comp.updated_at}`} comp={comp} me={me} /> : null}
          {comp.type === 'collector' ? <CollectorEditor key={`${comp.component_id}:${comp.updated_at}`} comp={comp} me={me} /> : null}
          {comp.type === 'dashboard' ? <DashboardEditor key={`${comp.component_id}:${comp.updated_at}`} comp={comp} me={me} tlsFingerprint={typeof sc?.facts?.['tls_fingerprint_sha256'] === 'string' ? (sc.facts['tls_fingerprint_sha256'] as string) : typeof comp.facts?.['tls_fingerprint_sha256'] === 'string' ? (comp.facts['tls_fingerprint_sha256'] as string) : null} factsUrl={typeof sc?.facts?.['url'] === 'string' ? (sc.facts['url'] as string) : typeof comp.facts?.['url'] === 'string' ? (comp.facts['url'] as string) : null} />
            : null}
        </div>
      ) : null}
      {tab === 'status' ? (
      <div class={presence !== 'online' ? 'as-of-panel' : ''} role={editable ? 'tabpanel' : undefined} id="panel-status" aria-labelledby={editable ? 'tab-status' : undefined}>
        {comp.type === 'collector' ? <CollectorView sc={sc} comp={comp} m={m} range={range} tz={d.tz} /> : null}
        {comp.type === 'probe' ? <ProbeView sc={sc} m={m} range={range} tz={d.tz} /> : null}
        {comp.type === 'dashboard' ? <DashboardView sc={sc} comp={comp} m={m} range={range} tz={d.tz} /> : null}
        {comp.type === 'runner' ? <RunnerView sc={sc} comp={comp} m={m} range={range} tz={d.tz} /> : null}
        {comp.type === 'speedtest' ? <EmptyState title="Speedtest component">No dedicated panels yet; see the process figures above.</EmptyState> : null}
      </div>
      ) : null}
    </>
  );
}

