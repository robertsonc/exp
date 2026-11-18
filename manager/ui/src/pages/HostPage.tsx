import type { JSX } from 'preact';
import { useEffect, useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { AuditEvent, Component, EnrolToken, FleetHostRow, Issue, Me, Page, StatusComponent, StatusReport } from '../api/types';
import { mutate, useResource } from '../data/hooks';
import { useHostData } from '../data/hostData';
import { useDirectory } from '../data/directory';
import { Badge, Button, ConfirmDialog, CopyField, Countdown, Dialog, EmptyState, ErrorBanner, Missing, Panel, ShapeBadges, SkeletonBlock, StatusPill, Tabs, healthPill } from '../components/atoms';
import { IssueRow, canAdmin } from '../components/Issues';
import { MetricChart, RangePicker, rangeFrom, useMetrics } from '../components/MetricChart';
import { notify } from '../components/Toasts';
import { Link, MetricTile, Sparkline } from '../components/viz';
import { PageHeader } from './common';
import { DASH, formatAbsolute, formatAgo, formatBps, formatDuration, formatMiB, formatPct, formatPps, formatVersion } from '../lib/format';
import { isSnoozed, sortIssues } from '../lib/issues';
import { redact } from '../lib/redact';
import { diskSeverity } from '../lib/state';
import { setQuery, useLocation } from '../router';
import { ApiFailure } from '../data/store';

const TABS = [
  { id: 'overview', label: 'Overview' }, { id: 'components', label: 'Components' }, { id: 'interfaces', label: 'Interfaces' },
  { id: 'config', label: 'Configuration' }, { id: 'activity', label: 'Activity' }, { id: 'actions', label: 'Actions' },
];

const pctFmt = (v: number | null) => (v === null ? DASH : formatPct(v));
const ppsFmt = (v: number | null) => (v === null ? DASH : formatPps(v));
const bpsFmt = (v: number | null) => (v === null ? DASH : formatBps(v));
const numFmt = (v: number | null) => (v === null ? DASH : String(Math.round(v * 100) / 100));

function StaleBanner({ presence, lastSeen, now }: { presence: string | null; lastSeen: string | null; now: number }): JSX.Element | null {
  if (presence === 'stale' || presence === 'offline') {
    return (
      <div class={`banner ${presence === 'offline' ? 'banner-fail' : 'banner-warn'}`} role="status" data-testid="stale-banner">
        <StatusPill state={presence} />
        <span>
          This host is {presence}: it last reported {formatAgo(lastSeen, now)} ({formatAbsolute(lastSeen)}). Every value on this page is <strong>as of that time</strong>, not current.
        </span>
      </div>
    );
  }
  return null;
}

function HostFacts({ r, hostState }: { r: StatusReport | undefined; hostState: string }): JSX.Element {
  const f = r?.facts;
  return (
    <dl class="facts">
      <div><dt>OS</dt><dd>{f?.os ? `${f.os.id ?? ''} ${f.os.version ?? ''}` : DASH}</dd></div>
      <div><dt>Kernel</dt><dd>{f?.kernel ?? DASH}</dd></div>
      <div><dt>Arch</dt><dd>{f?.arch ?? DASH}</dd></div>
      <div><dt>CPUs / memory</dt><dd>{f?.cpus ?? DASH} / {f?.mem_mb ? formatMiB(f.mem_mb) : DASH}</dd></div>
      <div><dt>Time sync</dt><dd>{f?.time ? `${f.time.synced ? 'synced' : 'NOT synced'}${f.time.offset_ms != null ? `, offset ${f.time.offset_ms} ms` : ''}` : DASH}</dd></div>
      <div><dt>State</dt><dd>{hostState}</dd></div>
    </dl>
  );
}

function OverviewTab({ id, hostName, tz, row, status }: { id: string; hostName: string; tz: string | null; row: FleetHostRow | undefined; status: StatusReport | undefined }): JSX.Element {
  const { query } = useLocation();
  const range = rangeFrom(query);
  const m = useMetrics('host', id, range);
  const issues = useResource<Page<Issue>>(ep.issues('open'), { paged: true });
  const mine = sortIssues((issues.data?.items ?? []).filter((i) => i.host_id === id));
  const m1 = status?.metrics;
  const mem = m1?.mem;
  return (
    <>
      <div class="metric-row">
        <MetricTile label="CPU" value={formatPct(m1?.cpu?.pct ?? row?.cpu_pct)} spark={row?.cpu_spark} sub={m1?.cpu?.load1 != null ? `load ${m1.cpu.load1}` : undefined} />
        <MetricTile label="Memory" value={formatPct(mem?.pct ?? row?.mem_pct)} sub={mem?.total_mb ? `${formatMiB(mem.used_mb)} of ${formatMiB(mem.total_mb)}` : undefined} />
        {(m1?.disk ?? []).map((d) => <MetricTile key={d.mount} label={`Disk ${d.mount}`} value={formatPct(d.pct)} sev={diskSeverity(d.pct)} sub={d.total_gb ? `${d.used_gb} of ${d.total_gb} GiB` : undefined} />)}
        <MetricTile label="Uptime" value={formatDuration(m1?.uptime_s ?? row?.uptime_s)} />
        <MetricTile label="Temp" value={m1?.temp_c_max != null ? `${m1.temp_c_max} °C` : DASH} />
      </div>
      <div class="range-bar"><h2 class="h2">Trends</h2><RangePicker value={range} /></div>
      <div class="charts">
        <MetricChart m={m} title="CPU (avg with max band)" range={range} tz={tz} fmt={pctFmt} yMax={100} keys={[{ key: 'cpu_pct', label: 'CPU', color: '--exp-line-network' }]} />
        <MetricChart m={m} title="Load average" range={range} tz={tz} fmt={numFmt} keys={[{ key: 'load1', label: 'load1', color: '--exp-line-internet' }]} />
        <MetricChart m={m} title="Memory" range={range} tz={tz} fmt={pctFmt} yMax={100} keys={[{ key: 'mem_pct', label: 'Memory', color: '--exp-line-dns' }]} />
        <MetricChart m={m} title="Disk" range={range} tz={tz} fmt={pctFmt} yMax={100} keys={[{ key: 'disk_pct', label: 'Disk (max)', color: '--exp-line-dhcp' }]} />
        <MetricChart m={m} title="Management network, packets/s" range={range} tz={tz} fmt={ppsFmt} keys={[{ key: 'net_rx_pps', label: 'in', color: '--exp-line-network' }, { key: 'net_tx_pps', label: 'out', color: '--exp-line-apps' }]} />
        <MetricChart m={m} title="Management network, bits/s" range={range} tz={tz} fmt={bpsFmt} keys={[{ key: 'net_rx_bps', label: 'in', color: '--exp-line-network' }, { key: 'net_tx_bps', label: 'out', color: '--exp-line-apps' }]} />
        <MetricChart m={m} title="Network errors and drops" range={range} tz={tz} fmt={numFmt} keys={[{ key: 'net_rx_errors', label: 'rx errors', color: '--exp-line-apps' }, { key: 'net_tx_errors', label: 'tx errors', color: '--exp-line-dhcp' }, { key: 'net_rx_drops', label: 'rx drops', color: '--exp-line-wifi' }, { key: 'net_tx_drops', label: 'tx drops', color: '--exp-line-dns' }]} />
        <MetricChart m={m} title="Disk write" range={range} tz={tz} fmt={numFmt} keys={[{ key: 'disk_write_kbps', label: 'write kB/s', color: '--exp-line-internet' }]} />
      </div>
      <div class="grid-2">
        <Panel title="Open issues" id="hi">
          {mine.length === 0 ? <EmptyState title="No open issues on this host" /> : (
            <ul class="issue-list">{mine.map((i) => <li key={i.issue_id}><IssueRow issue={i} hostName={hostName} compact now={Date.now()} />{isSnoozed(i, Date.now()) ? <span class="dim"> snoozed</span> : null}</li>)}</ul>
          )}
        </Panel>
        <Panel title="Recent events" id="ev">
          <Events report={status} />
        </Panel>
      </div>
    </>
  );
}

function Events({ report }: { report: StatusReport | undefined }): JSX.Element {
  const ev = report?.events ?? [];
  const rec = report?.reconcile;
  if (!rec && ev.length === 0) return <EmptyState title="No events reported yet" />;
  return (
    <ul class="events">
      {rec ? <li class={rec.result === 'ok' ? '' : 'sev-warn'}><time dateTime={rec.at}>{formatAgo(rec.at, Date.now())}</time> reconcile {rec.result}{rec.error ? `: ${rec.error}` : ''}{rec.duration_ms ? ` (${Math.round(rec.duration_ms)} ms)` : ''}</li> : null}
      {ev.slice(0, 12).map((e, i) => <li key={`${e.ts}${i}`} class={e.level === 'error' ? 'sev-fail' : e.level === 'warn' ? 'sev-warn' : ''}><time dateTime={e.ts} title={formatAbsolute(e.ts)}>{formatAgo(e.ts, Date.now())}</time> [{e.level}] {e.msg}</li>)}
    </ul>
  );
}

function ComponentsTab({ hostId, report, comps }: { hostId: string; report: StatusReport | undefined; comps: Component[] }): JSX.Element {
  const list = report?.components ?? [];
  const byKey = new Map(comps.map((c) => [`${c.type}/${c.id}`, c]));
  if (list.length === 0 && comps.length === 0) return <EmptyState title="No components on this host yet" />;
  const rows: { sc: StatusComponent | undefined; c: Component | undefined; type: string; id: string }[] = list.map((sc) => ({ sc, c: byKey.get(`${sc.type}/${sc.id}`), type: sc.type, id: sc.id }));
  for (const c of comps) if (!list.some((s) => s.type === c.type && s.id === c.id)) rows.push({ sc: undefined, c, type: c.type, id: c.id });
  return (
    <div class="comp-grid">
      {rows.map(({ sc, c, type, id }) => (
        <Panel key={`${type}/${id}`} class="comp-panel">
          <div class="comp-head">
            <h3>{c ? <Link to={`/hosts/${hostId}/components/${c.component_id}`}>{id}</Link> : id}</h3>
            <StatusPill state={healthPill(sc?.health ?? c?.health ?? 'unknown')} label={sc?.health === 'degraded' ? 'warn' : sc?.health ?? c?.health} />
          </div>
          <p class="dim">{type} {sc?.version ?? c?.version ?? ''} · {sc?.state ?? 'no report'}</p>
          {sc?.detail ? <p class="comp-detail">{sc.detail}</p> : null}
          <dl class="facts facts-compact">
            <div><dt>CPU</dt><dd>{sc?.process?.cpu_pct != null ? formatPct(sc.process.cpu_pct) : <Missing why="not reported" />}</dd></div>
            <div><dt>Memory</dt><dd>{sc?.process?.rss_mb != null ? formatMiB(sc.process.rss_mb) : <Missing why="not reported" />}</dd></div>
            <div><dt>Restarts</dt><dd className={sc?.process?.restarts ? 'sev-warn' : ''}>{sc?.process?.restarts ?? DASH}</dd></div>
            <div><dt>Uptime</dt><dd>{formatDuration(sc?.process?.uptime_s)}</dd></div>
          </dl>
        </Panel>
      ))}
    </div>
  );
}

function InterfacesTab({ report, spark }: { report: StatusReport | undefined; spark: (number | null)[] | undefined }): JSX.Element {
  const ifs = report?.facts.interfaces ?? [];
  const net = new Map((report?.metrics.net ?? []).map((n) => [n.iface, n]));
  if (ifs.length === 0) return <EmptyState title="No interfaces reported" />;
  return (
    <div class="table-scroll">
      <table class="plain">
        <caption class="sr-only">Network interfaces</caption>
        <thead><tr><th scope="col">Interface</th><th scope="col">Role</th><th scope="col">Link</th><th scope="col">Speed</th><th scope="col">Addresses</th><th scope="col">In</th><th scope="col">Out</th><th scope="col">Errors / drops</th><th scope="col">Trend</th></tr></thead>
        <tbody>
          {ifs.map((i) => {
            const n = net.get(i.name);
            const role = i.in_use_by === 'mgmt' ? 'mgmt' : i.in_use_by;
            return (
              <tr key={i.name}>
                <th scope="row">{i.name}</th>
                <td>{role}</td>
                <td><StatusPill state={i.state === 'up' ? 'ok' : i.state === 'down' ? 'fail' : 'unknown'} label={i.state} /></td>
                <td>{i.speed_mbps ? `${i.speed_mbps} Mb/s` : DASH}</td>
                <td>{(i.addrs ?? []).join(', ') || DASH}</td>
                <td>{n ? `${formatPps(n.rx_pps)} · ${formatBps(n.rx_bps)}` : <Missing why="not a host-namespace interface or no data" />}</td>
                <td>{n ? `${formatPps(n.tx_pps)} · ${formatBps(n.tx_bps)}` : DASH}</td>
                <td>{n ? `${(n.rx_errors ?? 0) + (n.tx_errors ?? 0)} / ${(n.rx_drops ?? 0) + (n.tx_drops ?? 0)}` : DASH}</td>
                <td>{i.in_use_by === 'mgmt' ? <Sparkline values={spark} width={64} height={18} /> : DASH}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function ConfigTab({ comps, host }: { comps: Component[]; host: { desired_version: number | null; applied_version: number | null } }): JSX.Element {
  return (
    <>
      <p class="config-versions">Desired configuration <strong>{formatVersion(host.desired_version)}</strong>, applied <strong>{formatVersion(host.applied_version)}</strong>
        {host.desired_version !== host.applied_version ? <Badge tone="warn">not yet applied</Badge> : <Badge tone="ok">in sync</Badge>}</p>
      <p class="dim">Read-only view of the configuration as last compiled for this host. Credentials are never part of it.</p>
      {comps.length === 0 ? <EmptyState title="No components configured" /> : comps.map((c) => (
        <Panel key={c.component_id} title={`${c.id} (${c.type})`}>
          <pre class="code" tabIndex={0} aria-label={`Rendered configuration of ${c.id}`}>{c.rendered_config ? JSON.stringify(redact(c.rendered_config), null, 2) : 'Not compiled yet.'}</pre>
        </Panel>
      ))}
    </>
  );
}

function ActivityTab({ id, report }: { id: string; report: StatusReport | undefined }): JSX.Element {
  const audit = useResource<Page<AuditEvent>>(ep.audit(`host:${id}`));
  return (
    <div class="grid-2">
      <Panel title="Audit" id="aud">
        {audit.loading ? <SkeletonBlock rows={3} /> : audit.error ? <ErrorBanner what="Could not load audit events." message={audit.error.message} onRetry={audit.refresh} /> : (audit.data?.items.length ?? 0) === 0 ? <EmptyState title="No audit events for this host" /> : (
          <ul class="events">{audit.data?.items.map((e) => <li key={e.evt_id}><time dateTime={e.ts} title={formatAbsolute(e.ts)}>{formatAgo(e.ts, Date.now())}</time> {e.actor}: {e.action}</li>)}</ul>
        )}
      </Panel>
      <Panel title="Agent events" id="ae"><Events report={report} /></Panel>
    </div>
  );
}

type ActionKind = 'restart' | 'rotate' | 'rotate-agent' | 'decommission' | null;

function ActionsTab({ hostId, hostName, comps, me }: { hostId: string; hostName: string; comps: Component[]; me: Me | undefined }): JSX.Element {
  const [kind, setKind] = useState<ActionKind>(null);
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState<EnrolToken | null>(null);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!token) return undefined;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [token]);
  const allowed = canAdmin(me);
  const comp = comps.find((c) => c.component_id === target) ?? comps[0];
  const close = () => { setKind(null); setError(null); setBusy(false); };
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      if (kind === 'restart' && comp) {
        const r = await mutate<{ desired_version?: number }>('POST', ep.restart(comp.component_id));
        notify('ok', `Restart of ${comp.id} queued${r?.desired_version != null ? ` (desired config v${r.desired_version})` : ''}`);
      } else if (kind === 'rotate' && comp) {
        await mutate('POST', ep.rotate(comp.component_id));
        notify('ok', `Credentials for ${comp.id} are being rotated`);
      } else if (kind === 'rotate-agent') {
        await mutate('POST', ep.rotateAgent(hostId));
        notify('ok', `The agent secret of ${hostName} will be rotated on its next poll`);
      } else if (kind === 'decommission') {
        await mutate('POST', ep.decommission(hostId));
        notify('ok', `${hostName} is being decommissioned`);
      }
      close();
    } catch (e) {
      setError(e instanceof ApiFailure ? `${e.message} (${e.code})` : 'Request failed');
      setBusy(false);
    }
  };
  const newToken = async () => {
    try {
      setToken(await mutate<EnrolToken>('POST', ep.enrolToken(hostId)));
    } catch (e) {
      notify('error', `Could not create an enrol token: ${e instanceof Error ? e.message : 'unknown error'}`);
    }
  };
  return (
    <div class="actions">
      {!allowed ? <p class="banner banner-warn" role="status">Your role does not allow changes. Actions need the admin role.</p> : null}
      <Panel title="Restart a component">
        <p class="dim">Queues a restart; the agent applies it on its next poll.</p>
        <label class="field"><span>Component</span>
          <select value={comp?.component_id ?? ''} onChange={(e) => setTarget((e.currentTarget as HTMLSelectElement).value)}>
            {comps.map((c) => <option key={c.component_id} value={c.component_id}>{c.id} ({c.type})</option>)}
          </select>
        </label>
        <Button disabled={!allowed || !comp} onClick={() => setKind('restart')}>Restart component</Button>
      </Panel>
      <Panel title="Rotate credentials">
        <p class="dim">Issues new ingest and API tokens for the selected component; the old ones keep working for 10 minutes. New values are delivered to the host and its peers, never shown here.</p>
        <div class="row-btns">
          <Button disabled={!allowed || !comp} onClick={() => setKind('rotate')}>Rotate credentials</Button>
          <Button disabled={!allowed} onClick={() => setKind('rotate-agent')}>Rotate agent secret</Button>
        </div>
      </Panel>
      <Panel title="New enrol token">
        <p class="dim">Valid for one hour. Shown once.</p>
        <Button disabled={!allowed} onClick={() => void newToken()}>Create enrol token</Button>
      </Panel>
      <Panel title="Decommission" class="danger-zone">
        <p class="dim">Removes this host from the fleet. Its components are stopped and its credentials revoked.</p>
        <Button variant="danger" disabled={!allowed} onClick={() => setKind('decommission')}>Decommission host</Button>
      </Panel>
      {kind ? (
        <ConfirmDialog
          title={kind === 'restart' ? `Restart ${comp?.id ?? ''}?` : kind === 'rotate' ? `Rotate credentials of ${comp?.id ?? ''}?` : kind === 'rotate-agent' ? `Rotate the agent secret of ${hostName}?` : `Decommission ${hostName}?`}
          body={kind === 'decommission'
            ? <p>This stops every exp component on <strong>{hostName}</strong> and revokes its credentials. Probes on it stop reporting and the host leaves the fleet.</p>
            : kind === 'rotate-agent' ? <p>The agent on <strong>{hostName}</strong> swaps its secret with the manager on its next poll. The old secret stays valid for 10 minutes.</p>
            : kind === 'restart' ? <p>The component <strong>{comp?.id}</strong> on <strong>{hostName}</strong> restarts; measurements may pause for a few seconds.</p>
              : <p>New tokens are issued for <strong>{comp?.id}</strong> on <strong>{hostName}</strong>. Peers pick them up on their next poll.</p>}
          confirmText={kind === 'decommission' ? 'Decommission' : kind === 'restart' ? 'Restart' : 'Rotate'}
          typeName={kind === 'decommission' ? hostName : undefined}
          busy={busy} error={error} onConfirm={() => void run()} onCancel={close}
        />
      ) : null}
      {token ? (
        <Dialog title="Enrol token" onClose={() => setToken(null)}>
          <p>Run this on the target host. It expires in <Countdown until={token.expires_at} now={now} /> and is shown only once.</p>
          <CopyField value={token.command} label="install command" />
          <div class="dialog-actions"><Button variant="primary" onClick={() => setToken(null)}>Done</Button></div>
        </Dialog>
      ) : null}
    </div>
  );
}

export function HostPage({ id, me }: { id: string; me: Me | undefined }): JSX.Element {
  const { query } = useLocation();
  const d = useHostData(id);
  const dir = useDirectory();
  const tab = TABS.some((t) => t.id === query.get('tab')) ? (query.get('tab') as string) : 'overview';
  const h = d.host.data;
  const row = dir.byId.get(id);
  const report = d.status.data?.report;
  const comps = d.comps.data?.items ?? [];

  // While the host is catching up with the desired version, refresh quickly and show progress.
  const applying = !!h && h.desired_version != null && h.applied_version != null && h.applied_version < h.desired_version;
  useEffect(() => {
    if (!applying) return undefined;
    const t = setInterval(() => { d.host.refresh(); d.status.refresh(); }, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applying]);

  if (d.host.loading) return <><PageHeader title="Host" /><SkeletonBlock rows={6} label="Loading host" /></>;
  if (!h) {
    return (
      <>
        <PageHeader title="Host" crumbs={[{ to: '/hosts', label: 'Hosts' }]} />
        {d.host.error?.status === 404 ? <EmptyState title="Host not found" action={<Link to="/hosts" class="btn">Back to hosts</Link>}>It may have been removed.</EmptyState>
          : <ErrorBanner what="Could not load this host." message={d.host.error?.message} onRetry={d.host.refresh} />}
      </>
    );
  }
  const healthy = report?.components.filter((c) => c.health === 'ok').length ?? 0;
  const presence = d.presence ?? 'online';
  return (
    <>
      <PageHeader
        title={h.name}
        crumbs={[{ to: '/hosts', label: 'Hosts' }]}
        sub={<>
          <Link to={`/sites/${h.site}`}>{h.site}</Link> · <ShapeBadges shapes={h.shapes} /> · {h.mgmt_ip ?? 'no management IP yet'} · agent {h.agent_version ?? DASH}
          {' '}(desired {formatVersion(h.desired_version)}, applied {formatVersion(h.applied_version)}) · uptime {formatDuration(report?.metrics.uptime_s)} · last report {formatAgo(d.lastReport, d.now)}
        </>}
        actions={<StatusPill state={presence === 'online' ? healthPill(row?.health ?? 'unknown') : presence === 'stale' ? 'stale' : presence === 'offline' ? 'offline' : 'unknown'} label={presence === 'online' ? (row?.health === 'degraded' ? 'warn' : row?.health ?? 'unknown') : presence} />}
      />
      <StaleBanner presence={presence} lastSeen={d.lastReport} now={d.now} />
      {applying ? <div class="banner banner-info" role="status"><Badge>applying</Badge><span>Applying {formatVersion(h.desired_version)}… {healthy} of {report?.components.length ?? 0} components healthy (currently {formatVersion(h.applied_version)}).</span></div> : null}
      <HostFacts r={report} hostState={h.state} />
      <Tabs label="Host sections" tabs={TABS} active={tab} onChange={(t) => setQuery({ tab: t === 'overview' ? null : t })} />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} class={`tabpanel${presence === 'stale' || presence === 'offline' ? ' as-of-panel' : ''}`}>
        {d.status.loading && tab !== 'actions' ? <SkeletonBlock rows={5} label="Loading status" /> : null}
        {tab === 'overview' ? <OverviewTab id={id} hostName={h.name} tz={d.tz} row={row} status={report} /> : null}
        {tab === 'components' ? <ComponentsTab hostId={id} report={report} comps={comps} /> : null}
        {tab === 'interfaces' ? <InterfacesTab report={report} spark={row?.net_spark} /> : null}
        {tab === 'config' ? <ConfigTab comps={comps} host={h} /> : null}
        {tab === 'activity' ? <ActivityTab id={id} report={report} /> : null}
        {tab === 'actions' ? <ActionsTab hostId={id} hostName={h.name} comps={comps} me={me} /> : null}
      </div>
    </>
  );
}
