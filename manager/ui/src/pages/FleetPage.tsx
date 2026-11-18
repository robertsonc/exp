import type { JSX } from 'preact';
import { ep } from '../api/endpoints';
import type { FleetSite, FleetSummary, FleetTop, Issue, Me, Page } from '../api/types';
import { useResource, useNow } from '../data/hooks';
import { useDirectory } from '../data/directory';
import { KpiTile, HealthBar, Sparkline, UsageBar, Link } from '../components/viz';
import { EmptyState, ErrorBanner, Panel, SkeletonBlock, Skeleton } from '../components/atoms';
import { IssueRow } from '../components/Issues';
import { AsOf, PageHeader } from './common';
import { DASH, formatCount, formatPct, formatPps, formatRate } from '../lib/format';
import { diskSeverity } from '../lib/state';
import { isSnoozed, sortIssues } from '../lib/issues';

function sumHealth(s: FleetSummary): { ok: number; warn: number; fail: number; unknown: number } {
  const t = { ok: 0, warn: 0, fail: 0, unknown: 0 };
  for (const c of Object.values(s.components_by_type_health)) {
    t.ok += c.ok ?? 0;
    t.warn += c.degraded ?? 0;
    t.fail += c.fail ?? 0;
    t.unknown += c.unknown ?? 0;
  }
  return t;
}

function Kpis({ s, now }: { s: FleetSummary; now: number }): JSX.Element {
  const h = sumHealth(s);
  const issues = s.open_issues.warn + s.open_issues.crit;
  const notOnline = s.hosts_total - s.hosts_online;
  return (
    <section class="kpi-strip" aria-label="Fleet key figures" data-testid="kpis">
      <KpiTile label="Hosts" to="/hosts" value={<span data-k="hosts">{s.hosts_online}/{s.hosts_total} online</span>}
        sub={notOnline > 0 ? `${s.hosts_by_state['stale'] ?? 0} stale · ${s.hosts_by_state['offline'] ?? 0} offline · ${s.hosts_by_state['pending'] ?? 0} pending` : 'all reporting'} tone={notOnline > 0 ? 'warn' : 'ok'} />
      <KpiTile label="Components" to="/hosts?health=fail" value={<span data-k="components">{h.ok} ok · {h.warn} warn · {h.fail} fail</span>}
        sub={h.unknown ? `${h.unknown} unknown` : undefined} tone={h.fail ? 'fail' : h.warn ? 'warn' : 'ok'} />
      <KpiTile label="Measurements" value={<span data-k="measurements">{s.measurements_per_min === null ? DASH : `${formatCount(s.measurements_per_min)}/min`}</span>} />
      <KpiTile label="Ingest" value={<span data-k="ingest">{formatRate(s.ingest_records_per_s, 's')}</span>} />
      <KpiTile label="Open issues" to="/issues" value={<span data-k="issues">{issues} <span class="kpi-small">({s.open_issues.crit} crit)</span></span>}
        tone={s.open_issues.crit ? 'fail' : issues ? 'warn' : 'ok'} />
      <KpiTile label="Version drift" to="/hosts?drift=1" value={<span data-k="drift">{s.version_drift_hosts} host{s.version_drift_hosts === 1 ? '' : 's'}</span>} tone={s.version_drift_hosts ? 'warn' : 'ok'} />
      <KpiTile label="Experience incidents" to="/dashboards" value={<span data-k="incidents">{s.open_experience_incidents === null ? DASH : `${s.open_experience_incidents} open`}</span>}
        sub="reported by collectors" tone={s.open_experience_incidents ? 'warn' : undefined} asOf={`as of ${s.as_of}`} />
      <p class="kpi-asof"><AsOf ts={s.as_of} now={now} label="Fleet figures as of" /></p>
    </section>
  );
}

function NeedsAttention({ me, now }: { me: Me | undefined; now: number }): JSX.Element {
  const issues = useResource<Page<Issue>>(ep.issues('open'), { paged: true });
  const dir = useDirectory();
  const list = sortIssues((issues.data?.items ?? []).filter((i) => !isSnoozed(i, now)));
  return (
    <Panel title="Needs attention" id="attn" class="attn">
      {issues.loading ? <SkeletonBlock rows={4} label="Loading issues" /> : issues.error ? <ErrorBanner what="Could not load issues." message={issues.error.message} onRetry={issues.refresh} /> : list.length === 0 ? (
        <EmptyState title="Nothing needs attention">No open issues. The fleet is healthy.</EmptyState>
      ) : (
        <ul class="issue-list">
          {list.slice(0, 6).map((i) => <li key={i.issue_id}><IssueRow issue={i} hostName={dir.byId.get(i.host_id)?.name ?? i.host_id} compact me={me} now={now} /></li>)}
        </ul>
      )}
      {list.length > 6 || list.length > 0 ? <p class="panel-foot"><Link to="/issues">View all issues ({list.length}) &rarr;</Link></p> : null}
    </Panel>
  );
}

function SitesPanel(): JSX.Element {
  const sites = useResource<{ items: FleetSite[] }>(ep.fleetSites);
  return (
    <Panel title="Sites" id="sites">
      {sites.loading ? <SkeletonBlock rows={3} label="Loading sites" /> : sites.error ? <ErrorBanner what="Could not load sites." message={sites.error.message} onRetry={sites.refresh} /> : (sites.data?.items.length ?? 0) === 0 ? (
        <EmptyState title="No sites yet" action={<Link to="/sites" class="btn btn-primary">Create a site</Link>}>Create a site, then add your first host.</EmptyState>
      ) : (
        <ul class="site-cards">
          {sites.data?.items.map((s) => (
            <li key={s.site} class="site-card">
              <Link to={`/sites/${s.site}`} class="site-name">{s.name}</Link>
              <HealthBar counts={s.health_bar} width={140} showLegend={false} />
              <span class="site-meta">
                {s.hosts} host{s.hosts === 1 ? '' : 's'}
                {s.ingest_records_per_s != null ? ` · ${formatRate(s.ingest_records_per_s, 's')} ingest` : ''}
                {s.probes_total ? ` · ${s.probes_reporting ?? 0}/${s.probes_total} probes` : ''}
              </span>
              {s.worst_issue ? <span class={`site-issue ${s.worst_issue.severity === 'crit' ? 'sev-fail' : 'sev-warn'}`}>{s.worst_issue.severity === 'crit' ? 'crit' : 'warn'}: {s.worst_issue.detail}</span> : null}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function TopList({ metric, title }: { metric: 'cpu' | 'mem' | 'disk' | 'net'; title: string }): JSX.Element {
  const top = useResource<FleetTop>(ep.top(metric));
  return (
    <div class="top-col">
      <h3>{title}</h3>
      {top.loading ? <Skeleton h={80} /> : top.error ? <ErrorBanner what={`Could not load ${title}.`} onRetry={top.refresh} /> : (
        <ol class="top-list">
          {top.data?.items.slice(0, 5).map((i) => (
            <li key={i.host_id}>
              <Link to={`/hosts/${i.host_id}`} class="top-name">{i.name}</Link>
              {metric === 'cpu' || metric === 'mem' ? <><Sparkline values={i.spark} width={64} height={18} tone={i.value >= 90 ? 'fail' : 'accent'} /><span class="top-val">{formatPct(i.value)}</span></> : null}
              {metric === 'disk' ? <><UsageBar pct={i.value} sev={diskSeverity(i.value)} width={90} /><span class={`top-val sev-${diskSeverity(i.value)}`}>{formatPct(i.value)}</span></> : null}
              {metric === 'net' ? <span class="top-val">{formatPps(i.value)} in / {formatPps(i.value_out)} out</span> : null}
            </li>
          ))}
          {top.data && top.data.items.length === 0 ? <li class="dim">No data yet</li> : null}
        </ol>
      )}
    </div>
  );
}

export function FleetPage({ me }: { me: Me | undefined }): JSX.Element {
  const now = useNow();
  const summary = useResource<FleetSummary>(ep.summary);
  return (
    <>
      <PageHeader title="Fleet overview" sub="Is the platform healthy, and where do I act? Agents report about once a minute; this page refreshes every 30 s." />
      {summary.loading ? <SkeletonBlock rows={2} label="Loading fleet summary" /> : summary.error && !summary.data ? <ErrorBanner what="Could not load the fleet summary." message={summary.error.message} onRetry={summary.refresh} /> : summary.data ? <Kpis s={summary.data} now={now} /> : null}
      <div class="grid-2">
        <NeedsAttention me={me} now={now} />
        <SitesPanel />
      </div>
      <Panel title="Fleet resources (top hosts, last hour)" id="res">
        <div class="grid-3">
          <TopList metric="cpu" title="Top CPU" />
          <TopList metric="disk" title="Top disk" />
          <TopList metric="net" title="Top network" />
        </div>
      </Panel>
    </>
  );
}
