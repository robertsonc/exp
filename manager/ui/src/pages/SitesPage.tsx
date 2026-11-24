import type { JSX } from 'preact';
import { useState } from 'preact/hooks';
import { ep } from '../api/endpoints';
import type { FleetSite, Me, Page, Site } from '../api/types';
import { useResource } from '../data/hooks';
import { Badge, Button, EmptyState, ErrorBanner, Panel, SkeletonBlock } from '../components/atoms';
import { canAdmin } from '../components/Issues';
import { HealthBar, Link } from '../components/viz';
import { Loadable, PageHeader } from './common';
import { HostsPage } from './HostsPage';
import { DeleteSiteButton, SiteAlertsPanel, SiteDialog, SiteHeartbeatPanel, SiteReleasePanel } from './SiteAdmin';
import { DASH, formatAbsolute, formatRate } from '../lib/format';

function SiteRollup({ s }: { s: FleetSite }): JSX.Element {
  return (
    <div class="rollup">
      <HealthBar counts={s.health_bar} width={220} />
      <span>{s.hosts} host{s.hosts === 1 ? '' : 's'}</span>
      {s.probes_total ? <span>{s.probes_reporting ?? 0}/{s.probes_total} probes reporting</span> : null}
      {s.ingest_records_per_s != null ? <span>{formatRate(s.ingest_records_per_s, 's')} ingest</span> : null}
    </div>
  );
}

export function SitesPage({ me }: { me?: Me | undefined }): JSX.Element {
  const [creating, setCreating] = useState(false);
  const sites = useResource<Page<Site>>(ep.sites, { paged: true });
  const roll = useResource<{ items: FleetSite[] }>(ep.fleetSites);
  const byRoll = new Map((roll.data?.items ?? []).map((s) => [s.site, s]));
  return (
    <>
      <PageHeader title="Sites" sub="Venues and halls. Each site has its own release target, alert settings and timezone."
        actions={<Button variant="primary" disabled={!canAdmin(me)} title={canAdmin(me) ? undefined : 'Requires the admin role'} onClick={() => setCreating(true)}>Create site</Button>} />
      {creating ? <SiteDialog onClose={() => setCreating(false)} /> : null}
      <Loadable loading={sites.loading} error={sites.data ? null : sites.error} onRetry={sites.refresh} what="sites">
        {(sites.data?.items.length ?? 0) === 0 ? <EmptyState title="No sites yet">Create your first site to start adding hosts.</EmptyState> : (
          <ul class="site-list">
            {sites.data?.items.map((s) => {
              const r = byRoll.get(s.site);
              return (
                <li key={s.site} class="panel site-row">
                  <div>
                    <h2 class="h2"><Link to={`/sites/${s.site}`}>{s.name}</Link></h2>
                    <p class="dim">{s.site} · {s.timezone} · release {s.release_version ?? DASH}{s.canary_state ? ` · canary ${s.canary_state}` : ''}</p>
                  </div>
                  {r ? <SiteRollup s={r} /> : <span class="dim">no roll-up yet</span>}
                </li>
              );
            })}
          </ul>
        )}
      </Loadable>
    </>
  );
}

export function SitePage({ slug, me }: { slug: string; me: Me | undefined }): JSX.Element {
  const [editing, setEditing] = useState(false);
  const site = useResource<Site>(ep.site(slug));
  const roll = useResource<{ items: FleetSite[] }>(ep.fleetSites);
  const r = roll.data?.items.find((s) => s.site === slug);
  if (site.loading) return <><PageHeader title="Site" /><SkeletonBlock rows={5} label="Loading site" /></>;
  const s = site.data;
  if (!s) {
    return (
      <>
        <PageHeader title="Site" crumbs={[{ to: '/sites', label: 'Sites' }]} />
        {site.error?.status === 404 ? <EmptyState title="Site not found" action={<Link to="/sites" class="btn">Back to sites</Link>} /> : <ErrorBanner what="Could not load this site." message={site.error?.message} onRetry={site.refresh} />}
      </>
    );
  }
  return (
    <>
      <PageHeader title={s.name} crumbs={[{ to: '/sites', label: 'Sites' }]} sub={<>{s.site} · {s.timezone}</>}
        actions={<><Button disabled={!canAdmin(me)} onClick={() => setEditing(true)}>Edit site</Button><DeleteSiteButton site={s} allowed={canAdmin(me)} /></>} />
      {editing ? <SiteDialog site={s} onClose={() => setEditing(false)} /> : null}
      <div class="grid-2">
        <Panel title="Health" id="sh">
          {r ? <SiteRollup s={r} /> : <SkeletonBlock rows={1} />}
          {r?.worst_issue ? <p class={r.worst_issue.severity === 'crit' ? 'sev-fail' : 'sev-warn'}>Worst issue: {r.worst_issue.detail} <Link to={`/hosts/${r.worst_issue.host_id}`}>open host</Link></p> : <p class="dim">No open issues.</p>}
        </Panel>
        <Panel title="Configuration" id="sc">
          <dl class="facts">
            <div><dt>Release</dt><dd>{s.release_version ?? DASH} {s.canary_state ? <Badge tone={s.canary_state === 'failed' ? 'fail' : 'neutral'}>canary {s.canary_state}</Badge> : null}</dd></div>
            <div><dt>Timezone</dt><dd>{s.timezone}</dd></div>
            <div><dt>Edge label</dt><dd>{s.edge_label || DASH}</dd></div>
            <div><dt>Retention</dt><dd>{s.retention ? `metrics ${s.retention.metrics_days ?? DASH} d, records ${s.retention.records_days ?? DASH} d` : DASH}</dd></div>
            <div><dt>Created</dt><dd title={formatAbsolute(s.created_at, s.timezone)}>{formatAbsolute(s.created_at, s.timezone)}</dd></div>
          </dl>
        </Panel>
      </div>
      <Panel title="Speedtest" id="sp">
        <p class="dim">The branded speedtest page for this site: branding, consent text, zones, limits and signage.</p>
        <Link to={`/sites/${slug}/speedtest`} class="btn btn-secondary">Open speedtest settings</Link>
      </Panel>
      <div class="grid-2">
        <SiteReleasePanel site={s} me={me} />
        <SiteHeartbeatPanel site={s} me={me} />
        <SiteAlertsPanel slug={slug} me={me} />
      </div>
      <HostsPage site={slug} />
    </>
  );
}
