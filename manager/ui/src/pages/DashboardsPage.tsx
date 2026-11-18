import type { JSX } from 'preact';
import { ep } from '../api/endpoints';
import type { Overview } from '../api/types';
import { useResource } from '../data/hooks';
import { EmptyState, Panel, StatusPill, healthPill } from '../components/atoms';
import { OpenDashboardButton } from '../components/OpenDashboard';
import { Link } from '../components/viz';
import { Loadable, PageHeader } from './common';

/** Every dashboard in the fleet, with single sign-on and a link to its editor (users, NOC tokens, TLS). */
export function DashboardsPage(): JSX.Element {
  const ov = useResource<Overview>(ep.overview);
  const rows = (ov.data?.hosts ?? []).flatMap((h) => h.components.filter((c) => c.type === 'dashboard').map((c) => ({ h, c })));
  return (
    <>
      <PageHeader title="Dashboards" sub="Opening a dashboard signs you in through the manager; you do not need a separate password." actions={<Link to="/hosts/new" class="btn">Add host</Link>} />
      <Loadable loading={ov.loading} error={ov.data ? null : ov.error} onRetry={ov.refresh} what="dashboards">
        <Panel>
          {rows.length === 0 ? (
            <EmptyState title="No dashboards yet" action={<Link to="/hosts/new" class="btn btn-primary">Add a host with the dashboard shape</Link>}>A dashboard is the live experience board for operators and the NOC.</EmptyState>
          ) : (
            <div class="table-scroll">
              <table class="plain" data-testid="dashboards-table">
                <caption class="sr-only">Dashboards</caption>
                <thead><tr><th scope="col">Dashboard</th><th scope="col">Host</th><th scope="col">Site</th><th scope="col">Health</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {rows.map(({ h, c }) => (
                    <tr key={c.component_id} data-dashboard={c.id}>
                      <th scope="row"><Link to={`/hosts/${h.host_id}/components/${c.component_id}`}>{c.id}</Link></th>
                      <td><Link to={`/hosts/${h.host_id}`}>{h.name}</Link></td>
                      <td><Link to={`/sites/${h.site}`}>{h.site}</Link></td>
                      <td><StatusPill state={healthPill(c.health)} label={c.health === 'degraded' ? 'warn' : c.health} /></td>
                      <td class="row-btns">
                        <Link to={`/hosts/${h.host_id}/components/${c.component_id}?view=configure`} class="btn btn-sm" aria-label={`Configure ${c.id}`}>Configure</Link>
                        <OpenDashboardButton dashId={c.id} primary />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </Loadable>
    </>
  );
}
