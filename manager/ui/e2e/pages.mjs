// Every page of the UI, for the axe-core and 390-px sweeps. Ids come from the live mock so the list never goes stale.
export async function allPages(getJson) {
  const hosts = (await getJson('/fleet/hosts?limit=1000')).items;
  const ov = await getJson('/overview');
  const byName = (n) => hosts.find((h) => h.name === n);
  const col = byName('hb-col-01');
  const pr = byName('hb-probe-05');
  const pending = hosts.filter((h) => h.state === 'pending');
  const compOf = async (h, type) => (await getJson(`/hosts/${h.host_id}/components`)).items.find((c) => c.type === type);
  const colC = await compOf(col, 'collector');
  const prC = await compOf(pr, 'probe');
  const dashHost = ov.hosts.find((h) => h.components.some((c) => c.type === 'dashboard'));
  const dashC = dashHost.components.find((c) => c.type === 'dashboard');
  const stBox = hosts.find((h) => h.shapes.includes('speedtest'));
  const stC = await compOf(stBox, 'speedtest');
  const runC = await compOf(stBox, 'runner');
  const comp = (h, c, extra = '') => `/hosts/${h.host_id}/components/${c.component_id}${extra}`;
  const pages = [
    ['fleet', '/fleet'], ['ops', '/ops'], ['issues', '/issues'], ['hosts', '/hosts'], ['hosts-new', '/hosts/new'],
    ['sites', '/sites'], ['site', '/sites/hall-b'],
    ['host-overview', `/hosts/${col.host_id}`], ['host-components', `/hosts/${col.host_id}?tab=components`], ['host-interfaces', `/hosts/${col.host_id}?tab=interfaces`],
    ['host-config', `/hosts/${col.host_id}?tab=config`], ['host-activity', `/hosts/${col.host_id}?tab=activity`], ['host-actions', `/hosts/${col.host_id}?tab=actions`],
    ['collector', comp(col, colC)], ['collector-edit', comp(col, colC, '?view=configure')],
    ['probe', comp(pr, prC)], ['probe-edit', comp(pr, prC, '?view=configure')],
    ['dashboard', `/hosts/${dashHost.host_id}/components/${dashC.component_id}`], ['dashboard-edit', `/hosts/${dashHost.host_id}/components/${dashC.component_id}?view=configure`],
    ['wizard-enrol', `/hosts/new?host=${pending[0].host_id}`], ['wizard-interfaces', `/hosts/new?host=${pr.host_id}`], ['wizard-apply', `/hosts/new?host=${pr.host_id}&step=apply`],
    ['speedtest-index', '/speedtest'], ['speedtest-settings', '/sites/hall-b/speedtest'], ['speedtest-component', comp(stBox, stC)],
    ['runner', comp(stBox, runC)], ['runner-edit', comp(stBox, runC, '?view=configure')],
    ['releases', '/releases'], ['dashboards', '/dashboards'], ['drills', '/drills'], ['audit', '/audit'], ['settings', '/settings'],
  ];
  return pages.map(([name, url]) => ({ name, url }));
}
