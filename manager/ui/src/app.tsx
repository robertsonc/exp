import type { JSX } from 'preact';
import { ep } from './api/endpoints';
import type { Me } from './api/types';
import { useResource } from './data/hooks';
import { AppShell } from './components/Shell';
import { ToastHost } from './components/Toasts';
import { AddHostPage } from './pages/AddHostPage';
import { AuditPage } from './pages/AuditPage';
import { ComponentPage } from './pages/ComponentPage';
import { DashboardsPage } from './pages/DashboardsPage';
import { DrillsPage } from './pages/DrillsPage';
import { FleetPage } from './pages/FleetPage';
import { HostPage } from './pages/HostPage';
import { HostsPage } from './pages/HostsPage';
import { IssuesPage } from './pages/IssuesPage';
import { NotFound } from './pages/Placeholder';
import { ReleasesPage } from './pages/ReleasesPage';
import { SettingsPage } from './pages/SettingsPage';
import { SpeedtestIndex, SpeedtestPage } from './pages/SpeedtestPage';
import { SitePage, SitesPage } from './pages/SitesPage';
import { matchRoute, useLocation } from './router';

export function App(): JSX.Element {
  const loc = useLocation();
  const me = useResource<Me>(ep.me).data;
  const m = matchRoute(loc.path);
  let page: JSX.Element;
  switch (m.name) {
    case 'fleet': page = <FleetPage me={me} />; break;
    case 'issues': page = <IssuesPage me={me} />; break;
    case 'hosts': page = <HostsPage me={me} />; break;
    case 'hostnew': page = <AddHostPage me={me} />; break;
    case 'host': page = <HostPage key={m.params['id']} id={m.params['id'] ?? ''} me={me} />; break;
    case 'component': page = <ComponentPage key={m.params['cid']} id={m.params['id'] ?? ''} cid={m.params['cid'] ?? ''} me={me} />; break;
    case 'sites': page = <SitesPage me={me} />; break;
    case 'site': page = <SitePage key={m.params['site']} slug={m.params['site'] ?? ''} me={me} />; break;
    case 'speedtest': page = <SpeedtestIndex />; break;
    case 'speedtestsite': page = <SpeedtestPage key={m.params['site']} slug={m.params['site'] ?? ''} me={me} />; break;
    case 'releases': page = <ReleasesPage me={me} />; break;
    case 'dashboards': page = <DashboardsPage />; break;
    case 'drills': page = <DrillsPage />; break;
    case 'audit': page = <AuditPage me={me} />; break;
    case 'settings': page = <SettingsPage me={me} />; break;
    default: page = <NotFound />;
  }
  return (
    <>
      <AppShell path={loc.path}>{page}</AppShell>
      <ToastHost />
    </>
  );
}
