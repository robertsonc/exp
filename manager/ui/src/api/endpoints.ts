// Endpoint paths (shared/openapi/admin.yaml). Keys are exactly the request URLs, so every consumer of
// the same URL shares one cache entry and one poll.
export const API = '/api/admin/v1';

const q = (params: Record<string, string | number | undefined | null>): string => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : '';
};

export const ep = {
  me: `${API}/me`,
  settings: `${API}/settings`,
  summary: `${API}/fleet/summary`,
  fleetSites: `${API}/fleet/sites`,
  hosts: `${API}/fleet/hosts?limit=1000`,
  overview: `${API}/overview`,
  top: (metric: 'cpu' | 'mem' | 'disk' | 'net', limit = 5) => `${API}/fleet/top${q({ metric, limit })}`,
  issues: (state: 'open' | 'resolved') => `${API}/issues${q({ state, limit: 1000 })}`,
  snooze: (id: string) => `${API}/issues/${encodeURIComponent(id)}/snooze`,
  sites: `${API}/sites`,
  site: (slug: string) => `${API}/sites/${encodeURIComponent(slug)}`,
  host: (id: string) => `${API}/hosts/${encodeURIComponent(id)}`,
  hostStatus: (id: string) => `${API}/hosts/${encodeURIComponent(id)}/status`,
  hostComponents: (id: string) => `${API}/hosts/${encodeURIComponent(id)}/components`,
  hostMetrics: (id: string, range: string) => `${API}/fleet/hosts/${encodeURIComponent(id)}/metrics${q({ range })}`,
  compMetrics: (id: string, range: string, keys?: readonly string[]) => `${API}/fleet/components/${encodeURIComponent(id)}/metrics${q(keys?.length ? { range, keys: keys.join(',') } : { range })}`,
  compProbes: (id: string) => `${API}/fleet/components/${encodeURIComponent(id)}/probes`,
  ifaceMetrics: (id: string, iface: string, range: string) => `${API}/fleet/hosts/${encodeURIComponent(id)}/interfaces/${encodeURIComponent(iface)}/metrics${q({ range })}`,
  audit: (resource: string) => `${API}/audit${q({ resource, limit: 25 })}`,
  restart: (cid: string) => `${API}/components/${encodeURIComponent(cid)}/restart`,
  rotate: (cid: string) => `${API}/components/${encodeURIComponent(cid)}/rotate`,
  enrolToken: (id: string) => `${API}/hosts/${encodeURIComponent(id)}/enrol-token`,
  decommission: (id: string) => `${API}/hosts/${encodeURIComponent(id)}/decommission`,
  rotateAgent: (id: string) => `${API}/hosts/${encodeURIComponent(id)}/rotate-agent`,
  hostCreate: `${API}/hosts`,
  component: (cid: string) => `${API}/components/${encodeURIComponent(cid)}`,
  ports: (cid: string) => `${API}/components/${encodeURIComponent(cid)}/ports`,
  releases: `${API}/releases`,
  releaseImport: `${API}/releases/import`,
  releaseUpload: `${API}/releases/upload`,
  siteRelease: (slug: string) => `${API}/sites/${encodeURIComponent(slug)}/release`,
  siteProbeHeartbeat: (slug: string) => `${API}/sites/${encodeURIComponent(slug)}/probe-heartbeat`,
  siteAlerts: (slug: string) => `${API}/sites/${encodeURIComponent(slug)}/alerts`,
  siteAlertsTest: (slug: string) => `${API}/sites/${encodeURIComponent(slug)}/alerts/test`,
  dashUsers: (dash: string) => `${API}/dashboards/${encodeURIComponent(dash)}/users`,
  dashUser: (dash: string, usr: string) => `${API}/dashboards/${encodeURIComponent(dash)}/users/${encodeURIComponent(usr)}`,
  nocTokens: (dash: string) => `${API}/dashboards/${encodeURIComponent(dash)}/noc-tokens`,
  nocToken: (dash: string, noc: string) => `${API}/dashboards/${encodeURIComponent(dash)}/noc-tokens/${encodeURIComponent(noc)}`,
  dashTls: (dash: string) => `${API}/dashboards/${encodeURIComponent(dash)}/tls`,
  sso: (dash: string) => `${API}/dashboards/${encodeURIComponent(dash)}/sso`,
  ssoLaunch: (dash: string) => `${API}/dashboards/${encodeURIComponent(dash)}/sso/launch`,
  speedtest: (site: string) => `${API}/sites/${encodeURIComponent(site)}/speedtest`,
  speedtestLogo: (site: string) => `${API}/sites/${encodeURIComponent(site)}/speedtest/logo`,
  speedtestPause: (site: string) => `${API}/sites/${encodeURIComponent(site)}/speedtest/internet-pause`,
  speedtestQr: (site: string) => `${API}/sites/${encodeURIComponent(site)}/speedtest/qr`,
  speedtestConsentHistory: (site: string) => `${API}/sites/${encodeURIComponent(site)}/speedtest/consent-history`,
  speedtestTls: (site: string) => `${API}/sites/${encodeURIComponent(site)}/speedtest/tls`,
  speedtestDeviceKey: `${API}/settings/speedtest-device-key`,
  integration: (kind: 'ec' | 'mist') => `${API}/integrations/${kind}`,
  thresholds: `${API}/settings/fleet-thresholds`,
  platformWebhook: `${API}/settings/platform-webhook`,
  platformWebhookTest: `${API}/settings/platform-webhook/test`,
  auditQuery: (p: { actor?: string; resource?: string; from?: string; to?: string }) => `${API}/audit${q({ ...p, limit: 100 })}`,
};
