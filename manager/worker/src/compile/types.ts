// Pure data model the compiler works over (loaded rows, JSON columns parsed, secrets resolved).
// Everything here is JSON-serializable so golden tests can use plain fixtures.

export type ComponentType = "probe" | "collector" | "dashboard" | "runner" | "speedtest";
export type HostState = "pending" | "enrolled" | "stale" | "offline" | "decommissioning" | "removed";

export interface WIface {
  name: string;
  state?: string;
  addrs?: string[];
  default_route?: boolean;
  in_use_by?: string;
}

export interface WHostFacts {
  arch?: "amd64" | "arm64";
  interfaces?: WIface[];
}

export interface WAction {
  id: string;
  type: "rotate_agent_secret" | "restart_component" | "collect_diagnostics";
  component_id?: string;
}

export interface WSite {
  site: string;
  name: string;
  timezone: string;
  edge_label: string;
  release_version: string | null;
  target_version: string | null;
  canary_host_id: string | null;
  canary_state: "none" | "canary" | "promoted" | "failed";
  event_net_reaches_mgmt: boolean;
  retention: Record<string, unknown>;
  alerts: Record<string, unknown>;
}

export interface WHost {
  host_id: string;
  name: string;
  site: string;
  state: HostState;
  arch: string | null;
  facts: WHostFacts;
  actions: WAction[];
}

export interface WComponentFacts {
  tls_fingerprint_sha256?: string;
  listen?: string;
  url?: string;
}

export interface WComponent {
  component_id: string;
  host_id: string;
  type: ComponentType;
  slug: string;
  config: Record<string, unknown>;
  enabled: boolean;
  facts: WComponentFacts;
  created_at: string;
}

export interface WSecret {
  plaintext: string;
  hash: string | null;
  /** previous hash while still inside its rotation grace, else null */
  previous_hash: string | null;
}

export interface WDashboardUser {
  dashboard_slug: string;
  username: string;
  role: "viewer" | "operator" | "admin";
  hash: string;
}

export interface WNocToken {
  noc_id: string;
  dashboard_slug: string;
  label: string;
  hash: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface WWebhook {
  webhook_id: string;
  site: string;
  format: "slack" | "teams" | "json";
}

export interface WArtifact {
  artifact_id: string;
  version: string;
  name: string;
  component: string;
  arch: "amd64" | "arm64" | "noarch";
  sha256: string;
  size: number;
}

export type LogoContentType = "image/png" | "image/svg+xml" | "image/jpeg";

/** Per-site speedtest intent (table speedtest_settings; 12-speedtest-analytics.md section 8). */
export interface WSpeedtest {
  /** validated SpeedtestSettingsPut minus consent */
  settings: Record<string, unknown>;
  consent: { text: string; version: number };
  /** admin switch "Pause internet leg" */
  paused: boolean;
  /** logo artifact row (component speedtest-logo) + its content type; null = no logo */
  logo: { artifact: WArtifact; content_type: LogoContentType } | null;
}

/** Connector settings of one integration (kind ec | mist) with its decrypted write-only credentials. */
export interface WIntegration {
  config: Record<string, unknown>;
  credentials: Record<string, string>;
}

export interface World {
  org: { id: string; name: string };
  settings: { agent_poll_interval_s: number; agent_status_interval_s: number };
  /** https base of this manager, used for the dashboards' SSO handoff; null until known */
  manager_url: string | null;
  sites: Record<string, WSite>;
  hosts: Record<string, WHost>;
  components: WComponent[];
  /** key: `${owner_ref}|${kind}` */
  secrets: Record<string, WSecret>;
  dashboard_users: WDashboardUser[];
  noc_tokens: WNocToken[];
  webhooks: WWebhook[];
  artifacts: WArtifact[];
  /** key: site slug; absent = the site never saved speedtest settings (defaults apply) */
  speedtest?: Record<string, WSpeedtest>;
  /** connectors (ec, mist) as stored by the integrations settings; credentials only ever flow into the runner's integrations.json */
  integrations?: { ec?: WIntegration; mist?: WIntegration };
  /** ISO time used for token-expiry filtering */
  now: string;
}

export const secretKey = (ownerRef: string, kind: string): string => `${ownerRef}|${kind}`;

/** exp.desired/1 without version / generated_at (these are assigned when persisting). */
export type DesiredBody = {
  schema: "exp.desired/1";
  host_id: string;
  org: { id: string; name: string };
  site: { id: string; name: string; timezone: string };
  agent?: { version: string; artifact: string; poll_interval_s: number; status_interval_s: number };
  release?: { version: string; manifest_url: string; signature_url: string };
  components: DesiredComponent[];
  actions: WAction[];
  decommission: boolean;
};

export interface DesiredComponent {
  type: ComponentType;
  id: string;
  component_id: string;
  version: string;
  artifact: { id: string; name: string; url: string; sha256: string; size: number };
  config: Record<string, unknown>;
  creds: Record<string, string>;
  /** speedtest only (CR-m6-contracts): branding assets the agent installs next to the component */
  assets?: Array<{ name: "logo"; content_type: string; artifact: { id: string; name: string; url: string; sha256: string; size: number } }>;
}

export interface CompileResult {
  /** null = hold: keep whatever the host has (nothing to say yet, or a precondition is unmet) */
  doc: DesiredBody | null;
  warnings: string[];
}
