// Hand-written types for the subset of shared/openapi/admin.yaml the UI reads. Unknown extra keys are
// tolerated (the API says additionalProperties: true). Everything from the network is untrusted.

export type Role = 'owner' | 'admin' | 'operator' | 'viewer';
export type Health = 'ok' | 'degraded' | 'fail' | 'unknown';
export type HostState = 'pending' | 'enrolled' | 'stale' | 'offline' | 'decommissioning' | 'removed';
export type Shape = 'probe' | 'collector' | 'dashboard' | 'runner' | 'speedtest';
export type ComponentType = Shape | 'speedtest';
export type Severity = 'warn' | 'crit';

export interface Me { email: string; role: Role }
export interface Settings { org_name: string; [k: string]: unknown }

export interface FleetSummary {
  as_of: string;
  hosts_by_state: Record<string, number>;
  hosts_total: number;
  hosts_online: number;
  components_by_type_health: Record<string, Record<Health, number>>;
  measurements_per_min: number | null;
  ingest_records_per_s: number | null;
  open_issues: { warn: number; crit: number };
  version_drift_hosts: number;
  open_experience_incidents: number | null;
}

export interface Issue {
  issue_id: string;
  kind: string;
  severity: Severity;
  host_id: string;
  component_id: string | null;
  /** Type of the component the issue is about; null for host-level issues. Absent on an API that predates the field. */
  component_type?: string | null;
  site: string;
  opened_at: string;
  resolved_at: string | null;
  last_value: number | null;
  detail: string;
  snoozed_until: string | null;
}

export interface FleetSite {
  site: string;
  name: string;
  hosts: number;
  health_bar: { ok: number; warn: number; fail: number; offline: number };
  probes_reporting?: number;
  probes_total?: number;
  ingest_records_per_s?: number | null;
  worst_issue?: Issue | null;
  release_version?: string | null;
  canary_state?: string | null;
}

export interface FleetHostRow {
  host_id: string;
  name: string;
  mgmt_ip?: string | null;
  site: string;
  shapes: Shape[];
  state: HostState;
  stale: boolean;
  health: Health;
  open_issues: number;
  cpu_pct?: number | null;
  mem_pct?: number | null;
  disk_pct_max?: number | null;
  uptime_s?: number | null;
  net?: { rx_pps?: number | null; tx_pps?: number | null; rx_bps?: number | null; tx_bps?: number | null } | null;
  work?: { measurements_per_min?: number | null; ingest_records_per_s?: number | null; sessions_active?: number | null; drills_active?: number | null; tests_per_hour?: number | null };
  cpu_spark?: (number | null)[];
  net_spark?: (number | null)[];
  agent_version?: string | null;
  desired_version?: number | null;
  applied_version?: number | null;
  last_seen: string | null;
}

export interface Page<T> { items: T[]; next_cursor: string | null }

export interface MetricPoint { t: number; avg: number | null; max: number | null }
export interface MetricSeries {
  range: string;
  step_s: number;
  as_of: string;
  series: Record<string, MetricPoint[]>;
  host_id?: string;
  component_id?: string;
  iface?: string;
}

/** GET fleet/components/{id}/probes: the collector's latest per-probe rows (CR-wp5-fleet-api-gaps item 2). */
export interface ProbeRow { probe_id: string; last_seen: string; records_per_min: number; clock_offset_ms: number | null }
export interface ProbeRows { component_id: string; as_of: string; reported_at: string | null; items: ProbeRow[] }

export interface FleetTop {
  metric: 'cpu' | 'mem' | 'disk' | 'net';
  as_of: string;
  items: { host_id: string; name: string; site: string; value: number; unit: 'pct' | 'pps'; value_out?: number | null; spark?: (number | null)[] }[];
}

export interface Site {
  site: string;
  name: string;
  timezone: string;
  edge_label: string;
  release_version: string | null;
  canary_host_id: string | null;
  canary_state: string | null;
  retention?: { metrics_days?: number; records_days?: number } | null;
  created_at: string;
  updated_at: string;
}

export interface Iface {
  name: string; mac?: string; state: 'up' | 'down' | 'unknown'; speed_mbps?: number | null; driver?: string | null;
  addrs?: string[]; default_route?: boolean; in_use_by: string;
}
export interface DiskInfo { mount: string; total_gb?: number; used_gb?: number; pct?: number }
export interface NetInfo {
  iface: string; role?: string; link?: 'up' | 'down' | 'unknown'; speed_mbps?: number | null;
  rx_pps?: number | null; tx_pps?: number | null; rx_bps?: number | null; tx_bps?: number | null;
  rx_errors?: number | null; tx_errors?: number | null; rx_drops?: number | null; tx_drops?: number | null;
}
export interface StatusComponent {
  type: string; id: string; version?: string; state: string; health: Health; detail?: string; since?: string | null;
  process?: { cpu_pct?: number | null; rss_mb?: number | null; restarts?: number | null; uptime_s?: number | null };
  metrics?: Record<string, unknown>;
  facts?: Record<string, unknown>;
}
export interface StatusReport {
  schema: string;
  agent: { version: string; desired_version?: number | null; applied_version?: number | null; uptime_s: number; last_poll?: string | null };
  facts: {
    hostname: string; os?: { id?: string; version?: string }; kernel?: string; arch: string; cpus?: number; mem_mb?: number;
    disk_free_mb?: number; python?: string; time?: { synced?: boolean; source?: string; offset_ms?: number | null };
    interfaces?: Iface[]; [k: string]: unknown;
  };
  metrics: {
    interval_s?: number; uptime_s?: number | null;
    cpu?: { pct?: number | null; iowait_pct?: number | null; load1?: number | null; load5?: number | null; load15?: number | null };
    mem?: { total_mb?: number; used_mb?: number; available_mb?: number; pct?: number; swap_used_mb?: number };
    disk?: DiskInfo[]; net?: NetInfo[]; temp_c_max?: number | null;
  };
  components: StatusComponent[];
  reconcile?: { at: string; result: string; error?: string | null; duration_ms?: number } | null;
  events?: { ts: string; level: 'info' | 'warn' | 'error'; msg: string }[];
}
export interface HostStatus {
  host_id: string; state: HostState; received_at: string;
  desired_version?: number | null; applied_version?: number | null; report: StatusReport;
}

export interface Host {
  host_id: string; name: string; site: string; shapes: Shape[]; state: HostState; mgmt_ip?: string | null;
  facts?: StatusReport['facts'] | null; last_seen: string | null; agent_version: string | null;
  desired_version: number | null; applied_version: number | null; created_at: string; updated_at: string;
}

export interface Component {
  component_id: string; host_id: string; type: ComponentType; id: string;
  config: Record<string, unknown>; rendered_config?: Record<string, unknown> | null;
  enabled: boolean; health: Health; version?: string | null; facts?: Record<string, unknown>;
  created_at: string; updated_at: string;
}

export interface OverviewHost {
  host_id: string; name: string; site: string; state: HostState; health: Health;
  components: { component_id: string; type: ComponentType; id: string; health: Health; version?: string | null }[];
}
export interface Overview {
  as_of: string;
  sites: { site: string; name: string }[];
  hosts: OverviewHost[];
  versions: Record<string, number>;
}

export interface AuditEvent { evt_id: string; ts: string; actor: string; action: string; resource: string; details?: Record<string, unknown>; ip?: string | null }

export interface EnrolToken { token: string; command: string; expires_at: string }

// ---- administration (step 2) ------------------------------------------------------------------------------------

export interface SecretState { set: boolean; updated_at: string | null }
export interface Retention { metrics_days: number; records_days: number }
export interface HostCreated { host: Host; enrol: EnrolToken }
export interface Accepted { host_id: string; action_id?: string; desired_version: number }

export interface Artifact { artifact_id: string; name: string; component: string; arch: string; sha256: string; size: number }
export interface Release {
  rel_id: string; version: string; source: 'github' | 'upload'; verified_at: string; notes_url?: string | null;
  min_agent_version: string; created?: string; artifacts: Artifact[]; sites?: string[];
}

export interface AlertsConfig {
  enabled: boolean; board_url?: string | null; timezone?: string; voice: 'plain' | 'sysadmin';
  hold_down_s: number; hold_back_s: number; reopen_s: number; calm_s: number;
}
export interface WebhookRead { id: string; format: 'slack' | 'teams' | 'json'; url: SecretState }
export interface Alerts { config: AlertsConfig; webhooks: WebhookRead[] }
export interface AlertTestResult { results: { webhook_id: string; ok: boolean; http_status?: number | null; error?: string | null }[] }

export interface DashboardUser { usr_id: string; username: string; role: 'viewer' | 'operator' | 'admin'; created_at: string }
export interface NocToken { noc_id: string; label: string; role: 'viewer'; expires_at: string | null; revoked_at: string | null; created_at: string }
export interface DashboardTlsCert { subject: string; issuer: string; not_before: string; not_after: string; sha256: string; san: string[] }
/** Write-only: the key and the PEM are never returned. */
export interface DashboardTls { mode: 'self_signed' | 'provided'; set: boolean; updated_at: string | null; cert: DashboardTlsCert | null }
export interface NocTokenCreated { noc: NocToken; token: string; url?: string | null }

export interface AdminEntry { email: string; role: Role; disabled?: boolean; last_seen?: string | null }
export interface OrgSettings {
  org_name: string; drills_enabled: boolean; drills_two_person: boolean; default_retention: Retention;
  release_channel?: string; owner: string; admins: AdminEntry[]; updated_at?: string;
}
export interface PlatformWebhook { format: 'slack' | 'teams' | 'json'; url: SecretState }
export type FleetThresholds = Record<string, Record<string, number>>;
export interface WebhookTestResult { ok: boolean; http_status?: number | null; error?: string | null }

// ---- speedtest settings (M6, shared/openapi/admin.yaml tag speedtest) ---------------------------------------------
// Intent only: the manager never receives a test result or evidence (SR-20), so nothing here carries one.

export interface SpeedtestZone { id: string; name: string }
export interface SpeedtestSettings {
  zones?: SpeedtestZone[];
  zone_labels?: { subnets: { cidr: string; zone: string }[] };
  branding?: { title?: string; logo_artifact?: string | null; colors?: { primary?: string; accent?: string; background?: string; text?: string }; languages?: string[]; copy?: Record<string, string> };
  display?: { show_network_details?: boolean };
  targets?: { down_mbps?: number; up_mbps?: number };
  limits?: { tests_per_10min_per_ip?: number; max_concurrent_per_ip?: number; max_concurrent_tests?: number; max_concurrent_internet?: number; bytes_local?: number; bytes_internet?: number; leg_token_ttl_s?: number; result_deadline_s?: number };
  internet_leg?: { enabled?: boolean; provider?: 'cloudflare'; paused?: boolean; auto_pause_wan_util_pct?: number };
  privacy?: { retention_days?: number; scrub_after_diagnosis?: boolean };
  core_guard?: { iface?: string; util_pct?: number; min_bytes?: number };
  serve?: { placement?: 'core' | 'dc' | 'other'; hostname?: string; listen_ip?: string; require_real_client_ip?: boolean; client_subnets?: string[]; translated_addresses?: string[]; port?: number };
  tls?: { mode: 'none' | 'provided' };
  dns_leg?: { enabled?: boolean; zone?: string; port?: number };
  path?: { gateway?: string; edge?: string | null; edge1?: string | null; note?: string };
  consent: { text: string; version?: number };
  device_key?: { set: boolean; updated_at: string | null };
  updated_at?: string;
}
export interface SpeedtestLogo { artifact: string; sha256: string; size: number; content_type: 'image/png' | 'image/svg+xml' | 'image/jpeg' }
export interface SpeedtestConsentHistory { items: { version: number; text: string; changed_by: string; created_at: string }[] }
export interface SpeedtestQr { items: { zone: string; name: string; url: string }[] }
export interface SpeedtestTls { set: boolean; updated_at: string | null; cert: DashboardTlsCert | null }
export interface SpeedtestDeviceKeyState { set: boolean; updated_at: string; key_id: string }
