-- exp-manager: initial schema (docs/spec/05-manager.md section 3 and 13/14, 10-drills-integrations.md minimal).
-- Forward-only. All tables carry org_id (future multi-tenancy) and created_at/updated_at (ISO-8601 UTC, ms, Z).
-- Secrets are never stored in plaintext: see worker/src/secrets/.

CREATE TABLE settings (
  org_id TEXT NOT NULL DEFAULT 'default' PRIMARY KEY,
  org_name TEXT NOT NULL DEFAULT '',
  drills_enabled INTEGER NOT NULL DEFAULT 0,
  drills_two_person INTEGER NOT NULL DEFAULT 0,
  require_enrol_approval INTEGER NOT NULL DEFAULT 0,
  default_retention_metrics_days INTEGER NOT NULL DEFAULT 30,
  default_retention_records_days INTEGER NOT NULL DEFAULT 7,
  agent_poll_interval_s INTEGER NOT NULL DEFAULT 30,
  agent_status_interval_s INTEGER NOT NULL DEFAULT 60,
  release_channel TEXT NOT NULL DEFAULT 'stable',
  fleet_thresholds_json TEXT NOT NULL DEFAULT '{}',
  platform_webhook_secret_id TEXT,
  manager_url TEXT,                 -- https base of this manager (SSO handoff target); learned from the first admin request
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE admins (
  admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL DEFAULT 'default',
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','admin','operator','viewer')),
  disabled INTEGER NOT NULL DEFAULT 0,
  last_seen TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX admins_email ON admins (email);

CREATE TABLE sites (
  site TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  timezone TEXT NOT NULL DEFAULT 'UTC',
  edge_label TEXT NOT NULL DEFAULT 'EC',
  release_version TEXT,          -- promoted version every host of the site runs
  target_version TEXT,           -- version being rolled out (canary first)
  canary_host_id TEXT,
  canary_state TEXT NOT NULL DEFAULT 'none' CHECK (canary_state IN ('none','canary','promoted','failed')),
  canary_started_at TEXT,
  event_net_reaches_mgmt INTEGER NOT NULL DEFAULT 0,
  retention_json TEXT NOT NULL DEFAULT '{}',
  alerts_json TEXT NOT NULL DEFAULT '{}',   -- no secrets (webhook URLs live in secrets)
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE hosts (
  host_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  name TEXT NOT NULL,
  site TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending'
    CHECK (state IN ('pending','enrolled','stale','offline','decommissioning','removed')),
  arch TEXT,
  facts_json TEXT NOT NULL DEFAULT '{}',
  actions_json TEXT NOT NULL DEFAULT '[]',   -- pending agent actions (rotate_agent_secret, restart_component, ...)
  last_seen TEXT,
  enrolled_at TEXT,
  agent_version TEXT,
  desired_version INTEGER,
  applied_version INTEGER,
  desired_hash TEXT,
  status_interval_s INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX hosts_site ON hosts (site);
CREATE INDEX hosts_state ON hosts (state, last_seen);

CREATE TABLE components (
  component_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  host_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('probe','collector','dashboard','runner','speedtest')),
  slug TEXT NOT NULL,
  config_json TEXT NOT NULL DEFAULT '{}',
  enabled INTEGER NOT NULL DEFAULT 1,
  facts_json TEXT NOT NULL DEFAULT '{}',     -- from status: health, state, tls fingerprint, listen, url
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX components_type_slug ON components (type, slug);
CREATE INDEX components_host ON components (host_id);

CREATE TABLE enrol_tokens (
  token_hash TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  host_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX enrol_tokens_host ON enrol_tokens (host_id);
CREATE INDEX enrol_tokens_expiry ON enrol_tokens (expires_at) WHERE used_at IS NULL;

CREATE TABLE agent_creds (
  host_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  secret_hash TEXT NOT NULL,
  previous_hash TEXT,
  previous_valid_until TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX agent_creds_secret ON agent_creds (secret_hash);
CREATE INDEX agent_creds_previous ON agent_creds (previous_hash) WHERE previous_hash IS NOT NULL;

CREATE TABLE desired_docs (
  host_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  version INTEGER NOT NULL,
  doc_json TEXT NOT NULL,           -- creds encrypted inside ("enc1:..."), decrypted at serve time
  content_hash TEXT NOT NULL,
  artifacts_json TEXT NOT NULL DEFAULT '[]',   -- artifact ids referenced (authorizes /artifacts/{id})
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE status_latest (
  host_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  received_at TEXT NOT NULL,
  report_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE status_history (
  hist_id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL DEFAULT 'default',
  host_id TEXT NOT NULL,
  received_at TEXT NOT NULL,
  report_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX status_history_host ON status_history (host_id, hist_id DESC);

CREATE TABLE releases (
  version TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  manifest_r2_key TEXT NOT NULL,
  signature TEXT NOT NULL,
  min_agent_version TEXT,
  verified_at TEXT NOT NULL,
  source TEXT NOT NULL,
  notes_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE artifacts (
  artifact_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  version TEXT NOT NULL,
  name TEXT NOT NULL,
  component TEXT NOT NULL,
  arch TEXT NOT NULL CHECK (arch IN ('amd64','arm64','noarch')),
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  r2_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX artifacts_version_name ON artifacts (version, name);
CREATE INDEX artifacts_select ON artifacts (version, component, arch);

CREATE TABLE secrets (
  secret_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  owner_ref TEXT NOT NULL,
  kind TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  nonce TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  hash TEXT,                       -- sha256 hex of the plaintext when the consumer only needs a verifier
  previous_ciphertext TEXT,
  previous_nonce TEXT,
  previous_version INTEGER,
  previous_hash TEXT,
  previous_valid_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX secrets_owner_kind ON secrets (owner_ref, kind);

CREATE TABLE dashboard_users (
  usr_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  dashboard_slug TEXT NOT NULL,
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
  hash TEXT NOT NULL,              -- pbkdf2_sha256$600000$salt$hash computed in the browser
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX dashboard_users_name ON dashboard_users (dashboard_slug, username);

CREATE TABLE noc_tokens (
  noc_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  dashboard_slug TEXT NOT NULL,
  label TEXT NOT NULL,
  hash TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX noc_tokens_dashboard ON noc_tokens (dashboard_slug);

CREATE TABLE webhooks (
  webhook_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  site TEXT NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('slack','teams','json')),
  secret_id TEXT NOT NULL,         -- the URL is a secret
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX webhooks_site ON webhooks (site);

CREATE TABLE integrations (
  kind TEXT NOT NULL PRIMARY KEY CHECK (kind IN ('ec','mist')),
  org_id TEXT NOT NULL DEFAULT 'default',
  config_json TEXT NOT NULL DEFAULT '{}',
  secret_id TEXT,
  allowlist_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- drills: minimal (10-drills-integrations.md); completed in a later WP-4 step.
CREATE TABLE drills (
  drl_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  site TEXT NOT NULL,
  type TEXT NOT NULL,
  params_json TEXT NOT NULL DEFAULT '{}',
  state TEXT NOT NULL DEFAULT 'draft',
  created_by TEXT NOT NULL,
  approved_by TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX drills_site ON drills (site, state);

CREATE TABLE drill_runs (
  run_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  drl_id TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending',
  started_at TEXT,
  ended_at TEXT,
  result_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX drill_runs_drill ON drill_runs (drl_id);

CREATE TABLE audit (
  evt_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  details_json TEXT NOT NULL DEFAULT '{}',
  ip TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX audit_ts ON audit (ts DESC);
CREATE INDEX audit_actor ON audit (actor, ts DESC);
CREATE INDEX audit_resource ON audit (resource, ts DESC);

-- Fleet roll-ups (05-manager.md section 13). Rates are summed per bucket; avg = sum / samples.
CREATE TABLE fleet_host_5m (
  host_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  samples INTEGER NOT NULL DEFAULT 0,
  cpu_sum REAL NOT NULL DEFAULT 0, cpu_max REAL,
  mem_pct_sum REAL NOT NULL DEFAULT 0, mem_pct_max REAL,
  disk_pct_max REAL,
  load1_max REAL,
  rx_pps_sum REAL NOT NULL DEFAULT 0, tx_pps_sum REAL NOT NULL DEFAULT 0,
  rx_bps_sum REAL NOT NULL DEFAULT 0, tx_bps_sum REAL NOT NULL DEFAULT 0,
  errors_sum REAL NOT NULL DEFAULT 0, drops_sum REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (host_id, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_host_5m_bucket ON fleet_host_5m (bucket);

CREATE TABLE fleet_host_1h (
  host_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  samples INTEGER NOT NULL DEFAULT 0,
  cpu_sum REAL NOT NULL DEFAULT 0, cpu_max REAL,
  mem_pct_sum REAL NOT NULL DEFAULT 0, mem_pct_max REAL,
  disk_pct_max REAL,
  load1_max REAL,
  rx_pps_sum REAL NOT NULL DEFAULT 0, tx_pps_sum REAL NOT NULL DEFAULT 0,
  rx_bps_sum REAL NOT NULL DEFAULT 0, tx_bps_sum REAL NOT NULL DEFAULT 0,
  errors_sum REAL NOT NULL DEFAULT 0, drops_sum REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (host_id, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_host_1h_bucket ON fleet_host_1h (bucket);

CREATE TABLE fleet_iface_5m (
  host_id TEXT NOT NULL,
  iface TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  samples INTEGER NOT NULL DEFAULT 0,
  rx_pps_sum REAL NOT NULL DEFAULT 0, tx_pps_sum REAL NOT NULL DEFAULT 0,
  rx_bps_sum REAL NOT NULL DEFAULT 0, tx_bps_sum REAL NOT NULL DEFAULT 0,
  errors_sum REAL NOT NULL DEFAULT 0, drops_sum REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (host_id, iface, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_iface_5m_bucket ON fleet_iface_5m (bucket);

CREATE TABLE fleet_component_5m (
  component_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  samples INTEGER NOT NULL DEFAULT 0,
  metrics_json TEXT NOT NULL DEFAULT '{}',    -- {key: [sum, max]}
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (component_id, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_component_5m_bucket ON fleet_component_5m (bucket);

CREATE TABLE fleet_component_1h (
  component_id TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  samples INTEGER NOT NULL DEFAULT 0,
  metrics_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (component_id, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_component_1h_bucket ON fleet_component_1h (bucket);

-- Fleet health issues (05-manager.md section 14).
CREATE TABLE issues (
  issue_id TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  kind TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('warn','crit')),
  host_id TEXT,
  component_id TEXT,
  site TEXT,
  opened_at TEXT NOT NULL,
  resolved_at TEXT,
  clean_reports INTEGER NOT NULL DEFAULT 0,   -- hysteresis: resolves after two consecutive clean reports
  last_value REAL,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX issues_open_host_kind ON issues (host_id, kind) WHERE resolved_at IS NULL;
CREATE INDEX issues_open ON issues (severity, opened_at) WHERE resolved_at IS NULL;
CREATE INDEX issues_site ON issues (site) WHERE resolved_at IS NULL;
CREATE INDEX issues_resolved ON issues (resolved_at) WHERE resolved_at IS NOT NULL;

CREATE TABLE issue_snoozes (
  snooze_id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id TEXT NOT NULL DEFAULT 'default',
  kind TEXT NOT NULL,
  host_id TEXT NOT NULL,
  until TEXT,                      -- NULL with until_resolved = 1 means "until the issue resolves"
  until_resolved INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX issue_snoozes_key ON issue_snoozes (host_id, kind);
