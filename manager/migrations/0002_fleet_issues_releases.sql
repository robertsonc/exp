-- WP-4 step 2: fleet roll-up detail, issue engine state, release/rollout bookkeeping. Forward-only.

-- settings: platform webhook format (the URL itself is a secret row, owner_ref 'platform')
ALTER TABLE settings ADD COLUMN platform_webhook_format TEXT NOT NULL DEFAULT 'json';

-- releases: public id + manifest creation time; sites: canary healthy-since (10-minute hold)
ALTER TABLE releases ADD COLUMN rel_id TEXT;
ALTER TABLE releases ADD COLUMN manifest_created TEXT;
ALTER TABLE sites ADD COLUMN canary_healthy_since TEXT;

-- hosts: compact latest host metrics (fleet tables never parse full status reports)
ALTER TABLE hosts ADD COLUMN latest_json TEXT NOT NULL DEFAULT '{}';

-- Host roll-ups: per-metric sample counts so a skipped (null) value never dilutes an average.
ALTER TABLE fleet_host_5m ADD COLUMN cpu_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN mem_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN disk_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN disk_pct_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN load_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN load1_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN net_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN pkts_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN dio_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN disk_write_kbps_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_5m ADD COLUMN disk_write_kbps_max REAL;

ALTER TABLE fleet_host_1h ADD COLUMN cpu_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN mem_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN disk_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN disk_pct_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN load_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN load1_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN net_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN pkts_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN dio_n INTEGER NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN disk_write_kbps_sum REAL NOT NULL DEFAULT 0;
ALTER TABLE fleet_host_1h ADD COLUMN disk_write_kbps_max REAL;

ALTER TABLE fleet_iface_5m ADD COLUMN pkts_sum REAL NOT NULL DEFAULT 0;

-- Component roll-ups: one normalised row per (component, key, bucket) so one statement can accumulate
-- every key of a report (json_each) without rewriting a JSON document. Replaces metrics_json tables.
DROP TABLE fleet_component_5m;
DROP TABLE fleet_component_1h;

CREATE TABLE fleet_component_metric_5m (
  component_id TEXT NOT NULL,
  key TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  n INTEGER NOT NULL DEFAULT 0,
  sum REAL NOT NULL DEFAULT 0,
  max REAL,
  PRIMARY KEY (component_id, key, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_component_metric_5m_bucket ON fleet_component_metric_5m (bucket);

CREATE TABLE fleet_component_metric_1h (
  component_id TEXT NOT NULL,
  key TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  org_id TEXT NOT NULL DEFAULT 'default',
  n INTEGER NOT NULL DEFAULT 0,
  sum REAL NOT NULL DEFAULT 0,
  max REAL,
  PRIMARY KEY (component_id, key, bucket)
) WITHOUT ROWID;
CREATE INDEX fleet_component_metric_1h_bucket ON fleet_component_metric_1h (bucket);

-- Issues: at most one OPEN issue per (host, kind, component); platform-webhook bookkeeping.
ALTER TABLE issues ADD COLUMN notified INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX issues_open_unique ON issues (host_id, kind, COALESCE(component_id, '')) WHERE resolved_at IS NULL;

-- Rule state: "since" for duration-gated rules, rolling samples for crash-loop / backlog rules.
CREATE TABLE issue_state (
  host_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  component_id TEXT NOT NULL DEFAULT '',
  org_id TEXT NOT NULL DEFAULT 'default',
  since TEXT,
  data TEXT,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (host_id, kind, component_id)
) WITHOUT ROWID;
