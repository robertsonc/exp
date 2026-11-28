-- Ops device status board (GET /api/admin/v1/ops/devices). Forward-only.
-- 1. integrations.kind gains 'central' (HPE Aruba Networking Central, the GreenLake-hosted "New Central"
--    API). SQLite cannot alter a CHECK constraint, so the table is rebuilt; nothing references it by FK
--    (secrets point at integrations through owner_ref = 'integration:<kind>', a plain string).
CREATE TABLE integrations_v6 (
  kind TEXT NOT NULL PRIMARY KEY CHECK (kind IN ('ec','mist','central')),
  org_id TEXT NOT NULL DEFAULT 'default',
  config_json TEXT NOT NULL DEFAULT '{}',
  secret_id TEXT,
  allowlist_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO integrations_v6 (kind, org_id, config_json, secret_id, allowlist_json, created_at, updated_at)
  SELECT kind, org_id, config_json, secret_id, allowlist_json, created_at, updated_at FROM integrations;
DROP TABLE integrations;
ALTER TABLE integrations_v6 RENAME TO integrations;

-- 2. Last poll of each platform's device inventory: counts only, never a device list or a credential.
--    The board reads this row and polls the vendor API again only when it is older than the cache TTL, so
--    any number of open boards cost at most one vendor poll per platform per TTL (Mist's per-token hourly
--    budget is shared with the runner; Central's per-second budget with every client of the account).
CREATE TABLE ops_device_status (
  kind TEXT NOT NULL PRIMARY KEY CHECK (kind IN ('mist','central')),
  checked_at TEXT NOT NULL,          -- last poll attempt (success or failure)
  ok_at TEXT,                        -- last successful poll; the counts below are from that poll
  total INTEGER,
  online INTEGER,
  offline INTEGER,
  by_type_json TEXT NOT NULL DEFAULT '{}',   -- {"ap": {"total": n, "online": n}, ...}
  error TEXT,                        -- why the last poll failed (null when it succeeded); no secrets
  config_fp TEXT NOT NULL DEFAULT '' -- fingerprint of config + credential version: a change discards the cache
);
