-- M6 p1: speedtest settings (12-speedtest-analytics.md section 8, CR-m6-manager). Forward-only, additive.
-- One row per site. `settings_json` holds the validated SpeedtestSettingsPut minus the consent block; the
-- consent text + version live in their own columns so that an edit can bump the version, and every version is
-- kept in speedtest_consent_history. The manager never stores test results or evidence (SR-20): nothing here
-- is a result, only intent.
CREATE TABLE speedtest_settings (
  site TEXT NOT NULL PRIMARY KEY,
  org_id TEXT NOT NULL DEFAULT 'default',
  settings_json TEXT NOT NULL DEFAULT '{}',
  consent_text TEXT NOT NULL DEFAULT '',           -- '' = never saved: the default text applies, version 1
  consent_version INTEGER NOT NULL DEFAULT 1,
  paused INTEGER NOT NULL DEFAULT 0,               -- admin switch "Pause internet leg" (operator role)
  logo_artifact_id TEXT,                           -- art_ id of the logo artifact (component speedtest-logo)
  logo_content_type TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE speedtest_consent_history (
  site TEXT NOT NULL,
  version INTEGER NOT NULL,
  text TEXT NOT NULL,
  changed_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (site, version)
);
