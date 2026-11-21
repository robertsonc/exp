"""SQLite schema of the speedtest tables (migration 2 of the collector database).

``speedtests``   one row per test (12 section 7.1 fields flattened for the query filters + the stored
                 ``exp.speedtest/1`` document WITHOUT ``client.ip``) and the raw identifiers
                 (``client_ip``, ``mac``, ``hostname``, ``username``: NULLed by the privacy scrub, never exported
                 without ``identifiers=true``) next to the low-cardinality ``device_key``.
``evidence``     one ``exp.evidence/1`` document per (test, kind), JSON text, bounded per test.
``diagnoses``    ``quick`` and ``final`` diagnosis per test (ordered causes with confidence and cited evidence).
``speedtest_audit``  durable audit trail of identifier views and purges (no raw identifier: a sha256 prefix).
"""
from __future__ import annotations

STATEMENTS: tuple[str, ...] = (
    """CREATE TABLE speedtests (
         seq INTEGER PRIMARY KEY AUTOINCREMENT,
         id TEXT NOT NULL UNIQUE,
         site TEXT NOT NULL,
         speedtest_id TEXT NOT NULL,
         started_ms INTEGER NOT NULL,
         ended_ms INTEGER NOT NULL,
         received_ms INTEGER NOT NULL,
         zone TEXT NOT NULL,
         zone_source TEXT NOT NULL,
         score INTEGER,
         local_down REAL, local_up REAL, internet_down REAL, internet_up REAL,
         local_loaded REAL, internet_loaded REAL,
         flags TEXT NOT NULL DEFAULT '[]',
         comment TEXT,
         ap_name TEXT, ssid TEXT, band TEXT, os_family TEXT,
         device_key TEXT,
         client_ip TEXT, mac TEXT, hostname TEXT, username TEXT,
         cause TEXT,
         state TEXT NOT NULL DEFAULT 'submitted',
         final_ms INTEGER,
         complete_status TEXT,
         scrubbed INTEGER NOT NULL DEFAULT 0,
         evidence_n INTEGER NOT NULL DEFAULT 0,
         metrics_done INTEGER NOT NULL DEFAULT 0,
         doc TEXT NOT NULL)""",
    "CREATE INDEX speedtests_site_started ON speedtests (site, started_ms)",
    "CREATE INDEX speedtests_started ON speedtests (started_ms)",
    "CREATE INDEX speedtests_zone ON speedtests (zone, started_ms)",
    "CREATE INDEX speedtests_ap ON speedtests (ap_name, started_ms)",
    "CREATE INDEX speedtests_ssid ON speedtests (ssid, started_ms)",
    "CREATE INDEX speedtests_cause ON speedtests (cause, started_ms)",
    "CREATE INDEX speedtests_score ON speedtests (score)",
    "CREATE INDEX speedtests_device ON speedtests (device_key)",
    "CREATE INDEX speedtests_ip ON speedtests (client_ip)",
    "CREATE INDEX speedtests_mac ON speedtests (mac)",
    "CREATE INDEX speedtests_pending ON speedtests (state, seq)",
    """CREATE TABLE evidence (
         test_id TEXT NOT NULL,
         kind TEXT NOT NULL,
         source TEXT NOT NULL,
         collected_ms INTEGER NOT NULL,
         status TEXT NOT NULL,
         size INTEGER NOT NULL,
         body TEXT NOT NULL,
         PRIMARY KEY (test_id, kind))""",
    """CREATE TABLE diagnoses (
         test_id TEXT NOT NULL,
         stage TEXT NOT NULL,
         updated_ms INTEGER NOT NULL,
         body TEXT NOT NULL,
         PRIMARY KEY (test_id, stage))""",
    """CREATE TABLE speedtest_audit (
         seq INTEGER PRIMARY KEY AUTOINCREMENT,
         ts_ms INTEGER NOT NULL,
         actor TEXT NOT NULL,
         action TEXT NOT NULL,
         subject TEXT NOT NULL,
         matched INTEGER NOT NULL DEFAULT 0,
         dry_run INTEGER NOT NULL DEFAULT 0)""",
    "CREATE INDEX speedtest_audit_ts ON speedtest_audit (ts_ms)",
)
