# CR-wp5-fleet-api-gaps: data the UI spec shows but the fleet API / mock does not provide

**Raised by:** WP-5 (manager UI)  **Affects:** WP-4 (Worker fleet API), WP-0 (mock_admin), `docs/spec/05-manager.md` sections 13 and 14

The UI renders every item below when the data is present and shows a dash with a tooltip ("not reported") when it is not,
so nothing is broken; these are the gaps against `11-manager-ui.md`.

1. **Collector `days_to_full`, `storage_free_gb`, `vm_storage_gb`, `records_db_gb`** are required `exp.health/1` collector
   metrics (`01-contracts.md` 8.1) but `mock_admin` collector components only report `ingest_records_per_s`, `probes_total`,
   `probes_reporting`, `vm_up`. The "days-to-full projection" panel therefore cannot be demonstrated against the mock
   (the e2e test injects the metric through a Playwright route). Proposal: seed the full collector metric set, including a
   collector with `days_to_full` under 7 and one under 2.
2. **Per-probe rows for the collector view** (probe, last seen, records/min, clock offset): not part of the collector health
   `metrics` or of any admin endpoint. The UI reads an optional `metrics.probes[]` array
   (`{probe_id,last_seen,records_per_min,clock_offset_ms}`) and otherwise lists the probes from the collector config.
   Proposal: add `probes` (bounded, <= 500 items) to the collector health metrics, or add
   `GET /fleet/components/{id}/probes`.
3. **Per-interface history** (Host detail > Interfaces "with sparklines") and **errors/drops series**: roll-ups keep
   host-level keys only (`net_rx_pps`, ...). The UI shows the management-interface sparkline from the fleet row and
   charts `net_*_errors` / `net_*_drops` only if the API returns those keys. Proposal: name the chartable host keys in
   `05-manager.md` section 13 (they are only implied there) and add the error/drop keys.
4. **Host metric key names** are not listed in the contract; the UI uses the mock's names: `cpu_pct mem_pct disk_pct load1
   net_rx_pps net_tx_pps net_rx_bps net_tx_bps disk_write_kbps`. The real Worker must use the same names or the charts show
   "not reported".
5. **Stacked "measurements by test" history** (probe view) needs per-test series; only the instantaneous
   `by_test_per_min` map is available, so the UI shows it as bars.
6. **Issue `type` filter** (11 section 4.2): the issue has no component type; the UI derives a scope (host, component,
   probe, collector, dashboard) from the issue kind (`src/lib/issues.ts: issueScope`). Proposal: a `component_type` field on `Issue`.

## Compatibility
All additive. No existing field changes meaning.

## Resolution (M3 p1, applied)
Items 1-6 are applied end to end (component, status report, manager storage, admin API, UI, mock_admin). Choices made:

2. Collector health metrics carry `probes[]` (`probe_id`, `last_seen`, `records_per_min`, `clock_offset_ms`): configured probes
   that delivered since the collector started, sorted by id, at most 500 rows and about 52 KB of JSON (the health document is
   capped at 64 KiB by the agent). The manager keeps the latest rows per collector (table `component_probes_latest`, replaced by
   every report, deleted when a report has no `probes` array) and serves them as `GET /fleet/components/{id}/probes`
   (`reported_at`, `items`). Malformed rows are dropped, never stored. The collector view lists them and adds configured probes
   that have not reported as dashes.
3. `GET /fleet/hosts/{id}/interfaces/{iface}/metrics?range=1h|6h|24h|48h&keys=rx_pps,tx_pps,rx_bps,tx_bps,errors,drops`
   serves `fleet_iface_5m` (5-minute buckets, 48 h; `errors` / `drops` are rx + tx per report, averaged per bucket; `max` is
   null). An interface without rows answers empty series. Host-level `net_errors` / `net_drops` (management interface) were
   already served; the host chart now uses them.
5. Probe components accept `by_test_<name>` keys, one per test of the catalog (01-contracts.md section 3), rolled up from
   `by_test_per_min` into the existing component roll-up tables (so 5 m / 1 h, 48 h / 30 d). The fixed catalog bounds the stored
   key set whatever a probe reports. A test absent from a report adds no sample (a gap, never a fabricated zero). The keys are
   chartable on request and are not part of the default key list.
6. `Issue.component_type` (`probe|collector|dashboard|runner|speedtest|null`) is stored with the issue, backfilled by migration
   `0004_fleet_gaps.sql`, and used by the UI type filter (`host` = null).
