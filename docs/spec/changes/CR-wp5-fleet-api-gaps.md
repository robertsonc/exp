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
