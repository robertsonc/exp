# CR-wp2-summary-and-query-extras

**From:** WP-2 (collector), step 3. **Status:** proposed (implemented compatibly inside `collector/`).

## What
1. `GET /api/v1/summary` (01-contracts.md section 5) only names the six tables (`clients, dhcp, dns, apps,
   throughput, servers`); `collector.yaml` says "row columns are defined by the collector implementation". The
   collector implements these row shapes (all keys always present, `null` when there is no data); WP-3 (dashboard)
   should render from them:
   - `clients[]`: `port, dhcp_runs, dhcp_ok_pct, dhcp_total_p50_ms, dhcp_total_p95_ms, dns_runs, dns_ok_pct,
     dns_p50_ms, dns_p95_ms, apps_runs, apdex, worst_app, worst_apdex, wifi_ssid, wifi_rssi_dbm, flags[],
     no_link_runs`
   - `dhcp[]`: `server, ports[], runs, ok_pct, offer_p50_ms, total_p50_ms, total_p95_ms, last_seen`
   - `dns[]`: `resolver, kind, runs, ports[], p50_ms, p95_ms, fail_pct`
   - `apps[]`: `app, apdex, runs, clients, p50_total_ms, p95_total_ms, ok_pct`
   - `throughput[]`: `port, provider, down_mbps, up_mbps, latency_idle_ms, latency_loaded_ms, bufferbloat_ms,
     outcome, ts` (latest run per port and provider in the window)
   - `servers[]`: `port, proto, requests, errors, p50_ms, sources[{client,count}], last_seen`
2. `GET /api/v1/query_range` additionally refuses (400 `step_too_small`) a step that would give more than 11,000
   points per series, answers `422 result_too_large` when VM's answer exceeds 32 MiB, and accepts `start`/`end`
   as epoch seconds as well as `...Z` timestamps. `422 too_many_series` is also returned when VM itself refuses
   (`-search.maxSeries=500`).
3. `POST /api/v1/incidents/{id}/ack` without an `X-Exp-User` header is refused with `403 forbidden` (an
   unattributable acknowledgement would defeat the audit trail). The collector cannot check the operator role
   itself: the dashboard session does (as the OpenAPI description already says).
4. SSE: no initial state snapshot is sent on connect (clients read `GET states` first); event ids are
   `<boot>.<n>` and an id from before a collector restart replays nothing.

## Why
The contract leaves these open; each is the most conservative reading (bounded work, no unattributed writes).

## Affected WPs
WP-3 dashboard (summary columns, SSE resume behaviour), WP-8 harness.

## Compatibility
Additive. No existing field changes meaning.
