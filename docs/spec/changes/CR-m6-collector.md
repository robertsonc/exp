# CR-m6-collector — collector speedtest analytics (M6 step a1, WP-11)

**From:** M6 step a1 (collector). **Affects:** `collector/`, `shared/schemas/collector.config.schema.json` (additive),
manager compile of the collector config/creds (WP-11/WP-5), dashboard (consumer of the query API), runner (consumer of
the feed/evidence/baseline routes). **Decision:** accepted; applied by the step. Binding companions:
`CR-m6-contracts.md`, `CR-m6-spec-resolutions.md`.

## What was built

`collector/exp_collector/speedtest/` (storage, diagnosis, privacy, VM metrics, SSE, handlers) plus minimal wiring in
`api.py` (router), `app.py` (service lifecycle, telemetry), `auth.py`/`server.py` (two more token scopes), `config.py`
(creds, `CollectorConfig.speedtests`), `store.py` (migration 2, `secure_delete`), `cli.py` (`speedtest purge`) and the
unit file (three more `LoadCredential=` lines). Every `speedtests` operation of `collector.yaml` is implemented.

## Decisions later steps must know

1. **Token scopes are structural.** `exps_` is looked up only in `speedtest_tokens.json` and works only on `POST
   speedtests`, `GET speedtests/{id}/status`, `POST speedtests/{id}/comment`; `expr_` only in `runner_tokens.json`, on
   the feed / evidence / complete / baseline routes; `expd_` on the rest. The identity must also be listed in
   `speedtests.speedtests` / `speedtests.runners` (else 401). Binding site = the collector's own `site` (the all-in-one
   box has one site). With `speedtests.enabled` false (or the block absent) every authenticated speedtest route answers
   404 `not_found`.
2. **Role of the dashboard user.** The collector cannot verify roles. `identifiers=true` is sent by the dashboard only for
   admin sessions (c0); the collector additionally **requires `X-Exp-User`** (403 `forbidden` without) and writes a durable
   audit row per use. `POST speedtests/purge` also requires `X-Exp-User`. Without `identifiers=true` the response is the
   privacy transform of the stored rows (raw IP/MAC/hostname/username removed everywhere in evidence, `device_key` kept).
3. **Evidence dedup / replace.** One document per (test, kind). Same `source` + `collected_at` + identical body is a
   no-op; an older `collected_at` never replaces a newer one (200, nothing stored); otherwise replace until final.
   Total bound is `max_evidence_kib` (default and maximum 256) per test (413 `evidence_too_large`, nothing half-stored).
   Order of checks: schema (400) -> `id_mismatch` (400) -> unknown test (404) -> other site (403) -> final (409) -> size.
4. **Final diagnosis.** On `evidence/complete`, and also by the collector when a test was never completed:
   `speedtests.finalize_after_s` (default 300) after `ended` (the runner's `window_after_s` 120 + a timeout). A test with
   no evidence at all ends as `evidence_state: unavailable`. Final evidence cannot change (409 `evidence_final`).
5. **Rules.** Every cause of 12 section 5.3 with the documented defaults as tunables in `speedtests.diagnosis` (new,
   additive; see the schema). Interpretations: "local leg slow" = below `local_slow_pct` (50 %) of the band/width
   expectation table (`wifi_expect_mbps`, defaults 5/80 = 450 Mb/s ... ; wired: 80 % of the port speed; without any
   evidence: below the score targets); `wifi_roaming` counts roams/auth events within `roam_slack_s` (300 = the whole
   evidence window, the runner pulls events for [start - 5 min, end + 2 min]) of the test; `qos_shaping` = a flow in
   `qos_limited_classes` (7-10) with a TCP slow duration (the vendor reference does not say which class is rate-limited);
   `wan_saturation` also fires on tunnel loss/latency/jitter health `major|critical`; `dns` also fires on a browser cold
   lookup above `dns_cold_ms`; `none` only when the score is at or above `none_score` (80) and is then the only cause;
   a degraded test where nothing fires gets an **empty cause list** ("could not pinpoint"), never an invented cause (the
   row `cause` is null, aggregates group it as `unknown`, the VM label is `unknown`).
6. **network_wide** uses the collector's own probe data (`rules.state` live or time-travel at the test's mid time), the
   nearest probe of the site: `same_ap` / `same_zone` when the probe's `label` contains the AP name / zone id, else
   `same_site`; the probe's newest record must be younger than `network_wide_age_s` (120). The posted `baseline` evidence
   is only a fallback. `GET speedtests/baseline` returns the same data (throughput from the probe's latest `throughput`
   record within 30 min, wifi from `wifi_hb` within 60 s).
7. **Score** is recomputed by the collector with `speedtests.targets` (the page's / box's figure is never stored).
8. **VictoriaMetrics.** Histograms with the VictoriaMetrics `vmrange` format (18 buckets/decade) and `_sum`/`_count`,
   labels `site, zone, leg, ssid, band, ap, os_family`; `exp_st_tests_total{site,zone,cause}`. Observed **once per test when
   its evidence is final** (zone/AP/SSID are known then), so VM lags SQLite by the evidence time (<= `finalize_after_s`);
   the SQLite `aggregate` endpoint is immediate. Each bounded label admits `metric_label_limit` (64) distinct values, then
   `other`; counters are in memory (a restart is an ordinary counter reset). `loaded_latency` of a leg = the worse of
   loaded down/up. Collector self-telemetry gains `exp_collector_speedtest_events_total{event}` when enabled.
9. **Privacy.** Raw identifiers live only in `speedtests.client_ip/mac/hostname/username` and in evidence JSON.
   `scrub_after_diagnosis` (default off) nulls the columns and redacts the evidence in the **same transaction** as the final
   diagnosis, and the retention job catches up on final tests that predate switching it on. The writer connection runs with
   `PRAGMA secure_delete=ON` (purged and scrubbed values do not linger in free pages). Retention (`retention_days`, default
   30) deletes tests, device metadata and evidence together (by `ended`). Purge is audited in `speedtest_audit` (actor,
   action, `by:<sha256 prefix of the subject>`, matched, dry_run; **never the identifier**) and in the audit log.
10. **Purge by MAC without the secret** can only match rows that still hold the raw MAC and answers
    `device_key_matched: false`; with the optional `device_key_secret` cred it also matches scrubbed rows through the key.
11. **CLI.** `exp-collector speedtest purge (--device-key | --mac | --ip | --test) VALUE [--dry-run] [--user NAME]` works
    on the database directly (also when the analytics are disabled), prints the purge result as JSON, audited as `cli:<user>`.
12. **Database.** Migration 2 adds `speedtests`, `evidence`, `diagnoses`, `speedtest_audit` (+ indexes for every query
    filter and the purge keys); `SCHEMA_VERSION` is 2 (the existing store tests were updated for that).

## Schema change (additive, `collector.config.schema.json`)

`speedtests` gains `correlation_window {before_s 300, after_s 120}`, `finalize_after_s`, `metric_label_limit` and
`diagnosis {none_score, wifi_rssi_dbm, wifi_snr_db, local_slow_pct, wifi_expect_mbps, wifi_util_pct, wifi_clients, roams,
roam_slack_s, wired_errors, wired_speed_mbps, wan_util_pct, internet_loaded_ms, qos_limited_classes, dns_slow_ms,
dns_slow_count, dns_cold_ms, policy_min_events, network_wide_age_s}`. All optional; documents without them are unchanged.

## Known gaps handed on

* The manager must compile `speedtests.*` for the collector, `speedtest_tokens.json`, `runner_tokens.json` and the optional
  `device_key_secret` (the unit already loads them; empty files are fine).
* `zone_name` in the user-safe status is the zone id (the collector does not hold zone display names; the box maps it).
* The dashboard needs the `X-Exp-User` pass-through for `identifiers=true` and for purge.
