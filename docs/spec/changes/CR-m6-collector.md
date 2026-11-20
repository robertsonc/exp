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

## Diagnosis: a test whose internet leg was not measured never reads "healthy" by default (p2)

*(Corrected 2026-11-20: two statements below are no longer true and are superseded by the follow-up at the end of this
file: "every rule runs" now holds only below `none_score` (at or above it only the internet-side rules run), and the
paused text no longer names a busy link. The `unavailable` status now also has the operator-switched-off variant
`internet_off`, which is not an outage.)*

Defect: the healthy short-circuit (score >= `none_score` -> cause `none`) was skipped only for `legs.internet.status`
"unavailable". "paused" (admin or EC-WAN auto-pause), "queued" and "skipped" also mean the score rests on the on-network leg
alone, so e.g. WAN util 90 % -> auto-pause -> local-only score 99 -> `none`, and `wan_saturation` was never evaluated.

Fix (`speedtest/diagnosis.py`, thresholds unchanged):

* `internet_measured` is False iff `legs.internet` exists and its status is not `ok` (absent leg: behaviour unchanged).
  When not measured there is no short-circuit; every rule runs as for a low score (unavailable + no WAN fault keeps
  `internet_path` / the internet-down text).
* If no rule fires, the local leg is known and not slow and score >= `none_score`: cause `none`, confidence 0.6, cites
  `legs score.total` and `legs internet.status`, with a status-specific blame-free user text (paused: venue network fine,
  internet check paused because the event's internet link is busy, try again in a few minutes; queued / skipped: result
  covers the venue network only) and NOC text "internet leg <status>: local-only score N; ...". Score < `none_score` and no
  rule fired stays USER_UNKNOWN / USER_PENDING_UNKNOWN.
* Spec rule kept: `none` only at score >= 80, and then the only cause. No new cause id and no new label value (consumers in
  service.py / VM histograms use the existing bounded `CAUSES`).
* Known interaction: auto-pause fires at 80 % WAN util while `wan_saturation` needs > 85 % (spec 6 table); at 82 % the user
  now gets the status text above instead of the false "below target" text.

Tests: `test_st_diagnosis.py::test_unmeasured_internet_*` (4 statuses x WAN 90 / 82) and
`test_internet_ok_high_score_still_short_circuits`.

## Diagnosis follow-up (2026-11-20): a high local-only score runs only the internet-side rules; `internet_off`; texts

Defects (reproduced on the p2 code, local 200/150 Mb/s, 15 ms loaded, cv 0 = local-only score 100):

1. With the internet leg paused / queued / skipped every rule ran, so the local-side rules judged a healthy test against
   the band / port expectations (200 Mb/s < 50 % of the 5/80 table value): good 5 GHz/80 MHz Wi-Fi (RSSI -55, SNR 40,
   util 30 %, 10 clients) gave `device_limit` 0.55 (ok leg: `none` 0.9); a healthy 1 Gb/s full-duplex port with 0 errors
   gave `device_limit` 0.5 with the Wi-Fi text to a wired user; the c0 `security.policy-block` evidence gave `policy_block`
   0.85 (with an ok leg the healthy short-circuit hides it); Wi-Fi evidence without rssi/snr gave cause [] and "Your speed
   is below target..." at score 100. The p2 fallback also required "local leg not slow", which the expectation table
   vetoed.
2. `internet_leg.enabled=false` (operator switched the leg off; slot reason `disabled`) was stored as
   `legs.internet {status: unavailable}` + flag `internet_unavailable`, identical to an outage, so every test at a site that
   does not test the internet read "the internet could not be reached right now".
3. The paused text said the check was paused "because the event's internet link is busy"; status paused also covers the
   admin pause (`pause_reason admin_pause`), and no reason travels in the result.
4. Internet down with `network_wide` first read "nearby network checks show the same slowdown" for an outage.

Fix (`speedtest/diagnosis.py`; no new cause id, no threshold change, the bounded `CAUSES` label set is unchanged):

* **Not measured** = `legs.internet` present with status unavailable / paused / queued / skipped (`internet_off` is
  stored as unavailable). **Internet down** = status unavailable AND flag `internet_off` absent.
* Not measured and score >= `none_score`: the score says the venue network is good, so only the rules for the path
  beyond it run: `wan_saturation`, `network_wide`, then `internet_path`, with the on-network leg taken as fine
  (`Ctx.local_good`: known and not slow, so the band / port expectation cannot veto them). One fires -> those causes,
  as before. None fires -> `none` 0.6 (cites `legs score.total`, `legs internet.status`, plus `legs flags.internet_off`
  when switched off) with the status-specific text; this path never returns USER_UNKNOWN / USER_PENDING_UNKNOWN.
  Local-side evidence (Wi-Fi, port, policy, QoS, DNS) is not turned into causes there, exactly as with a measured leg and a
  high score; it stays in the record.
* Score < `none_score` (or no score): every rule runs, unchanged.
* `internet_path`'s "leg could not run" branch fires only when the internet is down (not for `internet_off`). Internet down
  with no WAN fault keeps `internet_path` 0.55 + "The venue network is working, but the internet could not be reached right
  now." (A6.7).
* Texts: paused -> "The venue network is working well. The internet check is paused right now, so this result covers the
  venue network only." (true for the WAN auto-pause and the admin pause); `internet_off` -> "The venue network is working
  well. The internet part is not tested at this event, so this result covers the venue network only." (NOC: "internet leg
  switched off (internet_off): local-only score N; ..."); internet down with `network_wide` as the first (or appended
  second) cause -> "It is not just you: the internet cannot be reached from the venue network right now." Queued / skipped
  texts unchanged.
* e2e expectations kept, no e2e file changed: A6.4 paused leg during EC WAN 92.5 % -> `wan_saturation`, not
  `internet_path`; A6.7 'internet' in user_text + noc_text. The A6.4 `policy_block` case still needs an open (measured) leg,
  which `internet_leg_open` already waits for.

Box side: `speedtest/exp_speedtest/core.py` sets `internet_off` instead of `internet_unavailable` when the leg is switched
off (contract: `CR-m6-contracts.md` follow-up 2026-11-20).

Tests (`collector/tests/test_st_diagnosis.py`): `test_unmeasured_high_score_local_side_rules_do_not_fire` (cases a-d x
5 statuses incl. `off` x quick/final), `test_unmeasured_high_score_wan_hot_is_wan_saturation_whatever_the_local_evidence`
(WAN 90), `test_unmeasured_high_score_wan_below_threshold_is_none` (WAN 82),
`test_internet_ok_high_score_local_evidence_is_healthy` (control), `test_unmeasured_low_score_still_runs_every_rule`,
`test_internet_off_is_not_an_outage`, `test_internet_off_low_score_does_not_blame_the_internet`,
`test_paused_text_holds_for_an_admin_pause_too`, `test_internet_down_with_network_wide_says_the_internet_cannot_be_reached`,
`test_network_wide_text_unchanged_when_the_internet_is_not_down`; the p2 `test_unmeasured_internet_*` now also cover `off`.
