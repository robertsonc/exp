# CR-m6-contracts — M6 contracts moved into `shared/` ("WP-0 at M6", 01 §13/§14)

**From:** M6 contracts step (c0). **Affects:** WP-9 (runner), WP-10 (speedtest), WP-11 (collector/dashboard/manager
settings), WP-5 (manager UI/Worker by CR), WP-6 (agent assets), harness. **Decision:** accepted; applied by the step that
wrote it (additive to `shared/`). Companion: `CR-m6-spec-resolutions.md` (binding resolutions).

## What was added

| Area | Files |
|---|---|
| JSON Schemas (new) | `speedtest.schema.json` (`exp.speedtest/1`), `speedtest.submission.schema.json` (`exp.speedtest.submission/1`, the page → speedtest wire format: a fourth new file beyond the three the task named, because the page may not set server-observed fields), `evidence.schema.json` (`exp.evidence/1`, closed kind-specific `data` for wifi, wired, flows, wan, security, baseline, dns, identity), `speedtest.config.schema.json` (`exp.speedtest.config/1`) |
| JSON Schemas (additive) | `common` (`st_id`, `exps_/expr_/expl_/expk_/expt_/expv_` token defs, `device_key`, `ip_addr`, `zone_id`; `token` anyOf widened), `runner.config` (`correlation` block, M5 fields untouched), `collector.config` (`speedtests` block), `desired` (speedtest `config` → its schema, `assets[]`), `health` (`facts.url` accepts `http://`, `facts.tls_mode`) |
| OpenAPI | **new** `speedtest.yaml` (every §7.3 route, `GET /st/api/v1/config`, `GET /st/assets/{name}`, 429 + `Retry-After`, the loopback runner channel under tag `runner-channel`); `collector.yaml` (12 `speedtests` operations, security schemes `speedtestToken` and `runnerToken`, `Conflict`/`PayloadTooLarge` responses); `admin.yaml` (6 operations under tag `speedtest`). `test_openapi.py` covers all of it; every new operation names its implementing WP in `x-exp-wp` |
| `exp_common` | `ids.py` (`st_` id prefix, six new token prefixes, regex), `log.py` (redaction of the new prefixes), new `speedtest.py` (`new_speedtest_id`, `compute_score`, `score_basis`, `counters_disagree`, `device_key`, `normalize_mac`, view-key/proof/verifier helpers, bounds), tests in `shared/python/tests/test_speedtest.py` |
| Fixtures | `speedtest/` (6 valid results incl. policy-block, unresolved + `nat_suspected`, internet-unavailable, internet-queued, counters-disagree; 3 valid submissions), `evidence/` (all 8 kinds, plus identity variants, wifi-unavailable), `configs/{speedtest,speedtest.tls-provided,speedtest.minimal,runner.correlation,collector.speedtests}.json`, `desired/all-in-one-speedtest.json`, 60+ invalid fixtures; registered in `INDEX.json` / `gen_fixtures.py`; `test_fixtures.py` adds schema-anonymity, closedness, coverage, internal-consistency (scores, device_key, credential pairs) and Cloudflare-recording tests |
| Live recording | `test/fixtures/cloudflare/recording-2026-11-20.json`, `record.py`, `README.md` |
| Docs | `01-contracts.md` §14 (+ ports/users/units in §11, token row in §1, §9.4 pointer), `07-security.md` (SR-21…26 confirmed with enforcement tests, T20), `12-…` §7 pointer and stale-text fixes |
| Tooling | `test/fakes/mock_admin/admin_schemas.json` regenerated (it mirrors `admin.yaml`); `shared/exp_schema.py` got `noqa` markers so `ruff check shared` is green |

## Interface and token decisions (the part later steps must know)

1. **Tokens**: `exps_` (speedtest → collector; identity-bound per `speedtest_id`; collector cred `speedtest_tokens.json`),
   `expr_` (runner → collector; identity-bound per `runner_id`; `runner_tokens.json`), `expl_` (runner → speedtest
   loopback channel; speedtest holds `runner_channel_token_sha256`), `expk_` (device_key secret), plus the ephemeral
   page credentials `expt_` (leg token, memory only) and `expv_` (view proof). All sha256 at rest where stored. The prefixes
   do not collide with `expe_/expa_/expi_/expd_/expn_`; the runner keeps its `expi_` for `ext_*` ingest.
2. **Fragment key**: `k` stays in the URL fragment; the page sends `view_verifier = sha256(proof)` at session creation and
   `X-Exp-View-Proof: proof` afterwards, `proof = expv_ + b64url(HMAC-SHA256(k, "exp.st.view/1:" + id))`. Wrong/missing →
   404. `GET /st/r/{id}` serves a static shell. Details in 01 §14.2.
3. **device_key** = HMAC-SHA256(`expk_` secret bytes, normalized MAC), computed by the runner. The secret reaches the
   runner and (optionally) the collector as a cred, never the manager's results path (the manager receives no results).
4. **Runner channel direction**: although "runner → speedtest", the Mist lookup is pull-through: the speedtest records IPs the
   page asked about (`GET where/wanted`), the runner resolves them and pushes answers (`PUT where`); EC WAN utilization is
   pushed with `PUT pause`. The speedtest never calls the runner and never sees a MAC.
5. **Collector API split by caller**: `exps_` (ingest, status, comment), `expr_` (feed, evidence, complete, baseline),
   `expd_` (query, aggregate, stream, detail, purge). `identifiers=true` is requested by the dashboard only for admin-role
   sessions; raw `client.ip` is optional in `exp.speedtest/1` precisely because the scrub removes it.
6. **Desired state**: speedtest `config` is now validated; `assets[]` carries the branding logo (agent installs it to
   `/etc/exp/speedtest/assets/logo`, root `0644`). WP-6 must implement the download (the existing artifact route and SR-6 check
   already cover "referenced by the desired state").
7. **Evidence vendor fidelity**: the identifiers of every field are cited; where a vendor reference is silent the schema is
   generic and says so (see `CR-m6-spec-resolutions.md` B1).
8. **Ports/users**: speedtest TCP 80 (443 + redirect when `provided`) and UDP/TCP 53 on `serve.listen_ip`; runner UDP/TCP 5514
   and TLS 6514 on `syslog.bind`; the runner channel on 127.0.0.1:8480; users `exp-speedtest` (with `CAP_NET_BIND_SERVICE`) and
   `exp-runner`; unit `exp-speedtest.service`.

## Findings from the live Cloudflare recording that constrain the build

(Full detail in `test/fixtures/cloudflare/README.md`.) CORS and `Timing-Allow-Origin` work from an `http://` origin, so the
plain-HTTP page is viable and Resource Timing works; but **the colo is not readable from `__down`** (header `colo` is not
exposed and `cf-meta-colo` is absent on `__down`): the page must read `/cdn-cgi/trace` for it. The library's own requests
need no preflight. `logAimApiUrl` must be set to `null` so no results are sent to Cloudflare. `/cdn-cgi/trace` has no
`Timing-Allow-Origin`, so only its body is usable.

## Compatibility

Additive. The only widened existing contract fields are `common#/$defs/token` (anyOf), `desired` speedtest `config`
(was an unvalidated object, now `exp.speedtest.config/1`; no existing fixture or manager output used it) and
`health.facts.url` (https_url → http_url, a strict superset). `exp.runner.config/1` and `exp.collector.config/1` documents
without the new blocks are unchanged. Existing OpenAPI operations are untouched.

## Known gaps handed to later steps

* `speedtest.yaml` covers `GET /st/assets/{name}` for fonts only by naming; the font files themselves are a WP-10 build item.
* Diagnosis rule thresholds are the §5.3 defaults; their tuning knobs are not in `collector.config` yet (add by CR if needed).
* The manager Worker/UI (`manager/`) does not yet implement the new admin routes or compile the new configs/creds (WP-11/WP-5).

## Follow-up (2026-11-20): result flag `internet_off`

* **Flag:** `internet_off`, added to the `exp.speedtest/1` `flags` enum (`shared/schemas/speedtest.schema.json`, enum and
  description). Additive.
* **Meaning:** the operator switched the internet leg off (speedtest config `internet_leg.enabled=false`; the slot API
  answers `state unavailable`, `reason disabled`, unchanged). The result carries `legs.internet {status: "unavailable"}` and
  `internet_off` **instead of** `internet_unavailable`, so "not tested at this event" is no longer indistinguishable from
  an outage. `internet_unavailable` now means only that the leg could not run (outage). No new leg status.
* **Who sets it:** the box (`speedtest/exp_speedtest/core.py`, result build: `not cfg.internet_enabled`). The page cannot set
  flags (the submission schema is closed).
* **Consumers:** collector diagnosis (`internet_off` -> the leg is "not measured", never `internet_path` from the leg
  status; text "The internet part is not tested at this event, so this result covers the venue network only.", see
  `CR-m6-collector.md` follow-up 2026-11-20); collector storage / query (flags stored and returned as given, no
  enumeration); `shared/openapi/speedtest.yaml` `ResultAccepted.flags` (refers to the schema enum, no edit needed); dashboard
  detail (`static/speedtest/detail.js` renders every flag generically as a chip, "internet off", no label map, no edit);
  manager and `exp_common` (no enumeration of result flags, no edit); fixtures (no regeneration: the existing documents stay
  valid); the page (`speedtest/page/src/app.js`: `internet_off` or the public config `internet_leg.enabled=false` -> a
  venue-only verdict and the note "The internet part is not tested at this event.", never the outage sentence); the
  flags list in `01-contracts.md` section 14 (added).
* **Compatibility:** a box that sends `internet_off` needs a collector with this schema (ingest validates the closed enum
  and would answer 400); both ship in the same release / all-in-one box. Stored results that carry `internet_unavailable`
  for a switched-off leg (before this change) keep reading as an outage in the collector diagnosis and the dashboard; the
  page reads them as switched off while the box's config says so (it checks the live config too).
