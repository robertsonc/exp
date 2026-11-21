# CR-m6-spec-resolutions — resolutions of inconsistencies in `12-speedtest-analytics.md` (M6)

**Status:** accepted by the orchestrator; recorded and applied by the M6 contracts step (c0). **Binding** on every M6
step. Where `12-speedtest-analytics.md` (owner's updated spec, commit 7e62c7a: D15 = ONE speedtest box at the venue
core/DC, plain HTTP by default, always anonymous, location by correlation) disagrees with itself, this file decides.
`01-contracts.md` §14 and `12-…` §7 carry the pointers.

## A. Orchestrator resolutions

| # | Inconsistency | Resolution |
|---|---|---|
| 1 | Transport: §7.3 says "HTTPS 443"; D15/§4.3/§7.5 say plain HTTP | **TCP 80 on `serve.listen_ip` when `tls.mode = none`** (default); **TCP 443 (+ 80 → 443 redirect) only when `tls.mode = provided`**. Self-signed is not offered. The §7.3 heading is stale. |
| 2 | On-network byte cap: 400 MB (§4.2, §7.5) vs 200 MB (§4.4 core guard) | **200 MB per test** (`limits.bytes_local`); total concurrent tests per box **20** (`limits.max_concurrent_tests`); internet-leg slots **10** (`limits.max_concurrent_internet`). Internet cap stays 200 MB. |
| 3 | Retention: §6 (tests 90 d, evidence 30 d) vs §9 (30 d for all) | **§9 wins**: tests, device metadata and evidence default **30 days**; VM aggregates forever; **no automatic raw-identifier scrub by default**; optional `privacy.scrub_after_diagnosis` (drop raw IP/MAC/username/hostname after the final diagnosis, keep `device_key`) and a shorter `retention_days` are config. **A6.6 is asserted with scrub enabled; "no name/email field anywhere" is asserted always.** |
| 4 | §3.1 says "decision D16" | D16 was retired; the decision is **D15** (a doc nit). |
| 5 | `legs.path` (gateway/edge/edge+1) vs per-user results | `legs.path.{gateway,edge,edge1}` are **shared venue-infrastructure context timed from the box**, not per user; `device_icmp_ms` is **per test** (box → the requesting client only). The user's own path comes from correlation (EC flow, Mist switch). |
| 6 | NAT guard (A6.12) is under-specified | Identity resolution **fails closed** (`zone: unresolved`, flag `nat_suspected`, `identity.nat_reason`) when the observed client IP is **outside every configured attendee subnet while `serve.require_real_client_ip` is true**, **or equals a configured translated/edge address** (`serve.translated_addresses`), **or the Mist lookup for that IP in the window yields zero or more than one client MAC**. A test is never bound to a device on ambiguity. |
| 7 | A6.4 "drills as ground truth (M5 harness)": M5 drills were never built | Ground truth comes from **harness faults (`lanctl`, `netem`) + the vendor fakes' scenarios**. No drills in M6 (`drills_enabled` stays false). |
| 8 | HPE Aruba SSE (Axis) API connector (§5.2 source (b)) | **Out of scope / `unavailable`**: no local vendor documentation, so no field is guessed. The connector reports "unavailable"; SSE logs can still arrive via syslog. `runner.config` `sse.enabled` is always false; `integrations/{kind}` has no `sse`. |

## B. Resolutions added by the contracts step

1. **Vendor field names only from the local references** (Mist OpenAPI 3.1 in the `mistapi` 0.64.1 SDK; HPE
   `pyedgeconnect` 0.16.0a1). Every evidence field cites its source in its `description`. Where the reference is silent the
   contract says so instead of inventing: EdgeConnect time series expose only a runtime `COLUMN_DEF` (generic
   `wan.timeseries {columns, rows}` plus runner-derived `util_pct`), Mist client-event type names are discovered from Mist's
   event constants at runtime (free bounded text + a runner-derived `auth_failures` count), security-log vendor keys are
   parser input (normalized fields only). Flow rows are positional lists in `get_appliance_flows`; the schema names them
   with the index in each `description`.
2. **Anonymity is structural**: `additionalProperties: false` on every object of `exp.speedtest/1`,
   `exp.speedtest.submission/1` and `exp.evidence/1`; no bare `name`, `email`, `phone`, … property (evidence uses
   `ap_name`, `alarm_name`, `qname`); the Mist `guest` object (it carries name/email) is deliberately not mapped; the raw
   User-Agent is never stored; 802.1X/portal `username` exists only in the identity evidence as network-held operational
   data and is dropped by the scrub.
3. **Score**: floored total, internet leg preferred as basis (else on-network), stability = `1 − cv/0.5` minus 0.1 per
   failed request (the spec said "CV and failures" without a formula). See `exp_common.speedtest.compute_score`.
4. **`zone_source`** also admits `dhcp` (DHCP-syslog IP → MAC; subnet gives the coarse zone, so identity
   `resolved_by: dhcp` carries `zone_source: subnet`); the `GET /st/api/v1/where` echo uses the same enum.
5. **Zone map**: Mist AP / site → exp zone is `runner.config.correlation.sources.mist.zone_map` (first match wins); absent
   → the subnet fallback. A QR `?z=` only stamps `zone_hint`; a disagreement sets `zone_hint_conflict`.
6. **Where the NAT guard runs**: the speedtest evaluates the first two conditions itself (it knows the observed IP and its
   config) and answers `nat_suspected` in `where`; the runner evaluates the third (Mist lookup) and publishes the final
   answer in the identity evidence. Either failure leaves the stored zone `unresolved`.
7. **Auto-pause fails open**: a runner-published WAN utilization older than 90 s is ignored; an unreachable runner never
   keeps the internet leg paused (the admin switch is the deliberate override).
8. **Purge by MAC** needs the `device_key_secret` to reach rows whose raw MAC was scrubbed; the collector therefore gets
   that credential as an optional cred. Without it, purge-by-MAC only matches rows still holding the raw MAC
   (`device_key_matched: false` is reported).
9. **Cloudflare**: findings of the live recording (colo not readable from `__down`; set `logAimApiUrl: null`;
   `Timing-Allow-Origin` present; no preflight for the library's own requests; `Server-Timing` `cfSpeed*` summed) are in
   `test/fixtures/cloudflare/README.md` and are binding for the page build.
10. **Result id = session id** (`st_` + ULID); one session produces at most one stored test.

## Owner decisions (2026-11-21, on PR #5)

The four questions raised in the M6 PR were answered by the owner:

1. **`internet_off` flag: accepted.** The box sets `internet_off` instead of `internet_unavailable` when the operator
   switches the internet leg off (CR-m6-contracts follow-up 2026-11-20); dropping the internet leg from such results
   was the rejected alternative.
2. **`qos_shaping` is internet-side: accepted.** With an unmeasured internet leg and a high local-only score the
   EdgeConnect shaper on the client's WAN flows is evaluated with `wan_saturation`, `network_wide` and `internet_path`
   (implemented: CR-m6-collector follow-up 2026-11-21).
3. **Scrub errs toward deletion: accepted.** The owner asked whether MAC randomization makes this moot. Recorded answer:
   no. Per-SSID randomized MACs are stable for the length of an event, so within one network they still link a device's
   AP/zone trail, DHCP, flows and firewall lines; wired, managed and older devices keep burned-in MACs; DHCP hostnames
   often identify the person regardless. Randomization limits cross-network tracking, which is not what the scrub is for.
4. **Auto-pause at 80 % vs `wan_saturation` above 85 %: accepted** as spec defaults (a test in the gap reads "internet
   check paused, venue network fine", `none` at 0.6).
