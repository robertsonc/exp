# exp/runner — `exp-runner` (M6: correlation base + syslog receiver; no drills)

The runner correlates a speedtest result with what the network knew at that moment. For every new test it resolves **who** had
the client IP (identity, with a fail-closed NAT guard), pulls evidence from every configured connector, normalizes it to
`exp.evidence/1` (bounded, schema-validated), posts it to the collector and marks it final. It also hosts the **syslog receiver**
(UDP/TCP 5514, TLS 6514) with a 60-minute SQLite ring, and talks to the local speedtest over a loopback channel.

Specs: [12 §5](../docs/spec/12-speedtest-analytics.md), [01 §8.1 and §14](../docs/spec/01-contracts.md),
[SR-24/25](../docs/spec/07-security.md), CRs `CR-m6-*` in [../docs/spec/changes](../docs/spec/changes). Work package WP-9 (M6 part).
**M5 drills are not built** in this release: `drills_enabled` stays `false`; drill/puller fields in a config are ignored with one
warning. Connectors: Mist (identity + `wifi`/`wired`), EdgeConnect Orchestrator (`flows`/`wan` + auto-pause feed), the probe baseline,
the syslog connector (`security`/`dns`) and an SSE placeholder (see "Connectors").

```
exp-runner run|health|version|selftest   [--config /etc/exp/runner/config.json] [--state-dir D] [--run-dir D] [--creds-dir D] [--syslog-db F]
```

* `run` — the daemon. Refuses an invalid config (exit 78, reasons on stderr). With `correlation` absent or `enabled: false` it idles
  and reports `ok`.
* `health [--json]` — `exp.health/1` from the daemon's snapshot (`<run>/health.json`, written every 5 s). No/stale snapshot = `fail`
  (exit 1); `ok` and `degraded` exit 0.
* `selftest` — checks Python, config, credentials, ports, the SQLite ring, disk and `openssl`; exit 1 on any failure.

## Configuration (`exp.runner.config/1`, no secrets)

`correlation` (all optional, defaults in brackets): `enabled` [false], `window_before_s` [300], `window_after_s` [120],
`poll_interval_s` [5], `sources.syslog {listen [udp:5514, tcp:5514, tls:6514], bind [0.0.0.0], allow [] , rate_limit_lines_per_s
[200 per source], max_line_bytes [4096], ring_minutes [60, max 60], tls.mode [self_signed|provided]}`,
`sources.mist {sites, zone_map, max_calls_per_test [6], cache_ttl_s [30]}`, `sources.ec {appliances, max_flows [50], wan_util}`,
`sources.sse.enabled` (always false), `privacy.scrub_after_diagnosis` [false], `speedtest_channel.url` and
**`network {require_real_client_ip [true], client_subnets, translated_addresses, zone_subnets}`** (the NAT-guard / coarse-zone inputs,
mirrors of the speedtest config — `CR-m6-runner-network`; the manager compiles both from the same site settings).

Ports below 1024 are refused. An **empty `syslog.allow` receives nothing** (and the receiver is not started).

## Credentials (`$CREDENTIALS_DIRECTORY`, systemd `LoadCredential=`)

| File | Purpose | Needed |
|---|---|---|
| `collector_token` | `expr_` — runner → collector (feed, evidence, complete, baseline); identity-bound | yes |
| `device_key_secret` | `expk_` — `device_key = HMAC-SHA256(secret, MAC)` (`exp_common.speedtest.device_key`) | yes (without it no `device_key`) |
| `speedtest_channel_token` | `expl_` — localhost channel to `exp-speedtest` | when `speedtest_channel` is set |
| `integrations.json` | `{mist: {api_base, token}, ec: {url, api_key}}` — never an `sse` entry | Mist / EdgeConnect connectors |
| `syslog_tls.crt` / `syslog_tls.key` | TLS 6514 when `tls.mode = provided` (`self_signed`: generated under `<state>/tls/`) | optional |
| `ingest_token` | `expi_` — the M5 `ext_*` measurement poster (unused in M6) | no |

Missing credentials never crash the runner: it runs **degraded**, names what is missing in `health` and re-reads the directory every
loop (a token change takes effect without a restart; the agent restarts the unit on credential changes anyway).

## What happens to a test

1. **Discover** — `GET speedtests/feed` every `poll_interval_s` (the `expr_` token has no SSE route; the feed is the contract). The
   cursor is dropped every 60 s so nothing is missed.
2. **Wait** until the window `[start − window_before_s, end + window_after_s]` has closed (+2 s).
3. **Identity** (`identity.py`): the **NAT guard** first — the test is *not* bound to a device (zone `unresolved`, flag
   `nat_suspected`, `identity.nat_reason`) when the IP is outside every `client_subnets` entry while `require_real_client_ip` is true
   (`outside_subnets`; not evaluated when no subnet is configured), equals a `translated_addresses` entry (`translated_address`), or the
   Mist lookup returns more than one MAC (`ambiguous`) or none (`no_match`). Otherwise: Mist (r2) → DHCP-syslog IP → MAC (more than one
   MAC in the window = `ambiguous`) → subnet → coarse zone → the speedtest's own QR zone → `unresolved`. Mist unavailable/error is *not*
   ambiguity. An unresolved test still gets every connector (baseline, legs, syslog).
4. **Connectors** run concurrently, each under its own deadline; a failing/slow connector yields `error` for exactly its kinds.
   A kind nobody delivers is posted explicitly as `unavailable` (never silently missing).
5. **Normalize + bound** — every document is validated against `evidence.schema.json` (a violation becomes an `error` placeholder),
   the set is shrunk to the 256 KiB per-test budget (largest first, lists halved, marked `partial`), then posted per kind
   (replace-until-final) and `evidence/complete` is called.
6. **Idempotency** — `runner.db` remembers completed tests; a restarted runner never re-posts them. A crash between evidence and
   complete re-posts (replaces) the same eight documents, never sixteen.
7. **Privacy** — with `privacy.scrub_after_diagnosis` the client IP's syslog rows (ring and attached) are deleted after the final
   diagnosis; the collector scrubs its own rows. `device_key` is the only per-device key stored.

Health (`exp.health/1` runner): `correlations_per_hour`, `evidence_lag_s_p95`, `syslog_lines_per_s`, `syslog_dropped_per_min`,
`pullers[] {source, last_ok, errors_1h}`, `drills_active` (always 0), plus `pending_tests`, `syslog_ring_lines`, `syslog_refused_total`.
`degraded` = collector unreachable / token refused / missing credentials / a syslog listener down.

## Syslog receiver (SR-24)

UDP 5514 (one message per datagram), TCP 5514 and TLS 6514 (RFC 6587 octet-counting `LEN SP MSG` **or** LF framing, decided per
message; 1–8 digits + space = octet count, anything else = LF). Controls, all counted: source **allowlist** (checked before the TLS
handshake), per-source and global **token-bucket** rate limits (`dropped_rate`), **line-length bound** (oversize lines are skipped,
never buffered: `dropped_oversize`), bounded write queue, ≤ 64 connections, idle/handshake timeouts, TLS ≥ 1.2.
Lines are control-character-scrubbed and parsed — **never executed, followed or fetched**. Parsers: RFC 5424 (structured data), RFC
3164, CEF, LEEF 1.0/2.0, key=value, DHCP leases (ISC dhcpd, Kea, Microsoft audit CSV → IP→MAC), DNS query logs (BIND, dnsmasq,
`qname=` key=value), EdgeConnect firewall/zone-policy lines and unknown text (bounded raw + timestamp + IPs).
**EdgeConnect log text has no local vendor documentation**: it is parsed through the generic key=value / `ZBF <action> …` forms by
key name; this is not vendor ground truth (and there is no SSE connector — SSE logs can arrive by syslog).

The ring (`/var/lib/exp/runner/syslog.db`, `--syslog-db` for tests; mode 0600) is indexed by IP + time. Lines expire `ring_minutes`
(≤ 60) after receipt; lines **attached to a test's evidence** are kept for 30 days (the evidence retention) and deleted with it.
Limitation: DHCP bindings older than the ring (a lease renewed less often than hourly) are not visible to the DHCP fallback.

## Speedtest channel (loopback)

`http://127.0.0.1:8480/local/v1` with the `expl_` token: the runner polls `where/wanted` (every 2 s), resolves each IP through the
same identity step and `PUT`s `where` (zone, source, AP, SSID, band, `nat_suspected`, never a MAC or username); `PUT pause` carries
EdgeConnect WAN utilization (`sources.ec.wan_util.enabled`; `WanUtilMonitor` is the `PausePublisher` source) — no source, no value =
nothing is published and the speedtest fails open. The runner publishes the *held peak* of the last two minute buckets (the
hysteresis on the way down); the speedtest owns the threshold (`internet_leg.auto_pause_wan_util_pct`).

## Connectors (r2; `CR-m6-runner-connectors`)

Vendor field names come **only** from local, verified, MIT-licensed references, cited in each module's docstring and in the evidence
schema descriptions: the Mist OpenAPI 3.1 document of the `mistapi` 0.64.1 SDK and HPE's `pyedgeconnect` 0.16.0a1. They are dev-time
references and are never imported. All upstream calls go through `upstream.py`: https only (plain http for loopback test fakes),
timeouts, response-size cap, per-test **call budget** (retries count), retries with backoff for idempotent reads only, `429` pauses the
connector (`Retry-After` honoured) instead of hammering a shared token, a failure that makes the rest pointless (credential refused,
host down) skips the rest of the chain. Credentials are sent only as headers and never logged.

| Connector | Kinds | Calls |
|---|---|---|
| `mist` (`mist.py`) | identity provider, `wifi`, `wired` | client search by IP over the window (wireless + wired), client stats, AP stats (30 s cache), client events per AP, switch port stats; **<= 6 per test** (`max_calls_per_test`), event-type constants refreshed hourly outside the budget |
| `ec` (`ec.py`) | `flows`, `wan` (+ `security.ec_dropped_flows`) | per appliance: flows for the client IP (top-50 by bytes), appliance, interface state, interface time series, 4 health summaries, alarms; budget 32 per test; state/health/alarms cached 30 s |
| `baseline` (`baseline.py`) | `baseline` | `GET speedtests/baseline` with the runner's own collector client (nearest probe at test time) |
| `syslog` | `security`, `dns` | the local ring (denies/drops/URL/IPS/NAT/session-limit lines citing `syslog:<id>`; resolver query lines) |
| `sse` | none | HPE Aruba SSE (Axis) has no local vendor documentation: reported `unavailable` with the reason (health fact `sse`); SSE logs still arrive by syslog |

**Identity by IP (Mist)**: each site in `sources.mist.sites` is searched for the IP in the window (wireless and wired); the first site
with any hit decides. Exactly one MAC binds the test; zero or more than one fails closed (`no_match` / `ambiguous`); a budget or
upstream failure before the answer is *not* ambiguity (`mist_status: error`, the DHCP/subnet fallbacks apply). Zone = `zone_map`
(AP MAC / name prefix / site), then the subnet table. Mist "map zones" are not exp zones.

**Honest limits** (details in the CR): Mist client events have no MAC filter, so events are AP-level context for the APs the client was
seen on, kept only when classified (from the runtime event constants) as a roam or an authentication failure, and roams only count
when the client changed AP in the window; Mist client stats are the *current* state (a client that left makes `wifi` `partial`);
EdgeConnect time-series column names are not documented, so the interface/time/rx/tx columns are found in `COLUMN_DEF` at runtime
(unidentifiable = raw series kept, no utilization, `partial`); EdgeConnect log text has no vendor documentation.

**Adding a connector**: subclass `Connector` (`name`, `kinds`, `collect(ctx) -> [EvidenceResult]`, own timeouts), take calls from
`ctx.budget("<source>", n)` and register it in `app.default_connectors`; an identity source implements `IdentityProvider`.

## Troubleshooting

| Symptom | Look at |
|---|---|
| `health`: "no health snapshot" | the daemon is not running: `journalctl -u exp-runner`; `exp-runner selftest` |
| `degraded: missing credentials` | the named credential files under `/etc/exp/runner/creds/` (the agent guarantees the files exist; empty = missing) |
| `degraded: collector refused the runner token` | the `expr_` token is not this runner's (identity-bound to `runner_id` and site) — rotate in the manager |
| no syslog arrives | `syslog.allow` must contain the sender's CIDR; check `syslog_refused_total`; firewall for UDP/TCP 5514, TCP 6514 |
| `syslog_dropped_per_min` > 0 | per-source rate limit (`rate_limit_lines_per_s`) or oversize lines (`max_line_bytes`) |
| every test `nat_suspected` | the box sees NAT'd addresses: place it where attendee traffic arrives un-translated (D15), or fix `client_subnets` / `translated_addresses` |
| identity `unresolved` but Mist knows the client | `zone_map` has no entry for the AP, and no `zone_subnets` match |
| `wifi` `partial`, no `ap` | the Mist call budget (6) ran out, a call failed, or the client left (stats 404): see the `mist` puller errors |
| `wan` `partial`, no `wan_util_pct` | the Orchestrator time-series columns were not recognised (raw series is kept) or `maxWanBandwidth` is absent |
| Mist/EC `errors_1h` rising, evidence `error` | `429` (token quota: the connector pauses itself), refused credential (rotate in the manager) or an unreachable API |
| TLS 6514 not listening | `tls.mode = provided` without `syslog_tls.crt/.key`, or `openssl` missing for the self-signed certificate |

Tests: `/home/user/exp/.venv/bin/python -m pytest runner -q` (uses the fakes in `test/fakes`; no network). Lint: `ruff check runner`.
