# test/fakes — fakes for building against the contracts (WP-0, M6 additions)

Three stdlib-only servers (Python 3.10+, `http.server`, `ssl`). Each is a script **and** an importable module
(`start()` returns a running server, `.port` is the bound port, `.stop()` shuts it down). All bind `127.0.0.1`
by default and never touch a real network. They enforce the contracts for real (auth, validation, limits) so a
client that passes against them has met the spec; they are not production code and keep state in memory.

| Fake | For | Contract | Script |
|---|---|---|---|
| `fake_collector.py` | WP-1 probe, WP-3 dashboard | `shared/openapi/ingest.yaml`, `collector.yaml` | `python test/fakes/fake_collector.py` |
| `fake_manager.py` | WP-6 agent | `shared/openapi/agent.yaml` | `python test/fakes/fake_manager.py` |
| `mock_admin/server.py` | WP-5 manager UI | `shared/openapi/admin.yaml` | `python test/fakes/mock_admin/server.py` |
| `fake_st_collector.py` | WP-9 runner, WP-10 speedtest | `collector.yaml` (`speedtests`) | `python test/fakes/fake_st_collector.py` |
| `mist/server.py` | WP-9 runner (Mist connector) | Mist OpenAPI 3.1 (mistapi 0.64.1) | `python test/fakes/mist/server.py` |
| `orchestrator/server.py` | WP-9 runner (EdgeConnect connector) | pyedgeconnect 0.16.0a1 | `python test/fakes/orchestrator/server.py` |
| `cloudflare_speed/server.py` | WP-10 speedtest page / harness | `test/fixtures/cloudflare/recording-*.json` | `python test/fakes/cloudflare_speed/server.py` |
| `syslog_sender.py` | WP-9 runner (syslog listener) | RFC 5424/3164/5425/6587, CEF, LEEF, dhcpd, Kea, Windows DHCP | `python test/fakes/syslog_sender.py --to udp://127.0.0.1:5514` |
| `fake_ca.py` | the HTTPS fakes above | (helper) | runtime throwaway CA via the `openssl` CLI |

Use the project venv for tests (`/home/user/exp/.venv/bin/python`); the fakes themselves need only the stdlib
plus `shared/python/exp_common` (they add it to `sys.path` themselves).

```
.venv/bin/python -m pytest test/fakes -q        # the fakes' own tests (also validate every response body
                                                #   against the OpenAPI files with jsonschema + PyYAML)
.venv/bin/ruff check test/fakes
```

## Using a fake from another WP's tests

```python
import sys
sys.path.insert(0, "/home/user/exp/test/fakes")          # or compute it relative to your test file
import fake_collector, fake_manager
from mock_admin import server as mock_admin

fake = fake_collector.start(keepalive_s=0.2)              # port 0 -> ephemeral
try:
    url = f"http://127.0.0.1:{fake.port}"
    ...
finally:
    fake.stop()
```

Every `start()` accepts `host=`, `port=`, `tls=` and an injectable clock (`now_fn=lambda: epoch_seconds`) so tests
can cross time windows (ingest `ts_future`, the 5-minute SSE replay window, enrol-token expiry, the rotation
grace) without sleeping. `fake.app` is the in-memory application object for direct inspection.

Deterministic fake tokens are `prefix + base64url(sha256("fixture:<name>"))` (`fakes_common.fixture_token`,
`fakes_common.token_hash`). They are obviously fake and match the real formats.

## fake_collector

```
python test/fakes/fake_collector.py --listen 127.0.0.1:8443 --tls --state-dir /tmp/fc [--scenario dns-fail]
    [--ingest-tokens FILE] [--dashboard-tokens FILE] [--config collector.json] [--site hall-b]
    [--keepalive-s 15] [--force 429|503] [-v]
```

* Startup prints the listen URL, with `--tls` the self-signed certificate fingerprint as `AB:CD:...` (SHA-256 of
  the leaf, ready to paste into a probe's `tls_fingerprint_sha256`), and the default fake tokens
  (probe `probe-a1` ingest token, dashboard `dash-main` token) unless you pass token files.
* Token files are `{"<id>": "<sha256 hex of the token>"}` exactly like the collector's `ingest_tokens.json` and
  `dashboard_tokens.json`. In-process: `start(ingest_tokens={...}, dashboard_tokens={...})`.
* Ingest `POST /ingest/v1/measurements`: bearer `expi_`, `application/x-ndjson` (415 otherwise), optional gzip,
  <= 1000 lines (400 `too_many_lines`), <= 4 MiB wire (413), <= 16 MiB decompressed (413, reading stops),
  <= 64 KiB/line (`line_too_long`), `Measurement.from_dict(require_id=True)` per line (reserved labels, naive
  `ts`, bad ULID...), identity binding (`probe` = token identity, `site` = configured site, per-probe via
  `probe_sites=` or `--config`), `ts_future` (> 60 s ahead), `ts_too_old` (> `retention_days`, default 7),
  dedupe on `(probe,id)`. Result is the documented `{accepted,duplicates,rejected[],server_time}`.
* Backoff tests: `fake.app.set_force(429, retry_after=7, count=2)` (or 503; `scope="ingest|api|all"`), or at
  runtime `POST /_fake/force {"status":503,"count":3}` (loopback only).
* Query API `/api/v1/*` (bearer `expd_`; `/drills/control` takes an `expi_` token): `health`, `probes`, `state`,
  `states` (trivial rule: latest beat per line, `ok|warn|fail|unknown`; or `--scenario` fixture for probes with
  no data), `beats` (ingested data + the `beats/beats.json` fixture; > 6 h -> 400 `range_too_large`), `records`
  (filters + opaque cursor), `incidents` (fixtures + a derived incident when a line fails, closed when it
  recovers), `incidents/{id}/ack`, `summary` (canned), `query_range` (canned matrix; guards: only `exp_*`
  metrics, <= 2 KiB, <= 30 d, step >= 10 s, <= 500 series), `drills/*`, `GET /healthz` (no auth, `ok`).
* `GET /api/v1/stream?probes=a,b` or `?site=x`: SSE `beat` / `state` / `incident`, `retry: 3000` first,
  `: keepalive` every `keepalive_s` (15 by default), `Last-Event-ID` replays at most 5 minutes. Event ids are
  monotonic integers.
* `/_fake/` (loopback only): `GET stats`, `GET records?probe=`, `POST force|incident|state|abort|drill_report`.
* `--state-dir` also persists accepted records to `records.ndjson` and reloads them on start.

## fake_manager

```
python test/fakes/fake_manager.py --listen 127.0.0.1:8080 [--tls] [--state-dir DIR] [--scenario default|empty]
    [--install-sh FILE] [--enrol-rate 10] [-v]
```

* `--scenario default` (the CLI default) builds release `0.1.0` (small deterministic tarballs, manifest signed
  with a real Ed25519 key generated by the `openssl` CLI under `<state-dir>/release-key/`), one enrolled host
  (`srv-02`, fake agent secret) with the `probe-host` desired fixture, and one pending host with an enrol token.
  Their ids and fake credentials are printed at startup. `enrol` returns the matching `release_pubkey_pem`, so the
  agent can verify with `openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in manifest -sigfile sig.bin`.
* Agent API `/api/agent/v1/*` as in `agent.yaml`: `enrol` (per-IP rate limit 10/min -> 429, 401 unknown, 410
  used/expired, single use is atomic under concurrency, 400 on schema failure and the token is then *not*
  consumed), `desired` (`ETag: "<host_id>:<version>"`, `If-None-Match` -> 304), release `manifest` (exact bytes) and
  `manifest.sig`, `artifacts/{id}` (403 unless referenced by this host's current desired state; `Content-Length`;
  `ETag` = quoted sha256), `status` (<= 256 KiB, validated against `exp.status/1`), `rotate` (409 unless desired
  carries `rotate_agent_secret`; the old secret stays valid 600 s; the action is consumed and the version bumps),
  `decommissioned` (409 unless `decommission: true`; revokes every secret of the host).
* `GET /install.sh` serves a placeholder (or `--install-sh FILE`); `GET /healthz`.
* Scenario files in `--state-dir` (optional): `hosts.json` (`[{"name","site","enrolled","agent_secret","desired":
  "<fixture name>"}]`), `desired/<host_id>.json`, `releases/<version>/manifest.json[ + manifest.sig]`,
  `artifacts/<art_id>`.
* Control API `/_fake/` (loopback only, can be disabled with `control=False`): `POST hosts`, `POST enrol-token
  {"host_id","ttl_s"}` (negative ttl = already expired), `PUT desired/<host_id>` (`{"fixture":"rotate"}` or
  `{"doc":{...}}`), `GET status/<host_id>` (received reports), `GET hosts`, `POST release {"version"}`,
  `POST force {"status":503|500|429,"count":N,"retry_after":S}` or `{"unreachable":true,"count":1}` (the connection
  is closed without an answer). In-process the same operations are methods on `fake.app`.
* Fixture-based desired docs are rewritten so their artifact id/sha256/size point at bytes the fake can serve
  (`set_desired(..., synthesize=True)`), keeping the agent's hash checks honest.

## mock_admin

```
python test/fakes/mock_admin/server.py --listen 127.0.0.1:8787 [--no-auth] [--tls --state-dir DIR] [--enrol-delay-s 10 | --no-enrol-sim]
```

Serves `admin.yaml` under `/api/admin/v1/*` from deterministic in-memory state (`seed.py`): org "HPE Event NOC",
sites `hall-b`/`hall-c`/`keynote`, 24 hosts (17 enrolled, 3 stale, 2 offline, 2 pending) with realistic facts (each
enrolled host has exactly one `mgmt` default-route interface), 26 components of every type with health and
valid rendered configs, status reports, 26 issues across all 20 issue kinds (open / resolved / snoozed),
releases 0.1.0 and 0.1.1 (0.2.0 is importable), 48 audit events, dashboard users / NOC tokens (no secrets),
settings and fleet thresholds. Metrics are computed on demand: 5-minute steps (1h/6h/24h ranges) and 1-hour steps
(7d/30d), stale and offline hosts go `null` after their last report.

* Vite dev: proxy `/api/admin` to `http://127.0.0.1:8787`, or call it cross-origin from `http://localhost:5173`
  (the only origin that gets CORS headers; preflight for others is 403).
* Access simulation: every request needs a `Cf-Access-Jwt-Assertion` header (any non-empty value; it is **not**
  verified) unless `--no-auth`. The caller is `owner@example.com`, role `owner` (`GET /me`).
  Dev-only aids: `X-Mock-Role: viewer|operator|admin|owner`, `X-Mock-Email: someone@example.com` (for example to
  test the drill two-person rule), `X-Mock-Force: 429|500|503` to see error states.
* Add-host wizard: `POST /hosts` (or `POST /hosts/{id}/enrol-token`) returns a fake `expe_` token and the
  `curl ... | sudo bash -s -- <token>` command; the host turns `enrolled` with facts `--enrol-delay-s` (10) seconds
  later, so the "waiting for host" step can be exercised. Decommission completes after 20 s; a canary rollout
  promotes after 30 s.
* Enforced like the real thing: request bodies are validated against the `admin.yaml` schemas (generated into
  `mock_admin/admin_schemas.json`; run `python test/fakes/mock_admin/gen_admin_schemas.py` after the contract
  changes, a test fails if it is stale), roles per `x-exp-min-role` (403 `insufficient_role`), `PUT
  /components/{id}/ports` refuses the management interface (422 `mgmt_interface_refused`), unknown interfaces,
  duplicate ports; one audit event per successful mutation and never a secret value; fleet endpoints set
  `ETag` + `Cache-Control: private, max-age=15` and answer 304 to `If-None-Match` (the snapshot rolls every 15 s
  and on any mutation).
* Not simulated: Cloudflare JWT verification, real token/password storage, GitHub release import (a fixed
  catalogue `0.1.0`, `0.1.1`, `0.2.0`; `POST /releases/upload` checks the manifest and artifact hashes and the
  signature *format* only), real webhook delivery (tests always succeed).


---------------------------------------------------------------------------------------------------------------------------

# M6 fakes (speedtest analytics)

Common to all of them: stdlib only (the st collector also uses `jsonschema` when the test venv has it), `start()` returns a running server
(`.port`, `.app`, `.stop()`), injectable clock (`now_fn=`), a loopback-only `/_fake/` control API plus in-process methods, deterministic
scenarios. **No key, token or certificate is committed**: tokens are derived at runtime from `fixture:<name>` strings
(`fakes_common.fixture_token`, `mist.server.default_token()`, `orchestrator.server.default_credentials()`), and HTTPS uses a CA generated at
runtime (`fake_ca.make_server_tls(tmp_path)` -> `(ca, leaf)`; `start(tls=(leaf.cert_chain, leaf.key))`; clients verify with
`fake_ca.client_context(ca)`), so gitleaks has nothing to find. Vendor field names come only from the local, verified, MIT-licensed
references named per fake (dev-time references, never imported); where a reference is silent the fake says so (below) instead of
guessing, and a vendor-facing parser must not treat such a value as ground truth.

## fake_st_collector (speedtest box and runner against the collector)

`start(tokens=..., now_fn=..., scrub_after_diagnosis=False, window_before_s=300, window_after_s=120, device_key_secret=None)`;
`default_tokens()` gives `{family: {identity: {token, sha256, site}}}` for `speedtest` (`spd-core`, site `hall-b`, `exps_`),
`runner` (`runner-core`, `hall-b`, `expr_`) and `dashboard` (`dash-main`, `expd_`). Routes, tokens and error codes are the table in the module
docstring; in short: ingest (identity binding 403 `identity_mismatch`, idempotent, schema-validated), user-safe status (404 for other speedtests),
comment, the runner **feed** (poll, `after` cursor, `limit`, long-poll `wait_s` <= 25), **evidence** POST (`exp.evidence/1`, `id_mismatch`,
`evidence_final`, 413 `evidence_too_large` at 256 KiB/test, replace-on-repost), `evidence/complete` (final diagnosis, `already_final`, optional
privacy scrub that drops raw ip/mac/hostname/username and keeps `device_key` and the zone), **baseline** read, the dashboard list/detail/purge,
and the **SSE stream** (`speedtest`, `evidence`, `diagnosis`; `retry: 3000`, `: keepalive`, 300 s `Last-Event-ID` replay).
A token of the wrong family is unknown on a route (401), so "an `exps_` token cannot post evidence" is testable. `app.set_force(503|429, count,
retry_after)` or `POST /_fake/force` drives backoff tests; `app.set_baseline(data|None)`; `POST /_fake/window` changes the correlation window.
The **final diagnosis is a stand-in** with a few obvious rules (WP-11 owns the real rule engine); tests of the real engine must not use this fake.

## mist (Juniper Mist)

`start(token=None, tls=None, now_fn=..., rate_limit=5000)`; `fake.token`, `fake.state` (`MistState`), `fake.app.calls_to("clients/search")`
(per-test API budget assertions), `fake.app.set_rate_limit(n)`, `fake.app.set_force(status, count)`. Routes and operationIds are the table in
the module docstring (searchSiteWirelessClients / searchOrgWirelessClients with `ip` + `start`/`end`/`duration`, getSiteWirelessClientStats,
listSiteWirelessClientsStats, getSiteDeviceStats `radio_stat` util/channel/num_clients, searchSiteWiredClients, searchSiteSwOrGwPorts,
searchSiteWirelessClientEvents, listClientEventsDefinitions). `Authorization: Token <t>`; 401 otherwise; 429 with the OAS's documented
"5000 API Calls per hour" detail over a rolling hour (no `Retry-After`: the OAS documents none); pagination with `limit` / `search_after` /
`next`; wildcard filters (`prefix*`, `*sub*`); MACs are 12 hex digits. Scenarios: `healthy`, `weak_rssi`, `congested_ap`, `roaming`,
`wired_port_errors`, `nat_ambiguity` (two MACs on one IP), `no_client`; `fake.state.load_scenario(name, at=T, ip=..., mac=...)` or
`POST /_fake/scenario`. **Gaps stated in the OAS itself:** `events_client` has no client MAC and the event search has no MAC filter, so events
are AP/SSID/band/time scoped only; only two event type keys are OAS-documented (the others are fake-chosen and must be discovered through
`/const/client_events`). The test `test_mist.py` validates every response against the OAS schemas when the OAS file is present
(`EXP_MIST_OAS`, default: the session's vendor-src copy; skipped otherwise).

## orchestrator (HPE EdgeConnect Orchestrator)

`start(release="9.3.4", tls=None, now_fn=...)`; `fake.api_key`, `fake.user` (`(user, password)`), `fake.state` (`OrchState`),
`fake.app.interface_columns`, `fake.app.health_shape`, `fake.app.session_ttl_s`, `fake.app.expire_sessions()`. Auth as pyedgeconnect does it:
`X-Auth-Token: <key>`, or `POST /authentication/login` (`orchCsrfToken` cookie, then `X-XSRF-TOKEN` + the session cookie; the session cookie's
name is not in pyedgeconnect, the fake uses `fake_orch_session`). Endpoints (both the >= 9.3 query form and the older path form): appliance list,
`get_appliance_flows` (the 63-element positional rows with every index of the docstring; filters ip1/ip2/mask/port/application/protocol/vlan/filter,
`anyStartTime`/`termStartTime` epoch ms), `interfaceState`, `stats/timeseries/interface` and `trafficClass`, `health/{latency,loss,jitter,mos}PeriodSummary`,
`POST /alarm/appliance`. **Not documented by pyedgeconnect, so fake-chosen and flagged:** the time-series column names (a parser must read `COLUMN_DEF`;
`interface_columns` can be reordered to prove it), the `DATA` envelope, the health summary being a dict vs a list per tunnel, the session cookie name, and
the meaning of `ipEitherFlag` (the fake follows the docstring). Scenarios: `healthy`, `saturated_wan` (92.5 % of `maxWanBandwidth`), `qos_shaped`
(class 7 + shaper drops), `loss` (3.5 % + critical alarm), `firewall_drop` (ZBF drop, `drop_reason` 1); `POST /_fake/wan_load` changes WAN load over
time for auto-pause tests. HPE Aruba SSE has no fake: no local vendor documentation exists, the connector reports "unavailable" (CR-m6-spec-resolutions).

## cloudflare_speed (speed.cloudflare.com)

Built from `test/fixtures/cloudflare/recording-*.json` (newest by name). `__down?bytes=`, `__up`, `/cdn-cgi/trace` (with a `colo=` line), `OPTIONS`
preflights; **response header names, order and case, and every static value equal the recording's** (two `Server-Timing` lines, lowercase
`access-control-expose-headers`, `Timing-Allow-Origin`, ...); per-request values are generated (`Date`, `CF-RAY`, `cf-meta-request-time`,
`cf-meta-upload-bytes`, the `cfSpeedEdge`/`cfSpeedWorker`/`cfL4` figures), and the recording sandbox's real egress IP/city/coordinates are never replayed
(documentation values under the same names). Faithful to the recorded quirks: `colo` is not exposed and `cf-meta-colo` is absent on `__down`
(only `__up` has it), the trace has no `Timing-Allow-Origin`. Knobs (`fake.app.set(...)` or `POST /_fake/set`): `latency_ms`, `loaded_latency_ms` (requests
with `during=`), `down_bps`, `up_bps`, `fail` (`reset` | `http500` | `stall` | `slow_headers`), `fail_after_bytes` (cut mid-body), `colo`, `loc`,
`server_edge_ms`, `server_worker_ms`; `fake.app.kill()` / `heal()` and `POST /_fake/kill|heal`. `test_cloudflare_speed.py` asserts the headers against the recording,
so a re-recording shows up as a test diff.

## syslog_sender

Generators: `rfc5424_message` (structured data + escapes), `rfc3164_message`, `cef`, `leef` (1.0 / 2.0), `kv`, `ec_firewall` (**representative only**: no local
vendor documentation of the EdgeConnect firewall / zone-policy log text exists, nor for SSE; pyedgeconnect documents only the syslog *configuration*),
`dhcp_isc`, `dhcp_kea`, `dhcp_windows` (+ `WINDOWS_DHCP_HEADER`). Formats from the public RFCs / ArcSight CEF / IBM LEEF / dhcpd / Kea / Microsoft documentation as known,
not from local files (the module docstring cites each). Transports: `send_udp`, `send_tcp` (octet-counting or newline framing), `send_tls` (verifying;
`ca=`), `send(url, msgs)`. `Receiver(tls=(cert, key))` is a loopback UDP/TCP/TLS capture server (`.udp_port`, `.tcp_port`, `.tls_port`, `.wait_for(n)`) and
`parse_stream` is the framing parser, so the sender and the listener contract are both exercised.
