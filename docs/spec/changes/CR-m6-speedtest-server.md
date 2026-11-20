# CR-m6-speedtest-server — decisions made while building `exp-speedtest` (M6 step s1, WP-10)

**From:** M6 speedtest-server step (s1). **Affects:** the page (s2), the runner (WP-9), the collector (WP-11), the harness / e2e,
packaging, the manager compiler. **Decision:** accepted by the step that wrote it; **binding on later M6 steps**. Additive to
`shared/` (no shared file was changed by this step). Companions: `CR-m6-contracts.md`, `CR-m6-spec-resolutions.md`.

## 1. The view proof is derived with a FIXED sentinel session id (contract defect, resolved)

`01-contracts.md` §14.2 says the page derives `proof = expv_ + b64url(HMAC-SHA256(k, "exp.st.view/1:" + session_id))` and sends
`view_verifier = sha256_hex(proof)` **in `POST /st/api/v1/sessions`**, which is the request that *creates* the session id. The page
cannot know an id the server has not issued yet, and `SessionCreate` has no `session_id` field (`additionalProperties: false`,
pinned by `shared/openapi/test_openapi.py`).

**Resolution (no wire or helper change):** the proof is derived with the fixed sentinel id `st_00000000000000000000000000`
(a valid `st_` + ULID shape, so the unmodified helper accepts it):

```python
SENTINEL = "st_" + "0" * 26
proof    = exp_common.speedtest.view_proof(k, SENTINEL)      # expv_...   (JS: same HMAC, message "exp.st.view/1:" + SENTINEL)
verifier = exp_common.speedtest.view_verifier(proof)         # sent as view_verifier at session creation
```

Every later session route carries `X-Exp-View-Proof: <that proof>`; the share-link shell (`/st/r/{id}#k=...`) derives the same proof
from the fragment key. The box checks `sha256(proof)` against the stored verifier in constant time and does not look at the id in
the HMAC message, so nothing server-side depends on it. Security is unchanged: each test uses a fresh random `k`, hence a fresh
proof and verifier; binding the id into the HMAC added nothing because a verifier is stored per session. The page (s2), the e2e
tests and any tool MUST use the sentinel. `exp_common.speedtest.view_proof(k, real_id)` still works as a function but its output
will NOT verify against a verifier created from the sentinel proof.

## 2. Behaviour the contract left open (all conservative readings)

| # | Topic | Decision |
|---|---|---|
| 1 | `GET /st/down?bytes=N` over the budget | `N` outside `1..100_000_000` or non-numeric -> `400 invalid_request`. `N` larger than the session's **remaining** budget -> `413 budget_exceeded` with `details.remaining` (the page retries smaller). It is **refused, never clamped**, so a `200` always carries exactly `N` octets. The budget counts down + up bytes of the on-network leg and shrinks with the core guard while a test runs. |
| 2 | `POST /st/up` | `Content-Length` required (`411`), no chunked bodies (`501`), reserved against the budget before the first byte is read (`413`), body read and discarded in 1 MiB buffers, `X-Exp-Received` echoes what was read. |
| 3 | Token errors | unknown / malformed / MAC-failing token -> `401 invalid_token`; expired -> `401 token_expired`; valid token from another address -> `403 ip_mismatch`. Repeated failures from one address (60/min) -> `429 rate_limited`. |
| 4 | Concurrency definition | a session is *active* until its result is submitted or its leg token has expired (+5 s grace); the result may still be accepted until `result_deadline_s`. `max_concurrent_per_ip` and `max_concurrent_tests` count active sessions. |
| 5 | Rate limits | `POST sessions`: `429 rate_limited`, `details.limit` one of `tests_per_10min_per_ip`, `max_concurrent_per_ip`, `max_concurrent_tests`, always with `Retry-After`. All other unauthenticated routes: a per-address token bucket (20 req/s, burst 60) with the same 429. The leg endpoints are limited by their token (budget, ping cap 5000/session). |
| 6 | `zone_hint` | unknown zone (or any hint when no zones are configured) -> `400 invalid_request` (`details.field=zone_hint`) on session creation and `invalid_result` on submission; `GET where?z=` ignores an unknown hint (best effort) and `400`s only a malformed slug. A hint never overrides a Mist/subnet answer and never rescues a NAT-suspected address. |
| 7 | NAT guard at the box | `nat_suspected` when `serve.require_real_client_ip` and `serve.client_subnets` is **non-empty** and the observed IP is outside all of them, or the IP is in `serve.translated_addresses`, or the runner's cached answer says so. With no `client_subnets` configured the first condition has nothing to compare against and does not apply. Fails closed: zone `unresolved`, source `unresolved`, flag `nat_suspected`. |
| 8 | DNS leg without arrivals | no registered nonce reached the box's DNS server (no delegation, or the DNS server is down/disabled) -> `legs.dns = {cold_ms: null, warm_ms: null, resolver_ip: null, source: "probe"}` and flag `dns_fallback`; the browser's DNS figures are discarded (they cannot have been a cold lookup through our authority). The collector fills the probe figure (c0). |
| 9 | `dns_cold_split` | an *estimate* available after the result is submitted: `device_to_resolver_ms = warm_ms`, `resolver_to_authority_ms = max(0, cold_ms - warm_ms)`. The box never pings a resolver (a UDP source address is spoofable: SR-22). |
| 10 | `edge1: auto` | TTL-limited ICMP echo toward the fixed constant `1.1.1.1` (never client-chosen; TTL never exceeds edge+1): the hop answering as the configured `edge` is hop N, the sender of hop N+1's time-exceeded is edge+1. Needs `path.edge`; retried every 5 min while unresolved. |
| 11 | ICMP mechanism | unprivileged datagram ICMP socket (needs `net.ipv4.ping_group_range` to include the service gid); fallback argv-only `ping` (`requirements.apt`: iputils-ping); neither -> path legs empty and health `degraded`. No `CAP_NET_RAW` is used or needed. |
| 12 | Core-guard link speed | `/sys/class/net/<iface>/speed`; unknown (virtual NIC) assumes 1 Gb/s, the conservative choice; the per-test cap falls linearly from `bytes_local` (utilization <= `util_pct`) to `min_bytes` (100 %). |
| 13 | Internet leg state at session creation | `unavailable` (disabled), `paused`, `queued` (no free slot or a queue exists), `ok`. `ok` means "a slot is free now"; the page still calls `internet-slot acquire` before Cloudflare. Granted slots live 60 s without a release; queued sessions that stop polling for 15 s lose their place. A configured `enabled=false` overrides whatever a client submits (`legs.internet = {status: unavailable}`). |
| 14 | Result handling | the box overwrites `client.ip`, `site`, `server`, `started` (first leg-token use, else creation), `ended`, `observed.*`, byte counters, `score`, `flags`; non-`ok` legs keep only `status` + `server`; `colo` becomes `server: cloudflare:<COLO>`; `observed.session_ms` is clamped to the schema's 60 000. `counters_disagree` compares the browser's local-leg `bytes` with the box's `down + up` (skipped when the browser sent none). One result per session: `409 already_submitted`; after `result_deadline_s` or a restart of the box: `409 result_deadline_passed`. |
| 15 | Quick diagnosis in `ResultAccepted` | the box forwards synchronously (3 s budget) and returns the collector's quick diagnosis **projected to user-safe fields** (cause ids + confidence + `user_text`; `cites: []`, `noc_text: ""` to satisfy the shared `diagnosis` def). On any failure it returns `diagnosis: null` and the result stays in the spool. |
| 16 | `GET sessions/{id}` after a restart / for share links | the box keeps `view_verifier`, the stored result **without `client.ip`** and the comment in its own SQLite (`/var/lib/exp/speedtest/speedtest.db`, 0600, retention `privacy.retention_days`), so a share link works days later. State/diagnosis/evidence/checks/zone come from the collector (`GET speedtests/{id}/status`, cached 1 s); if the collector is unreachable the view degrades to `state: submitted`, `evidence.state: pending` rather than failing. `network_details` is dropped unless `display.show_network_details`. |
| 17 | Comments | stored verbatim (control characters except `\t\n\r` refused), at most 3 replacements (`409 conflict` after), relayed to the collector through the same durable spool (a `404` from the collector means "result not delivered yet" and is retried for ~2.5 min). The text is never logged. |
| 18 | Spool bounds | 5000 rows / 64 MiB / 7 days. When full the box answers `503 spool_full` (`Retry-After: 30`) to NEW results and un-marks the session so the page may retry; it never drops old rows. Rows are deleted on collector acceptance, so a spooled raw `client.ip` lives only while the collector is unreachable. |
| 19 | Runner channel | `/local/v1/*` on `local_channel.listen` (default `127.0.0.1:8480`): the peer must be exactly `127.0.0.1` (else `403` before any token check); `expl_` bearer vs `runner_channel_token_sha256` (re-read every 10 s, so rotation needs no restart). `PUT pause` honours the runner's `pause` verdict when present, else `wan_util_pct > internet_leg.auto_pause_wan_util_pct`; stale (> 90 s) is ignored. |
| 20 | Peer address | the TCP peer is the client address; `X-Forwarded-For` is never consulted (D15). |
| 21 | CSP | `default-src 'self'; script-src <hashes>; style-src 'self' <hashes>; connect-src 'self' http://*.<dns_zone> [https://*.<dns_zone> when provided] https://speed.cloudflare.com; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. Hashes come from `speedtest/exp_speedtest/static/csp-hashes.json` (`{"schema":"exp.speedtest.csp/1","script":["sha256-..."],"style":["sha256-..."]}`, written by the page build); absent or invalid -> derived from the page's inline blocks. No `unsafe-inline` / `unsafe-eval`. |
| 22 | Assets | `/st/assets/<name>` serves `/etc/exp/speedtest/assets/<name>` (the `logo`, sniffed PNG/JPEG/WebP/SVG) and `speedtest/exp_speedtest/static/assets/<name>` (fonts `.woff2`/`.woff`; **the page step ships them**); never follows symlinks, <= 1 MiB, locked-down CSP + `sandbox`. |
| 23 | Download payload | 32 MiB of `os.urandom` at `<state>/payload.bin`, served with `sendfile` at rotating offsets (a temp file when the state dir is not writable). Over TLS (`provided`) the box uses `pread` + `send` (no kTLS), so the 2 Gb/s figure is a plain-HTTP figure. |
| 24 | Health | `exp.health/1` from `/run/exp/speedtest/status.json` (2 s): `fail` = daemon not running, HTTP listener down, collector `auth_failed` / `tls_pin_mismatch`; `degraded` = collector unreachable (spooling), DNS-leg server or runner channel not bound, no ICMP mechanism, spool > half full. `local_leg_gbps_p95` = p95 of per-second aggregate box throughput (seconds with traffic) over the last hour. |
| 25 | Packaging hooks | `speedtest/systemd/exp-speedtest.service`, `speedtest/requirements.apt`, `speedtest/bin/exp-speedtest`; `packaging/pack.py` `COMPONENTS`, the root `Makefile` `COMPONENTS` and `pyproject.toml` `testpaths` do **not** list `speedtest` yet (not this step's paths): add it. |

## 3. Not done / handed on

* The page itself (s2): `static/index.html` is a placeholder; fonts under `static/assets/` are missing.
* `exp-speedtest` has no `selftest` of the live ICMP path (reported as `icmp backend: dgram|ping|none`).
* The manager compiler (`manager/worker/src/compile/speedtest.ts`) must write the creds named in `config.py`'s docstring
  (`collector_token`, `runner_channel_token_sha256`, `tls.crt`, `tls.key`).
