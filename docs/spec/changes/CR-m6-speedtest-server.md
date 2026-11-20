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
| 25 | Packaging hooks | `speedtest/systemd/exp-speedtest.service`, `speedtest/requirements.apt`, `speedtest/bin/exp-speedtest` follow the other components' layout (`@PREFIX@ @CONFIG@ @CREDS@ @VERSION@` placeholders). The root `Makefile` (`COMPONENTS`, `LINT_DIRS`) and `pyproject.toml` `testpaths` now list `speedtest` (surgical additive edits by this step). `packaging/pack.py` `COMPONENTS` / `PER_ARCH_COMPONENTS` and the vendor lock (`dnspython` is declared for `probe` only: the speedtest needs it too) do **not** list `speedtest` yet; the platform step must add them. |
| 26 | Internet engine in a worker (A6.10) | The vendored Cloudflare engine no longer runs on the page's main thread (its string upload bodies are encoded synchronously by `fetch()`: 770-830 ms main-thread tasks, 35.6 fps in the upload phase). `page/build.py` writes ONE file, `static/assets/cf-engine.js` (~63 KB: `src/engine-prelude.js` + the verbatim library wrapper, library file sha256 4b4ec8c0... asserted by `build.py` (`LIB_SHA256`; the upstream archive hash 08e3c0b4... is pinned in vendor.lock and `test_vendored_files_match_vendor_lock`) + `src/engine-bridge.js`); the library is no longer inlined in `index.html` (one inline script left: `app.js`). In a `DedicatedWorkerGlobalScope` the prelude sets `self.window = self` (the library only reads `window.location.origin`; it touches no `document`/`localStorage`) and the bridge answers `{cmd:"start", config}` / `{cmd:"pause"}` with `started`, `phase`, `results`, `error`, `running`, `finish`, `fatal` messages carrying plain snapshots (bandwidth/latency points with bps, bytes, duration, transferSize, ping; down/up/idle/jitter/loaded latencies). On the main thread the file only exposes `window.CFSpeedTest`. `app.js` `EngineHost` has the engine's callback/play/pause/results surface; **fallback**: `new Worker` throws, the worker errors or says nothing for 6 s after start -> the same file is loaded as a classic `<script src>` and the engine runs on the main thread as before. `logAimApiUrl`/`logMeasurementApiUrl` stay null and the internet plan stays latency/download/upload. Served via `/st/assets/cf-engine.js` (only from the packaged `static/assets/`, never the operator's assets dir), `Content-Type: text/javascript; charset=utf-8`, `nosniff`, `Cache-Control: public, max-age=300` like the other assets, and **its own CSP** (CSP3: a dedicated worker takes its policy from its script response, not the page): `default-src 'none'; <the page's connect-src>; frame-ancestors 'none'` (`StaticSite.worker_csp`, built from the same inputs as `build_csp`). **Page CSP change**: `worker-src 'self'` (never `blob:`/`data:`) and `script-src <hashes> 'self'`; `'self'` is needed ONLY for the same-origin engine file (worker start, and the main-thread fallback `<script src>`); no `unsafe-inline`/`unsafe-eval`. `build.py --out DIR` now also writes `assets/cf-engine.js` (reproducible; the packaging hook overlays the whole tree). Page weight counts the worker file (HTML + engine, gzip -9, + fonts <= 200 KB). Tests: `test_page_browser.py::test_full_test_390` (a worker with that URL ran; internet cv < 0.3, stability >= 40) and `::test_full_test_without_workers_falls_back_to_the_main_thread` (init script deletes `window.Worker`; complete result, comparable figures), `test_page_build.py` (verbatim-once library, worker CSP exact, host/URL-template checks cover the engine file). *(Follow-up 2026-11-20 at the end of this file: switched-off internet leg on the results page, engine-host robustness, worker-path proof, A6.10 weight.)* |

## 3. Not done / handed on

* The page itself (s2): `static/index.html` is a placeholder; fonts under `static/assets/` are missing.
* `exp-speedtest` has no `selftest` of the live ICMP path (reported as `icmp backend: dgram|ping|none`).
* The manager compiler (`manager/worker/src/compile/speedtest.ts`) must write the creds named in `config.py`'s docstring
  (`collector_token`, `runner_channel_token_sha256`, `tls.crt`, `tls.key`).

## Item 26 follow-up (2026-11-20): switched-off internet leg, engine-host robustness, worker-path proof, A6.10 weight

* **Switched-off internet leg on the results page** (`page/src/app.js`). The verdict said "Online apps and calls will not work
  until the internet is back." for every internet leg with status `unavailable`, including a leg the operator switched off
  (`internet_leg.enabled=false`), so every attendee at such a site was told there was an outage while the notice on the same
  screen said "The internet part of the test is not available at this event.". The page now treats the leg as **off** when the
  result's flags carry `internet_off` (the box sets it instead of `internet_unavailable`: `CR-m6-contracts.md` follow-up
  2026-11-20) **or** the public config says `internet_leg.enabled === false` (the live run's result is shown from what the page
  measured; results stored before the flag existed). Per state of the internet leg:
  * off: the venue-network verdict + "The internet part is not tested at this event."; flag note "The internet part is not
    tested at this event." **instead of** (never in addition to) "The internet part of the test was not available.";
  * `unavailable` and not off (an outage, e.g. Cloudflare unreachable): unchanged, "... Online apps and calls will not work
    until the internet is back.";
  * `paused` / `queued` / `skipped`: unchanged, "... The internet part was not measured this time.";
  * "Good for" stays "(not checked)" for all four in each of these states. An `ok` leg is judged as before even when the config
    is off now (a share link of an older measured result); a result without `legs.internet` that is not off keeps its previous
    verdict (judged on the leg shown). Absent `flags` / `legs.internet` (older stored results) never throw.
  * The share link (`/st/r/{id}#k=...`) loads the public config before the stored result, so both inputs exist there too.
    Consequence: while the leg is switched off, a result stored before `internet_off` existed (it carries
    `internet_unavailable`) reads "not tested at this event" on the page, and so does a genuine-outage result viewed after the
    operator switched the leg off (no false outage message; the collector and the dashboard read the stored flags as given).
* **Engine-host robustness** (`app.js` `EngineHost`, `page/src/engine-bridge.js`). Every end of the worker leg is terminal: after
  `started`, a worker `error` event or a `fatal` message once a snapshot exists ends the leg once (`onError` + `onFinish`),
  terminates the worker and ignores every later message, error event and engine callback. Before: an error after `started` ended
  the leg but left the worker running (fetching) and its later messages still drove the UI; `fatal` after a snapshot only
  counted an error and the leg waited for a `finish`. `fatal` before any snapshot (or before `started`) falls back to the main
  thread as before. The fallback's re-entry guard is set at its start (before: only once the classic script had loaded, so two
  triggers could insert two scripts and start two main-thread engines). The worker is also terminated after `finish`. The bridge
  posts `fatal` (no longer `error`) when `engine.play()` throws while the engine is not running (`isRunning` false), `error`
  when it is; on the main thread a throwing `play()` ends the leg (`onError` + finish) when the engine is not running and counts
  an error when it is. Message validation is unchanged (`num()` snapshots, `textContent` only).
* **Tests** (`speedtest/tests/test_page_browser.py`, `tests/ui/page_scenarios.js`). `test_full_test_390` now proves the worker
  path rather than only "a worker with that URL was created": no `<script src>` element is in the DOM after the run (every
  fallback path inserts `/st/assets/cf-engine.js` as one) and the engine's first phase came < 4 s after the internet leg started
  (measured ~60 ms; a silent worker is replaced after 6 s). `test_full_test_without_workers_falls_back_to_the_main_thread` asserts
  the opposite (exactly one such element). `test_internet_disabled_in_config` asserts the "not tested at this event" verdict and
  flag note, "(not checked)" and no "until the internet is back", on the live result and on the share link;
  `test_cloudflare_unreachable_is_unavailable_not_a_failure` keeps the outage sentence and now also asserts a single "not
  available" note. New `test_engine_worker_misbehaving_ends_the_leg_or_falls_back_once[error_after_start|fatal_after_snapshot|
  fatal_before_snapshot]`: a scripted stand-in `Worker` installed by the scenario's init script (no product hook) whose late
  events still reach the page's handlers; all three fail against the previous code.
* **A6.10 weight gate** (`test/e2e/m6/test_a610_page_quality.py`). The gate gzipped the page's files from the load-time network
  snapshot (taken before Go), which no longer contains the engine (fetched when the internet leg starts), so it measured HTML +
  fonts only, not HTML + engine + fonts as this item says. It now adds `http://<box>/st/assets/cf-engine.js` (asserted to have
  been requested during the run) and gzips it from the phone's namespace like the other files. Build figures today: HTML 28.6 KB
  + engine 15.3 KB (gzip -9) + fonts 102.6 KB = 146.6 KB <= 200 KB.
* **References corrected.** `app.js`, `engine-prelude.js` and the A6.10 docstring cited "item 9" for the worker engine (item 9 is
  `dns_cold_split`): now item 26. The `packaging/vendor.lock` note for `@cloudflare/speedtest` said `build.py` wraps the library
  "inside the single self-contained page"; it now names the separate engine file `assets/cf-engine.js` (note text only, no hash
  changed).
