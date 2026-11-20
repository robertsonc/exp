# exp-speedtest

The **speedtest box** (M6, WP-10): one `exp-speedtest` process at the venue core / DC that serves the branded speedtest page, the
session API and the on-network leg, runs the DNS-leg authoritative server and the core -> edge path timer, validates what the
page reports, and forwards `exp.speedtest/1` results to the collector on the same host. It is one of four components of the
*all-in-one* profile (probe + collector + runner + speedtest); attendee VLANs reach it **routed and un-NAT'd** (D15).

Specs: `docs/spec/12-speedtest-analytics.md`, `docs/spec/01-contracts.md` section 14, `docs/spec/changes/CR-m6-*.md`
(especially `CR-m6-speedtest-server.md`, the decisions of this component). Contracts: `shared/openapi/speedtest.yaml`,
`shared/schemas/speedtest*.json`, `shared/python/exp_common/speedtest.py`.

```
page ──HTTP──▶ exp-speedtest ──exps_──▶ collector ◀──expr_── runner
 (browser)        ▲  └─ DNS-leg authority (UDP/TCP 53)          │
                  └──── expl_, 127.0.0.1:8480 ──── runner ──────┘   (Mist "where" cache, EC WAN utilization)
```

## Run

```
exp-speedtest run            [--config /etc/exp/speedtest/config.json]
exp-speedtest health [--json]               # exp.health/1; exit 0 = ok|degraded, 1 = fail
exp-speedtest version
exp-speedtest pause-internet --on | --off   # the admin switch, effective within ~1 s, survives nothing but the state file
exp-speedtest selftest                      # offline checks; prints the ICMP mechanism found
```

Stand-alone (no manager) works exactly like a managed host: a local config plus a credentials directory.

```
exp-speedtest run --config ./config.json --creds-dir ./creds --state-dir ./state --run-dir ./run --assets-dir ./assets
```

| Path | Contents |
|---|---|
| `/etc/exp/speedtest/config.json` | `exp.speedtest.config/1` (no secrets); minimal example: `test/fixtures/configs/speedtest.minimal.json` |
| `/etc/exp/speedtest/assets/logo` | branding logo (PNG/JPEG/WebP/SVG, <= 1 MiB), installed by the agent from the desired state |
| `$CREDENTIALS_DIRECTORY/collector_token` | `exps_` token for the collector (read again for every delivery) |
| `$CREDENTIALS_DIRECTORY/runner_channel_token_sha256` | sha256 hex of the runner's `expl_` token (re-read every 10 s) |
| `$CREDENTIALS_DIRECTORY/tls.crt`, `tls.key` | only when `tls.mode = provided` |
| `/var/lib/exp/speedtest/` | `speedtest.db` (0600: session verifiers, stored results without `client.ip`, comments, the delivery spool), `payload.bin` (32 MiB of random bytes for `/st/down`), `runtime.json` (the manual pause switch) |
| `/run/exp/speedtest/status.json` | counters and listener state written every 2 s, read by `health` |

## What it listens on

| Listener | Where | Notes |
|---|---|---|
| page + API + on-network leg | `serve.listen_ip` TCP **80** (`tls.mode = none`, default) or **443** (`provided`) | `serve.port` overrides for tests/dev |
| 80 -> 443 redirect | `serve.listen_ip` TCP 80, only when `tls.mode = provided` | `Location` uses `serve.hostname`, never the `Host` header |
| DNS-leg authority | `serve.listen_ip` UDP + TCP **53** (`dns_leg.port` for tests) | answers only `dns_leg.zone`; the box's own resolver is untouched |
| runner channel | `127.0.0.1:8480` (`local_channel.listen`, loopback only) | peer must be exactly 127.0.0.1, `expl_` bearer |

The unit grants `CAP_NET_BIND_SERVICE` only. If port 53 cannot be bound the box keeps serving, reports `degraded`, and the page
falls back to the probe's DNS figure; if the HTTP port cannot be bound it exits.

## The test, as the box sees it

1. `POST /st/api/v1/sessions` (consent version, optional `zone_hint`, `view_verifier`) -> session id, a 60 s **leg token**
   (`expt_`, HMAC-signed with a per-process key, bound to the session and the observed client address, byte budget), limits,
   three DNS nonces, the internet-leg state. 6 tests / 10 min / address, 1 concurrent / address, 20 concurrent / box, else `429` +
   `Retry-After`.
2. On-network leg with the leg token: `GET /st/ping`, `GET /st/down?bytes=N` (`sendfile` from the payload file, budgeted),
   `POST /st/up` (read and discard in 1 MiB buffers, counted). Per-session counters feed the browser-vs-box cross-check
   (`counters_disagree` above 20 %). The per-test budget (default 200 MB, down + up) shrinks while `core_guard.iface` is busy.
3. Internet leg: `POST .../internet-slot` (FIFO, `max_concurrent_internet` slots), paused by the admin switch, by
   `internet_leg.paused`, or by the runner's WAN utilization (a value older than 90 s is ignored: fail open).
4. DNS leg: the page resolves `<nonce>.<dns_zone>` through the device's own resolver; the box's DNS server records the first
   arrival and the resolver address per nonce; `GET http://<nonce>.<zone>/st/px` is the timing target (`204`,
   `Timing-Allow-Origin: *`). No arrival -> `dns.source = probe` + `dns_fallback`.
5. `GET .../path` (or SSE): gateway / edge / edge+1 idle and loaded RTT from the box, `edge1_addr`, `resolver_seen`, and the ICMP
   RTT box -> **this client only**. Targets are the configured hops and live session clients; nothing a client sends can
   choose one (SR-22, enforced and tested).
6. `POST .../result` (once, from the session's address, within `result_deadline_s`): the box validates
   `exp.speedtest.submission/1`, **overwrites** `client.ip`, `site`, `server`, timestamps and byte counters, recomputes the score
   (`exp_common.speedtest.compute_score`), fills the DNS and path legs, sets the flags, writes the result to the on-disk spool and
   forwards it (idempotent by id; backoff 1 s -> 60 s; a collector outage or restart loses nothing).
7. `GET .../sessions/{id}`: the user-safe view (quick/final diagnosis as cause ids + plain text, evidence progress, "what the
   network team sees" checks), read from the collector; `X-Exp-View-Proof` only (see below). `POST .../comment` (<= 500 chars,
   stored verbatim as text, never logged).

**View proof.** The fragment key `k` never reaches the box. The page sends `view_verifier = sha256(proof)` at creation and
`X-Exp-View-Proof: proof` afterwards, with `proof = view_proof(k, "st_" + "0" * 26)` -- the fixed sentinel id, because the
real id does not exist when the verifier is sent (`CR-m6-speedtest-server.md` item 1). Wrong or missing proof and unknown id
are the same `404`.

## Security posture (SR-21/22/23/26)

Strict HTTP/1.1 parser (request line 8 KiB, head 16 KiB and 64 headers, 10 s head deadline, no chunked bodies, origin-form
targets only), at most 512 connections (48 per address), a per-address request budget, bad-token throttling, bounded JSON
bodies with duplicate keys refused, no directory listing (assets are a name lookup, never a path), `Content-Security-Policy`
with script/style **hashes** from the page build (`static/csp-hashes.json`; no `unsafe-inline`/`unsafe-eval`),
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`. The TCP peer is the client address;
`X-Forwarded-For` is never consulted. The DNS-leg server never recurses (`RA = 0`), refuses everything outside its zone and all
zone transfers, rate-limits per source and drops (never answers) malformed packets and responses. Secrets and comment text never
reach a log line (`exp_common.log` also redacts every token prefix). Plain HTTP is the default (D15): the page carries no user
credentials, the leg token is 60 s / single session / byte-budgeted, results are bound to the observed address.

## Path timer: ICMP without `CAP_NET_RAW`

Unprivileged datagram ICMP sockets need the service's group in `net.ipv4.ping_group_range`:

```
sysctl -w net.ipv4.ping_group_range="0 2147483647"     # or the gid of exp-speedtest only
```

Without it the box falls back to the system `ping` run with an argv list (`requirements.apt`: `iputils-ping`); with neither,
the path legs are empty and `health` says `degraded`. `edge1: auto` traces toward `1.1.1.1` with TTL <= edge+1 (see the CR).

## DNS delegation

Delegate the DNS-leg zone to the box: `t.speed.<event-domain>. NS ns.t.speed.<event-domain>.` plus the glue
`ns.t.speed.<event-domain>. A <serve.listen_ip>`; the box answers the glue itself. No certificate is needed over plain HTTP.
Without the delegation the DNS leg reports `probe` / `dns_fallback`.

## Performance (A6.2)

`pytest speedtest -m bench` (server as its own process, 4 parallel keep-alive streams of `GET /st/down?bytes=25000000` over
loopback, 6 s, this 4-core container; server CPU from `/proc/<pid>/stat`):

| Measure | Result | Requirement |
|---|---|---|
| aggregate download | **25 - 46 Gb/s** across three runs (25.2, 46.1, 40.9) | >= 2 Gb/s |
| server CPU | **0.85 - 1.46 cores**, i.e. **~0.03 cores per Gb/s** | <= 1 core per Gb/s |
| server counters vs client totals | **0.0 %** difference (identical byte totals, 19 - 35 GB moved per run) | within 5 % |

These are loopback figures with `sendfile`; over TLS (`tls.mode = provided`) the box uses `pread` + `send` and is slower. A
1.5 s smoke of the same harness (counter agreement and a 0.2 Gb/s floor) runs in the normal suite.

## Tests

```
.venv/bin/python -m pytest speedtest -q          # ~1 min: unit + integration against the fake collector (test/fakes)
.venv/bin/python -m pytest speedtest -m bench -s # the throughput benchmark
.venv/bin/ruff check speedtest
```

The suite starts the real daemon in-process (or `bin/exp-speedtest run` as a subprocess) against `fake_st_collector` over TLS,
uses `127.0.0.x` addresses as distinct attendee clients, validates real responses against `shared/openapi/speedtest.yaml`, and
needs no network. Real-ICMP tests skip when unprivileged ICMP sockets are not permitted on the machine.

## Layout

```
bin/exp-speedtest            entry point (tarball layout bin/ + lib/ + vendor/, or the dev tree)
exp_speedtest/config.py      exp.speedtest.config/1 + defaults, paths, credentials
exp_speedtest/core.py        sessions, limits, budgets, results, user-safe view, runner channel logic (no sockets)
exp_speedtest/httpd.py       strict HTTP/1.1 server;  routes.py (public)  channel.py (runner, loopback)
exp_speedtest/{tokens,limits,slots,guard,whereis,ua}.py   leg tokens, limiters, internet slots, core guard, zone resolver
exp_speedtest/dnsleg.py      DNS-leg authority (vendored dnspython);  path.py  ICMP path timer
exp_speedtest/{store,forward}.py   SQLite state + spool; pinned-TLS collector client and durable delivery
exp_speedtest/{daemon,health,cli}.py   wiring, exp.health/1, command line
exp_speedtest/static/        index.html (the page; the page step replaces the placeholder), csp-hashes.json, assets/
systemd/exp-speedtest.service, requirements.apt
```
