# exp/collector - `exp-collector`

Ingest, VictoriaMetrics, rules engine, incidents, alerts, query API. Spec:
[docs/spec/03-collector.md](../docs/spec/03-collector.md). Work package WP-2.

**Status: complete for M1/M2 (step 3 of 3).** HTTPS server, auth, ingest pipeline, SQLite store, VictoriaMetrics
writer, pruning, health, CLI, systemd units, the rules engine, verdicts, incidents and alerts, time travel, the
full dashboard query API, the SSE hub, the summary tables, self-telemetry and the end-to-end daemon wiring.
Not in this build: the reflector (M4, `exp-collector reflector` is a stub) and drill storage (M5, the three drill
routes are wired and answer `404 drill_not_found` / `{"abort":[]}`).

## What runs

| Unit | Command | Notes |
|---|---|---|
| `exp-collector.service` | `exp-collector run` | user `exp-collector`; HTTPS on `listen` (mgmt IP, never a wildcard) |
| `exp-victoriametrics.service` | `exp-collector vm-exec` | user `exp-vm`; loopback only; flags derived from the validated config |
| `exp-reflector.service` | `exp-collector reflector` | M4 stub: prints `reflector disabled` and exits 0 when disabled |
| `exp-iperf3.service` | `exp-collector iperf3-exec` | `iperf3 -s -p <port> -B <listen ip>` |

## CLI

```
exp-collector run        [--config PATH]            daemon (SIGTERM = graceful: queued points go to vm_backlog)
exp-collector health     [--json] [--config PATH]   exp.health/1; exit 0 iff status == ok; answers from a snapshot (< 1 s)
exp-collector version
exp-collector selftest   [--config PATH] [--vm-binary PATH]
exp-collector prune --now [--config PATH]           delete expired records/incidents once
exp-collector rules eval --probe ID [--at TS|now] [--voice plain|sysadmin] [--config PATH]
                                                    print the State of a probe at a moment, evaluated purely
                                                    from the records in SQLite (time travel)
exp-collector replay FILE [--at TS ...] [--alerts] [--from TS --to TS] [--tz ZONE] [--voice V]
                          [--board-url URL] [--format text|slack|teams|json]
                                                    run the rules (and with --alerts the incident engine, 2 s
                                                    ticks) over an NDJSON(.gz) recording; prints States / messages
                                                    (EXM outage: the README's nine pages are --from 02:55:00; a
                                                    110 s DNS failure at 02:45 outlasts hold_down_s and pages)
exp-collector vm-args | vm-exec | iperf3-exec | reflector
```

Common options: `--config` (default `/etc/exp/collector/config.json`), `--state-dir` (default `$STATE_DIRECTORY`
or `/var/lib/exp/collector`), `--run-dir` (`$RUNTIME_DIRECTORY` or `/run/exp/collector`), `--creds-dir`
(`$CREDENTIALS_DIRECTORY`), `--tls-key/--tls-cert` (default `<state>/tls/{key,cert}.pem`; dev only).
An invalid config exits 78 and prints every problem; the collector never starts on one.

## Configuration

`exp.collector.config/1` (validated with `exp_common.config` against `shared/schemas/collector.config.schema.json`).
Credentials (`ingest_tokens.json`, `dashboard_tokens.json`, `webhooks.json`) come from `$CREDENTIALS_DIRECTORY`
and are re-read within 5 s of a change (bad file: previous good set stays, error logged without content). See
`docs/spec/changes/CR-wp2-cred-rotation-loadcredential.md` for how the agent must deliver rotated files.

Alerting keys (all optional): `alerts.{enabled, board_url, timezone, voice, hold_down_s, hold_back_s, reopen_s,
calm_s}` as in the contract; `rules.edge_label` names the WAN edge in texts ("the EC"); `rules.lines` limits the
lines that can page. Webhooks come from `webhooks.json` (`[{id, format: slack|teams|json, url}]`); URLs are
`https` only, destinations resolving to private, loopback or link-local addresses are refused unless listed in
`alerts.webhook_allow` (IPs, CIDRs or host names; see `docs/spec/changes/CR-wp2-webhook-allowlist.md`).

Hard limits: <= 512 connections (excess `503`), 10 s for the request line + headers in total, request line
<= 8 KiB, headers <= 64 / 32 KiB, body <= `ingest.max_body_mb` (<= 4 MiB wire), <= 16 MiB decompressed,
<= `ingest.max_records` (<= 1000) lines, <= 64 KiB per line.

## Ingest in one paragraph

`POST /ingest/v1/measurements` (ingest token) -> back-pressure check (VM queue > 200k points, backlog over the
disk cap, or SQLite writer lag > 5 s -> `429` + `Retry-After`) -> body -> bounded gunzip -> per line: JSON ->
`Measurement.from_dict(require_id=True)` -> identity binding (`probe` = token identity, `site` = that probe's
configured site; an unconfigured probe stores nothing) -> time window (`ts_future` > 60 s, `ts_too_old` >
`records_days`) -> `INSERT OR IGNORE` on `(probe, id)` in SQLite. Only then is a line `accepted`; its series are
queued for VM and the observers are called. Per-line results come back in the `200` body. VM being down never
affects acceptance: batches are persisted to `vm_backlog` and drained oldest-first on recovery.

## Rules engine (`rules.py`, `verdict.py`, `engine.py`)

The single implementation of the rules (decision D3), ported from EXM `pulse.py` / `pulse-core.js`.
* **Beats.** Records measured together (all ports of one `gateway` beat, the two resolvers of one `dns_hb` beat,
  one client run of `app` checks) become one beat: `0` ok, `1` warn, `2` fail (>= half of the ports/checks
  failing), `3` unknown (`outcome: error`: the probe could not run it; never a network failure).
* **Lines** `network` (gateway, 30 s window), `dhcp` (dhcp_hb, 30 s), `dns` (dns_hb, 30 s), `internet`
  (trace + ping, 120 s), `apps` (app, 120 s), `wifi` (wifi_hb, 30 s), `path` (path, 180 s). A line is `fail`
  when >= half of the beats in its window failed, `warn` on any failure (network/dhcp/dns) or when a third of
  the beats were slow/failed (internet/apps/wifi/path), `unknown` when it has no beat in the window.
  Constants: RECENT 60 s, TRACE_HOLD 30 s, flap window 10 min, last-outage lookback 15 min, evaluation history
  70 min (a long outage needs three good beats in a row to know where it began).
* **Where** (`where_of`): `link ports switch gateway lan edge isp wan resolver dns_path dns apps dhcp ssid wifi
  path` with the EXM rules (one lost trace does not blame the edge unless both resolvers are silent too).
  The collector falls back to the alternate resolver's records when a beat has no DHCP-given resolver record.
* **Verdict text** in two voices (`plain`, `sysadmin`); quips are picked from when the incident started, so they
  do not change every second. Probe text is cleaned (`verdict.clean`) before it enters a sentence.
* **Live** evaluation: `RulesEngine.observe` (ingest observer) feeds per-probe ring buffers, a 2 s tick evaluates
  every probe and caches the State for the API/SSE (`rules_eval_ms` self-telemetry, `rules_eval_ms_p95` health).
  **Time travel** (`state(probe, at)`) reads `[at - 70 min, at]` from SQLite: same records, same output.

## Incidents and alerts (`incidents.py`, `alerts.py`)

Holds (`hold_down_s` 20, `hold_back_s` 60), reopen within `reopen_s` 300 (`again`), the third failure inside 10
minutes sends one `flapping` message and then stays quiet until the line has been fine for `calm_s` 600, folding
(DHCP/DNS/Internet/Apps under Network, Internet and Apps under DNS, Apps under Internet, Path under Network,
Wi-Fi under Network while the laptop is on its target network: recorded with `folded_into`, never paged
separately, listed in the cause's page), silent probe (no record for 90 s). Every message is a row in
`incidents` (`down|again|flapping|back`; `end_ms` set when it ends) whether or not a webhook is configured;
open state is checkpointed in `meta` (`incidents:<probe>`) so a restart mid-outage does not page twice.
Messages hold the line, what, since (site timezone), where + why and `<board_url>/probe/<probe>?at=<start>`.
Webhooks: Slack, Teams, JSON; all probe text is escaped (no links, no mentions); 3 retries with backoff
(5/15/45 s); a failure is logged without the URL; redirects are never followed. `Store.ack_incident` records
`acked_by`/`acked_at` (`POST incidents/{id}/ack`).

## Storage and files

`<state>/records.db` (0600, WAL, `synchronous=NORMAL`; tables `records`, `incidents`, `vm_backlog`, `meta`;
`meta.schema_version` + ordered migrations; a database from a newer collector is refused),
`<state>/tls/{key,cert}.pem`, `<state>/vm/` (VictoriaMetrics), `<run>/health.json` (status snapshot written
every 5 s; no secrets). Pruning runs hourly in batches of 10,000 rows; closed incidents are kept 90 days.

## Health

`health --json` reads `<run>/health.json` (written by the daemon), adds `facts.tls_fingerprint_sha256` (from the
certificate on disk) and `facts.listen`, and derives `status`: `fail` = daemon not running / stale snapshot /
no TLS cert / < 0.5 GB free; `degraded` = VM unreachable or backlog non-empty, credential reload failing, low
disk, `days_to_full` < 3; else `ok`. `days_to_full` = free storage / 24-h average growth of (records DB + VM
data), sampled every 10 min and kept in `meta`; `null` when growth <= 0 or history < 10 min. `open_incidents`
(causes without an end), `webhook_failures_1h`, `rules_eval_ms_p95` and `sse_clients` are live.

## Query API (`api.py`, `summary.py`, `queryguard.py`, `drills.py`)

Base `https://<collector>:8443/api/v1/`, `Authorization: Bearer expd_...` on everything; `GET /healthz` is the only
open route (`ok` / `fail`). `X-Exp-User` is logged (sanitised) for audit and recorded as `acked_by`; it is never
used for authorization (the dashboard session enforces roles). Responses are validated against
`shared/openapi/collector.yaml` and the shared schemas by the tests. Errors are the contract envelope
`{"error":{"code","message","details"}}`; expensive reads (time travel, beats, summary, query_range) are capped at
a few in flight and answer `429` + `Retry-After` beyond that.

| Route | Notes |
|---|---|
| `GET health` | status, VM up/lag, ingest rate and rejects, probes reporting, free disk |
| `GET probes?site=&limit=&cursor=` | last seen, newest age, probe version, state `ok|warn|fail|unknown` |
| `GET state?probe=&at=&voice=` | `exp.state/1`; `at` = time travel from SQLite; unknown probe `404 unknown_probe` |
| `GET states?site=&at=&voice=` | State-lite list (paged) |
| `GET beats?probe=&from=&to=` | `exp.beats/1` with incident/drill/ext markers; `to - from` <= 6 h else `400 range_too_large` |
| `GET records?probe=&test=&outcome=&from=&to=&limit=&cursor=` | stored measurements, oldest first; `limit` <= 1000 (default 100); cursor = opaque `(ts_ms, id)` keyset |
| `GET incidents?probe=&site=&from=&to=&open=` | newest first, keyset cursor; folded consequences have `folded_into` |
| `POST incidents/{id}/ack` | body `{note?}` (<= 512 chars); needs `X-Exp-User` (else `403 forbidden`); first ack wins; audited in the `exp-collector.audit` log and announced as an SSE `incident` event; `204` |
| `GET summary?probe=&minutes=` | `minutes` <= 1440; tables `clients` (per port: DHCP/DNS/app health, worst app, Wi-Fi), `dhcp` (servers seen), `dns` (per resolver, pooled), `apps` (Apdex), `throughput` (latest per port/provider, bufferbloat), `servers` (target ports: requests, errors, top sources); ported from EXM `report.py` |
| `GET query_range?query=&start=&end=&step=` | proxied to VM, see below |
| `GET stream?probes=a,b` or `?site=` | SSE, see below |
| `GET drills/control` | executor ingest token (`expi_`, not a dashboard token): `{"abort":[run_id,...]}`; M5 plugs a registry into `app.drills` |
| `GET drills/{run_id}`, `POST drills/{run_id}/abort` | `404 drill_not_found` until M5 |

**query_range guards** (`queryguard.py`; all refused before VM sees the query): only `exp_*` metric names (the
MetricsQL is tokenized with a small allow-list grammar: every bare identifier must be `exp_...`, every selector
must hang off an `exp_` name or pin `__name__="exp_..."`, `__name__` regex/negative matchers, `WITH` templates,
comments, non-ASCII and backslash escapes are refused) -> `400 invalid_query`; query <= 2 KiB; range <= 30 d
(`range_too_large`); step >= 10 s and <= 11,000 points per series (`step_too_small`); more than 500 series (or VM's
own `-search.maxSeries`) -> `422 too_many_series`; VM unreachable or garbled -> `503 vm_unavailable` + `Retry-After`
(ingest is unaffected); 10 s timeout. `start`/`end` are `...Z` timestamps (epoch seconds also work), `step` is `30s`,
`1m`, `1h` or plain seconds.

**SSE** (`sse.py`): events `beat {probe,line,t,v}`, `state` (State-lite, sent when a probe's roll-up changes),
`incident` (opened, ended or acknowledged). Preamble `retry: 3000`, a `: keepalive` comment every 15 s, event ids
`<boot>.<n>`. Every client has a bounded queue of 1,000 events; one that falls behind (or whose socket stalls) is
disconnected, never waited for, and resumes with `Last-Event-ID` from the 5-minute ring buffer (an id from before
a collector restart replays nothing: re-read `states`). Filters `probes=` (<= 64 ids) or `site=`, exactly one;
at most 256 clients (`429`). Dead peers are noticed within about a second. Clients are counted in `sse_clients`
(health + `exp_collector_sse_clients`).

## The daemon (`app.py`)

`exp-collector run` starts, in order: credentials, SQLite (migrations), VM writer (drains `vm_backlog`), webhook
sender, rules engine (warms its buffers from SQLite and restores open incidents), the HTTPS server, the health
monitor, the pruner and the self-telemetry. The rules loop ticks every 2 s and also right after records arrive
(at most every 0.5 s), so a state change reaches a dashboard within about a second of the batch that caused it.
**SIGTERM/SIGINT**: stop SSE, stop accepting, let in-flight requests finish (<= 5 s), final checkpoints, queued VM
points go to `vm_backlog`, webhook queue stops, SQLite closes; exit 0. **SIGHUP** (and the 5 s mtime poll)
re-reads the credential files. **SIGKILL** loses nothing that was acknowledged: records are in SQLite before a
line is `accepted`, a replayed spool is deduplicated on `(probe, id)`.

Self-telemetry (every 15 s, straight into VM): `exp_collector_ingest_records_total{result}`,
`exp_collector_ingest_bytes_total`, `exp_collector_vm_backlog_points`, `exp_collector_sse_clients`,
`exp_collector_rules_eval_ms`, `exp_collector_probe_clock_offset_ms{probe}`.

## Extension points

- `app.router.add(method, "/api/v1/...", handler, auth="dashboard")` - fixed route table; `/api/*` routes must use
  dashboard auth and `/ingest/*` routes ingest auth (enforced at registration).
- `app.ingestor.subscribe(callback)` - called with the list of accepted `Measurement`s, after they are durable.
- `app.monitor.extra_sources.append(fn)` - `fn() -> dict` merged into the health metrics.
- `app.hub` (`sse.Hub`): `publish(kind, payload)`, `client_count()`; `app.drills`: replace with an object that
  has `abort_list()`, `report(run_id)`, `abort(run_id, user)` (M5).
- `app.sse_clients` / `app.rules_eval_ms` - callables used by the self-telemetry series.
- `app.rules` (`RulesEngine`): `state(probe, at_ms=None, voice=None)`, `states(site, at_ms, voice)`,
  `beats(probe, from_ms, to_ms)`, `severity(probe)`, `subscribe(cb)` (events `state`, `beat`, `incident`);
  `app.store.list_incidents(...)`, `get_incident`, `ack_incident`; `exp_collector.incidents.incident_doc(row)`.
- `app.store.write(fn)` - run SQL on the single writer thread; `app.store.reader()` - read-only connection.

## Troubleshooting

| Symptom | Look at |
|---|---|
| `refusing to start: ...` (exit 78) | the config problems it lists; `exp-collector selftest` |
| `cannot start: TLS key ... accessible to 'other'` | key mode must not grant "other" any access (agent creates it 0600) |
| probes get `401` | token not in `ingest_tokens.json`, wrong kind (`expd_` on ingest), or rotation not yet delivered |
| probes or dashboards get `429` | probes: `vm_backlog_points` / VM down / disk slow (`health --json`), honour `Retry-After`; dashboards: too many heavy queries or > 256 SSE clients |
| dashboards get `401` | wrong or rotated `expd_` token (an `expi_` token never works on `/api`, a dashboard token never on `/ingest` or `drills/control`); after a rotation send SIGHUP or wait 5 s |
| `query_range` answers `503 vm_unavailable` | VictoriaMetrics is down (`journalctl -u exp-victoriametrics`); ingest keeps working and the backlog drains on recovery |
| `query_range` answers `400 invalid_query` | the query touches a non-`exp_` metric, is > 2 KiB or uses unsupported syntax: the message says which |
| a probe cannot connect: "pin mismatch" | the probe/dashboard config pins an old `tls_fingerprint_sha256`; compare with `exp-collector health --json` (`facts`), the agent republishes it after a certificate change |
| SSE keeps reconnecting | the client is too slow (queue overflow) or a proxy buffers: the stream sends `X-Accel-Buffering: no`; check `journalctl` for "SSE client disconnected" |
| records `identity_mismatch` | probe's `probe`/`site` differ from the token identity / configured site |
| health says `daemon is not running` | no fresh `<run>/health.json`: `systemctl status exp-collector` |
| VM backlog keeps growing | VM unit down or refusing data (`journalctl -u exp-victoriametrics`) |
| a verdict looks wrong | `exp-collector rules eval --probe ID --at <ts>` shows the State from the stored records |
| no alert arrived | `incidents` has the row anyway; `journalctl -u exp-collector` says `alert ... refused/failed for <hook id>` (never the URL); private destinations need `alerts.webhook_allow` |
| "No data for ..." everywhere | the probe stopped reporting for > 90 s: nothing on the board is current |

## Tests

`/home/user/exp/.venv/bin/python -m pytest collector -q` (`collector/tests/golden/` replays the converted EXM
outage and the synthetic `where` cases; the real-VictoriaMetrics test is marked `harness` and is
skipped when docker or the pinned image is missing) and `.venv/bin/ruff check collector`.
