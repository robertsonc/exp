# 03 — Collector (`exp-collector`)

The site's hub: authenticated ingest, storage (VictoriaMetrics for metrics, SQLite for records and
incidents), the **rules engine** that turns beats into line states, verdicts, and incidents,
alert delivery, and the query API and live stream for dashboards. Contracts: `01-contracts.md`
§2–5, §9.2, §11.

Prior art: `reference/exm/lib/exm/pulse.py` (rules), `alert.py` (incidents/alerts),
`static/pulse-core.js` + `static/pulse.html` (verdict phrasing and "where" logic), `remote.py`
(ingest policy), `report.py` (details tables), `web.py` (API + SSE hub), `tail.py` (time-window reads).

## 1. Process model

| Unit | Role |
|---|---|
| `exp-victoriametrics.service` | VictoriaMetrics single-node (bundled, pinned version + sha256), user `exp-vm`, `-httpListenAddr=127.0.0.1:8428 -retentionPeriod=<metrics_days>d -storageDataPath=/var/lib/exp/collector/vm -memory.allowedPercent=<pct> -search.maxQueryDuration=10s -search.maxSeries=500` |
| `exp-collector.service` | Python daemon, user `exp-collector`: HTTPS server (ingest + query API + SSE), ingest pipeline, VM writer, rules engine, incident/alert engine, pruner |
| `exp-reflector.service` | UDP/TCP 8862 reflector for `path` tests (`02-probe.md` §7) |
| `exp-iperf3.service` | `iperf3 -s -p 5201` |

Package: `collector/exp_collector/{config,server,auth,ingest,store,vmwriter,rules,verdict,incidents,alerts,api,sse,summary,prune,cli}.py`,
`collector/exp_collector/reflector.py`, tests in `collector/tests/`. Python 3.10+ stdlib only.

## 2. HTTPS server

`http.server.ThreadingHTTPServer` with an `ssl.SSLContext` (TLS ≥ 1.2) using the locally generated
key/cert in `/var/lib/exp/collector/tls/`. Hard limits: ≤ 512 concurrent connections (excess
→ `503`), 10 s header read timeout (slowloris), body limits from config, request-line ≤ 8 KiB.
Routes are a fixed table — anything else is `404`. `GET /healthz` is the only unauthenticated
route.

**Auth:** `Authorization: Bearer <token>` → `sha256` → constant-time lookup in `ingest_tokens.json`
(probes and runners) or `dashboard_tokens.json` (dashboards). Credentials are re-read when the agent
updates them (a poll of the credentials directory every ≤ 10 s by `(mtime_ns, size, inode)`; a bad file keeps the previous good set and
is logged without its content). systemd refreshes `LoadCredential=` copies only at unit start, so the **agent restarts
the unit** when it changes a credential file (`01-contracts.md` §11); the poll serves dev/test layouts and mirrors
(`--creds-dir`). A token-file value is a sha256 string or, during a rotation overlap, `[current, previous]`
(`01-contracts.md` §9.2); other shapes are ignored (logged once). Ingest tokens are valid only
on `/ingest/*`; dashboard tokens only on `/api/*`.

## 3. Ingest pipeline

1. Read the body within limits; gunzip with a running byte cap (zip-bomb guard: stop at 16 MiB).
2. For each line: JSON parse (≤ 64 KiB) → `exp_common.schema.Measurement.from_dict()` (all the
   untrusted-input rules in `shared/SCHEMA.md`) → **identity binding**: `probe` must equal the token's
   identity and `site` must equal that probe's configured site → time window (`01-contracts.md` §4).
3. `INSERT OR IGNORE` into `records` (primary key `(probe, id)`) — durable dedupe that survives
   restarts. Count `duplicates`.
4. Accepted records go onto the **VM write queue** (series from `Measurement.series()`) and to the
   **live state** (per-probe beat ring buffers), and are announced to the SSE hub.
5. Respond with per-line results.

Back-pressure: if the VM write queue exceeds 200,000 points or the SQLite writer lags > 5 s, answer
`429` with `Retry-After`. Records are never accepted unless they are in SQLite.

## 4. Storage

**SQLite** `/var/lib/exp/collector/records.db` (WAL, `synchronous=NORMAL`):
- `records(probe, id, ts_ms, site, test, outcome, body)` — `body` is the full measurement JSON;
  indexes `(probe, ts_ms)`, `(probe, test, ts_ms)`.
- `incidents(id, probe, site, line, kind, start_ms, end_ms, where_json, facts_json, folded_into, acked_by, acked_at)`.
- `vm_backlog(seq, payload)` — points not yet written to VM (VM down or slow).
- `meta(key, value)` — schema version, rules state checkpoints.

**VictoriaMetrics:** batched `POST /api/v1/import` (JSON lines: `{"metric":{"__name__":…,labels},
"values":[v],"timestamps":[ms]}`) every 1 s or 5,000 points. On failure, persist to `vm_backlog` and
retry with backoff; drain the backlog oldest-first on recovery (A1.4 / A3.3).

**Pruning:** hourly, delete `records` older than `retention.records_days` in batches of 10,000
(never one long transaction); incidents are kept 90 days. VM retention is VM's own.

## 5. Rules engine (single source of truth — decision D3)

Port `pulse.py` (and the JS twin `pulse-core.js` where the Python is incomplete) to
`rules.py`/`verdict.py`. The JS copy is **not** ported to the dashboard.

**Lines** (defaults; keys match `01-contracts.md` §5):

| Line | Source tests | Beat cadence | State window |
|---|---|---|---|
| `network` | `gateway` (all ports) | 10 s | 30 s |
| `dhcp` | `dhcp_hb` | 10 s | 30 s |
| `dns` | `dns_hb` (DHCP resolvers; alternate corroborates) | 10 s | 30 s |
| `internet` | `trace` (+ `ping`, control path) | 10 s (trace rotates) | 120 s |
| `apps` | `app` | per test interval | 3 × interval |
| `wifi` | `wifi_hb` | 10 s | 30 s |
| `path` | `path` | per test interval | 3 × interval |

Constants to keep from EXM: `RECENT = 60 s`, `TRACE_HOLD = 30 s` (a single lost trace never sets a
verdict), flap window 10 min.

**Functions** (port semantics exactly; names may follow Python style):
- `beats(records, line)` → beat values `0 ok / 1 warn / 2 fail / 3 unknown`. `outcome: error`
  (the probe could not run the test) → `3`, never a network failure. A heartbeat record covering
  N ports yields a beat whose value reflects the ports: all ok → 0; some failing → 1 (or 2 when ≥
  half); all failing → 2.
- `state_of(beats, line, at)` → `fail` when ≥ half the beats in the state window failed; `warn` on
  degraded beats; `unknown` when no beat in the window (stale); otherwise `ok`.
- `since_of`, `last_outage(…, 15 min)`, `flaps(…, 10 min)`.
- **Per-port rotation of `dns_hb` (A1.2 decision, no behaviour change; owner decision point).** With N client
  ports the probe rotates `dns_hb` one port per beat, so each beat covers a single port's namespace. A DNS
  failure confined to ONE port's namespace therefore fails only about 1/N of the beats in the 30 s window:
  fewer than half, so the `dns` line is `warn`, not `fail` (the rotation makes "some ports" visible as
  degraded beats). A site-wide DNS failure fails every beat and is `fail`. The `where_of` verdict is
  unaffected (it reads the per-port records). Alternatives if the owner wants a single broken port to read
  as `fail` (probe every port each beat, or count a window as `fail` when any port's last beat failed)
  change alert noise and probe load; they are deliberately NOT done here. Pinned by the M1 e2e A1.2.
- `where_of(records, at, states)` → the path segment and its explanation. Must reproduce every EXM
  verdict: `link, switch, gateway, lan, edge, isp, wan, resolver, dns_path, apps, dhcp, ssid, wifi`,
  plus `path`. Rules carried over:
  - all ports fail the gateway → `gateway`; some ports → `ports`/`switch` by pattern;
  - DHCP-given resolver silent but the alternate answers → `resolver`; both silent while the
    gateway answers → `dns_path`/`edge`;
  - trace stops after the first hop (the gateway/edge) **and** the control-path trace reaches the
    target → `edge` ("It's the EC. The ISP answers around it; our traffic dies after 10.1.0.2.");
    both fail → `isp`/`wan`;
  - **one lost trace does not blame the edge** — unless both resolvers are silent too (the
    2026-10-27 15:14 lesson);
  - Wi-Fi off the target SSID → `ssid`; Wi-Fi down while wired is fine → `wifi`.
  - `edge_label` (e.g. "EC") names the edge segment in text.
- `verdict(states, where, voice, tz)` → `headline` + `sub`, in `plain` or `sysadmin` voice (port the
  sentence tables from `pulse.html` and `alert.py` `HEAD/BACK/QUIP_*`). **Fix these EXM bugs, do not
  port them:** doubled periods when interpolated text ends with "." ("ACME_CORP..", "1 a.m.."); a
  traceroute "from null" when no client holds a lease (say that no client could run it); "No error
  text in the last 60 seconds" shown while the line itself lists errors; overview and board
  disagreeing (impossible now — one implementation).
- **Time travel:** `state(probe, at)` evaluates from records in `[at − max_window − RECENT, at]`
  (SQLite, or the live ring buffers when `at` is now). Pure and deterministic: same records →
  same output.
- Live evaluation every 2 s for every probe; results are cached for the API and SSE.

## 6. Incidents and alerts

Port `alert.py` (`Alerter`) to `incidents.py` + `alerts.py`:
- **Holds:** a line becomes `down` after failing continuously for `hold_down_s` (20 s) and `back`
  after `hold_back_s` (60 s) of ok.
- **Again:** a re-failure within `reopen_s` (5 min) reopens the incident as `again`.
- **Flapping:** from the third failure inside the flap window, one `flapping` message, then quiet
  until the line has been calm for `calm_s` (10 min).
- **Folding** (`PARENTS`): DHCP, DNS, and Internet failures that start while Network fails, and
  Internet while DNS fails, and Wi-Fi while Network fails with the laptop on the target network, are
  **consequences**: recorded with `folded_into`, not paged separately.
- **Silent probe:** no records for 90 s → a `probe silent` incident ("Nothing on this screen is current"), with `Incident.line = "probe"` (`01-contracts.md` §5; it names the probe itself, not a network line).
- Every incident is written to `incidents`. Webhook delivery is optional (`webhooks.json`): Slack,
  Teams, JSON formats, with all probe-supplied text **escaped** so it cannot create links or
  mentions (port `_slack`/`_teams` escaping). 3 retries with backoff; failures are logged without
  the URL (the URL is a secret).
- Message content: line, what, since (site timezone), where + explanation, and a link
  `<board_url>/probe/<probe>?at=<start>`.
- `POST /api/v1/incidents/{id}/ack` records `acked_by` (from `X-Exp-User`, operator role).

## 7. Query API and SSE

Implements `01-contracts.md` §5. Implementation notes:
- `beats` and `state` come from the rules engine; `records` from SQLite (cursor = `(ts_ms, id)`).
- `summary` ports `report.py` `dashboard_summary` (clients, DHCP servers seen, DNS, apps, throughput,
  target-server access) for the details tables; row shapes are fixed in `01-contracts.md` §5.
- `query_range` proxies to VM with the guards in the contract plus VM's own limits (`-search.maxSeries=500`, 11,000 points per series, 32 MiB answers); timeout 10 s.
- **SSE hub:** each client has a bounded queue (1,000 events); a client that falls behind is
  disconnected (it reconnects and resumes). A 5-minute ring buffer supports `Last-Event-ID`.

## 8. TLS identity

The agent generates the collector's key and certificate before first start
(`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 3650 -subj "/CN=<collector_id>"
-addext "subjectAltName=IP:<listen-ip>"`), into `/var/lib/exp/collector/tls/` (key `0600`
`exp-collector`). `exp-collector health` prints `tls_fingerprint_sha256` and `listen`; the agent puts
both into the status report so the manager can pin them in probe and dashboard configs.

## 9. Self-telemetry

Written directly to VM: `exp_collector_ingest_records_total{result}`, `exp_collector_ingest_bytes_total`,
`exp_collector_vm_backlog_points`, `exp_collector_sse_clients`, `exp_collector_rules_eval_ms`,
`exp_collector_probe_clock_offset_ms{probe}` (from `probe_self`).

## 10. CLI

`exp-collector run` · `health --json` (`exp.health/1`: collector metrics of `01-contracts.md` §8.1 —
ingest rates, backlog, storage, `days_to_full` — and facts `tls_fingerprint_sha256`, `listen`) · `version` · `selftest` · `rules eval --probe <id> --at <ts> [--voice]` (print State) ·
`replay <ndjson[.gz]> --at <ts>…` (run the rules + incident engine over a file; used by golden tests)
· `prune --now`.

## 11. Porting map

| exp module | From |
|---|---|
| `rules.py` | `exm/pulse.py` (`beats`, `state_of`, `since_of`, `last_outage`, `flaps`, `where_of`, `states`) + `static/pulse-core.js` |
| `verdict.py` | sentence logic in `exm/static/pulse.html`, `alert.py` (`HEAD`, `BACK`, `QUIP_*`, `WHERE`) |
| `incidents.py`, `alerts.py` | `exm/alert.py` (`Alerter`, `PARENTS`, `REOPEN_MS`, `CALM_MS`, `SILENT_MS`, escaping) |
| `ingest.py` | `exm/remote.py` (`Ingest` policy), but push + SQLite dedupe instead of SSH pull + RAM dedupe |
| `summary.py` | `exm/report.py` (`dashboard_summary`) |
| `sse.py`, `api.py` | `exm/web.py` (`Hub`) |

## 12. Golden data

The golden page sequence (nine pages) is the replay over 02:55-04:28, as in EXM's own replay. A full-file replay also pages
the 02:45 `dns_hb` failure (110 s outlasts `hold_down_s = 20`); the hold is not special-cased. End times differ from EXM's by up to
~10 s because exp stamps the start time (`test/fixtures/exm/README.md`).

WP-0 provides `test/fixtures/convert_exm.py`, which converts the real EXM outage fixture
`reference/exm/test/fixtures/outage-2026-10-27.jsonl.gz` into `exp.measurement/1` NDJSON
(`test/fixtures/outage-2026-10-27.exp.ndjson.gz`), mapping EXM's multi-port records onto the
per-port catalog. The golden expectations come from `reference/exm/test/unit.py`.

## 13. Acceptance tests (WP-2 definition of done)

1. Ingest guards: zip bomb, > 1,000 lines, oversize line, bad JSON, reserved label, naive/future
   timestamp, `probe` ≠ token identity, `site` mismatch — each rejected with the right code; valid
   lines in the same batch still accepted.
2. Dedupe across a restart: replaying a spool after restart stores nothing twice.
3. VM down for 10 min: ingest keeps accepting; backlog drains on recovery; no gaps in `query_range`.
4. **Golden rules:** replaying the converted outage fixture reproduces EXM's verdicts — every
   `where` class; the gateway outage at 03:10 (`10.1.0.1`, 12 of 12 ports); "one lost traceroute
   does not blame the edge"; the 15:14 both-resolvers-silent exception; and the alert engine emits
   the same **9 messages** (one page per cause) with folding.
5. Verdict text: no doubled punctuation across all sentence templates and both voices (property test).
6. Webhook text escaping: probe-controlled strings cannot produce links or mentions.
7. Query guards: non-`exp_` metric, 31-day range, 1-s step, > 500 series — refused; SSE resume works.
8. Load: 50 probes × 20 records/s for 30 min on 4 vCPU/8 GB: p95 ingest < 100 ms, no backlog, CPU < 60%.
