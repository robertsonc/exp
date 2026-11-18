# test/fakes — fakes for building against the contracts (WP-0)

Three stdlib-only servers (Python 3.10+, `http.server`, `ssl`). Each is a script **and** an importable module
(`start()` returns a running server, `.port` is the bound port, `.stop()` shuts it down). All bind `127.0.0.1`
by default and never touch a real network. They enforce the contracts for real (auth, validation, limits) so a
client that passes against them has met the spec; they are not production code and keep state in memory.

| Fake | For | Contract | Script |
|---|---|---|---|
| `fake_collector.py` | WP-1 probe, WP-3 dashboard | `shared/openapi/ingest.yaml`, `collector.yaml` | `python test/fakes/fake_collector.py` |
| `fake_manager.py` | WP-6 agent | `shared/openapi/agent.yaml` | `python test/fakes/fake_manager.py` |
| `mock_admin/server.py` | WP-5 manager UI | `shared/openapi/admin.yaml` | `python test/fakes/mock_admin/server.py` |

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
