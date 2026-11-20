# exp/dashboard — `exp-dashboard`

Auth, federation over collectors, the Pulse board SPA. Spec: [docs/spec/04-dashboard.md](../docs/spec/04-dashboard.md). Work package WP-3.
Step 1 (this tree): server, auth, sessions, CSRF, federation, SSE multiplexing, headers, health, CLI, unit.
Step 2 (done) is the SPA under `exp_dashboard/static/`: Pulse board, overview, incidents, login, NOC page, kiosk.

Python 3.10+, stdlib only. Runs from the dev tree (`dashboard/bin/exp-dashboard`) and from a release
tarball (`bin/` + `lib/` + `vendor/`).

## CLI

```
exp-dashboard run          [--config PATH] [--log-level L] [--log-json]
exp-dashboard health       [--config PATH] [--json]      # exit 0 for ok and degraded, 1 only for fail
exp-dashboard version
exp-dashboard selftest     [--config PATH]
exp-dashboard hash-password [--iterations N]              # password on stdin -> pbkdf2_sha256$... (dev/tests)
```

Common options: `--config` (default `/etc/exp/dashboard/config.json`; validated against
`exp.dashboard.config/1`, an invalid config exits 78 with the reason), `--state-dir` (default
`$STATE_DIRECTORY` or `/var/lib/exp/dashboard`), `--creds-dir` (`$CREDENTIALS_DIRECTORY` or
`/etc/exp/dashboard/creds`), `--run-dir` (`$RUNTIME_DIRECTORY` or `/run/exp/dashboard`), and for
development `--tls-cert/--tls-key`.

Make a local-user hash: `printf 'pw\n' | exp-dashboard hash-password`.

## Configuration and credentials

Config: `exp.dashboard.config/1` (`docs/spec/01-contracts.md` 9.3). Credential files (all optional;
an empty or unreadable file means "none", malformed content fails closed):

| File | Content |
|---|---|
| `collector_tokens.json` | `{collector_id: "expd_..."}` per-collector query tokens |
| `sso_secret` | base64, 32 bytes; HS256 secret shared with the manager |
| `local_users.json` | `[{username, role, hash: "pbkdf2_sha256$600000$<salt_b64>$<hash_b64>"}]` (local `admin` is treated as `operator`) |
| `noc_tokens.json` | `[{id, sha256, label, role, expires}]` (sessions are always read-only viewers) |
| `tls.key`, `tls.crt` | only with `tls.mode = provided` |

TLS: `self_signed` loads `<state>/tls/cert.pem` + `key.pem` (created by the agent before first start);
`provided` loads the credential files. Certificates are re-read when they change.

## What it serves

* HTTPS (TLS >= 1.2) on `listen.https`; `listen.http_redirect` answers only with a redirect to the
  configured `url` origin (never the `Host` header).
* Static SPA files from `exp_dashboard/static/` at `/<relative path>` (known content types only, no
  listing, no traversal, no dotfiles, no symlink escape). `/`, `/probe/<id>`, `/incidents`, `/drills`,
  `/login` fall back to `index.html`; `/noc` serves `noc.html`; `/auth/login` serves `login.html`.
* `/auth/sso` (POST body only), `/auth/login`, `/auth/noc` (POST body only), `/auth/logout`,
  `/auth/session` (current user, role, CSRF token, config for the SPA).
* `/api/v1/*`: federated collector API (`probes states incidents health` fan out; `state beats records
  summary` route by probe; `query_range` needs `collector=<id>` when several collectors exist; `drills/<run>`;
  `incidents/<id>/ack` and `drills/<run>/abort` need operator), plus `collectors` (reachability) and
  `stream` (SSE). List responses carry `"collectors":[{collector_id, site, ok, error?}]`.
* `/healthz`: `ok`.

Browser contract for the SPA: send the cookie automatically (same origin), and on every non-GET request
the header `X-Exp-CSRF: <csrf from /auth/session or the login response>`; the browser adds `Origin`.

## Security notes

Cookie `__Host-exp_session` (Secure, HttpOnly, SameSite=Lax, Path=/), 256-bit id, only its SHA-256 is
stored (`sessions.db`, mode 0600). Login throttle: 5 failures per username / 20 per IP per 15 min -> 429.
Logs never contain tokens, passwords or request bodies (the access log is off; auth events are logged
without secrets). HSTS only when `tls.mode = provided`. See `docs/spec/changes/CR-wp3-dashboard-runtime-paths.md`.

## Troubleshooting

* `refusing to start: ...` (exit 78): fix the config named in the message.
* `cannot start: cannot load the TLS certificate/key`: the agent has not generated `<state>/tls/*.pem`
  (or the provided `tls.crt`/`tls.key` are empty).
* `health --json` says `service is not running`: `systemctl status exp-dashboard`; the socket is
  `<run>/health.sock`.
* Collector flagged `tls_pin_mismatch`: the collector certificate changed; update
  `tls_fingerprint_sha256` in the config. `unauthorized`: wrong `expd_` token in `collector_tokens.json`.
  `no_credential`: no entry for that collector.
* Users cannot sign in with SSO: check `sso_secret` (32 bytes base64), `auth.sso.issuer` and that the
  `aud` of the manager token equals `dashboard_id`.

## Tests

`/home/user/exp/.venv/bin/python -m pytest dashboard -q` (uses `test/fakes/fake_collector.py` with TLS pins;
no internet), `/home/user/exp/.venv/bin/ruff check dashboard`.


## The SPA (`exp_dashboard/static/`)

Vanilla ES modules, no build step, no CDNs/fonts/analytics (works offline). `index.html` -> `/app.js` -> `js/main.js`.

| Route | View |
|---|---|
| `/` | Overview: all probes (federated State-lite) grouped by site; "Hall B collector unreachable" banner on partial results |
| `/probe/<id>` | Pulse board: verdict, where-chain, lines with beat strips, failing, details, live via SSE; `?at=<UTC>` rewinds (live paused, "Back to live", arrows/Esc, click or drag a strip); `?voice=plain|sysadmin`; stale banner "Nothing on this screen is current" when the newest result is > 30 s old or the feed is down; `?static=1` = REST only (no SSE) |
| `/incidents` | Filters (status/site/line/text, kept in the URL); operators acknowledge (CSRF header); each row links to the board at the incident start |
| `/login`, `/auth/login` | JS login form / server-rendered form (no script) |
| `/noc#t=expn_...` | Reads the fragment, removes it from the address bar, POSTs it to `/auth/noc`, continues to `/?kiosk=1` |
| `/?kiosk=1[&rotate=30][&site=x]` | Wall mode: no chrome, wall-size type, rotates overview + each probe (worst first) every N s (2..600) |

Security (SR-13): every remote string goes through `createTextNode`/`textContent` (`js/dom.js`); inline handlers, inline
scripts and styles do not exist (dynamic values use CSS custom properties). `tests/test_ui_static_safety.py` greps the
tree. Icons are CSS masks of `shared/ui/icons`. Theme: dark default, toggle dark/light/auto (`localStorage`, optional).

`shared/ui` is vendored into `static/vendor/ui/` by `scripts/sync-ui.sh`; `tests/test_ui_vendor.py` fails on drift.

Browser tests: `tests/test_ui_browser.py` drives `tests/ui/scenarios.js` (Playwright + Chromium, global install) against
the real server and three fake collectors. Skipped when node/playwright are missing. The "no request leaves the LAN"
capture (spec 7.7) needs a network namespace and belongs to the WP-8 harness.

## Speedtest analytics (M6, `12-speedtest-analytics.md` section 8)

Views (`exp_dashboard/static/speedtest/`, same SPA conventions: textContent only, no inline script/style, CSP unchanged):

| Route | View |
|---|---|
| `/speedtests` | Overview: tests/hour, medians by leg, score distribution, top causes, zones coloured by p50 score (icon + word), "users vs probes" (user-test scores against the nearest probe's worst line state, last 24 h), filterable test list. Range 1 h..30 d, site filter. Polls every 30 s (`?static=1` = once) |
| `/speedtests/breakdowns` | zone / AP / SSID / band / OS family / hour by median score, down, up, loaded latency or count; worst-10 APs by p50 score with at least N tests (`min=`) |
| `/speedtests/test/<st_id>` | Detail: two legs side by side, score parts, diagnosis with cited evidence (links to the evidence cards), evidence timeline (Wi-Fi roams/events, RSSI, AP utilization, top flows, WAN utilization/alarms, security hits, probe beats; text alternative), one card per evidence kind, the user's comment as text, device block |
| `/speedtests/support` | Paste `.../st/r/<id>#k=...` or a bare id and land on the detail. The `#k=` key is never sent anywhere (dropped in the browser). `/st/r/<id>` on the dashboard host redirects the same way. Admins: search by IP/MAC/hostname (audited) and purge by subject |

API (`exp_dashboard/speedtests.py`): `GET /api/v1/speedtests`, `/speedtests/aggregate`, `/speedtests/<id>`, `POST /speedtests/purge`.
List/aggregate fan out to every collector and add `collectors:[{collector_id, ok, error?}]` (a collector with analytics
off is flagged `speedtests_disabled`); the list cursor is a composite of the per-collector cursors and one page holds up
to `limit` rows per collector; aggregates sum counts and combine medians as count-weighted means (`approximate: true`).
Detail asks every collector (first hit wins; 502 if a collector could not be asked and none had it).

Roles (SR-25): raw IP/MAC/hostname/username are requested from a collector (`identifiers=true` + `X-Exp-User`, audited by
the collector) only for an **admin** session (SSO) that sends `identifiers=1`; for everyone else the flag is dropped and the
response is also run through `sanitize_detail` (defence in depth). Purge is admin only, CSRF protected, needs `confirm:true`
(the UI does a dry run first), is sent to every collector, and is logged without the identifier (hash prefix only).
Tests: `tests/test_speedtests_api.py` (against `tests/st_fake.py`, the collector's speedtest routes on the shared fake,
using the collector's own `privacy.redact_evidence`), `tests/test_speedtest_ui.py` + `tests/ui/st_scenarios.js`
(Playwright; screenshots in `$EXP_ST_SHOTS`, default the M6 e2e-artifacts `dashboard/` directory).
