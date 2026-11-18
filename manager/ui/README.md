# exp manager UI (WP-5)

Preact + TypeScript (strict) + Vite single-page app for the exp manager: fleet health roll-up and administration.
Spec: [docs/spec/11-manager-ui.md](../../docs/spec/11-manager-ui.md); API: [shared/openapi/admin.yaml](../../shared/openapi/admin.yaml).
Step 1 delivered the app shell, design system, data layer and the fleet health views. Step 2 adds the administration flows
described below. Drills are a placeholder page that says they arrive in M5 (nothing on it acts).

No CDNs, no third-party fonts, no analytics. Runtime dependencies: `preact`, `uplot` (vendored through npm, MIT). Design tokens
come from `shared/ui` (aliased as `@shared`, bundled by Vite; icons are drawn as CSS masks over `currentColor`).

## Commands

| | |
|---|---|
| `npm ci` | install exact pinned versions (see `package-lock.json`) |
| `npm run dev` | Vite dev server on :5173; `/api` is proxied to the mock admin API |
| `npm run build` | `tsc --noEmit && vite build` into `dist/`, then the size budget check |
| `npm test` | vitest: formatting, state logic, data layer (fake fetch + fake timers), tables, security grep, PBKDF2 hashing, SSO form parsing, editor models, thresholds |
| `npm run e2e` | Playwright against `vite preview` + mock_admin on free ports (both are started and killed by the script): fleet views, every administration flow, axe-core, 390 px, visual snapshots (about 5 min) |
| `UPDATE_SNAPSHOTS=1 npm run e2e` | rewrite the baselines in `tests/__snapshots__/` |
| `npm run size` | JS must be <= 300 KB gzipped (currently about 90 KB) |

Develop against the mock:

```
.venv/bin/python test/fakes/mock_admin/server.py --listen 127.0.0.1:18080 --no-auth
cd manager/ui && npm run dev            # proxy target: EXP_API_TARGET (default http://127.0.0.1:18080)
```

`npm run e2e` uses the globally installed Playwright and Chromium (no download: it resolves `playwright` from
`npm root -g`; `EXP_PYTHON` overrides the Python used for the mock, default `<repo>/.venv/bin/python`). Time-dependent
behaviour (freshness amber after 90 s, red after 5 min) is tested with Playwright's fake clock.

## Serving `dist/` from the Worker (WP-4)

`dist/` is plain static files (`index.html`, `assets/*` with hashed names). Requirements for the Worker's Static Assets binding:

* **SPA fallback:** every non-`/api` path that is not an existing file must return `index.html` with status 200, because
  routes are real URLs (`/fleet`, `/hosts/h_...`, `/hosts/h_.../components/cmp_...`, `/sites/hall-b`, ...).
  In `wrangler.toml`: `[assets] directory = "../ui/dist"`, `not_found_handling = "single-page-application"`,
  and route `/api/*`, `/install.sh`, `/healthz` to the Worker first (`run_worker_first = ["/api/*", "/install.sh", "/healthz"]`).
  `vite preview` already behaves this way, which is what the e2e tests rely on.
* `assets/*` are content-hashed: serve with `Cache-Control: public, max-age=31536000, immutable`; `index.html` with `no-cache`.
* The UI sends no credentials of its own: requests are same-origin, authenticated by the Cloudflare Access cookie / JWT that the
  Worker verifies. It never uses `localStorage` for anything but theme, hosts column choice and saved views (all wrapped in try/catch).
* Security headers: `public/_headers` (copied into `dist/` by Vite, applied by Cloudflare Static Assets) sets, for `/*`,
  `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and
  `Permissions-Policy: camera=(), microphone=(), geolocation=()`. There are no inline scripts or styles (`style` objects are applied
  through the DOM API, which `style-src 'self'` permits; `data:` is for the bundled icon masks). The e2e run applies the same headers to every
  non-API response, so a CSP violation fails it. The SSO handoff page is not part of the SPA: the Worker answers it with its own CSP (script
  hash, `form-action` pinned to the dashboard origin); see the safety rules below.
* Sign out links to `/cdn-cgi/access/logout`.

## Layout

```
src/
  api/        types.ts (hand-written subset of admin.yaml), endpoints.ts (URLs are the cache keys)
  data/       store.ts (polling client), hooks.ts, directory.ts, hostData.ts
  lib/        format.ts (section 6 rules), state.ts (staleness, thresholds, backoff), hosts.ts, issues.ts, csv.ts, ...
  charts/     align.ts (gap-preserving time grid), TimeSeriesChart.tsx (uPlot)
  components/ AppShell pieces, StatusPill, KpiTile, HealthBar, Sparkline, VirtualTable, Tabs, dialogs, ...
  pages/      FleetPage, IssuesPage, HostsPage, HostPage, ComponentPage, SitesPage
tests/        vitest
e2e/run.mjs   Playwright harness
scripts/check-size.mjs
```

## Data layer behaviour (section 2)

* One cache entry per endpoint URL, shared by every component that uses it; `If-None-Match` with the stored ETag; a 304 keeps the data
  and counts as a successful refresh.
* Polls every 30 s; paused while the tab is hidden; refetch on focus / visibility and after every mutation.
* Failures back off 60 s, 120 s, 240 s, then 5 min; the banner "Can't reach the manager" is amber, red once nothing has succeeded
  for 5 min, and the last data stays on screen. Recovery is automatic.
* `401` shows "Your Cloudflare Access session expired" with a Reload button; `403` with code `unknown_admin` shows "Your account is
  not an admin"; any other `403` (`insufficient_role`) is local to that call.
* The client clock is corrected with the response `Date` header so "N s ago" is right on a skewed laptop.
* A host is never shown as current from old data: if our copy is older than 90 s, staleness is extrapolated (stale after 3 x its
  interval, offline after 10 min).

## Security

Everything from the API is untrusted. It is rendered only through Preact text nodes; `tests/security.test.ts` fails the build on
`innerHTML`, `dangerouslySetInnerHTML`, `eval`, `new Function`, `document.write`, `javascript:` and similar sinks anywhere in `src/`.
CSV export neutralises spreadsheet formulas. Links taken from API facts must be `https:`. Rendered configs are redacted
defensively (`src/lib/redact.ts`). Destructive actions require typing the host name.

## Notes for step 2

Placeholders: Releases, Dashboards (SSO handoff), Drills, Audit, Settings; site create/edit; the add-host wizard.
Contract gaps found while building: `docs/spec/changes/CR-wp5-*.md`.


## Administration (step 2)

| Where | What |
|---|---|
| `/hosts/new` | Add-host wizard: name, site, shapes -> one-liner with copy button, 1 h countdown and "waiting for the host" (polls every 3 s) -> facts and, for a probe, the interface picker -> Apply and progress until every component is healthy. The host id and step live in the URL, so a reload resumes; the one-liner is shown once and can be reissued. |
| `/hosts/{id}?tab=actions` | Restart component, rotate component credentials, rotate agent secret, new enrol token, decommission (type the host name). |
| `/hosts/{id}/components/{cid}?view=configure` | Editors. Probe: heartbeat, tests and intervals, app targets (with Apdex T), DNS names, path peers, labels. Collector: retention, alerts. Dashboard: title, address, collectors, TLS mode and fingerprint, local users, NOC tokens, Open dashboard. |
| `/sites`, `/sites/{site}` | Create, edit, delete; release target (canary, rollback); alert settings with write-only webhook URLs and "Send test". |
| `/releases` | Imported versions, import by version, upload manifest + signature + artifacts, per-site target and canary status, rollback. |
| `/dashboards` | Every dashboard with Configure and Open dashboard. |
| `/audit` | Filter by actor, resource prefix and time (filters live in the URL). |
| `/settings` | Organisation, admins (invite by email and role), drills switches, fleet thresholds, platform webhook (write-only). |
| `/drills` | Placeholder: drills arrive in M5. |

Safety rules the code follows (and the tests check):

* Every mutation goes through the data layer (`mutate`, `mutateText`, `mutateForm`). The Worker enforces, for POST/PUT/PATCH/DELETE on
  `/api/admin/v1/*` (after the Access JWT check; failure is `403 {"error":{"code":"csrf_refused"}}`): (a) the custom header
  `X-Exp-Request` (any non-empty value; the UI sends `1`), which a cross-site form or simple request cannot set; (b) when there is a body,
  `Content-Type: application/json` (optional `; charset=utf-8`), except `POST /releases/upload`, which must be `multipart/form-data`;
  (c) an `Origin` header, if present, must equal the Worker's own origin, and `Sec-Fetch-Site`, if present, must be `same-origin` or `none`.
  GETs are unaffected. SSO handoff: the SPA's CSP pins `form-action 'self'`, so the SPA never submits the token form itself. The UI
  calls `POST dashboards/{id}/sso/launch` (header-bearing, so CSRF-guarded like any mutation) which returns a same-origin launch URL
  `/api/admin/v1/dashboards/{id}/sso/page?n=<nonce>`; a new window navigates to it (a GET, which needs the Access JWT of the same admin)
  and the Worker answers with the auto-submitting page under its own CSP (`form-action` pinned to the dashboard origin). The nonce is a
  stateless HMAC over (admin email, dashboard, expiry), 30 s TTL, bound to that admin and dashboard; it is not a dashboard credential, and
  without it the GET is `403 invalid_launch_nonce`. `POST dashboards/{id}/sso` (returns the page directly) remains for API clients and
  obeys the same header rule. The form action is the admin-set dashboard `url` or the host's management IP, never the agent-reported
  `facts.url` (shown in the UI as information only).
* Destructive actions confirm; decommission, user delete and site delete require typing the name.
* Secrets are write-only: webhook URLs show `set . updated <time>` and an empty box, never the value; NOC tokens are shown once (copy buttons, NOC URL
  `https://<dash>/noc#t=expn_...`) and live only in component state; the password for a dashboard local user is hashed in the browser with WebCrypto
  (`src/lib/pbkdf2.ts`: PBKDF2-SHA256, 600,000 iterations, 16-byte random salt, `pbkdf2_sha256$600000$<salt b64>$<hash b64>`, the format
  `dashboard/exp_dashboard/auth.py` verifies) and only that string is sent. The e2e test feeds the browser-made hash to the dashboard's verifier.
* "Open dashboard" asks the manager for the SSO handoff form, reads `action` and `token` out of it with strict patterns (https, path `/auth/sso`,
  JWT shape), and submits a form it builds itself into a window opened from the click and detached (`opener = null`). No HTML from the network is
  ever injected.
* Editors merge into a copy of the stored intent and keep keys they do not know. Intent assumptions are listed in
  `docs/spec/changes/CR-wp5-admin-ui-intent.md`.

## Tests

* `tests/*.test.ts` (vitest, jsdom): pure logic and the data layer.
* `e2e/run.mjs` drives everything else; `e2e/admin-tests.mjs` holds the administration flows, `e2e/pages.mjs` lists every page for the axe-core
  (`@axe-core/playwright`, WCAG 2.1 A/AA, serious and critical, both themes) and 390-px sweeps, and `e2e/snapshots.mjs` does the pixel comparison
  (`pixelmatch`, 2 % tolerance, volatile content masked) against `tests/__snapshots__/`. The mock is started with `--enrol-delay-s 4` so the wizard
  does not wait 10 s.
