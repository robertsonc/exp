# 04 — Dashboard (`exp-dashboard`)

Where operators watch the experience. An on-prem HTTPS service that authenticates users, serves
the SPA, and **federates** the query API of one or more collectors. It must work fully on the LAN
when the internet and the manager are unreachable (Principle 2). Contracts: `01-contracts.md` §5,
§9.3, §12.

Prior art: `reference/exm/lib/exm/static/{pulse.html,pulse-core.js,overview.html}` (UX and
rendering), `web.py` (routes). The rule logic in `pulse-core.js` is **not** ported — state comes
from the collector (decision D3).

## 1. Process

`exp-dashboard.service`, user `exp-dashboard`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, hardened
(`ProtectSystem=strict`, `ReadWritePaths=/var/lib/exp/dashboard`, `NoNewPrivileges`, `PrivateTmp`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`). Listens on 443 (TLS) and 80 (redirect only).
Package: `dashboard/exp_dashboard/{config,server,auth,sessions,federate,sse,cli}.py` and
`dashboard/static/` (no build step). Python 3.10+ stdlib.

**TLS:** `tls.mode = self_signed` → the agent generates a P-256 cert (SAN = host IPs and hostname)
and reports its fingerprint; the manager UI shows it so users can verify the browser warning.
`provided` → cert/key from creds.

## 2. Authentication and sessions

| Route | Purpose |
|---|---|
| `POST /auth/sso` | SSO handoff from the manager (`01-contracts.md` §12). Works whenever the user's browser can reach both. |
| `GET/POST /auth/login` | Local accounts (manager-managed, PBKDF2-SHA256 600k hashes in `local_users.json`). Work offline. |
| `POST /auth/noc` | NOC token exchange: the NOC URL is `https://<dash>/noc#t=expn_…`; the page reads the fragment (never sent to servers or logs) and POSTs it; the dashboard checks `sha256` against `noc_tokens.json` (and `expires`) and issues a read-only session. |
| `POST /auth/logout` | Ends the session. |

- Sessions: random 256-bit id in a cookie (`__Host-exp_session; Secure; HttpOnly; SameSite=Lax; Path=/`),
  stored hashed in SQLite `/var/lib/exp/dashboard/sessions.db` (survive restarts). Lifetime
  `session_hours`; NOC sessions renew while the page is open.
- Login throttling: 5 failures per username and 20 per IP in 15 min → `429`. Constant-time
  comparisons. Generic error text ("username or password is wrong").
- CSRF: state-changing requests require `SameSite` cookie **and** a matching `Origin` and a
  per-session CSRF token header.
- Roles: `viewer` (read), `operator` (+ acknowledge incidents, abort a running drill), `admin`
  (SSO only; same as operator on the dashboard). When the credential files change (rotation,
  user removed), affected sessions are invalidated within 30 s.

## 3. Federation

The SPA talks only to the dashboard's own `/api/v1/*`, which mirrors the collector API
(`01-contracts.md` §5) across `collectors[]`:
- Probe-scoped calls (`state`, `beats`, `records`, `summary`) route to the collector that owns the
  probe (probe → collector map refreshed from `probes` every 30 s).
- List calls (`probes`, `states`, `incidents`) fan out in parallel (timeout 3 s each) and merge.
  The response adds `"collectors":[{"collector_id","ok","error"?}]` so the UI can show partial
  results ("Hall B collector unreachable") instead of failing.
- `stream`: one upstream SSE connection per collector, multiplexed to all browser clients;
  reconnect with backoff and `Last-Event-ID`.
- Upstream calls use the per-collector `expd_` token, pinned TLS (`exp_common.tlspin`), and add
  `X-Exp-User`.

## 4. SPA (static, offline-safe)

Vanilla ES modules, **no external CDNs, fonts, or analytics** (it must work with no internet). Design
tokens in `shared/ui/tokens.css` (HPE design language, `reference/netvitals/DESIGN.md`): dark NOC
theme by default plus light theme, HPE green `#01A982` accent, state colors ok/warn/fail/unknown
always paired with an icon or shape (never color alone).

| View | Route | Content (port EXM UX) |
|---|---|---|
| **Overview** | `/` | "N of M probes need a look." Grouped by site; per-probe row: name, line chips (Network/DHCP/DNS/Internet/Apps/Wi-Fi/Path), headline, live/stale. Collector reachability banner. |
| **Pulse board** | `/probe/<id>` | Verdict headline + sub (large, room-readable); **path chips** (ports › switch › gateway › edge › ISP › DNS › apps) with the failing segment highlighted and its explanation; one row per line with state word, detail, and an EKG-style **heartbeat trace** over 15 min; **playhead**: drag the "since" bar or click a beat to look back, drag past the left edge to pan, `?at=<UTC>` deep links, `←/→` step, `Esc`/"Back to live"; **What's failing** cards; **Details** tables from `summary`; timeline markers (incidents, drills, correlated events). |
| **Incidents** | `/incidents` | Filterable list; operator can acknowledge. Each links to the board at the incident start. |
| **Drills** | `/drills` | (M5) runs with expected vs observed detection; a running drill shows a banner with **Abort** (operator). |
| **Kiosk** | `?kiosk=1[&rotate=30]` | Chrome hidden; rotates through sites/probes; for wall screens. |

Behaviour:
- Live updates via `stream`; when looking back, the board fetches `state?at=` (debounced 150 ms
  while dragging) and `beats` for the window.
- **Stale guard:** if the newest result is > 30 s old, the headline says so ("Nothing on this screen
  is current") — never show stale green.
- Voice toggle (`plain`/`sysadmin`), passed as `voice=` to the API; preference in `localStorage`
  (wrapped in try/catch; the page works without it).
- All probe-, collector-, or user-supplied text is inserted with `textContent` (no `innerHTML`):
  probe input is untrusted and must not become markup.
- Accessibility: keyboard reachable controls, ARIA live region for headline changes, WCAG AA
  contrast, `prefers-reduced-motion` respected. Layout works at 390 px with 16 px gutters and no
  horizontal scroll.
- `?static=1` renders from REST only (no SSE) for screenshots and reports — headless browsers stall
  on pages holding an EventSource open; tests use a CDP client.

Performance: a board with 7 lines × 15 min renders in < 50 ms; SSE updates apply in < 10 ms.

## 5. Security headers

Every response: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API
responses. No inline scripts or styles. HSTS only when `tls.mode = provided`.

## 6. CLI

`exp-dashboard run` · `health` (JSON: status, version, collectors reachable, TLS fingerprint) ·
`version` · `selftest`.

## 7. Acceptance tests (WP-3 definition of done)

1. SSO: a valid token creates a session; expired, replayed (`jti`), wrong `aud`/`iss`, or bad
   signature → refused. Token in a URL query is ignored.
2. Local login with throttling; NOC token exchange (fragment never reaches server logs); logout;
   a removed user's session ends within 30 s of the creds update.
3. Unauthenticated `/api/*` → 401; viewer cannot ack; CSRF without the token → 403.
4. A probe label `<img src=x onerror=alert(1)>` renders as text (XSS test); CSP header present.
5. Federation over 3 collectors; one collector down → partial results + banner, board still works.
6. Rewind: the board at `?at=T` shows exactly the collector's `state?at=T`.
7. Offline: in a namespace with no default route (no internet, no manager), login with a local user
   and NOC token, and live updates all work; no request leaves the LAN (asserted by capture).
8. Kiosk rotation; 390-px layout has no horizontal scroll (CDP screenshot check).
