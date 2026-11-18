# 11 — Manager UI: fleet health and administration

The manager UI is where admins live. Besides administration (sites, hosts, releases, users, drills),
it is the **fleet health roll-up**: every collector, dashboard, probe, and runner — host resources
(CPU, memory, disk, uptime), network counters (packets/s and bits/s in and out, errors, drops), and
component work (measurements per minute, ingest rate, backlog, storage runway, sessions).

It is **not real-time.** Agents report every 60 s (30 s minimum, `status_interval_s`); the UI polls
every 30 s and always shows how old the data is. Experience monitoring in real time is the
dashboard's job (`04-dashboard.md`); the manager answers "is the platform itself healthy, and where
do I act?"

Data sources: status reports (`01-contracts.md` §8), component health (`§8.1`), the fleet API
(`§13`), and fleet roll-ups and issues (`05-manager.md` §13–14).

## 1. Quality bar

- **Answer in five seconds:** the overview tells an admin whether anything needs action and where,
  without scrolling.
- **Every number has a time:** "as of 45 s ago"; stale data is visibly stale, never shown as current.
- **Dense but calm:** data tables and small multiples, not gauges and rainbows. Color is reserved
  for state and threshold breaches, always paired with an icon or text.
- **Fast at fleet scale:** 500 hosts render smoothly; the overview loads in < 1.5 s.
- **Consistent:** one design system (`shared/ui/tokens.css`, HPE design language from
  `reference/netvitals/DESIGN.md`), light and dark themes, the same components everywhere.

## 2. Tech

- Preact + TypeScript (strict) + Vite, built into static assets served by the Worker.
- Charts: **uPlot** (vendored, MIT, ~50 KB) for time series; hand-rolled SVG for sparklines and
  health bars. No CDN, no web fonts from third parties, no analytics.
- Data layer: a small polling client — per-endpoint cache, `If-None-Match`/ETag, 30-s interval,
  paused while the tab is hidden (Page Visibility API), immediate refetch on focus and after
  mutations, exponential backoff with a visible "can't reach the manager" banner.
- Routing: client-side with real URLs (`/fleet`, `/hosts/h_…`, `/hosts/h_…/components/cmp_…`), so
  every view is linkable and filters live in the query string.

## 3. Information architecture

```
┌ AppShell ─────────────────────────────────────────────────────────────────────┐
│ ▣ HPE EXP  Org name      [⌕ search hosts, sites, components]   Updated 12 s ago │ user ▾
├───────────┬───────────────────────────────────────────────────────────────────┤
│ Fleet     │                                                                   │
│ Issues ●3 │                       page content                                │
│ Hosts     │                                                                   │
│ Sites     │                                                                   │
│ Releases  │                                                                   │
│ Dashboards│                                                                   │
│ Drills    │                                                                   │
│ Audit     │                                                                   │
│ Settings  │                                                                   │
└───────────┴───────────────────────────────────────────────────────────────────┘
```
Global search jumps to a host, site, or component by name, IP, or id.

## 4. Pages

### 4.1 Fleet overview (`/fleet`, home)
```
┌ KPI strip ──────────────────────────────────────────────────────────────────────────────────┐
│ Hosts 47/48 online │ Components 61 ok · 2 warn · 1 fail │ Measurements 18.2k/min │ Ingest 305/s │
│ Open issues 3 (1 crit) │ Version drift 2 hosts │ Experience incidents open 1 (from collectors)  │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
┌ Needs attention ────────────────────────────┐ ┌ Sites ─────────────────────────────────────┐
│ ● CRIT col-hallb disk 96% — 2 days to full  │ │ Hall B   ████████▒░  12 hosts  305/s ingest │
│ ▲ WARN probe-a7 no lease on 3/12 ports 6 min│ │ Hall C   ██████████   9 hosts  210/s        │
│ ▲ WARN dash-main collector col-hallc unreach│ │ Keynote  ██████▒▒▒░   6 hosts  88/s  1 warn  │
│ … view all issues →                         │ └─────────────────────────────────────────────┘
└─────────────────────────────────────────────┘
┌ Fleet resources (small multiples, 24 h) ────────────────────────────────────────────────────┐
│ Top CPU   ▁▂▃█▇ col-hallb 82%   ▁▁▂▂▃ col-hallc 41%   …                                      │
│ Top disk  col-hallb 96% ████████████▉   col-keynote 71% ████████▌   …                       │
│ Top net   col-hallb mgmt 41k pps in / 3k out   …                                            │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```
- KPI tiles link to pre-filtered views. "Experience incidents open" is a count reported by
  collectors (not data-plane detail) and links to the dashboard via SSO.
- Sites cards: a stacked health bar (ok/warn/fail/offline), hosts, probes reporting/total, ingest rate, worst issue.

### 4.2 Issues (`/issues`)
All open fleet issues (`05-manager.md` §14): severity, issue, host/component, site, since, last
value. Filters: severity, site, type, issue kind. Actions: **snooze** (1 h / 24 h / until resolved,
per issue kind per host, audited), open host. Resolved issues remain in a "recent" tab for 7 days.

### 4.3 Hosts (`/hosts`) — the fleet table
| Column | Content |
|---|---|
| Host | name, mgmt IP; badge `stale` / `offline` when applicable |
| Site | |
| Shapes | badges P/C/D/R |
| Health | worst component health + open issue count |
| CPU | % (1-min avg of the last interval) + 1-h sparkline |
| Memory | % used |
| Disk | max % of `/` and `/var/lib/exp`; amber ≥ 85, red ≥ 95 |
| Uptime | host uptime (`12d 4h`) |
| Net | mgmt interface pps in/out and Mb/s in/out + 1-h sparkline |
| Work | probes: measurements/min; collectors: ingest records/s; dashboards: sessions; runners: active drills |
| Version | applied (amber if ≠ desired) |
| Last report | relative ("45 s ago"), absolute on hover |

Filter chips (site, shape, health, version, state), free-text search, sort on any column, column
chooser, saved views (in `localStorage`, try/catch), CSV export of the current view. Virtualized
rows (500+). Below 768 px the table becomes a card list.

### 4.4 Host detail (`/hosts/{id}`)
Header: name, site, shapes, state, OS/kernel/arch, mgmt IP, agent version (desired vs applied),
host uptime, last report, time sync status. Tabs:
- **Overview:** charts for CPU (avg + max band, load average), memory, disk per mount, mgmt network
  pps and bps in/out with errors and drops; range picker 1 h · 6 h · 24 h · 7 d · 30 d; open issues;
  recent events (reconcile results, restarts, rollbacks).
- **Components:** one panel per component (§4.5), each with state, health, version, process CPU and
  memory, restarts, uptime.
- **Interfaces:** table of every interface: name, role (`mgmt`, `probe:c01`, `none`), link, speed,
  addresses, pps and Mb/s in/out, errors and drops, with sparklines.
- **Configuration:** desired vs applied version and a read-only view of the rendered config (never
  creds); edit links to the component editors.
- **Activity:** audit and agent events for this host.
- **Actions:** restart component, rotate credentials, new enrol token, decommission (confirm dialogs
  name the host and the consequence).

### 4.5 Component views (`/hosts/{id}/components/{component_id}`)
| Type | Panels |
|---|---|
| **Collector** | ingest records/s (accepted, duplicate, rejected) chart; rejects by reason; VM backlog; storage used (VM + records) with a **days-to-full projection**; probes reporting vs total (table: probe, last seen, records/min, clock offset); SSE clients; open experience incidents (count + "Open board"); webhook failures (1 h); rules evaluation p95 |
| **Probe** | **ports grid** — one tile per port: role, link, lease IP/gateway, pps and Mb/s in/out, errors, last heartbeat outcome per line; measurements/min by test (stacked chart); failures/min; spool depth and push lag; clock offset; collector reachability; "Open board" (SSO to the dashboard's probe page) |
| **Dashboard** | collectors reachable vs total; active sessions; requests/min; SSE clients; login failures (1 h); TLS fingerprint; "Open dashboard" (SSO) |
| **Runner** | active drills; pullers (source, last success, errors 1 h); allowlist size |

### 4.6 Sites (`/sites`, `/sites/{site}`)
List and detail: the site's hosts table (§4.3 pre-filtered), health roll-up, release version and
canary status, alert settings, edge label, timezone. Create/edit as in `05-manager.md` §10.

### 4.7 Add-host wizard, releases, dashboards, drills, audit, settings
As specified in `05-manager.md` §10 (wizard with copy-field + countdown + live wait, interface
picker), `10-drills-integrations.md` (drills), with the same components and states. Settings adds
**fleet thresholds** (`05-manager.md` §14) and the **platform webhook**.

## 5. Components (design system)

`AppShell`, `NavItem` (with badge), `GlobalSearch`, `FreshnessIndicator` ("Updated 12 s ago"; turns
amber after 90 s, red after 5 min without a successful refresh), `KpiTile`, `StatusPill`
(ok/warn/fail/unknown/stale/offline — icon + text), `HealthBar` (stacked), `Sparkline`,
`TimeSeriesChart` (uPlot; avg line + max band; gaps drawn as gaps; tooltip with site-timezone and UTC
time; range picker; "table view" toggle for accessibility), `MetricTile` (value, unit, sparkline),
`DataTable` (virtualized, sortable, filter chips, column chooser, CSV export, keyboard navigation),
`FilterBar`, `IssueRow`, `PortTile`, `Tabs`, `Drawer`, `ConfirmDialog` (destructive actions type the
host name), `CopyField`, `Countdown`, `EmptyState`, `ErrorBanner` (partial data), `Skeleton`.

## 6. Formatting rules

- Rates: pps with SI suffixes (`41.2k pps`); bit rates in `Mb/s`/`Gb/s`; bytes in binary units (`GiB`).
- Percentages: whole numbers, one decimal under 10%.
- Durations: `45 s`, `12 min`, `4 h 12 min`, `12 d 4 h`.
- Times: relative in lists ("45 s ago"), absolute on hover in the site's timezone plus UTC; charts
  label the timezone.
- Missing values: `—` with a tooltip saying why ("no report yet", "not applicable", "stale").
- **Stale data:** a host whose last report is older than 3 × its status interval is shown greyed
  with a `stale` badge, and its values are labelled "as of <time>". Offline (> 10 min) hosts show
  their last values only in the detail page.

## 7. States

Every view has loading (skeletons), empty (with the next action, e.g. "Add your first host"), error
(retry + what failed), and partial (some data missing — e.g. a component that has never reported
metrics) states. Mutations show inline progress and the resulting desired-state version; the UI
then watches the host until `applied_version` catches up ("Applying… 2 of 3 components healthy").

## 8. Accessibility and responsiveness

WCAG 2.1 AA: keyboard reachable everything, visible focus, table semantics with headers, ARIA live
region for the freshness indicator and mutation results, charts with text summaries and a table
view, contrast AA in both themes, `prefers-reduced-motion`. Layout works from 390 px (16 px gutters,
no horizontal page scroll; wide tables scroll inside their container or become card lists).

## 9. Performance budget

- Overview first render < 1.5 s on a cold load with 500 hosts; subsequent polls < 300 ms.
- Hosts table: 500 rows sort/filter < 100 ms; scrolling 60 fps (virtualized).
- Charts: a 30-day series renders < 100 ms.
- Total JS ≤ 300 KB gzipped (uPlot included).
- Fleet API p95 < 300 ms (`05-manager.md` §13).

## 10. Demo and development data

`manager/scripts/seed-demo.ts` creates a realistic fleet in local D1: 3 sites, 48 hosts (collectors,
dashboards, probes with 4–16 ports, a runner), 30 days of roll-ups with diurnal load, a disk filling
toward full, a crash-looping component, a stale host, an offline host, version drift, and open
issues. Used by UI development, visual tests, and customer demos (`npm run seed:demo`).

## 11. Acceptance (WP-5 definition of done, additions)

Playwright against `wrangler dev` with the demo seed:
1. The overview shows the seeded KPIs and issues exactly (counts match the fleet API).
2. A host past 3 × interval renders `stale` with "as of"; offline after 10 min; never shown as current.
3. Hosts table: filter + sort + saved view + CSV export; 500 rows sort < 100 ms.
4. Host detail charts for every range; gaps (no data) are shown as gaps; table-view toggle works.
5. Probe ports grid shows per-port link/lease/pps; collector days-to-full matches the API projection.
6. Snoozing an issue hides it for the period and writes an audit event.
7. Freshness indicator: manager unreachable → amber, then red, with a banner; recovers automatically.
8. axe-core: no serious violations on every page in both themes; 390-px screenshots have no horizontal scroll.
9. Visual regression snapshots for overview, hosts, host detail, collector, probe views.
