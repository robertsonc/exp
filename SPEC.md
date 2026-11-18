# exp — Product & System Specification (v1.0)

**exp** — *Event network eXperience Platform.* Synthetic users on the event network measure what
real attendees experience; collectors store it in a time-series database; dashboards tell the NOC,
in one sentence, whether the network is fine and where it is breaking; a Cloudflare-hosted central
manager deploys and runs the whole thing from admin intent. Resilience **drills** deliberately
break things in a controlled way to prove the monitoring (and the network's failover) works.

This document is the **source of truth** for building exp. It is written so a multi-agent build
session can implement the system in parallel without the conversation that produced it.

| Doc | Contents |
|---|---|
| `SPEC.md` (this) | Purpose, principles, architecture, decisions, milestones, acceptance |
| `docs/spec/01-contracts.md` | **Every interface**: schemas, APIs, desired state, configs, file layout, ports |
| `docs/spec/02-probe.md` | Probe |
| `docs/spec/03-collector.md` | Collector (ingest, TSDB, rules engine, alerts, query API) |
| `docs/spec/04-dashboard.md` | Dashboard |
| `docs/spec/05-manager.md` | Central manager (Cloudflare Workers SaaS) |
| `docs/spec/06-agent.md` | Host agent (enrol + reconcile) |
| `docs/spec/07-security.md` | Threat model and security requirements |
| `docs/spec/08-operations.md` | Packaging, releases, deployment, upgrades, testing, CI |
| `docs/spec/09-work-packages.md` | Parallel work breakdown, ownership, dependencies, definition of done |
| `docs/spec/10-drills-integrations.md` | Resilience drills (chaos) and event correlation |
| `docs/spec/11-manager-ui.md` | Manager UI: fleet health roll-up, issues, hosts, administration |
| `docs/spec/12-speedtest-analytics.md` | Branded user speedtest with per-device correlation (Wi-Fi, flows, security logs, probes) — M6 |
| `KICKOFF.md` | Ready-to-use kickoff instructions for the multi-agent build session |
| `reference/` | Read-only prior art (EXM, netvitals, perf, chaos_monkey) to port from |

Normative words: **MUST**, **SHOULD**, **MAY** (RFC 2119).

---

## 1. Purpose and users

**Problem.** At events, the network team learns about a bad attendee experience from attendees.
Device dashboards (APs, switches, SD-WAN) report device health, not experience: an EdgeConnect can
pass its own IP SLA while every client's traffic dies behind it (observed in the EXM lab).

**exp answers, every 10 seconds:** *Can a client get on the network (link, DHCP), resolve names
(DNS), reach the internet and the apps that matter, and how good is it (latency, loss, jitter,
throughput, MOS)?* — and *where on the path* the failure is: ports › switch › gateway › edge ›
ISP › DNS › apps.

**Users.**
- **Platform admin** — deploys the manager once, enrols hosts, sets intent, manages releases,
  secrets, users, drills. Works mostly in the manager UI.
- **NOC operator** — watches dashboards on wall screens and laptops during the event; acknowledges
  incidents; may run pre-approved drills.
- **Event stakeholder** — read-only dashboard view (NOC link).
- **Attendee / exhibitor** (M6) — runs the branded speedtest on the event network and gets a
  plain-language diagnosis; never signs in.

## 2. Principles (non-negotiable)

1. **Simplicity for deployment and operation.** One command to deploy the manager. One copy-paste
   command per host. No per-host hand configuration. Upgrades and rollbacks are clicks.
2. **The data plane never depends on the cloud.** If the internet or the manager is down, probes
   keep measuring, collectors keep storing and alerting, dashboards keep working on the LAN. (The
   moment you most need the dashboard is when the internet is broken.)
3. **Probe input is untrusted.** Everything a probe, laptop, or host sends is validated against a
   fixed schema and bound to the sender's identity.
4. **Declarative, not remote-shell.** The manager publishes *desired state*; agents converge to it.
   The manager can never run arbitrary commands on a host. Software installed on hosts is only
   ever an artifact signed with the offline release key.
5. **Least privilege, scoped and revocable credentials.** Per-component credentials, issued by the
   manager, rotatable, revocable. No shared master secret on any host.
6. **Fail closed, never destructively.** A failed safety check refuses and explains; it never
   powers off, wipes, or "fixes" something it does not own.
7. **Verify the end state, not a proxy.** Tests assert the outcome (the incident fired, the port
   is in the namespace, the policy *blocked* the request), and every enforcement control has a
   test proving it enforces — not merely that it is configured. (Lesson: a Conditional Access
   policy silently left in report-only mode.)
8. **Low-cardinality metrics, detailed records.** TSDB series stay low-cardinality; high-detail
   data (URLs, trace hops, error text) lives in records.
9. **Reuse proven logic.** Port from `reference/` where it exists; do not reinvent.

## 3. Glossary

| Term | Meaning |
|---|---|
| **Organization** | One manager deployment (single-tenant). |
| **Site** | A logical event location (e.g., `hall-b`). Owns collectors, probes, dashboards. |
| **Host** | An Ubuntu machine running `exp-agent`. |
| **Shape / component** | A role on a host: `probe`, `collector`, `dashboard`, `runner`. A host may run several (all-in-one is supported). |
| **Port** | A probe test interface. Role `client` (DHCP client, runs tests) or `target` (static-IP test server). |
| **Measurement** | One measured network transaction (`exp.measurement/1`). |
| **Beat** | A heartbeat measurement (every 10 s) feeding a **line**. |
| **Line** | A user-facing dimension on the board: Network, DHCP, DNS, Internet, Apps, Wi-Fi, Path. |
| **Verdict** | The one-sentence headline + "where" for a probe at a moment. |
| **Incident** | A line's failure episode: down → (again/flapping) → back. |
| **Desired state** | The per-host document the manager publishes and the agent converges to. |
| **Drill** | A controlled, time-boxed, auto-reverting fault injected to validate detection/failover. |
| **Speedtest** (M6) | A user-run, two-leg (local + internet) browser test, cataloged with an **evidence bundle** correlated for that device (`12-speedtest-analytics.md`). |

## 4. System architecture

```
                    ┌──────────────────── Cloudflare ─────────────────────┐
  Admin browser ──▶ │  exp-manager (Worker)  · Access (SSO) · D1 · R2      │
   (SSO via Access) │  intent → desired state · releases · secrets · audit │
                    └───────────────▲─────────────────────────────────────┘
                                    │ HTTPS, outbound only (agent pull)
        ┌───────────────────────────┼────────────────────────────┐
        │ event network / on-prem   │                            │
  ┌─────┴──────┐  measurements  ┌───┴─────────────┐  query/SSE  ┌─┴────────────┐
  │ exp-probe  │ ─────────────▶ │ exp-collector   │ ◀────────── │ exp-dashboard│◀── NOC (LAN)
  │ (+agent)   │  HTTPS :8443   │ + VictoriaMetrics│  HTTPS:8443 │ (+agent)     │
  │ test ports │  pinned TLS    │ + rules/alerts  │             │ HTTPS :443   │
  └────────────┘                │ + reflector     │             └──────────────┘
                                │ (+agent, runner)│──▶ webhooks (Slack/Teams/JSON)
                                └─────────────────┘──▶ EC Orchestrator / Mist APIs (drills, events)
```

- **Control plane:** manager ⇄ agents. Agent → manager only (outbound HTTPS 443). Agents poll for
  desired state, download signed artifacts, install, configure, report status.
- **Data plane:** probe → collector (ingest), dashboard → collector (query). All on-prem, over
  the management network, TLS with certificate pinning distributed by the manager.
- **Collector** = ingest + validation + VictoriaMetrics + record store (SQLite) + **rules engine**
  (line state, verdict, incidents) + alerting + query API + reflector/iperf3 endpoints.
- **Dashboard** = auth + static SPA + federated query proxy over one or more collectors.
- **Runner** (optional shape, usually on a collector host) = executes drills and event-correlation
  pullers on-prem, where the Orchestrator/Mist endpoints are reachable.

## 5. Decision log

| # | Decision | Rationale / alternatives rejected |
|---|---|---|
| D1 | **Agent-pull provisioning** with one-liner bootstrap (`curl … install.sh \| sudo bash -s -- <token>`). | Workers can't hold outbound SSH; storing host passwords in a SaaS is a liability. SSH push and hybrid rejected. |
| D2 | **VictoriaMetrics** single-node per collector. | One small binary, Prometheus-compatible, push+pull. SQLite (scale), Prometheus+pushgateway (more parts), InfluxDB (heavier) rejected. |
| D3 | **Rules engine is server-side only** (collector, Python). Dashboard renders state from the API. | EXM ran rules in both JS and Python with parity tests; drift caused real bugs (overview vs board mismatch). One implementation. |
| D4 | **Manager = Cloudflare Workers (TypeScript) + D1 + R2 + Workers Secrets + Rate Limiting + Cron + Static Assets.** No KV/Durable Objects in v1. | Fewest moving parts. DO-based push notification is a v2 option. |
| D5 | **Admin auth = Cloudflare Access**, and the Worker **also verifies the Access JWT** on every admin route (fail closed). | No password code to write; SSO for free. Defense in depth against Access misconfiguration. |
| D6 | **Single-tenant**: one manager per organization, deployed into the operator's Cloudflare account. Tables carry `org_id` for a future multi-tenant mode. | Matches "once the manager instance is deployed, the admin signs in". |
| D7 | **Python 3.10+, stdlib-first** for probe, collector, dashboard, agent. Only vendored deps: `dnspython` (probe). Ubuntu 22.04/24.04. JSON configs (no `tomllib`, which is 3.11+). | Nothing to `pip install` on hosts; Ubuntu ships python3. |
| D8 | **Dashboard is an on-prem shape**, reachable on the LAN even with the internet down. SSO handoff from the manager when online; manager-managed local accounts and NOC tokens work offline. | Principle 2. Cloudflare Tunnel remote access is a later option (§12). |
| D9 | **Collector TLS is self-signed and pinned.** The agent generates the key/cert on the collector host; its SHA-256 fingerprint flows to probes/dashboards via desired state. | No CA to run; no browser involved on this path. |
| D10 | **Signed releases.** Offline Ed25519 release key; per-release manifest signed; agents verify with `openssl` (no Python crypto deps). Release public key pinned at enrolment. | Manager compromise cannot push unsigned code. |
| D11 | **Probe architecture = one long-running daemon with an internal scheduler** (no supercronic/cron), netns per test port (EXM model) or host mode. | Fewer processes and packages; EXM's netns model is proven. |
| D12 | **Platform versioning**: one semver for all components; agent N supports components N and N-1. | Simple compatibility story. |
| D13 | **Drills are opt-in, allowlisted, time-boxed, auto-reverting, audited, and executed on-prem by a runner.** | Breaking a live network must be deliberate and bounded. |
| D14 | **Fleet health is a roll-up, not real-time:** agents send host/process/component metrics in the status report every 60 s (30–300); the manager keeps latest values plus D1 roll-ups (5 min × 48 h, 1 h × 30 d) and evaluates fleet issues; the UI polls every 30 s. | One channel (no extra agents or exporters); D1 is ample to 500 hosts; Analytics Engine is the scale-out path. |
| D15 | **User speedtest is an on-prem shape with two legs** (local LAN server + Cloudflare edge Worker); correlation with Wi-Fi, flow, security-log, and probe data runs asynchronously in the runner; results and evidence stay on-prem; anonymous by default. | The server must see the client's real LAN IP to join network data, and it must work with the internet down; two legs localize the fault. |

## 6. Component summaries

Full detail in `docs/spec/02–06`. Interfaces in `docs/spec/01-contracts.md`.

- **Probe** (`exp-probe`): owns test ports (netns each), holds DHCP leases, runs heartbeats every
  10 s (gateway, DHCP discover, DNS, traceroute/control path) and scheduled tests (DHCP DORA, DNS,
  app/HTTP Apdex, throughput, path quality, Wi-Fi), serves target-server ports, spools locally,
  pushes to its collector.
- **Collector** (`exp-collector`): authenticated ingest bound to probe identity, schema validation,
  dedupe, VictoriaMetrics write, SQLite records/incidents, rules engine (line states, verdict,
  where), alerting (holds, again, flapping, folding), query API + SSE, reflector + iperf3 server.
- **Dashboard** (`exp-dashboard`): HTTPS server, sessions (SSO handoff, local users, NOC tokens),
  federated proxy to collectors, the Pulse board + overview + incidents + drill results SPA.
- **Manager** (`exp-manager`): Access-protected admin UI/API with a **fleet health roll-up**
  (CPU/memory/disk/uptime, pps and bps in/out, measurements/min, ingest, storage runway, issues —
  `11-manager-ui.md`), sites/hosts/components intent, enrol
  tokens, desired-state compiler, release import/storage (R2), secrets (AES-GCM), dashboard users
  and NOC tokens, alert/integration settings, drills, audit log; agent API.
- **Agent** (`exp-agent`): bootstrap via `install.sh`, enrol, poll desired state (ETag), verify
  and install signed artifacts, render configs and credentials, manage systemd units, health-check,
  roll back, report facts/status, self-update, decommission.
- **Runner** (`exp-runner`, M5): drill execution and event-correlation pullers, on-prem; in M6 also
  the speedtest correlation connectors (Mist client, EC flows, syslog/SSE security logs).
- **Speedtest** (`exp-speedtest`, M6): branded on-prem speedtest page and local-leg server; results
  to its collector; diagnosis and analytics in collector/dashboard (`12-speedtest-analytics.md`).

## 7. Key flows

### 7.1 Deploy the manager (once)
`manager/deploy.sh` with a scoped Cloudflare API token → creates D1, R2, secrets, migrations,
Worker, Access application + policy (owner email) → prints the URL. Admin opens it and signs in
through Access. Detail: `05-manager.md §9`, `08-operations.md §3`.

### 7.2 Add a host ("point at an Ubuntu host, pick a shape")
1. Manager UI → **Add host**: name, site, shapes (any of probe/collector/dashboard/runner).
2. Manager shows a single command with a single-use, 1-hour enrol token:
   `curl -fsSL https://<manager>/install.sh | sudo bash -s -- expe_XXXXXXXX…`
3. Admin runs it on the host. `install.sh` checks the OS, downloads and verifies the agent, and
   enrols: the token is exchanged for a per-agent credential.
4. The host appears in the UI with its **facts** (interfaces, addresses, time sync). For a probe,
   the admin ticks which interfaces are test ports (the management interface is refused).
5. The manager compiles desired state; the agent installs the components, configures them, wires
   probe → collector → dashboard (endpoints, pinned TLS fingerprints, tokens), and reports health.
6. Target: **host usable within 2 minutes of running the command** on a typical event VM.

### 7.3 Measure → see
Probe beat → spool → HTTPS batch → collector validates, binds identity, stores (VM + SQLite) →
rules engine updates line state/verdict → SSE pushes to dashboards (< 2 s write-to-screen) →
incidents → webhooks.

### 7.4 Upgrade
Admin imports release `vX.Y.Z` (from GitHub Releases or upload) → manager verifies the manifest
signature → admin sets target version per site (canary host first) → agents install, health-check,
and roll back automatically on failure.

### 7.5 Drill (M5)
Admin schedules a drill against an opted-in target → runner executes it with an auto-revert timer
→ probes measure → rules engine detects → drill report: expected vs observed detection, time to
detect, time to recover, pass/fail. Detail: `10-drills-integrations.md`.

## 8. Non-functional requirements

| Area | Requirement |
|---|---|
| Scale (per collector) | ≥ 50 probes, ≥ 600 test ports, ≥ 1,000 records/s sustained ingest. |
| Scale (per dashboard) | ≥ 20 collectors federated. |
| Scale (manager) | ≥ 500 hosts per organization. |
| Latency | Probe write → dashboard render < 2 s p95 on LAN. Desired-state change → agent applied < 60 s p95 (default poll 30 s). |
| Retention | Metrics 30 days, records 7 days (configurable). Probe spool 7 days / 500 MB. |
| Availability | Data plane fully functional with manager unreachable and with internet down. |
| Footprint | Probe ≤ 150 MB RSS; collector ≤ 2 GB RAM at max scale; agent ≤ 50 MB. |
| Time | All timestamps UTC ISO-8601 with `Z`. Hosts MUST run NTP; skew > 5 s is flagged. |
| Platforms | Ubuntu 22.04/24.04 LTS, amd64 and arm64. |
| Browser | Current Chrome, Edge, Firefox, Safari; usable at 390 px width; keyboard accessible. |
| Brand | HPE design language (`reference/netvitals/DESIGN.md`): HPE green `#01A982`, enterprise clarity, room-readable. |

## 9. Milestones and acceptance criteria

Each milestone is accepted only when its **end-to-end acceptance tests** (in `test/e2e/`) pass in CI.

### M1 — Data spine (manual install, no manager)
- Install probe + collector + dashboard on one Ubuntu VM (all-in-one) and on separate VMs from
  release tarballs with a local config file.
- **A1.1** Board shows all lines green within 30 s of start; beats render every 10 s.
- **A1.2** Blocking DNS on a probe's test-port namespace turns DNS red within 30 s with
  "where: resolver/dns_path"; unblocking turns it green and logs an incident (down→back).
- **A1.3** Rewind (`?at=`) to a past incident shows the state at that moment.
- **A1.4** Collector restart: no duplicate and no missing records (probe spool replays).
- **A1.5** Ingest rejects records whose `probe` ≠ token identity, reserved labels, bad timestamps.

### M2 — Control plane
- **A2.1** `deploy.sh` deploys the manager to a fresh Cloudflare account; owner signs in via Access.
- **A2.2** Admin API refuses requests without a valid Access JWT, even if Access were bypassed
  (direct Worker request with a forged header → 401). *Enforcement test.*
- **A2.3** Add host → one-liner → host enrols, reports facts; assigned shapes converge < 2 min;
  probe data reaches the collector; dashboard opens via SSO handoff from the manager.
- **A2.4** Enrol token is single-use and expires; enrol endpoint is rate-limited (> 10/min/IP → 429).
- **A2.5** Upgrade to a new release; a deliberately broken release auto-rolls back; an unsigned or
  tampered artifact is refused.
- **A2.6** Rotate a probe ingest token and the agent secret without data loss.
- **A2.7** Decommission a host: components removed, credentials revoked, host gone from UI.
- **A2.8** Fleet view: every host shows CPU/memory/disk/uptime/pps/bps and its component metrics
  within 2 status intervals; filling a collector disk past 85 % opens a `disk_high` issue; stopping a
  host's agent marks it `stale` then `offline` — never shown as current.

### M3 — Multi-site, alerts, offline
- **A3.1** 3 collectors × 2 sites federated in one dashboard; overview correct.
- **A3.2** Slack/Teams/JSON webhooks with holds, again, flapping, folding (port of EXM behaviour).
- **A3.3** Manager unreachable for 30 min → no data loss, alerts still fire, dashboards work.
- **A3.4** Internet uplink down → LAN dashboard login (local user / NOC token) works.

### M4 — Measurement depth
- **A4.1** Path quality (netvitals lineage): bidirectional UDP/TCP to the collector reflector, with
  forward/return loss, jitter, MOS, PQI.
- **A4.2** Throughput: Cloudflare speed test + iperf3 to the collector; never two concurrent throughput tests per probe.
- **A4.3** Target-server ports (static IP, HTTP/HTTPS/ICMP, fault controls) — EXM `server.py` lineage.
- **A4.4** Linux Wi-Fi client probe on a Wi-Fi interface (SSID join, RSSI/SNR, roam detection).

### M5 — Drills and correlation
- **A5.1** Local drills (DNS block, gateway block, port down, netem) detected with correct "where".
- **A5.2** EC Orchestrator drills (WAN interface down, VRRP master fail) against an allowlisted
  test appliance, auto-restored, with time-to-detect/recover in the report.
- **A5.3** Kill switch aborts and restores within 5 s.
- **A5.4** Mist and EC events appear as markers on the board timeline.

### M6 — Speedtest analytics
- **A6.1–A6.8** in `12-speedtest-analytics.md` §11: two-leg test from a zone QR code in ≤ 20 s;
  local leg ≥ 2 Gb/s; abuse limits and token-checked Worker; drill-verified diagnoses (`wifi_signal`,
  `wan_saturation`, `policy_block`, `network_wide`); identity resolution with fallback; anonymous-mode
  deletion verified; works with the internet down; no per-user labels in VM.

## 10. Repository layout

```
exp/
  SPEC.md  KICKOFF.md  README.md  ROADMAP.md  VERSION  Makefile
  docs/spec/                 specification (this set)
  shared/                    contracts: schemas/, openapi/, python/exp_common/, ui/   (integrator-owned)
  probe/                     exp-probe        (Python)
  collector/                 exp-collector    (Python + VictoriaMetrics)
  dashboard/                 exp-dashboard    (Python server + static SPA)
  agent/                     exp-agent + install/install.sh (Python)
  runner/                    exp-runner       (Python, M5; correlation connectors M6)
  speedtest/                 exp-speedtest    (Python server + static page, M6)
  manager/                   exp-manager: worker/ (TS), ui/ (TS SPA), migrations/, deploy.sh, wrangler.toml
  packaging/                 build + sign scripts, systemd unit templates, release keys (public)
  test/                      fixtures/, harness/ (container LAN), e2e/
  reference/                 read-only prior art — NEVER imported by product code
  .github/workflows/         CI + release
```

## 11. Out of scope for v1
Multi-tenant hosted SaaS; Windows/macOS probes (the EXM macOS Wi-Fi agent stays reference-only);
non-Ubuntu hosts; Kubernetes deployment; long-term (> 30 day) analytics; SNMP/device polling (exp
measures experience, not devices — devices enter only as correlated events).

## 12. Future options (not v1)
Cloudflare Tunnel remote access to dashboards behind Access; Durable-Object push for instant
desired-state delivery; central TSDB roll-up across sites; LLM-assisted root-cause summaries over
incidents + correlated events; synthetic voice/video (WebRTC) tests.

## 13. Open questions for the owner (defaults assumed until answered)

| # | Question | Default assumed |
|---|---|---|
| Q1 | Single-tenant per deployment, or a hosted multi-tenant SaaS later? | Single-tenant (D6). |
| Q2 | Access identity provider? | One-time PIN by email; any IdP can be added in Zero Trust. |
| Q3 | License? | Proprietary/private until decided. |
| Q4 | Wi-Fi probe hardware (USB adapter model)? | Any `nl80211` adapter supported by `iw`/`wpa_supplicant`. |
| Q5 | Which EC Orchestrator / appliances are allowed drill targets? | None until allowlisted in the UI. |
| Q6 | Brand name and casing in UI ("HPE exp", "EXP")? | "exp" in code, "HPE EXP" in UI titles. |
| Q7 | Speedtest: domain/cert, security log sources, identity source, privacy sign-off, WLAN platforms? | See `12-speedtest-analytics.md` §13. |
