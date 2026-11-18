# exp — Architecture

Draft. Component responsibilities are settled; two foundational decisions are open (end of doc)
and gate the detailed build. Written to the mantra: **simplicity for deployment and operation.**

## Component responsibilities

### Probe (Python, on Ubuntu hosts near the users)
- Generates and measures synthetic network transactions on the event network: DHCP lease, DNS
  resolution, gateway reachability, app reachability/Apdex, throughput, heartbeats. (Evolves
  from EXM `lib/exm` tests.)
- Emits structured **measurement records** (one schema, in `shared/`) — status + timing + context.
- Reports to a collector. Stateless beyond a short local spool so a brief collector outage
  loses nothing.
- Optional perturbation behaviours (chaos/perf lineage): inject a fault or load and measure the
  response — always opt-in, always scoped to the event network.

### Collector (Python)
- Receives probe reports (push), de-duplicates, and writes them to a **TSDB**.
- Serves the dashboard's query API (current state, history/rewind, incidents).
- One collector can serve many probes; multiple collectors roll up to the dashboard.

### Dashboard (static SPA)
- Read-only admin view of network experience: a one-line verdict, per-dimension lines
  (network/DHCP/DNS/internet/wifi), drill-down, drag-to-rewind, "what's failing / where".
  (Evolves from EXM Pulse.)
- Talks only to the collector API. No business logic in the browser.

### Central manager (Cloudflare Workers, SaaS)
- The one place an admin signs in. Holds the **desired state** of the whole platform.
- Admin registers a host (address + access) and declares a **shape**: probe, collector, or
  dashboard. The manager turns that intent into a deployed, configured, secret-provisioned
  component.
- Responsible for **distribution**: software artifacts, secrets, config, metadata — delivered
  to the right component, by intent, with an audit trail.
- Storage: Cloudflare D1 (relational state/inventory), KV (fast config lookups), R2 (software
  artifacts), Durable Objects (per-host coordination), Workers Secrets / encrypted columns
  (secrets at rest). Auth via an identity provider (TBD, likely Cloudflare Access or OIDC).

## Data flow

1. Probe runs tests on a schedule → emits measurement records.
2. Probe pushes records to its collector → collector writes to TSDB.
3. Dashboard queries the collector → renders live experience + history.
4. Central manager, out of band, keeps every component on its intended software + config +
   secrets, and records what's deployed where.

## Trust & secrets (principles, carried from EXM/SASE work)

- The central manager is the root of trust for distribution. Every component authenticates to
  the manager (and/or its collector) with a per-component credential the manager issues.
- Secrets are delivered over authenticated channels and never logged. Least privilege per
  component. Credentials are rotatable and revocable from the manager.
- A component compromise must not expose the whole platform (scoped credentials, no shared
  long-lived master secret on hosts).

## Decisions (resolved 2026-11-18)

### D1 — Host provisioning: **agent-pull + one-liner bootstrap**
Cloudflare Workers can't hold a persistent outbound SSH session, and storing host passwords in a
SaaS is a liability — so provisioning is pull-based:

- Admin adds a host in the dashboard and gets a short-lived enrol command:
  `curl -fsSL https://<mgr>/enrol/<token> | sudo bash`.
- The bootstrap installs **`exp-agent`**, which exchanges the single-use enrol token for a
  long-lived **per-agent credential**, then continuously pulls its **desired state** — assigned
  role (probe / collector / dashboard), config, secrets, and software version — and reconciles
  the host to it (install/upgrade, write config, place secrets, (re)start the service).
- No SSH passwords are ever stored in the SaaS. All traffic is agent → manager, outbound only
  (NAT-friendly). Per-agent credentials are rotatable and revocable from the manager.

### D2 — TSDB: **VictoriaMetrics** (single-node to start)
- The collector writes probe measurements to VictoriaMetrics (JSON-line import / Prometheus
  remote-write). The dashboard queries through the collector, which proxies MetricsQL/PromQL.
- **Cardinality discipline:** series labels stay low-cardinality (`probe`, `site`, `test`,
  `outcome`, `iface`, `resolver`). High-cardinality values (specific URLs, trace hops) live in
  the full measurement record / event log, not as series labels. See `shared/`.

## Agent ↔ Manager protocol (sketch)

- `POST /enrol` `{enrol_token}` → `{agent_id, agent_key}` — token is single-use, short TTL.
- `GET /agents/{id}/desired` (auth: `agent_key`) → `{role, version, config, secrets, ...}`.
- `GET /artifacts/{name}/{version}` → signed software bundle (R2).
- `POST /agents/{id}/status` → health, running version, last reconcile result.

Manager storage: **D1** desired state & inventory, **KV** fast config, **R2** software artifacts,
**Durable Objects** per-host coordination, encrypted secrets delivered only over the
authenticated pull. Admin auth via Cloudflare Access / OIDC.

## Measurement contract

Defined in `shared/` (`exp_schema.py` + `SCHEMA.md`): one record per measured transaction, with
numeric `metrics` that map to VictoriaMetrics series as `exp_<test>_<metric>`. This is the single
contract probes, collectors, and the dashboard share.
