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

## Open decisions (gating detailed build)

### D1. How does the Cloudflare-hosted manager provision an Ubuntu host?
Cloudflare Workers can't hold a persistent outbound SSH session, so "the SaaS SSHes in" needs a
concrete shape. Three candidates (tradeoffs in the decision record once chosen):
- **Agent-pull + one-liner bootstrap** — admin runs a `curl … | sudo bash` from the dashboard on
  the host; a tiny `exp-agent` enrols and continuously pulls its role/config/secrets. No host
  passwords stored in the SaaS; works behind NAT. Simplest/safest steady state.
- **SSH push via a self-hosted deployer** — admin enters SSH user/password in the UI; a small
  deployer the operator runs performs the install over SSH. Matches "just give it SSH creds";
  the SaaS holds host credentials (encrypted).
- **Hybrid** — admin enters SSH creds; a deployer uses them *once* to lay down the agent, then
  discards them; steady state is agent-pull.

### D2. TSDB in the collector.
Candidates: VictoriaMetrics (single small binary, Prometheus-compatible, push+pull), a
SQLite/DuckDB-based store (max simplicity, EXM-JSONL evolution), Prometheus (+pushgateway), or
InfluxDB. Choice sets the collector's ingest and query layer.

Both are being settled now; the rest of the architecture is stable regardless.
