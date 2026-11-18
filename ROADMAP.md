# exp — Roadmap

Built in thin, runnable slices. Each phase ends with something you can actually use.

## Phase 0 — Foundation ✅
Repo, README, architecture, the measurement schema (`shared/`), decisions locked
(agent-pull provisioning; VictoriaMetrics TSDB).

## Phase 1 — Data spine (runnable MVP)
The experience-monitoring core, reusing EXM, no control plane yet.
- **probe/** — `exp-probe`: runs a handful of tests (gateway, DNS, app reachability, heartbeat),
  emits `Measurement` records, pushes them to a collector. Local spool so a brief outage is lossless.
- **collector/** — `exp-collector`: HTTP ingest endpoint → validate → write to VictoriaMetrics;
  a query API (current state + range) the dashboard calls.
- **dashboard/** — minimal admin view off the collector API: per-site/probe experience lines.
- **Milestone:** `docker compose up` (VM + collector) + a probe on a host → live telemetry in the dashboard.

## Phase 2 — Control plane (the SaaS)
What makes it a platform, not just EXM.
- **manager/** — Cloudflare Worker: admin sign-in, host inventory, desired-state store (D1/KV/R2/DO),
  enrol endpoint + one-liner bootstrap, artifact & secret distribution, status ingest.
- **agent/** — `exp-agent`: bootstrap, enrol (token → per-agent key), reconcile loop
  (pull desired role/config/secrets/version → apply → report).
- **Milestone:** add a host in the dashboard, run one command on it, watch it become a probe/collector/dashboard on its own.

## Phase 3 — Operability & depth
- Packaging & signed upgrades driven by the manager; multi-site collector roll-ups.
- Alerting (incidents, webhooks) — carry EXM's rules.
- chaos/perf probe behaviours (opt-in perturb-and-measure).
- Test suites per component (unit + container integration), CI.

## Principles
- Simplicity for deployment and operation above all.
- Reuse EXM where proven; don't rebuild what works.
- Low-cardinality metrics; records carry the detail.
- Least-privilege, rotatable, revocable credentials; no shared host master secret.
