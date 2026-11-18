# exp — Roadmap

Milestones and their acceptance tests are defined in [SPEC.md §9](SPEC.md); the parallel build plan
is in [docs/spec/09-work-packages.md](docs/spec/09-work-packages.md).

| Milestone | Delivers | Status |
|---|---|---|
| **M0 — Specification & contracts** | Spec set, decisions, hardened measurement schema; WP-0 turns contracts into schemas/OpenAPI/`exp_common`/fakes | Spec ✅ · WP-0 pending |
| **M1 — Data spine** | Probe, collector (VictoriaMetrics, rules, incidents, query API), dashboard; manual install from tarballs | pending |
| **M2 — Control plane** | Cloudflare manager, agent + one-line bootstrap, signed releases, rollout/rollback, rotation, decommission, **fleet health UI** (roll-ups, issues, hosts/component views) | pending |
| **M3 — Multi-site, alerts, offline** | Federation across collectors, Slack/Teams/JSON webhooks, NOC tokens, manager/internet-down operation | pending |
| **M4 — Measurement depth** | Path quality (MOS/PQI), throughput (Cloudflare + iperf3), target ports, Linux Wi-Fi probe | pending |
| **M5 — Drills & correlation** | Local and EC Orchestrator drills with guardrails and reports; Mist/EC events on the timeline | pending |
