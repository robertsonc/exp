# exp — Event network eXperience Platform

Network **experience** monitoring for event networks: synthetic probes measure what a real
user's traffic would see (can I get a lease, resolve a name, reach the apps, how fast),
collectors aggregate those measurements into a time-series database, and a dashboard shows
admins the live experience and where it's breaking.

**Mantra: simplicity for deployment, and simplicity for operation.** One command to stand up
a component. One place to see everything. No per-host babysitting.

## Lineage

`exp` builds directly on work already done:

- **EXM** (`~/labs/exm`) — the direct ancestor. Its Python probe library (gateway, DHCP, DNS,
  apps, speedtest, heartbeats), SSH-pull collector, and Pulse dashboard are the starting point
  for `exp`'s probe, collector, and dashboard.
- **netvitals** — network-quality measurement and a self-contained web UI.
- **chaos / perf** — fault-injection and load/latency concepts, folded in as optional probe
  behaviours (a probe can also *perturb* and measure the response).

What `exp` adds beyond EXM: a real **TSDB** in the collector, and a **central manager** that
turns admin intent into deployed, configured, secret-provisioned components across many hosts.

## Components

| Component | What it is | Language |
|---|---|---|
| **Probe** | Lightweight package that generates and measures network transactions, reports status + measurements | Python |
| **Collector** | Central collection point; ingests probe reports, aggregates into a TSDB, serves the dashboard API | Python |
| **Dashboard** | Where admins watch network experience — stats and telemetry from the platform | Static SPA |
| **Central manager** | SaaS orchestrator on Cloudflare. Admin signs in, points at an Ubuntu host, picks a shape (probe/collector/dashboard); the manager distributes software, secrets, config, and metadata per intent | Cloudflare Workers (TS) |

## How it fits together

```
                         ┌──────────────────────────────────────┐
                         │   Central Manager  (Cloudflare SaaS)  │
                         │   intent → software, secrets, config  │
                         └───────────────┬──────────────────────┘
             deploy / configure / enrol  │  (model TBD — see docs/ARCHITECTURE.md)
          ┌─────────────────────────────┼─────────────────────────────┐
          ▼                              ▼                             ▼
   ┌─────────────┐  reports      ┌───────────────┐   query      ┌───────────────┐
   │   Probes    │ ─────────────▶│   Collector   │ ◀─────────── │   Dashboard   │
   │ (Ubuntu)    │  measurements │  + TSDB        │  telemetry   │  (admins)     │
   └─────────────┘               └───────────────┘              └───────────────┘
```

## Status

Scaffolding. Two foundational decisions are being settled before component build-out — see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): (1) how the Cloudflare manager provisions a host,
and (2) the TSDB. Everything else follows the EXM patterns.

## Layout

- `manager/` — Cloudflare Worker central manager (SaaS)
- `probe/` — Python probe package
- `collector/` — ingest + TSDB + dashboard API
- `dashboard/` — admin SPA
- `shared/` — result/event schema and config contracts
- `docs/`, `scripts/`
