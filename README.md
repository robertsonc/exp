# exp — Event network eXperience Platform

Synthetic users on the event network measure what attendees experience — link, DHCP, DNS,
internet, apps, Wi-Fi, path quality — every 10 seconds. Collectors store it in VictoriaMetrics and
turn it into one-sentence verdicts with *where* the path is breaking. Dashboards show it to the NOC,
on the LAN, even when the internet is down. A Cloudflare-hosted central manager deploys and runs
everything from admin intent: point it at an Ubuntu host, pick a shape, paste one command.
Resilience drills prove the monitoring and the network's failover actually work.

**Mantra: simplicity for deployment and operation.**

## Status

**Specification complete; implementation not started** (except the hardened measurement schema in
`shared/`). Build it with a multi-agent session — start at [KICKOFF.md](KICKOFF.md).

## Documents

| | |
|---|---|
| [SPEC.md](SPEC.md) | Source of truth: principles, architecture, decisions, milestones, acceptance |
| [KICKOFF.md](KICKOFF.md) | How to run the build (multi-agent), with a paste-ready prompt |
| [docs/spec/](docs/spec/) | Contracts, component specs, security, operations, work packages, drills |
| [ROADMAP.md](ROADMAP.md) | Milestones M0–M5 |
| [reference/](reference/README.md) | Prior art to port from (EXM, netvitals, perf, chaos_monkey) — read-only |

## Components

| Shape | What it does | Tech |
|---|---|---|
| **Probe** | owns test ports, behaves like an attendee's device, measures, ships to its collector | Python 3.10+ |
| **Collector** | ingest, VictoriaMetrics, rules engine (state, verdict, where), incidents, alerts, query API | Python + VictoriaMetrics |
| **Dashboard** | auth, federated queries, the Pulse board, overview, incidents, NOC/kiosk mode | Python + static SPA |
| **Runner** | resilience drills (EC Orchestrator) and Mist/EC event correlation, on-prem | Python |
| **Central manager** | SaaS control plane: intent, desired state, signed releases, secrets, users, audit — and the **fleet health roll-up** (CPU/memory/disk/uptime, pps/bps, measurements, storage runway, issues) | Cloudflare Workers (TS), D1, R2, Access |
| **Agent** | enrols a host with one command and keeps it converged to desired state | Python |

## Lineage

EXM (event experience monitor — the direct ancestor), Network Vitals (bidirectional path quality,
MOS/PQI), sdwan_perf (multi-vantage throughput), SD-WAN chaos monkey (failover drills).
