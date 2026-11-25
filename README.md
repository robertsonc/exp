# exp — Event network eXperience Platform

Synthetic users on the event network measure what attendees experience — link, DHCP, DNS,
internet, apps, Wi-Fi, path quality — every 10 seconds. Collectors store it in VictoriaMetrics and
turn it into one-sentence verdicts with *where* the path is breaking. Dashboards show it to the NOC,
on the LAN, even when the internet is down. A Cloudflare-hosted central manager deploys and runs
everything from admin intent: point it at an Ubuntu host, pick a shape, paste one command.
Resilience drills prove the monitoring and the network's failover actually work.

**Mantra: simplicity for deployment and operation.**

## Status

**Milestones M0–M3 and M6 implemented and accepted; v0.3.0 released (0.1.0: M0–M2; 0.1.1: M3 and the agent netns-port fix; 0.2.0: M6 speedtest and Raspberry Pi hosts; 0.3.0: heartbeat cadence and lab fixes).** Contracts; probe, collector, dashboard; Cloudflare
manager + admin UI; agent + one-line bootstrap; signed reproducible releases; CI. The M1 (A1.1–A1.5), M2 (A2.2–A2.8)
and M3 (A3.1–A3.4: multi-site federation, webhook alerts, manager outage, site internet outage) acceptance suites pass
in containers (`test/e2e/`); M1 runs in CI on every push, M1–M3 nightly (`e2e.yml`, A3.3 with the full 30-minute outage).
The control panel is deployed at https://exp-control.harnessed.cloud ([deployment record](docs/deployments/exp-control.md)).
Next: M4 (path quality, throughput, target ports, Wi-Fi),
M5 (drills, correlation), M6 (speedtest analytics) — see [ROADMAP.md](ROADMAP.md).

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
| **Speedtest** (M6) | self-contained, branded speedtest page served by an exp box; times Wi-Fi/LAN, DNS, gateway, edge, edge+1, and Cloudflare, and correlates each result with that device's Wi-Fi, flows, and security logs | Python + one-file page |
| **Central manager** | SaaS control plane: intent, desired state, signed releases, secrets, users, audit — and the **fleet health roll-up** (CPU/memory/disk/uptime, pps/bps, measurements, storage runway, issues) | Cloudflare Workers (TS), D1, R2, Access |
| **Agent** | enrols a host with one command and keeps it converged to desired state | Python |

## Lineage

EXM (event experience monitor — the direct ancestor), Network Vitals (bidirectional path quality,
MOS/PQI), sdwan_perf (multi-vantage throughput), SD-WAN chaos monkey (failover drills).
