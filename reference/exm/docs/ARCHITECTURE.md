# Architecture

## Components and data flow

```
probe VM (exm-probe)                                   collector VM (exm-collector)
─────────────────────                                  ────────────────────────────
supercronic (exm-cron) ─► exm run dhcp|dns|apps|speedtest      exm-follow@<probe> ── ssh ──► exm stream (on the probe)
                       ─► exm heartbeat (every 10 s)                  │ checks every line (remote.Ingest)
                       ─► exm summary --emit (every minute)           ▼
exm-dhcp@<port>  udhcpc lease holders, one per namespace       /var/lib/exm-collector/probes/<probe>/<day>/<test>.jsonl
exm-server@<port> Minis targets (static, HTTP/HTTPS/ping)              │
        │                                                             ├─► exm-web    boards, overview, APIs (read-only)
        ▼                                                             └─► exm-alert  rules (pulse.py) ─► incidents log ─► webhook
/var/lib/exm/results/<day>/<test>.jsonl  (7 days)
```

- **Pull, not push.** The collector connects out to each probe's management address. Probes need no credentials for the collector, and the collector needs no inbound ports except the dashboard's. A probe keeps 7 days, so a collector restart or network break loses nothing: each follower asks for everything since the last line it stored (`stream since=<emitted>`), bounded by `backfill_hours`.
- **One board per probe.** A board reads its probe's results directory plus those of any laptops attached to it (`attach_to`), whose `wifi_*` results form its Wi-Fi row. A local probe (all-in-one) is read in place.
- **The details tables come from the probe.** Only the probe knows its ports and their roles, so it computes the summary (`report.dashboard_summary`) and publishes it every minute as a `summary` result; the collector adds Wi-Fi.

## Trust boundaries

| Boundary | Control |
|---|---|
| collector → probe | the collector's ed25519 key, accepted only for user `exm-stream`, with `restrict,command="/opt/exm/bin/exm stream"` (no shell, pty or forwarding; optional `from=`). `exm stream` accepts `stream` or `stream since=<UTC>` and nothing else. The probe's host key is pinned on the collector (`StrictHostKeyChecking=yes`). |
| collector → laptop | the same model: `command="…/stream.sh"`, which accepts `stream [ssid-hex=<hex>]` only |
| probe/laptop → collector (data) | every line is untrusted: JSON only (no NaN/Infinity), test names `[a-z][a-z0-9_]{0,31}` (they name files), timestamps well formed and not in the future, nesting depth ≤ 10, strings ≤ 4096, lists ≤ 5000, numbers finite, line ≤ 256 KB (16 KB from a laptop, rebuilt from a fixed schema), `probe_id` overwritten with the configured name, duplicates dropped |
| browser → dashboard | read-only GETs on fixed routes; no login (a deliberate choice for the lab); text is rendered with `textContent`, never as HTML |
| secrets | the webhook URL: `/etc/exm/alert-webhook`, root 0600 (empty: incidents logged, nothing sent), handed to the unprivileged alerter by systemd `LoadCredential`, never logged. The collector's SSH keys and pinned host keys: `/etc/exm/collector/keys/`, owned by root, readable by the `exm-collector` group only (0750 / keys 0640): the followers can use them, never change them. |
| services | probe tests run as root (raw sockets, namespaces). On the collector: the dashboard runs as a DynamicUser with a read-only filesystem; followers and the alerter run as `exm-collector` and may write only the `probes/`, `state/` and `incidents/` directories under the root-owned `/var/lib/exm-collector`. Root never changes ownership recursively and refuses symlinks wherever it touches a path, so a compromised service user cannot steer root's file operations. On the probe, the `exm-stream` user owns nothing: its home, `.ssh` and `authorized_keys` are root's. |

## The result line

One JSON object per line, `ts` first (the readers find a line's time by its position). Written by `events.emit` under an exclusive lock, which also stamps `emitted`, so each file is in `emitted` order.

| Field | Meaning |
|---|---|
| `ts` | when the test started (UTC, ms) |
| `emitted` | when the line was written; the collector's resume cursor |
| `probe_id`, `client_id`, `iface`, `vlan`, `zone` | where it ran (`client_id` null for whole-probe tests) |
| `test`, `target`, `resolver` | what ran, against what |
| `outcome` | `ok`, `degraded`, `fail`, `portal`, or `harness_error` (the probe failed, never the network) |
| `phase_ms` | timings (e.g. DHCP phases, `rtt`, `gateway`, `dns`) |
| `value` | the test's own detail (e.g. the gateway check's per-port map, a traceroute's hops) |
| `error`, `agent_ver`, `config_ver`, `hw_class` | |
| `source` | on the collector: `probe:<name>` or `remote:<laptop>` |

Tests: `gateway`, `dhcp_hb`, `dns_hb` (with `alt` and `ping_ms`), `trace`, `trace_ctl`, `dhcp`, `dhcp_lease`, `dns`, `dns_dot`, `dns_intercept`, `app`, `speedtest`, `server_access`, `summary`; from laptops `wifi_hb`, `wifi_app`, `wifi_speed`.

The dashboard works on a compact form of each line (`web.compact`): `t w k c g r o m l e`, plus per test `up n down flap ug nl` (gateway), `rc lh lt dt hp` (traceroutes), `sx sp ax ao ap` (DNS heartbeat), `sv` (DHCP heartbeat), `rs p sd tg gk` (Wi-Fi). `l` is the board line: 0 Network, 1 DHCP, 2 DNS, 3 Internet, 4 Wi-Fi, or null (diagnostic only).

## The rules

`lib/exm/static/pulse-core.js` (the page) and `lib/exm/pulse.py` (the alerter and the overview) implement the same rules: beats per line, a line's state (fail when half or more of its recent beats failed; windows 30 s, Internet 2 min), when a problem began (`since`, "before" when the loaded data runs out), the last outage, flapping, and **where** (`whereOf`): link, switch, gateway, lan, edge, isp, wan, resolver, dns_path, apps, dhcp, ssid, wifi. `test/unit.sh` replays a real outage through both and fails on any difference. Change one, change the other.

## Storage and state

| Path | What |
|---|---|
| probe `/var/lib/exm/results/` | results, 7 days (`exm prune`) |
| probe `/var/lib/exm/state/` | rotations, lease state, gateway carrier counters |
| collector `/var/lib/exm-collector/probes/<name>/` | streamed results, 14 days (prune timer) |
| collector `/var/lib/exm-collector/state/follow-<name>.json` | each follower's cursor (`hwm`) |
| collector `/var/lib/exm-collector/state/alert-<board>.json` | open incidents, so a restart doesn't page twice |
| collector `/var/lib/exm-collector/incidents/<board>.jsonl` | every down / again / flapping / back, with start, end, what, where and the board link |

## Extending: correlation with Mist and EdgeConnect

The incident log and the APIs are the entry points for root-cause work:

- `GET /api/incidents?probe=NAME&hours=24`: what broke, when (`start_iso`, `end_iso`), on which line, the facts, and `where` (e.g. `{"seg": "edge", "lh": "10.1.0.2", "lt": 1}`).
- `GET /api/history?probe=NAME&minutes=30&at=<UTC>`: the evidence around a moment.
- `GET /api/boards`: every probe's lines and verdict right now.

For a timeline of device events (Mist AP/switch/port events and config audits, EdgeConnect alarms and template pushes), the natural shape is one more kind of result, written by whatever fetches them (an MCP-driven session, or a poller on the collector) into `/var/lib/exm-collector/probes/<board>/<day>/ext_<source>.jsonl` with the same line format (`ts` first, `test: "ext_mist"`, `outcome`, `target` the device, `value` the event, `error` a one-line summary). Then:
1. `web.compact` maps `ext_*` to a new compact kind with `l: null`, so it never colours a line.
2. `web.LIVE_TESTS` includes it, so it streams and rewinds with everything else.
3. `pulse.html` draws it as a marker on the time axis, and "What's failing" lists events within a few minutes of the moment shown.
4. `alert.Alerter._facts` adds nearby events to a page ("Mist: switch port ge-0/0/12 down at 22:00:18").

The probe and its stream don't change for any of this; only the collector does.
