# 10 — Resilience drills and event correlation (M5)

Two capabilities built on the platform:
1. **Drills** (chaos_monkey lineage): deliberately inject a bounded fault and verify that the
   network fails over and/or exp detects it correctly — with time to detect and time to recover.
2. **Correlation** (EXM handoff task): pull device events from Mist and the EdgeConnect
   Orchestrator and place them on the same timeline as the experience data, so "what broke"
   (exp) sits next to "why" (device events).

Prior art: `reference/chaos_monkey/sdwan_chaos_monkey.py` (`run_wan_interface_chaos_test`,
`run_vrrp_chaos_test`, include/exclude node filters, continuous cycles), `reference/exm/lib/exm/server.py`
(target-port faults, netem).

## 1. Concepts

| Object | Meaning |
|---|---|
| **Drill** | A definition: type, target, parameters, duration, expectations, schedule (once or recurring). |
| **Run** | One execution of a drill: `scheduled → preflight → active → reverting → done\|aborted\|failed`. |
| **Executor** | The component that applies the fault: the **probe** for `local.*` drills, the **runner** for `ec.*`. |
| **Expectation** | What should happen: e.g. "DNS line fails within 30 s with `where = dns_path`", or "no line fails for more than 5 s (failover works)". |

## 2. Drill types

| Type | Executor | Fault | Revert | Typical expectation |
|---|---|---|---|---|
| `local.dns_block` | probe | drop UDP/TCP 53 in one port's namespace (tagged nft rules) | delete exactly those rules | DNS fail, `where=resolver\|dns_path`, TTD ≤ 30 s |
| `local.gateway_block` | probe | drop traffic to the gateway in one port's namespace | delete rules | Network warn (one port), `where=ports` |
| `local.port_down` | probe | link down on one probe test port | link up | Network warn for that port |
| `local.netem` | probe | `tc netem` delay/loss/jitter on a test or target port | `tc qdisc del` | Apps/Path degraded |
| `local.target_fault` | probe | target server HTTP delay/status | clear fault | Apps fail for that target |
| `ec.wan_down` | runner | disable one WAN interface on an allowlisted EC appliance via the Orchestrator API | re-enable it | failover: no line fails > N s; or detection at `edge` |
| `ec.vrrp_fail` | runner | bring down the LAN interface on the current VRRP master (allowlisted appliance) | bring it back | VRRP failover within N s; Network/Internet impact ≤ N s |

Local drills only ever touch the probe's **own** test ports and namespaces — they simulate
failures from a client's point of view without affecting anyone else.

## 3. Execution model

1. An admin creates a drill (UI or API). It is validated: drills enabled for the org, target in the
   allowlist, duration ≤ cap, one external drill per site at a time.
2. Approval (second admin when `drills_two_person`). Start (now or scheduled ≥ 2 min ahead).
3. The manager compiles the run into the executor's desired state:
   `drills: [{"run_id","type","params","start","until","abort":false}]` (probe or runner config).
   While a run is within `[start − 60 s, until + 60 s]`, the executing host's agent polls every **2 s**.
4. **Preflight** at `start`: target healthy, the site's lines ok for the last 2 min, no open
   incidents, executor clock synced. Any failure → run `failed` with the reason; nothing is changed.
5. The executor **writes the revert intent to disk first** (`/var/lib/exp/<executor>/drills/<run>.json`
   with `until`), then applies the fault, then posts `drill` measurements (`phase=start`).
6. At `until`, or on abort, it reverts, verifies the revert (re-reads interface/rule state or the
   Orchestrator object), and posts `phase=revert` (or `abort`). On executor restart, any intent
   whose `until` has passed — or whose run is no longer desired — is reverted immediately.
7. The collector correlates the run with states and incidents: **TTD** (fault start → expected
   line state), **TTR** (revert → line ok), max impact (lines and durations), and pass/fail against
   the expectation. The report is available via `GET /api/v1/drills/{run_id}` and is summarized to
   the manager through the executor's status facts.

**Abort paths (≤ 5 s, A5.3):** (a) manager UI/API abort or **abort-all** → desired state
`abort: true` (agents are fast-polling); (b) dashboard **Abort** (operator, LAN, works offline) →
`POST /api/v1/drills/{run_id}/abort` on the collector → executors poll
`GET /api/v1/drills/control` on their collector every 2 s while a run is active. Either path triggers
an immediate revert.

## 4. Guardrails (all mandatory)

1. **Off by default.** Only an owner can enable drills for the organization.
2. **Allowlist.** External targets (appliance `nePk` + interface name, or VRRP group) must be
   allowlisted by an owner from the discovered inventory. Nothing outside the allowlist can be
   targeted — the runner re-checks the allowlist from its own config before acting.
3. **Time box.** Default 120 s, hard cap 900 s, enforced by the manager, the executor, and the
   persisted revert intent.
4. **Revert before fault.** The revert intent is persisted before the fault is applied.
5. **One at a time.** At most one external drill per site and one local drill per port.
6. **Preconditions** (§3.4) — the system refuses to start a drill on an already unhealthy network.
7. **Kill switch** — both abort paths, ≤ 5 s.
8. **Dry run** — validates targets, permissions, and API reachability with read-only calls.
9. **Two-person approval** (optional setting) for external drills.
10. **Audit** every create/approve/start/abort/revert, with actor and outcome; timeline markers
    on every affected board.

## 5. EdgeConnect Orchestrator integration

- Configured by an owner: base URL, API key (write-only secret), optional CA bundle for an on-prem
  Orchestrator (TLS verification always on), and the drill allowlist.
- Calls observed in the reference implementation: `GET /gms/rest/appliance`,
  `GET /gms/rest/deployment?nePk=…`, `GET /gms/rest/appliance/rest?nePk=…&url=vrrp&cached=false`,
  and interface get/set through `/gms/rest/appliance/rest?nePk=…&url=networkInterfaces`.
- **The API key is sent only in a request header** (per the Orchestrator API docs, e.g.
  `X-Auth-Token`) — never in the URL query string. Request URLs, headers, and exception text are
  redacted before logging (the reference code put `apiKey=` in URLs and logged request exceptions).
  The runner exposes no inbound HTTP/Socket interface.
- **Request and response field names MUST come from the Orchestrator API documentation
  (`orchestrator-apiDocs.json`) or recorded live responses — not from the reference code.** Fixtures
  built from code encode its bugs (lesson from earlier work). The CI fake Orchestrator is built from
  those documents.
- The runner reports discovered inventory (appliances, WAN interfaces, VRRP groups) in its status
  facts so the manager UI can offer allowlist choices; discovery is read-only.

## 6. Correlation pullers (runner)

| Source | Pulled | Normalized to |
|---|---|---|
| Mist | site events (AP/switch/gateway up/down, port events, config changes), via the Mist API token | `ext_mist` measurement: `target` = device name, labels `kind` (`ap\|switch\|port\|gateway`), `severity`; `detail` = `{device_id, event, message, raw_id}` |
| EC Orchestrator | alarms and audit/events for the appliances serving the site | `ext_ec`: labels `kind` (`wan\|tunnel\|vrrp\|appliance`), `severity`; `detail` = `{nePk, alarm, message, raw_id}` |

The runner posts these to its collector with its own ingest token (identity-bound like a probe),
deduped by `raw_id`. Pull every 60 s with backoff; respect API rate limits (Mist ~5,000 requests
per hour per token). Boards show them as timeline markers; incidents list nearby events ("Mist:
switch port ge-0/0/12 down at 22:00:18").

## 7. Contracts added by this document

Already reflected in `01-contracts.md`: test `drill` (§3), probe and runner `drills` config (§9),
collector drill endpoints (§5).

## 8. Acceptance (A5.x)

1. Each `local.*` drill on the harness: correct detection and `where`, TTD/TTR reported, revert
   verified, nothing left behind (rules, qdiscs, link state).
2. `ec.wan_down` and `ec.vrrp_fail` against the documentation-built fake Orchestrator: allowlist
   enforced (non-allowlisted target refused at manager **and** runner), revert verified, report correct.
3. Kill switch via manager and via dashboard (manager unreachable) → reverted within 5 s.
4. Runner killed mid-drill → on restart the fault is reverted immediately.
5. Preconditions refuse a drill while an incident is open.
6. Mist and EC events appear as markers at the right times on the board.
