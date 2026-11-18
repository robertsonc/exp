# reference/ — prior art (read-only)

Snapshots of earlier projects that exp builds on. **Product code must never import from here.**
Port the logic, cite the source in a comment, and write new tests against the exp contracts.

| Directory | Origin | What to port |
|---|---|---|
| `exm/` | HPE EXM 0.9.1 (`~/labs/exm`), event network experience monitor — the direct ancestor | Probe tests (`lib/exm/heartbeat.py`, `gateway.py`, `dhcptest.py`, `dnstest.py`, `apps.py`, `speedtest.py`), port/namespace handling (`netns.py`, `lease.py`, `hooks/`), target servers (`server.py`), **rules** (`pulse.py`: `beats`, `state_of`, `since_of`, `last_outage`, `flaps`, `where_of`; `static/pulse-core.js`), **alerts** (`alert.py`: `Alerter`, `PARENTS`, holds, escaping), details tables (`report.py`), dashboard UX (`static/pulse.html`, `overview.html`), test harness and package tests (`test/harness.sh`, `test/package.sh`, `test/unit.py`), the real outage fixture (`test/fixtures/outage-2026-10-27.jsonl.gz`), the macOS Wi-Fi agent (`mac/`, reference only). |
| `netvitals/` | Network Vitals (`~/netvitals`) — bidirectional path instrument | Path quality scoring (`netquality.py`: `quality_score` (MOS), `pqi_score`, `score_label`, `classify_loss_pattern`, `loss_verdict`), stream design; design language (`DESIGN.md`, `PRODUCT.md`). |
| `perf/` | `sdwan_perf` (`~/GitHub_robertsonc/perf`) — multi-vantage iperf3 harness | iperf3 orchestration and result parsing (`runner.py`), interface counter sampling (`poller.py` `WirePoller`), overhead/loss attribution (README table). |
| `chaos_monkey/` | SD-WAN chaos monkey (`~/bgintel/staging_tgen/chaos_monkey`) | Drill concepts: WAN-interface and VRRP-master failure tests, include/exclude target filters, continuous cycles (`sdwan_chaos_monkey.py`). **Take Orchestrator field names from the API docs, not from this code.** |

## Known defects in the reference code — do NOT port

Found by security review of these snapshots. They are left unmodified here (frozen prior art);
exp's specs forbid each pattern.

| Where | Defect | exp rule |
|---|---|---|
| `chaos_monkey/chaos_dashboard.py` | Web UI binds `0.0.0.0` with **no authentication** on state-changing routes (`/api/start_test`, `/api/stop_test`) and Socket.IO with `cors_allowed_origins="*"` | the runner exposes **no inbound interface** at all; drills are started only via the manager or the authenticated dashboard (`10-drills-integrations.md`, SR-12) |
| `chaos_monkey/chaos_dashboard.py` | HTML built with `innerHTML` from unescaped appliance/result fields (XSS) | untrusted text only via `textContent` (SR-13) |
| `chaos_monkey/sdwan_chaos_monkey.py` | Orchestrator API key appended to the **URL query string** (`apiKey=`), and request exceptions (which include the URL) logged | key only in a request **header**, URLs and exception text **redacted** before logging (`10-drills-integrations.md` §5, SR-14) |

If you still run the original chaos monkey dashboard (`~/bgintel/staging_tgen/chaos_monkey`), the
first two apply to it too: keep it bound to localhost or behind authentication.

Excluded on purpose: real configuration files (e.g. the chaos monkey's `nodes.yaml`), lab deployment
configs, handoff notes with lab details, credentials of any kind. A secret scan was run over this tree
when it was created.

**Privacy:** this tree contains internal tooling and lab addressing. Keep the exp repository
**private**, or remove `reference/` before publishing anywhere public.
