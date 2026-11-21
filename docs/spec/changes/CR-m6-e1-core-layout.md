# CR-m6-e1-core-layout — the `core` harness layout and A6.1 / A6.2 / A6.3 / A6.7 / A6.9 / A6.11 (M6 step e1)

**From:** M6 step e1 (integrator, e2e). **Affects:** `test/harness/`, `test/e2e/m6/`, `collector/` (one defect), CI (`e2e.yml` job `m6`).
**Decision:** accepted; binding on later M6 steps. Companions: `CR-m6-spec-resolutions.md`, `CR-m6-speedtest-server.md`, `CR-m6-agent-packaging.md`.

## The layout (`harness.sh up core`, docker prefix `expm6`, subnet `172.30.46.0/24`)

One all-in-one box `core` (probe + collector + runner + speedtest + dashboard) installed from a **real signed 0.2.0 release**
(`packaging/build.sh`, throwaway key) by `test/harness/install-manual.sh`, which now also knows the `runner` and `speedtest` shapes
(units, users, creds, selftest, health gate; the `ping_group_range` step is the agent's `pingsys` in miniature). The box has a
**routed core interface** `core0 10.9.0.10/24` behind the gateway; the attendee VLAN `10.1.0.0/24` reaches it through the gateway
**un-NAT'd** (the edge still NATs towards the isp). The LAN dnsmasq delegates `t.speed.exp.test` to the box; `speed.cloudflare.com`
resolves to the fake Cloudflare (namespace `cf`, https, throwaway CA trusted by the test Chromium by public-key pin only); the fake
Mist and fake Orchestrator run on the management network (https, harness CA). Attendees are Playwright Chromium (390 x 844) in client
network namespaces with DHCP leases (`lanctl client-dhcp`, busybox `udhcpc`). Details: `test/harness/README.md`.

## Findings (all resolved in the harness or the product; later steps must know)

1. **Defect (collector, fixed): internet down read "looks healthy".** With the internet leg `unavailable` the score rests on the
   on-network leg alone and is high; `diagnose()` short-circuited to `none` ("Your connection looks healthy.") before
   `rule_internet_path` could say anything. A6.7 requires the diagnosis to say so. Now an unavailable internet leg skips the `none`
   shortcut, the existing `internet_path` hit (confidence 0.55, NOC text "internet leg could not run (unavailable) ...") fires and the
   user text is "The venue network is working, but the internet could not be reached right now." No new cause id (the enum is a contract).
   Regression: `collector/tests/test_st_diagnosis.py::test_internet_down_is_not_healthy`.
2. **All-in-one port clash (config rule for the manager compile).** The speedtest owns TCP 80 on `serve.listen_ip`; the dashboard's
   default `0.0.0.0:80` redirect listener then fails with `EADDRINUSE` (the dashboard never becomes healthy). In the all-in-one
   profile the compiled dashboard config must bind its listeners to the management address (`listen.https` / `listen.http_redirect`
   `<mgmt-ip>:443` / `:80`), as the harness does. (Not changed here: the manager compiler is another step's; flagged for the integration gate.)
3. **`edge1: auto` needs a real hop beyond the edge.** The box traces toward the constant `1.1.1.1` with TTL <= edge+1; where that
   address is local to the next router (the old harness put it on the isp loopback) the probe is answered at TTL edge+1 as "reached"
   and `edge1` stays unresolved by design. The core layout therefore places `1.1.1.1` one router beyond the isp (namespace `cf`); the
   box then reports `edge1_addr 10.255.2.2`. A venue whose edge+1 is the destination itself gets no `edge1` (documented behaviour).
4. **No `sch_netem` in the dev sandbox kernel** (many cloud / firecracker images lack it). `lanctl delay --at gateway|edge|wan --ms N`
   is therefore implemented with an NFQUEUE hold (`test/harness/net/pktdelay.py`, stdlib netlink client, constant one-way delay on one
   egress), which needs only `nfnetlink_queue`. Delay model (cumulative per hop): gateway = core<->gateway link, edge = gateway<->edge,
   wan = edge<->isp; the box times its hops cumulatively, so a delay moves the legs timed to a hop at or beyond its link and none before;
   the per-segment (waterfall) values are the differences gateway, edge - gateway, edge1 - edge (A6.9, `test_a69_legs.py` docstring).
   Two caveats found while building it: (a) ICMP time-exceeded errors a router generates itself are not held (after a user-space hold
   they never reached the receiver on this kernel; they carry no leg timing, the box times echo replies); (b) the box's `path.*_ms.idle`
   is the **median of the last 5 minutes** of idle samples (`path.WINDOW_S`, shared venue-infrastructure health), so a fault of seconds
   cannot move it: A6.9 restarts `exp-speedtest` (empty ring) and waits ~16 s (>= 3 fresh samples) before each measured run.
5. **A6.2 numbers** (installed service, 4 keep-alive streams, 6 s, 4-core sandbox; `a62-bench.json`): ~47 Gb/s aggregate over the box's own
   address, 0.03 server cores per Gb/s, byte counters equal to the clients' totals (0.0 % apart); a routed attendee-namespace client reaches
   ~34 Gb/s. Plain HTTP + `sendfile`; the TLS figure is lower by design (CR-m6-speedtest-server item 23).
6. **A6.9 DNS leg**: via the delegation the box sees the gateway (`10.9.0.1`) as the resolver; `cold_ms` carries the delayed gateway link,
   `warm_ms` is the cache. `lanctl delegation off` (the zone answers NXDOMAIN) gives `source: probe` + `dns_fallback`.
7. **A6.11 TLS**: with `tls.mode = provided` the harness test uses a throwaway self-signed certificate (SAN: box IP, the DNS-leg zone and
   its wildcard) pinned in Chromium; the cert/key are installed as the unit's `tls.crt` / `tls.key` credentials, never committed.
8. **Purge end state** is asserted by querying the collector database (every table, every column as text) for the raw MAC (both spellings)
   and IP before and after a purge by test, MAC and IP; the audit table holds only `by:<hash>` subjects. The box's own `speedtest.db`
   never held a raw address or MAC (asserted).

## Not done here (explicit)

* A6.12 (NAT guard, translated addresses) is step e2; the layout leaves `serve.translated_addresses` empty and has no NAT'd path yet.
* No SSE connector (decision 2 of the owner decisions); no drills.
