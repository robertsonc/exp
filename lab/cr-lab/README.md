# cr-lab: every exp role in one containerlab topology

A self-contained venue: three probe VLANs, five attendee clients with background traffic and real browser speed tests,
and the full server side (collector, dashboard, speedtest + runner) behind a routed core with DHCP relay, syslog and NAT
to the internet. Nothing here touches the existing `br-isp-a`, `br-isp-b` or `br-lan-s1` bridges or any running lab.

```
 probe-a ─┐ VLAN 10 ┌─ client1, client2        hall-a  172.30.10.0/24
 probe-b ─┤ VLAN 20 ├─ client3, client4        hall-b  172.30.20.0/24
 probe-c ─┘ VLAN 30 └─ client5                 hall-c  172.30.30.0/24
            │
         access (AOS-CX: SVIs .1, ip helper -> svc)
            │ 172.30.255.0/31
          core (FRR) ── edge (FRR) ── isp (NAT out eth0) ── internet
            │ 172.30.255.2/31   172.30.255.4/31
   ┌────────┼──────────┬──────────┐
 collector  box        dash       svc
 .1.1       .1.3       .1.5       .1.7      (172.30.1.x, /31 each to core)
            speedtest  dashboard  Kea DHCP, dnsmasq DNS,
            + runner              rsyslog -> runner
```

| Node | Role | Data plane (eth1) | Mgmt (eth0, cr-lab-mgmt) |
|---|---|---|---|
| collector | exp collector (+ iperf3 target) | 172.30.1.1 | 172.31.250.11 |
| box | exp speedtest + exp runner (they must share a host: loopback channel) | 172.30.1.3 | 172.31.250.12 |
| dash | exp dashboard, published on the lab host's **:8443** | 172.30.1.5 | 172.31.250.13 |
| svc | Kea DHCPv4 (3 scopes), dnsmasq DNS, rsyslog forward to the runner | 172.30.1.7 | 172.31.250.14 |
| probe-a/b/c | exp probe; eth1 is the test port on VLAN 10/20/30 | DHCP | 172.31.250.21-23 |
| client1-5 | attendee devices (no agent): DHCP, traffic loop, headless speed tests | DHCP | unused |
| access | AOS-CX, SVIs + DHCP relay + syslog | 1/1/1 172.30.255.1 | 172.31.250.5 |
| core, edge | FRR static routing | /31 transit | .2, .3 |
| isp | NAT to the internet through the lab host | 172.30.255.5 | .4 |

**Two paths.** Agents use eth0 (`cr-lab-mgmt`, out-of-band) to reach the manager and each other, as a real box with a
management port would. Attendee traffic, including every speed test, takes the venue path (SVI -> core -> edge -> isp),
so the speedtest box sees real, un-NAT'd client addresses, as it must.

**Hosts.** Lab hosts are Ubuntu 24.04 containers running systemd (`images/host`), so the manager's own `install.sh` runs
unchanged. They are privileged (containerlab's default for linux nodes): systemd, network namespaces, raw DHCP sockets
and NAT need it. That is acceptable on a lab host and nowhere else.

## Requirements (lab host)

containerlab, Docker, and these local images: `vrnetlab/aruba_arubaos-cx:20250822141147`, `quay.io/frrouting/frr:9.1.0`,
`jrei/systemd-ubuntu:24.04` and `mcr.microsoft.com/playwright:v1.63.0-noble` (build bases, pulled on first build). About 10 GB RAM (the AOS-CX VM takes ~4-8 GB),
4+ vCPU, outbound HTTPS to the manager, Ubuntu and npm mirrors, and mcr.microsoft.com (the client image build).

## 1. Build and deploy

```bash
cd lab/cr-lab
scripts/build-images.sh     # cr-lab/host:1 and cr-lab/client:1 (the client base image is ~1 GB on first pull)
scripts/deploy.sh           # containerlab deploy, waits for the AOS-CX, DHCP on the clients
scripts/check.sh            # routing, DHCP, DNS, page and internet from each client
```

Before enrolment the page check reads `000` (nothing listens on 172.30.1.3 yet). Everything else should be `ok`.

## 2. Manager setup (exp-control)

Use a **new site** (e.g. `CR-Lab clab`). Reusing `CR-Lab` would give that site two collectors (your existing host and
this one). If you do reuse it, decommission the old collector host first.

1. **Hosts -> Add host** six times, all in the new site. Paste each enrol token into `tokens.env` (copy from
   `tokens.env.example`), then run:
   ```bash
   scripts/enrol.sh collector         # first: the others need its address and TLS pin
   scripts/enrol.sh                   # the rest
   rm tokens.env                      # tokens are single-use
   ```
   Set `EXP_MANAGER=https://...` to point at another manager. Behind a proxy, export `HTTPS_PROXY` before running it.
2. **Assign components** (host page -> add component):

   | Host | Component | Settings |
   |---|---|---|
   | collector | collector | iperf3 **on** (port 5201). Listen is auto-detected as 172.31.250.11:8443 (the default-route interface). |
   | box | speedtest **and** runner | see 3 and 4 |
   | dash | dashboard | *Address operators use*: `https://<lab host IP>:8443` |
   | probe-a/b/c | probe | mode netns; test port **eth1**, role *client* (DHCP); throughput: *iperf3 (collector)* on. Never assign eth0, which is the management port. |

3. **Speedtest -> site -> Speedtest settings**

   | Field | Value |
   |---|---|
   | Host name | `speed.cr-lab.test` (dnsmasq on svc resolves it to 172.30.1.3) |
   | Listen address | `172.30.1.3` |
   | Placement / Transport | core / plain HTTP |
   | Zones (id: name) | `hall-a`: Hall A, `hall-b`: Hall B, `hall-c`: Hall C |
   | Zone labels (subnet: zone) | `172.30.10.0/24`: hall-a, `172.30.20.0/24`: hall-b, `172.30.30.0/24`: hall-c |
   | Attendee subnets | leave empty (defaults to the zone-label subnets) |
   | Answer DNS test queries / DNS zone | on / `t.speed.cr-lab.test` (svc forwards that zone to the box) |
   | Path: Gateway / Edge / Edge + 1 | auto / `172.30.255.3` / `172.30.255.5` |
   | Measure the internet leg | on |

4. **Runner component (box)**: *Correlate speedtests* on; Syslog *Accept from (CIDR)*:
   `172.30.1.7/32, 172.30.255.1/32` (svc's Kea and dnsmasq lines, and the AOS-CX). Leave Mist and EdgeConnect empty:
   identity then comes from the DHCP syslog fallback (Kea `DHCP4_LEASE_ALLOC` lines).

Wait for every component to read *running* in the manager, then run `scripts/check.sh` again: the page check should read
`200` from every client.

## 3. Generate traffic and tests

```bash
scripts/traffic.sh speedtest client1                  # one real test through headless Chromium; prints score/verdict
scripts/traffic.sh speedtest client3 --report "video freezes in hall B"   # with a problem report
scripts/traffic.sh burst                              # all five at once (local-leg load on the box)
scripts/traffic.sh start light                        # background loop on every client (busy = ~4x the rate)
scripts/traffic.sh status
scripts/traffic.sh stop
```

The loop mixes web/DNS lookups (dnsmasq query lines reach the runner as DNS evidence), 5-25 MB downloads from
`speed.cloudflare.com`, 8 s iperf3 bursts to the collector, and a full speed test every 6 (busy) or 12 (light) cycles.
Every action is time- and size-bounded. Logs: `/var/log/lab-traffic.log` in each client.

**What to look at.** The dashboard (`https://<lab host>:8443/`): probe lines per VLAN, speedtests by zone. On a test, the
evidence should show identity `resolved_by: dhcp` (the DHCP syslog fallback) with the client's MAC and zone, and the DNS lines. The manager shows
component health for all six hosts.

**Not testable here.** Mist and EdgeConnect evidence (no live org/Orchestrator), Wi-Fi fields, and EC auto-pause.
Opening the page from your laptop does not work either: the box serves only on 172.30.1.3, and a NAT'd laptop would
(correctly) fail the NAT guard. Use the clients.

## AOS-CX

`configs/access.cfg` is **unverified** against this image build. It follows AOS-CX 10.x conventions (`no routing` +
`vlan access`, SVIs with `ip helper-address`, `logging <ip> udp <port>`). The first boot takes 5-10 minutes. Console:

```bash
telnet clab-cr-lab-access 5000          # or: ssh admin@clab-cr-lab-access (password admin, vrnetlab default)
show running-config
show ip interface brief
show dhcp-relay
```

If a line was rejected, fix it there and copy the working config back into `configs/access.cfg`.

## Troubleshooting

| Symptom | Check |
|---|---|
| `net-up.sh` keeps retrying DHCP | Is the switch booted (`docker logs clab-cr-lab-access`)? `show dhcp-relay`; on svc: `journalctl -u kea-dhcp4-server`, `tcpdump -ni eth1 port 67` |
| Client has a lease, no internet | `docker exec clab-cr-lab-isp iptables -t nat -L -v`; `docker exec clab-cr-lab-core ip route` |
| Enrol fails at "cannot reach ... over HTTPS" | Proxy: `export HTTPS_PROXY=...` before `scripts/enrol.sh`; or the lab host's outbound policy |
| A host node (collector, box, svc...) exits right after deploy | systemd could not start. Check `stat -fc %T /sys/fs/cgroup` on the lab host: `cgroup2fs` is expected. On cgroup v1, add `- /sys/fs/cgroup:/sys/fs/cgroup:rw` to that node's `binds` |
| Speed test `ok:false` | Is the page up (`check.sh`)? Then `docker exec clab-cr-lab-box journalctl -u exp-speedtest -n 50` |
| No DHCP identity on tests | Runner *Accept from* includes 172.30.1.7/32? On svc: `journalctl -u rsyslog`; on box: `tcpdump -ni eth1 udp port 5514` |

## Teardown

```bash
scripts/destroy.sh
```

Then decommission the six hosts in the manager.
