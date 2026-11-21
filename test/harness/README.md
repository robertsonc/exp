# test/harness - container LAN harness (WP-8)

A simulated event network and exp "hosts" in Docker, so the data spine can be tested end to end without hardware or the
internet. Design ported from `reference/exm/test/harness.sh` (bridge with a **pinned MAC**, dnsmasq DHCP + DNS, veth
"ports", NAT); extended with a router chain (so traceroute has hops), local app servers, a fault API and systemd hosts.

```
 host container (systemd PID 1)            net container (--privileged --pid=host)
   tp0 tp1 tp2  --veth--  br-ev (MAC 02:e0:00:00:00:01) --- gw-ev 10.1.0.1 [ns gw : dnsmasq DHCP+DNS, router]
   eth0 (mgmt) ---+                                                          |  10.255.1.0/30
                  |                                                    [ns edge: NAT]
   mgmt network   +--- default route via the net container                    |  10.255.2.0/30
   172.30.41.0/24 ---- eth0 --- rt-isp 10.255.3.0/30 -------------------- [ns isp : 1.1.1.1  8.8.8.8
                                                                            142.250.80.46 (google) ... HTTP/HTTPS,
                                                                            resolvers 1.1.1.1 / 8.8.8.8]
```

* **Event VLAN:** the three test ports of a host are veth pairs plugged into `br-ev`; the probe moves them into
  namespaces and gets DHCP leases from dnsmasq in `gw` (router and DNS 10.1.0.1).
* **Simulated internet:** the `isp` namespace owns 1.1.1.1 and 8.8.8.8 (ICMP + DNS), and the addresses of
  `google.com`, `apple.com`, `microsoft.com`, `cloudflare.com` (and subdomains) with local HTTP and HTTPS servers. The
  HTTPS certificate comes from a throwaway CA created at start that only the host containers trust. No upstream DNS is
  configured anywhere and the mgmt network does not NAT, so nothing leaves the simulation. The probe's default
  config (ping 1.1.1.1/8.8.8.8, trace to 8.8.8.8, `google.com` ...) therefore works unchanged.
* **Two paths:** the event LAN goes gw -> edge -> isp; the management path (the probe's *control-path* trace)
  goes host eth0 -> net container -> isp, so "the edge is down but the ISP answers around it" is expressible.
* **Layouts** (`harness.sh up all|split|multisite`): `all` = one host `h1` (docker name `expm1-h1`, 172.30.41.11, three ports);
  `split` = `hc` (172.30.41.12, no ports; collector + dashboard) and `hp` (172.30.41.13, three ports; probe).
  Docker resources are prefixed `expm1-` (`EXP_HARNESS_PREFIX`) on `172.30.41.0/24` (`EXP_HARNESS_SUBNET`).

### Layout `multisite` (M3: A3.1 federation, A3.2 webhooks)

Two event LANs in one net container, three collectors, one dashboard, one webhook receiver (own docker prefix `expm3` and
subnet `172.30.43.0/24` when driven by `test/e2e/m3`, so it runs beside the M1 suite):

```
 site 1 (hall-b)  br-ev  + gw  10.1.0.1  (dnsmasq)  --\
                                                      >-- edge (NAT) -- isp (1.1.1.1 8.8.8.8 apps)
 site 2 (hall-c)  br-ev2 + gw2 10.2.0.1  (dnsmasq)  --/     hosts: hb1 (.21) hb2 (.22) -> site 1, hc1 (.23) -> site 2,
                                                                   each collector + probe with 3 ports;  hd (.24) dashboard
 net container 9443/tcp: webhook receiver (https, harness CA), every POST -> /var/lib/lan/webhooks.jsonl
```

The fault API takes the site where it matters: `plug ... --site N`, `cut-egress --site N`, `gateway-down --site N` (the
gateway drops everything from its LAN: the "Network down" fault), `canary IP --site N`; `block-dns` follows the port's
site; `restore` clears every site. `hooks-mode CODE|ok` makes the receiver answer an error status (retry tests),
`hooks-clear` truncates its log. Host names/addresses: see `layout_hosts` in `harness.sh`.

### Layout `core` (M6: A6.1 A6.2 A6.3 A6.7 A6.9 A6.11, `test/e2e/m6`)

ONE all-in-one box `core` (probe + collector + runner + speedtest + dashboard) on a **routed core segment**; the attendee VLAN
reaches it through the gateway **without NAT** (D15). Own docker prefix/subnet `expm6` / `172.30.46.0/24`.

```
 client ns (phone, DHCP)  --  br-ev 10.1.0.0/24 --- gw [dnsmasq: server=/t.speed.exp.test/10.9.0.10] --- gw-core 10.9.0.1/24 -- br-core -- core0 10.9.0.10 (box)
                                                      |  10.255.1.0/30                                                       eth0 172.30.46.11 (mgmt: collector, dashboard)
                                                   [ns edge: NAT of the LAN ranges towards the isp; 10.9.0.0/24 routed back, un-NAT'd]
                                                      |  10.255.2.0/30
                                                   [ns isp 10.255.2.2 (edge+1)] -- 10.255.5.0/30 -- [ns cf: 1.1.1.1, speed.cloudflare.com 104.16.132.230 (fake Cloudflare, https)]
 net container, management address 172.30.46.2: fake Mist (8485) and fake EdgeConnect Orchestrator (8486), https, harness CA
```

* `1.1.1.1` lives one router beyond the isp (namespace `cf`) so the box's TTL-limited trace has a real "edge+1" hop.
* `speed.cloudflare.com` resolves (LAN dnsmasq) to the fake Cloudflare; its throwaway certificate is trusted by the test Chromium by
  public-key pin only (`--ignore-certificate-errors-spki-list`), never installed anywhere.
* Clients: `lanctl plug ... --site 1` + `lanctl client-dhcp` (busybox `udhcpc`, copied in from the host image) give a network
  namespace a lease from the LAN dnsmasq; `test/e2e/m6/m6lib.py` runs Playwright Chromium (390 x 844 phone) in it with
  `nsenter -n` and a private mount namespace carrying the DHCP-given `resolv.conf`.
* `harness.sh up core` also needs `EXP_LAN_CORE=1` inside the net container (set by harness.sh) and the repository mounted at
  `/opt/repo` (the fakes run from it).

## Commands

```
make -C test/harness up [LAYOUT=all|split]     down | status | shell [HOST=h1] | build
make -C test/harness ci                        build + run test/e2e/m1 (A1.1-A1.5) + always clean up
make -C test/harness ci-m3                     build + run test/e2e/m3 (A3.1-A3.4, multisite layout) + clean up
test/harness/harness.sh lanctl <cmd>           the fault API
```

### Fault API (`net/lanctl`, run inside the net container)

| command | effect |
|---|---|
| `plug LABEL --pid P --ifname IF --mac MAC` / `unplug LABEL` / `ports` | manage the veth test ports (`harness.sh up` plugs `<host>-tp0..2`) |
| `block-dns LABEL\|all [--resolver-only]` | drop UDP+TCP/53 from that port's MAC at the gateway: both the DHCP-given resolver 10.1.0.1 and the public ones (`--resolver-only`: only 10.1.0.1) |
| `cut-egress [--at gateway\|edge]` | that router stops forwarding (it still answers TTL-exceeded: traceroute names the last hop) |
| `cut-internet` | the whole simulated internet goes away on every path (the `isp` namespace drops all non-loopback traffic: event LANs via the edge AND the management network); A3.4 |
| `restore` | remove every fault (flushes the `EXP_FAULT_*` chains, `cut-internet` included) |
| `status` | JSON of the faults in place |
| `delay --at gateway\|edge\|wan --ms N` / `delay-clear` | core layout: a constant one-way delay on ONE link (+N ms RTT of everything beyond it); held by `net/pktdelay.py` over NFQUEUE, so it needs no `sch_netem` (the dev sandbox kernel has none) |
| `delegation on\|off` | core layout: the gateway resolver forwards the DNS-leg zone to the box / answers NXDOMAIN for it |
| `client-dhcp --pid P --ifname IF` | core layout: DHCP client in the namespace of process P; prints the lease as JSON |
| `nat-core on\|off` | core layout: the gateway masquerades attendee traffic towards the box (the box sees `10.9.0.1`, a translated source: the A6.12 NAT-guard path, a D15 violation); `restore` turns it off, `status` reports `nat_core` |
| `fake cf\|mist\|orch METHOD PATH [JSON]` | core layout: the fakes' loopback-only `/_fake/` control API (cf = fake Cloudflare speed server) |
| `canary IP` | exit 0 when the resolver answers `canary.exp.test` (known-good control before/after a fault) |

## Manual installer and the acceptance suite

`install-manual.sh <dist-dir> <shape...>` (run inside a host) is the M1 manual install; it is documented in
`docs/admin-guide.md` ("Manual install (M1, no manager)"). `test/e2e/m1/` installs a **real signed release** with it
(throwaway key, or `EXP_E2E_DIST` + `EXP_E2E_PUBKEY`) and runs A1.1-A1.5 of `SPEC.md` section 9 in both layouts.

## Environment notes (learned the hard way)

* Host containers run `mount --make-rshared /`: systemd builds `LoadCredential=` directories in a helper mount
  namespace and moves them into place, which only reaches the service when `/` is shared (true on a VM, false in
  Docker). Without it a service starts with a missing `$CREDENTIALS_DIRECTORY`.
* The mgmt network is *not* `--internal`: Docker drops (br_netfilter) anything an internal network sends to a
  non-local address, which would break the management path to the simulated internet. Masquerade is off instead.
* Requires: Docker with privileged containers, `--cgroupns=host` (cgroup v1 or v2), and the images `ubuntu:24.04`.
* `make ci` also needs, beyond Docker: `packaging/.cache` populated (`packaging/fetch-vendor.sh`, the suite builds a
  real release), Node plus Playwright with Chromium for `test/e2e/m1/board.js` (`npm install --no-save --prefix
  test/e2e/m1 playwright@<pinned>` then `npx playwright install --with-deps chromium` from that directory; a global
  install resolvable via `NODE_PATH` also works), and a non-root user in the `docker` group is enough (no sudo needed
  for M1). The M2 suite additionally needs a writable `/etc/hosts` (`sudo chmod o+w /etc/hosts` on a non-root runner).
  CI (`.github/workflows/ci.yml`, job `harness`) does all of this explicitly; the images are built, never pre-pulled.

`pktwatch.py OUT.json SUBNET...` (stdlib AF_PACKET, run inside a host; there is no tcpdump in the image) records every packet with an
endpoint outside the given subnets; A3.4 runs it on the dashboard host while `cut-internet` is in force.
