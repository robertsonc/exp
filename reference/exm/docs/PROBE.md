# HPE EXM probe

HPE EXM (Event network eXperience Monitor): the probe package.

The probe end of the Event EXM platform: one VM emulating wired clients, one per test interface, each continuously running DHCP, DNS, speed-test and app-transaction tests, plus 10-second heartbeats. Results are JSON lines in the spec's event schema, kept locally for 7 days and streamed to the collector (exm-collector package), which runs the dashboard and alerts.

## How it works

| Piece | What it does |
|---|---|
| Client namespaces | Each physical port moves into its own network namespace, `exm-<id>`. It keeps its burned-in MAC, gets its own DHCP lease, routes and resolver. This is the spec's access mode. A port is never moved if it carries an address, is enslaved to a bond or bridge, or holds the default route. |
| Lease holder | `busybox udhcpc` per namespace, supervised by `exm-dhcp@<id>.service`. Its hook configures only that namespace and writes `/etc/netns/exm-<id>/resolv.conf`, which is what every process in the namespace sees as `/etc/resolv.conf`. The host's resolver is never touched. On stop it sends DHCPRELEASE. |
| Tests | Python, run inside each namespace by `exm run <test> <client>`. |
| Bypass relays | `exm-bypass.service` connects Silicom bypass ports at boot. See *Silicom bypass adapters*. |
| Scheduler | supercronic (`exm-cron.service`) runs `/etc/exm/crontab`, which `exm crontab` generates from the config. |
| Results | `/var/lib/exm/results/<UTC date>/<test>.jsonl`, world-readable, kept `retention_days` (7). Each line is stamped `emitted` as it is written, so every file is in order and a collector can resume from where it left off. |
| Collector link | `exm stream`, run over SSH by the collector as the `exm-stream` user (forced command, nothing else). Replays results since the collector's cursor, then follows live. |

### Tests

| Test | Cadence (default) | Measures |
|---|---|---|
| `dhcp` | every 5 min per client | A raw-socket client (scapy) using the client's own MAC and client-id, so it re-confirms the held binding instead of taking a new lease. DORA, plus INIT-REBOOT every 3rd run. Phase timings from kernel packet timestamps, retries with 4/8/16 s backoff, every offering server (rogue detection), ARP conflict probe on the acked address, gateway ARP time, time to first DNS answer, lease options. |
| `dns` | every 5 min per client | The DHCP-learned resolvers and Google, Cloudflare, Quad9 and OpenDNS, asked for A, AAAA and HTTPS on a random sample of the spec's 50 domains. Percentiles, rcodes, timeouts, AD bit. Interception check per public resolver, and DNS-over-TLS reachability. |
| `apps` | every 5 min per client | The spec's 10 app transactions through the client's DHCP resolver, scored as Apdex against each app's T. A connectivity check that gets the wrong answer is classed `portal`. |
| `speedtest` | one client every 10 min, rotating | Cloudflare and Netflix fast.com: throughput plus idle and loaded latency (bufferbloat). Never two at once. |
| `gateway` | every 10 s, all ports at once | Network heartbeat. Per port: link state, link drops since the last run (the kernel's `carrier_changes`), and one ping to the gateway. One event per run: `ok` when every port passed, `degraded` when some failed or a link dropped and came back, `fail` when half or more failed. |
| `dhcp_hb` | every 10 s, next client in rotation | DHCP heartbeat. One DHCPDISCOVER with the client's own MAC and client-id, waiting up to 3 s for an OFFER. It never sends a REQUEST, so no lease is taken or changed and the server offers the client's existing address. |
| `dns_hb` | every 10 s, next client in rotation | DNS heartbeat. One A query to the resolver DHCP gave that client and one to an alternate (`dns_alt`), 2 s timeout, and a ping to both: a dead resolver, a dead path, and a resolver that answers ping but not DNS are three different problems. Only the DHCP-given resolver's DNS answer decides the outcome. |
| `trace` | every 10 s, next client in rotation | Traceroute to `trace_target` (8.8.8.8): one ICMP echo per TTL, paced 20 ms apart (Google's edge drops a simultaneous burst). Records the last hop that answers. Diagnostic only: it never colours a line. |
| `trace_ctl` | every 10 s, after `trace` | The same traceroute from the probe's management path, which reaches the ISP without the WAN edge the test ports use. If it gets out and `trace` doesn't, the fault is the edge. |
| `summary` | every minute | The details tables (per client, resolver, app, server port), computed here because the probe knows its ports, and streamed to the collector like any result. |

The heartbeats run together as `exm heartbeat` (about 1-3 s, using plain sockets inside each namespace). They catch a dead DHCP or DNS server within about 13 s. A full DORA test takes 28 s of retries before it reports a failure.

Clients are staggered: with 12 clients on a 5-minute cadence, client N fires 25 s after client N-1, and each client's DHCP, DNS and app runs are offset within its slot. An unplugged port records a clear `no link` result instead of running.

### Outcome classes

`ok`, `degraded`, `fail`, `portal`, and `harness_error`. The last means the probe itself failed, never the network.

## Install

A probe is a Linux VM (Ubuntu 24.04 tested) with one management interface (the default route, SSH from the collector) and one or more test interfaces. Test interfaces are moved into namespaces and need nothing configured on them; give each a `[[client]]` (or a server port) in `/etc/exm/exm.toml`.

```
tar xzf exm-probe-<version>.tar.gz && cd exm-probe-<version>
./install.sh --preflight      # no root, changes nothing: every configured port must be free to move
sudo ./install.sh             # packages, supercronic (bundled, sha256-pinned), /opt/exm, units, start
```

Idempotent: run it again to upgrade or repair. It keeps `/etc/exm/exm.toml`, results and collector keys. On a first install it writes an example config with two ports (`ens19`, `ens20`): edit it, then `sudo exm apply`. The installer refuses to move a port that carries an address, is enslaved to a bond or bridge, or holds the default route, so the management interface is safe. `sudo ./uninstall.sh` returns every port to the host; `--purge` also removes config, results and the stream user.

**Upgrading from 0.9.0 (UXM).** EXM was called UXM until 0.9.1. This installer migrates a UXM probe in place: it stops the `uxm-*` units (the ports go back to the host for a moment, then into `exm-*` namespaces), moves `/etc/uxm/uxm.toml` to `/etc/exm/exm.toml` (paths inside it follow; `hostname_prefix` and `vendor_class` are yours and are left alone, with a note if they still say uxm; to change them, edit and `sudo systemctl restart 'exm-dhcp@*'`, since `exm apply` leaves running lease holders alone), moves `/var/lib/uxm` to `/var/lib/exm` with all results, renames `uxm-stream` to `exm-stream` (same uid, collector keys kept, forced command now `exm stream`), and removes `/opt/uxm`. Upgrade the collector next: until then a 0.9.0 collector can't log in (it still asks for `uxm-stream`) and that probe's board pauses; the follower catches up from its cursor once both are on 0.9.1, so nothing is lost. On an all-in-one host, upgrade the probe first, then the collector, back to back.

## Link to the collector

On the collector: `sudo exm-collector probe add <probe_id> --host <this probe's management address>`. It prints a key line. Here:

```
sudo exm authorize-collector 'ssh-ed25519 AAAA... exm-collector@dc-vm:probe-01' [--from 192.0.2.5]
```

That creates the `exm-stream` system user (once) and lets the key run `exm stream` and nothing else (`restrict,command=...`; `--from` limits it to the collector's address). `exm deauthorize-collector 'KEY'` or `--all` takes it back. The probe needs `sshd` on its management interface.

## Operate

```
exm status                    # links, addresses, leases (non-root: last snapshot, refreshed each minute)
exm summary --minutes 30      # DHCP, DNS, Apdex and speed-test roll-up from the result files
sudo exm run dns c03          # run one test on one client now
sudo exm speedtest-next       # next speed test in the rotation
journalctl -u exm-cron -u 'exm-dhcp@*' -f
```

`exm version` prints the release. Edit `/etc/exm/exm.toml`, then `sudo exm apply`, which rewrites the crontab, reconciles the DHCP holders and restarts the scheduler.

To run anything from a test port, prefix it with the port's namespace: `sudo ip netns exec exm-c01 mtr -n 8.8.8.8`.

## Server ports: a target for Marvis Minis

Any port can be switched from emulated client to a **hard-coded test server** by setting `role = "server"` and a fixed `address`, `gateway` and `dns` for it in `/etc/exm/exm.toml`, then running `sudo exm apply`. The address must be outside the segment's DHCP pool. `exm-server@<id>.service` then:

- **claims the address safely.** It waits for link, then probes the wire per RFC 5227. If any host answers for the address, it refuses, logs `REFUSED`, and retries every 30 s, so it never takes an address someone else holds.
- **serves what Minis tests.** Ping and traceroute for *Network* targets. `http://<ip>/` and `https://<ip>/` return **200 on every path**, because Minis counts an *Application* target reachable only on 200. HTTPS uses a self-signed certificate. Whether Minis checks certificates is undocumented, so prefer the `http://` URL. `/bytes/N` returns N bytes and `/health` returns a small JSON document.
- **logs every request** with source address and user agent to `results/<day>/server_access.jsonl`. `exm summary` lists requests per server port by source, which is how Minis checks show up.

The client ports test each server too, as app `lab-server-<id>`: a ping, then HTTP and HTTPS each required to return 200. EXM and Minis therefore measure the same target.

Faults can be injected to check that Minis notices them:

```
sudo exm server set s01 --http-status 503         # Minis: not 200, unreachable
sudo exm server set s01 --http-delay-ms 2000      # slow application response
sudo exm server set s01 --netem "delay 100ms loss 5%"   # latency and loss on the port
sudo exm server clear s01
exm server show
```

In Mist, add the server under **Organization > Admin > Settings > Marvis Minis > Add Application**. Use target type *Application* with `http://<address>/`, or *Network* (beta) with the address.

## Silicom bypass adapters

srv-02's 12 ports are on three Silicom **PE2G4BPi35L** quad-port bypass adapters (Intel I350, PCI subsystem `1374:03d0`), from Silver Peak appliances. Each pair of ports (.0 with .1, .2 with .3) sits behind relays. As shipped, these cards were set to **power up in Disconnect mode**: the jacks are left open, so every port shows no carrier even when cabled, and the standard igb driver can't change that. On 2026-10-23 all six pairs on srv-02 were written to standard-NIC mode with a connected power-up default (`set_std_nic on`, `set_disc_pwup off`), stored on the cards. Standard-NIC mode was confirmed to override a later `set_disc on`.

`exm-bypass.service` fixes it at every boot: it loads Silicom's `bpctl_mod` and turns Disconnect and Bypass off on each pair. It does not change the cards' stored power-up settings. Install the driver once with `sudo tools/install-bpctl.sh`. It is built through DKMS, so it rebuilds on kernel updates. If the driver ever fails to load, the unit shows as failed and the ports stay disconnected, which `exm status` reports as `nocar`.

To make the cards behave as plain NICs with no driver needed at all, change their stored setting once. This persists through power loss and can be undone with `off`:

```
sudo bpctl_util 0a:00.0 set_disc_pwup off     # per pair: connected at power-up
sudo bpctl_util 0a:00.0 set_std_nic on        # or: standard NIC mode at all times
```

## Not done yet, and why

- **QUIC.** This curl build has no HTTP/3, so the spec's QUIC-fallback measurement isn't taken. Apps marked `quic` say so in their results.
- **M-Lab ndt7** is off. M-Lab publishes every result with the client IP, which the spec lists as an open question. The provider runs if an `ndt7-client` binary is installed and `ndt7` is added to `speedtest.providers`.
- **Uncached DNS** needs a zone you control, which the spec also lists as open.
- **irtt and iperf3** need endpoints that don't exist yet.
- **IPv6** is disabled on client ports by default, so results are deterministic IPv4. Set `ipv6 = true` per client to enable it.
- **Trunk mode** is not built, since this host's ports are access ports.

## Validation

`test/harness.sh` rebuilds a probe in a container: three fake ports on a bridged LAN with dnsmasq, NATed out. It checks each test and the scheduler end to end, plus negative controls: a rogue DHCP server with and without ping-check, DNS interception in two rounds, a captive portal, DNS going down without DHCP being marked down, a port losing link, a link that drops and recovers between heartbeats, the internet cut past the gateway (the traceroute names the last hop; the control path still gets out), and a silent resolver (the alternate still answers). It runs the collector's dashboard and alerter against the probe's results (all-in-one) to check the live stream, the past-window API, every "where" verdict and an end-to-end alert. `test/package.sh` installs the release tarballs in systemd containers, twice each, links a probe to a collector over SSH and checks the stream. `test/upgrade.sh` installs the real 0.9.0 (UXM) tarballs, gives them history, upgrades them in place (a linked pair and an all-in-one host) and checks that nothing was lost or left behind. A failed check prints its evidence.
