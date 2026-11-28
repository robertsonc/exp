# 02 — Probe (`exp-probe`)

A synthetic user. It owns one or more **test ports**, makes each one behave like an attendee's
device (DHCP lease, DNS, web), measures every transaction, and ships the measurements to its
collector over the management network. Contracts: `01-contracts.md` §2–4, §9.1, §11.

Primary prior art: `reference/exm/lib/exm/` (netns, lease, heartbeat, gateway, dhcptest, dnstest,
apps, speedtest, server), `reference/netvitals/netquality.py` (path quality, MOS/PQI),
`reference/perf/` (iperf3 + wire counters).

## 1. Process model

| Unit | Role |
|---|---|
| `exp-probe-netns.service` | oneshot. Preflight, create one namespace per port (`exp-<port_id>`), move each port in, bring it up, write a per-namespace `resolv.conf`. **On stop, move every port back to the host namespace explicitly before deleting the namespace** (deleting a namespace destroys virtual ports otherwise; EXM lesson). |
| `exp-probe-lease@<port>.service` | busybox `udhcpc -f -R` inside the port's namespace, holding the lease; a hook writes address/router/DNS state to `/run/exp/probe/<port>/lease.json`. `-R` releases on stop. |
| `exp-probe-target@<port>.service` | target server for `role: target` ports (§5.10). |
| `exp-probe.service` | the daemon: scheduler, test workers, spool, shipper, `probe_self`. Runs as root with hardening (`ProtectSystem=strict`, `ReadWritePaths=/var/lib/exp/probe /run/exp/probe`, `NoNewPrivileges=yes`, `PrivateTmp=yes`). |

Package layout: `probe/exp_probe/{config,netns,lease,scheduler,spool,shipper,tlspin,target,selftel,cli}.py`,
`probe/exp_probe/checks/{gateway,dhcp,dns,trace,ping,app,throughput,path,wifi}.py`, unit tests in
`probe/tests/`. Python 3.10+, stdlib plus vendored `dnspython`. External tools used: `ip`
(iproute2), busybox `udhcpc`, `curl` (≥ 7.81, for `-w '%{json}'`), `iperf3`, `iw`/`wpa_supplicant`
(Wi-Fi only), `tc` (faults), `openssl`. They are listed in `requirements.apt`.

## 2. Modes

- **`netns`** (default, EXM model): every port is isolated in its own namespace with its own lease,
  routes, and resolver, so N ports behave like N independent clients.
- **`host`**: for single-test-NIC VMs. Tests run in the host namespace bound to the test interface
  (`SO_BINDTODEVICE`); DHCP is the host's own. One port only. `mgmt_iface` must differ from the test
  interface unless explicitly `allow_shared: true` (then traceroute's control path is disabled).

## 3. Preflight (fails closed)

Runs on install, on every netns start, and as `exp-probe preflight` (non-root: read-only checks).
A port is **refused** — nothing is changed, a clear reason is reported — if it:
- is the `mgmt_iface` or holds the default route;
- carries a global IP address in the host namespace;
- is enslaved to a bond/bridge/team;
- does not exist (unless it is already inside its `exp-*` namespace — upgrade case);
- is a Wi-Fi interface assigned a non-`wifi` role.

Ports with **no carrier on every port at once** produce a hint: check the NIC (e.g. bypass or
disconnect-mode cards), not the cables (lab lesson). Preflight never powers anything off or
modifies a port it does not own.

## 4. Scheduler

- **Heartbeat cycle** every `heartbeat.interval_s` (10 s), aligned to the wall clock (`t % 10 == 0`),
  for all ports. Within a cycle, `gateway` (all ports), `dhcp_hb`, `dns_hb`, and `ping` run in
  parallel; **traces run one after another, never together** (test-port trace, then control-path trace).
  Two concurrent sweeps from behind one public address get rate-limited and falsely blame the edge.
- **Rotation:** `dhcp_hb`, `dns_hb`, and `trace` each use one client port per cycle, rotating
  through ports (persisted rotation index), so load stays constant as ports grow.
- **Scheduled tests** (`dhcp`, `dns`, `app`, `throughput`, `path`, `wifi_join`): each runs every
  `interval_s` per port, **staggered** evenly across the interval (`slot = interval / ports`) with ±10%
  jitter.
- **No overlap:** a test that is still running when its next slot arrives is skipped and counted
  (`probe_self.detail.skipped`). `throughput` is **globally serialized per probe** and never runs
  in the same 10-s cycle as a `trace`.
- **Budget:** a worker pool (default 8) caps concurrency; heartbeat work has priority over scheduled work.
- A heartbeat cycle MUST complete in < 7 s at 64 ports (timeouts in §5 enforce it).

## 5. Tests

Each test returns one or more `Measurement`s (catalog: `01-contracts.md` §3). Timeouts are hard.
A test that cannot run (missing lease, tool crash) emits `outcome: error` with a reason —
never `fail`, which is reserved for a network failure.

### 5.1 `gateway` (beat, every port)
Read link state and carrier-change count from `/sys/class/net/<iface>`; ARP + ICMP echo to the
port's gateway from inside its namespace (raw socket), 2 tries, 1 s timeout. `fail` when no reply
(and say which IP); `degraded` on partial loss. Detail carries the gateway IP and MAC. Port:
`reference/exm/lib/exm/gateway.py`, `heartbeat.py` (`_ping`/`_echo`).

### 5.2 `dhcp_hb` (beat, rotating port)
Send **DISCOVER only — never REQUEST** (a heartbeat must not create or alter bindings) via a raw
socket in the port's namespace, with a probe-unique transaction id. Collect offers for
`offer_collect_s` (default **3.0 s**: ping-checking DHCP servers answer ~1–2 s late). Record
`offer_ms` of the first offer and `offers` count; more than one distinct server id → detail
`rogue_suspect: true`. Port: `heartbeat.py` (`dhcp_hb`).

### 5.3 `dhcp` (scheduled DORA)
Full DORA timing that **re-confirms the binding the lease holder already has** rather than taking
a second lease (EXM `dhcptest.py` behaviour). Record phase timings, lease time, router, DNS options.

### 5.4 `dns_hb` (beat) and `dns` (scheduled)
Query each DHCP-learned resolver and the `alternate_resolver` for a rotating name from
`heartbeat.dns_names`, inside the namespace, with `dnspython`, 2 s timeout; also ICMP-ping each
resolver (`ping_rtt_ms`, 2 tries 0.5 s apart — public resolvers rate-limit ICMP). The alternate
resolver lets the rules engine tell "the DHCP-given resolver is down" from "DNS traffic dies at the
edge". Port: `heartbeat.py` (`dns_hb`), `dnstest.py`.

### 5.5 `trace` (beat, rotating port) and control path
ICMP TTL sweep to `heartbeat.trace.target`, **paced `pace_ms` (20 ms) per hop** (a simultaneous burst
is dropped by large providers' edges and falsely reports the target unreachable), `max_hops`
30, `timeout_s` 2. Record `reached`, `hops`, `last_ttl`, `last_ip`, hop list in detail. Then, if
`control_path: true`, the same sweep from the **management interface** (host namespace) labelled
`path=control`: the internet path that does not traverse the event network, so the rules engine can
say "it's the edge" vs "it's the ISP". Port: `heartbeat.py` (`trace`, `trace_ctl`).

### 5.6 `ping` (beat)
ICMP echo to each `heartbeat.ping` target from the rotating port. Small fixed target set only.

### 5.7 `app` (scheduled)
`curl` inside the namespace with `-w '%{json}'` timing (DNS, connect, TLS, TTFB, total), redirects
followed (max 5), 15 s max, body discarded after counting bytes. Apdex per target:
satisfied ≤ T, tolerating ≤ 4T. Degraded/fail thresholds from config. Port: `apps.py`.

### 5.8 `throughput` (scheduled, serialized)
- **cloudflare:** download/upload via `speed.cloudflare.com` (`__down`/`__up`), with idle and
  loaded latency (bufferbloat). Port: `speedtest.py` (`cloudflare`). Minimum interval 600 s.
- **iperf3:** `iperf3 -J` to the site's iperf3 server — a target port with `serve.iperf3` (or the
  collector where the event network can reach it) (perf lineage), 10 s, TCP then optional
  UDP at a configured rate. During the window, sample the port's `/proc/net/dev` counters (perf
  `WirePoller`) and report wire bytes against payload to expose overhead and loss attribution.
- NDT7/M-Lab is **not** used (it publishes client IPs).

### 5.9 `path` (scheduled, netvitals lineage)
Bidirectional stream to a reflector reachable from the test port's network — by default a target
port with `serve.reflector` (§5.10); the collector's reflector only where the event network can reach it:
- **UDP:** packets at `rate_kbps` for `duration_s` with sequence numbers and send timestamps; the
  reflector returns each with its own sequence. Compute RTT, jitter (RFC 3550 interarrival),
  **forward loss and return loss separately from sequence gaps** (no clock sync needed), and **MOS**
  (E-model; port `netquality.py` `quality_score`), plus the loss pattern (`classify_loss_pattern`).
- **TCP:** a short TCP stream measuring goodput stability and retransmits → **PQI** (`pqi_score`).
- `experience` (0–100) combines MOS/PQI per netvitals scoring (`score_label` bands).
Reflector protocol: §7.

### 5.10 Target ports (`role: target`, EXM `server.py` lineage)
The port gets a static address after an **RFC 5227 ARP probe gets no reply** (if anyone answers,
fail closed and report the conflict — never take an address another host uses). It serves HTTP
:80 and HTTPS :443 (self-signed) returning 200 on any path, `/bytes/<n>` (≤ 100 MB), `/health`,
and answers ICMP. **Fault controls** (for drills and manual testing): HTTP delay, HTTP status
override, and `tc netem` delay/loss/jitter on the port, each with a mandatory expiry (≤ 15 min).
Requests are counted into `target_access` every 60 s. With `serve.reflector: true` the target
port also runs the §7 reflector (and `serve.iperf3: true` an iperf3 server), which is the usual
`path`/`iperf3` peer: it sits on the event network, which normally cannot reach the management
network where collectors live. Port: `server.py` (`claim_address`, `set_netem`, fault files).

### 5.11 `wifi_hb` / `wifi_join` (M4; CR-wifi-open-owe)
A Wi-Fi interface with `role: wifi` and an `ssid`. Its whole radio moves into the port's namespace
(`iw phy <phy> set netns name exp-<port>`; back with `iw phy <phy> set netns 1`, since a cfg80211 interface
refuses `ip link set netns`). Preflight refuses a radio that also carries another interface (the whole
phy moves), an rfkill-blocked radio, an interface NetworkManager manages, and one another `wpa_supplicant`
drives. `exp-probe-wifi@<port>` runs `wpa_supplicant` in the namespace with a generated config that
lists **only the target SSID** (hex-encoded); `exp-probe-lease@<port>` holds the DHCP lease as on a client port.

**Open and Enhanced Open (OWE) networks only**: an event's public Wi-Fi has no credential, and none is
stored, delivered or configured. `security: auto` (default) offers OWE first and plain open second;
`open` / `owe` force one. `band` restricts the scan (`freq_list`); `country` sets the regulatory domain
(needed by some cards for 5 / 6 GHz). The radio's permanent MAC is used (no randomisation), so a venue
NOC can allowlist the probe past a captive portal.

`wifi_hb` runs every beat on every Wi-Fi port and reports link, RSSI, noise, SNR, tx rate, channel,
BSSID, security and gateway RTT. Not associated, on the wrong SSID (`on_target: false`), no lease, or a
silent gateway → `fail`; while off target the probe asks the supplicant to rejoin at most every 60 s
(EXM lesson: a client roamed to a guest SSID and kept "passing" while bypassing the network under test).
A **captive portal** (the connectivity check `tests.wifi.portal_url`, default
`http://connectivitycheck.gstatic.com/generate_204`, does not return its empty 204) → `degraded` with
`detail.portal: true`; the probe reports a portal and never clicks through it. Weak RSSI / SNR, slow or
lossy gateway → `degraded`.

`wifi_join` (scheduled by `tests.wifi.interval_s`) drops and rejoins the network to time association,
key exchange and DHCP; the port is offline for a few seconds each run, and the other heartbeats skip the
port meanwhile. Heartbeat `gateway`/`dns_hb` also run on the Wi-Fi port. PSK and 802.1X are not supported.

### 5.12 `probe_self` (60 s)
Spool depth/bytes, push lag (now − oldest unshipped `ts`), clock offset (from
`timedatectl show-timesync` or chrony), CPU, RSS, dropped records, skipped tests.

## 6. Spool and shipper

- **Spool:** SQLite (WAL) at `/var/lib/exp/probe/spool.db`, table `(id TEXT PRIMARY KEY, ts, body
  BLOB)`. Every measurement is written to the spool **before** any send. Bounded by `spool.max_mb`
  and `spool.max_days`; on overflow, drop oldest first and count `dropped_total`.
- **Shipper:** sends oldest-first batches (≤ 500 records or 1 MiB, gzip) to
  `/ingest/v1/measurements`; deletes lines the collector reported as accepted, duplicate, or rejected;
  follows the status table in `01-contracts.md` §4. Backoff 1 s → 60 s with full jitter. Steady state:
  ship within 1 s of a beat.
- Collector `fallback` URLs are tried in order when the primary is unreachable for > 60 s.

## 7. Reflector protocol (served by the collector; shared helper in `exp_common`)

UDP on port 8862. Request datagram: `EXP1` magic, 1-byte type (`0x01` probe), 16-byte session id,
uint32 seq, uint64 send time (ns, sender clock), padding to the requested size (≤ 1,400 bytes).
Reply: same header with type `0x02`, the reflector's own uint32 reply seq, and uint64 receive/send
times. The reflector answers only sessions announced over TCP 8862 control (`HELLO <session>
<probe_id>` with the probe's ingest token as the authenticator) and rate-limits per session — it is
not an open amplifier. TCP 8862 also carries the PQI stream.

## 8. TLS pinning client (`exp_common.tlspin`)

The collector certificate is self-signed. Connect with `ssl.CERT_NONE`, then compare the SHA-256 of
the leaf certificate (DER) with the configured `tls_fingerprint_sha256` in constant time; on
mismatch, close and report `tls_pin_mismatch` (never fall back to unpinned). TLS ≥ 1.2.

## 9. CLI

`exp-probe run` (service) · `health` (JSON; exit 0 healthy) · `version` · `preflight [--config]` ·
`selftest` (offline checks) · `test <test> --port <id> [--once]` (run one test, print measurements,
do not spool) · `spool stat` · `target set <port> --http-delay-ms N --http-status N --netem "delay 100ms loss 1%" --for 5m` · `target clear <port>`.

`health --json` exits 0 for `ok` and `degraded`, 1 for `fail` (`01-contracts.md` §8.1). `degraded` is used only for states this section defines as healthy: collector unreachable or unconfigured while the spool accepts writes, throttling (429), a client port without a lease that a recent error record explains. `fail`: invalid config, daemon not running, a missing namespace or port, an unexplained lease-less client port, spool write failures, a shipper not pushed for > 120 s with a backlog, `auth_failed` (401) and `tls_pin_mismatch`. In `host` mode `mgmt_iface` must differ from the test interface unless `allow_shared: true` (then the control-path traceroute is disabled); in `netns` mode it is ignored.

`health --json` emits `exp.health/1` with the probe metrics and per-port counters of
`01-contracts.md` §8.1 (read inside each namespace). It is healthy when: config valid, namespaces present for all ports, each client port has a
lease (or a recent `error` explaining why), shipper pushed within 120 s (or the collector is down
and the spool is accepting).

## 10. Porting map

| exp module | From | Notes |
|---|---|---|
| `netns.py` | `exm/netns.py` | keep `guard`, explicit port return on `down`; add `host` mode |
| `lease.py` | `exm/lease.py`, `exm/hooks/` | udhcpc argv + hook → JSON lease state |
| `tests/gateway.py` | `exm/gateway.py`, `heartbeat.py` | one record per port |
| `tests/dhcp.py` | `exm/heartbeat.py` (`dhcp_hb`), `dhcptest.py` | discover-only beat; DORA re-confirm |
| `tests/dns.py` | `exm/heartbeat.py` (`dns_hb`), `dnstest.py` | alternate resolver + resolver ping |
| `tests/trace.py` | `exm/heartbeat.py` (`trace`, `trace_ctl`) | pacing, sequential |
| `tests/app.py` | `exm/apps.py` | curl `%{json}` |
| `tests/throughput.py` | `exm/speedtest.py`, `reference/perf/runner.py`, `poller.py` | drop ndt7; keep fast.com optional |
| `tests/path.py` | `reference/netvitals/netquality.py` | streams + scoring functions |
| `target.py` | `exm/server.py` | ARP claim, faults, netem |
| `spool.py`, `shipper.py` | new | EXM used SSH pull; exp pushes |

Do **not** port: supercronic/crontab generation (`cron.py`), the SSH stream server (`stream.py`),
TOML config (`config.py` uses `tomllib`).

## 11. Acceptance tests (WP-1 definition of done)

Run in the container harness (`test/harness/`, from `reference/exm/test/harness.sh`): a bridge with a
**pinned MAC**, dnsmasq for DHCP+DNS, veth "ports", NAT out.
1. Preflight refuses a port with an address, a bonded port, and the default-route interface; nothing changes.
2. Netns start/stop round-trips: every port returns to the host namespace (real and veth).
3. All heartbeat tests produce schema-valid measurements every 10 s on 3 ports; the cycle finishes < 7 s.
4. Negative controls: a rogue DHCP server (with and without ping-check) is flagged; DNS
   interception and a captive portal are detected by `app`; blocking DNS fails `dns_hb` but not `dhcp_hb`.
5. Trace names the last hop when egress is cut past the gateway; the control path still reaches the target.
6. Spool: kill the collector 5 min, restart → every record arrives exactly once, in order.
7. TLS pin mismatch → no data sent, health reports `tls_pin_mismatch`.
8. Target port refuses to claim an address already in use; faults expire on their own.
9. `path` against the collector reflector reports forward and return loss separately under induced one-way loss (netem on one direction).
