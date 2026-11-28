# exp/probe — `exp-probe`

A synthetic user on the event network: it owns one or more **test ports**, makes each behave like an attendee's
device (own namespace, own DHCP lease, own resolver), measures every transaction and ships the measurements to
its collector over the management network. Spec: [docs/spec/02-probe.md](../docs/spec/02-probe.md); contracts:
[docs/spec/01-contracts.md](../docs/spec/01-contracts.md) sections 2-4, 8.1, 9.1, 11. Work package WP-1.

**Status (step 2 of 2, M1):** config, preflight, namespaces/host mode, lease holder, scheduler, spool, shipper,
`probe_self`, health, CLI and units (step 1) plus the M1 measurement tests: `gateway`, `dhcp_hb`, `dhcp`, `dns_hb`,
`dns`, `trace` (+ control path), `ping`, `app`; on Wi-Fi ports (open / OWE networks, M4) `wifi_hb` + `wifi_join`.
`throughput`, `path` and target ports (`role: target`) are M4+: a configured test without a module is logged once and
skipped (never reported as a fake result).

## Layout

```
probe/
  bin/exp-probe              entry script (dev tree and release tarball)
  exp_probe/                 config preflight netns lease scheduler spool shipper selftel health runner daemon cli
    hooks/udhcpc-hook        busybox udhcpc event hook -> `exp-probe udhcpc-hook`
    netio.py icmp.py dhcpwire.py   namespace sockets (setns thread), ICMP echo + paced TTL sweep, DHCP on the wire
    checks/                  measurement tests: gateway dhcp dns trace ping app (+ common.py); NOT named tests/ (packaging drops tests/)
  systemd/                   exp-probe.service, exp-probe-netns.service, exp-probe-lease@.service, exp-probe-target@.service
  requirements.apt           busybox iproute2 iputils-ping curl openssl iperf3
  tests/                     unit tests (fake `ip`, fake clock, fake_collector over TLS); tests/harness/ = real namespaces
```

## CLI

```
exp-probe run          [--config PATH]   daemon: scheduler, workers, spool, shipper, probe_self
exp-probe health [--json]                 exp.health/1; exit 0 = healthy (ok or degraded), 1 = fail; < 5 s, <= 64 KiB
exp-probe version | selftest              selftest = offline checks (spool, batching, schema); lists missing tools
exp-probe preflight [--json]              read-only port check; 0 ok, 1 a port is refused, 2 host state unreadable
exp-probe test <test> --port <id> [--once]  run one test, print its measurements, do NOT spool
exp-probe spool stat [--json]             depth, bytes, oldest ts, dropped_total
exp-probe netns up|down                   (exp-probe-netns.service) create / tear down the port namespaces
exp-probe lease <port>                    (exp-probe-lease@<port>.service) exec busybox udhcpc -f -R in the namespace
exp-probe wifi <port>                     (exp-probe-wifi@<port>.service) exec wpa_supplicant (open / OWE) in the namespace
exp-probe target set|clear|serve ...      M4 stub: prints "target ports arrive in M4", exit 69
```

Every subcommand takes `--config PATH` (default `/etc/exp/probe/config.json`), validates it with
`exp_common.config` against `exp.probe.config/1` and **refuses to start** on an invalid one, printing every
problem (exit 78). Extra rules the schema cannot express: unique port ids and interfaces, no port on
`mgmt_iface`, `host` mode = exactly one `client` port (`allow_shared: true`, host mode only, lets the single test
NIC be the management NIC and disables the control-path trace; see `docs/spec/changes/CR-wp1-allow-shared.md`).

## Config in one screen

`collector: null` means measure and spool (the shipper idles until the manager fills it in). Defaults: heartbeat 10 s
with gateway/dhcp/dns on, trace to `8.8.8.8` paced 20 ms with the control path, spool 500 MB / 7 days. DHCP identity
per client port: `dhcp.hostname` (default `exp-<probe_id>-<port_id>`, never a person's name), `vendor_class`
(`exp-probe`), `client_id` (`mac`|`hostname`). The ingest token is the systemd credential `ingest_token`
(`LoadCredential=`), never in the config.

## Modes

* **netns (default).** One network namespace and one DHCP lease per client port (`exp-<port_id>`); the probe tests every
  port independently. Needs one or more test NICs plus a separate management NIC (`mgmt_iface`).
* **host (single test NIC).** Used when the box has only one test NIC: exactly one client port, tested from the host
  namespace with no namespaces created. `mgmt_iface` must differ from that port unless `allow_shared: true` is set;
  with `allow_shared` the control-path trace is disabled (the management path and the test path are the same wire).
  Preflight still refuses anything that would take over the management interface.

## How it behaves

* **Preflight (fails closed).** A port is refused if it is `mgmt_iface`, holds the default route, carries a global
  address in the host namespace, is a bond/bridge/team member or such a device (or has VLAN children), does not exist
  (unless already inside its `exp-*` namespace), or is Wi-Fi with a non-`wifi` role. `netns up` runs it over **all**
  ports first: one refusal means nothing at all is changed. Preflight is read-only (`ip ... show`); it never touches a
  port it does not own. No carrier on every port gives a hint to check the NIC (bypass/disconnect-mode cards).
* **Namespaces.** `exp-<port_id>`; per-namespace `/etc/netns/exp-<port>/resolv.conf` (written from the lease).
  `netns down` stops processes in the namespace, takes the port down, **moves it back to the host explicitly and
  verifies it**, and only then deletes the namespace. A port that cannot be returned keeps its namespace and the
  unit fails (deleting it would destroy a virtual port).
* **Lease.** `udhcpc -f -R` with the hook writing `/run/exp/probe/<port>/lease.json` atomically.
* **Scheduler.** Wall-clock aligned 10 s beats; gateway/dhcp_hb/dns_hb/ping in parallel, traces one after another
  (test port, then control path); one rotating port per cycle for dhcp_hb/dns_hb/ping/trace (index persisted in
  `/var/lib/exp/probe/rotation.json`); scheduled tests staggered `interval/ports` with +-10 % of a slot of jitter;
  overlap = skipped and counted; `throughput` is serialized and mutually exclusive with traces (a trace due while a
  throughput test runs is skipped and counted); heartbeat work has priority over scheduled work.
* **Spool and shipper.** Every measurement goes to `/var/lib/exp/probe/spool.db` (SQLite WAL) **before** any send;
  bounded by `spool.max_mb`/`max_days`, oldest dropped first and counted (`dropped_total`). Batches of <= 500 records and
  <= 1 MiB gzip, oldest first, over TLS pinned to `tls_fingerprint_sha256` (mismatch: nothing is sent, ever). Status
  table: 200 deletes the batch, 400/413 split, 401 stop + retry every 60 s, 429 `Retry-After`, 503/network backoff
  1 s to 60 s with full jitter; fallback URLs after 60 s of the primary being unreachable.
* **Health.** The daemon writes `/run/exp/probe/status.json`; `health` combines it with the spool file, the leases and
  live per-namespace counters. `fail` = config invalid, daemon not running, namespace/port missing, no lease without a
  recent explanation, shipper stuck > 120 s with a backlog, `auth_failed`, `tls_pin_mismatch`. `degraded` (exit 0) =
  collector unreachable/not configured/throttling while the spool accepts, or a lease gap explained by a recent error.
  See `docs/spec/changes/CR-wp1-health-exit.md`.

## Measurement tests (M1)

All run inside the port's namespace (a thread that `setns(2)`'d into it; raw sockets, no child process per check,
except `curl`). Records follow the catalog in `01-contracts.md` section 3 exactly; `outcome` is `ok|degraded|fail`
(network verdict) or `error` (the probe could not run it; never conflated with `fail`). Try one:
`exp-probe test <test> --port c01 --once` prints the measurements and does not spool (`trace --path control|test|both`).

| test | what it does | outcome |
|---|---|---|
| `gateway` (beat, every port) | link + `carrier_changes` read in the namespace, 4 ICMP echoes (100 ms apart, 1 s grace) to the lease's router; `detail` gateway ip/mac/neighbor state | no link or no reply `fail`; `0 < loss < 50` `degraded`; `loss >= 50` `fail` (2 echoes could never express "degraded", see the module doc) |
| `dhcp_hb` (beat, rotating) | **DISCOVER only (SR-18)**: AF_PACKET client with the port's MAC and DHCP identity, offers collected `tests.dhcp.offer_collect_s` (3 s) | no offer `fail` (`server=none`); first offer > 1000 ms or >1 server (or one not in `tests.dhcp.allowed_servers`) `degraded` with `detail.rogue_suspect` |
| `dhcp` (scheduled) | DORA that **re-confirms the held binding**: same MAC/client-id/hostname/vendor as udhcpc, asks for the held address, REQUEST to the holder's server; configures nothing, never DECLINE/RELEASE; requires a lease | no offer/ACK, NAK `fail`; retry, rogue offer, other address (lease holder is nudged with SIGUSR1), `total_ms > 1500` `degraded` |
| `dns_hb` (beat, rotating) / `dns` (scheduled) | dnspython A query to each lease resolver (`resolver_kind=dhcp`) and `heartbeat.alternate_resolver` (`alternate`), 2 s; resolver ICMP `ping_rtt_ms`; `.invalid` NXDOMAIN canary for interception (`detail.nxdomain_canary`) | timeout/rcode!=0/no records `fail`; slow (> 250 ms) or intercepted `degraded`. `dns`: one record per (resolver, name), 2 attempts |
| `trace` (beat, rotating) | ICMP TTL sweep, one probe per `pace_ms`, replies collected while pacing, stops at the target; `path=test` from the port, then `path=control` from the host namespace pinned to `mgmt_iface`; sweeps are serialized | reached `ok` (`degraded` > 250 ms); not reached `fail` naming the last hop; no client with a lease: `error` "no client could run it: ..." |
| `ping` (beat, rotating) | 4 echoes per `heartbeat.ping` target (hostnames via the port's resolvers); falls back to the `ping` binary without a raw socket | all lost `fail`; any loss or mean > 250 ms `degraded` |
| `app` (scheduled) | `curl -w '%{json}'` (argv, in the namespace), redirects <= 5, 15 s; apdex on `total_ms` | curl error, HTTP >= 500, captive portal `fail`; HTTP 4xx, `total > 4T` or `apdex < 0.85` `degraded` |

Optional knobs (all under `tests.<test>`, ignored by the frozen schema's other readers, see
`docs/spec/changes/CR-wp1-test-options.md`): `thresholds` (`dhcp.offer_ms`/`total_ms`, `dns.rtt_ms`, `trace.rtt_ms`,
`ping.rtt_ms`, `app.slow_factor`/`apdex_min`), `dhcp.allowed_servers`, and per `app` target `expect_status` /
`expect_body`. Captive-portal detection is built in for `*/generate_204`, `*/gen_204`, captive.apple.com,
msftconnecttest.com and detectportal.firefox.com, and flags a plain-http target redirected to another site.

## Troubleshooting

| Symptom | Look at |
|---|---|
| no carrier on every port | check the NIC before the cables: a bypass or disconnect-mode card keeps the link down until its driver/bypass setting is changed. Per-port, check cable and switch port. |
| `netns up` exits 1, "REFUSED c01 (...)" | the reason is the fix: remove the address/bond/bridge, or pick another NIC. Nothing was changed. |
| `health`: waiting for collector fingerprint (`collector: null`, note `no_collector`) | the config has no `collector.tls_fingerprint_sha256` yet; the manager fills it in once the collector reports its pin. Until then nothing is sent (the shipper never connects unpinned) and records accumulate in the spool, bounded by its size cap. Fix: wait for the manager to push config, or set the collector url and fingerprint by hand. |
| `health`: `tls_pin_mismatch` | the collector certificate changed; update `collector.tls_fingerprint_sha256` (the manager does this when the collector reports a new pin). Nothing is sent meanwhile; records wait in the spool. |
| `health`: `auth_failed` | the ingest token was rotated/revoked; the agent rewrites `/etc/exp/probe/creds/ingest_token` and restarts the unit. The probe retries every 60 s. |
| port has no lease | `journalctl -u exp-probe-lease@<port>`; `cat /run/exp/probe/<port>/lease.json`; `ip -n exp-<port> addr`. |
| `exp-probe-netns` fails on stop | a port did not return to the host; the namespace is kept on purpose. `ip -n exp-<port> link` shows where it is. |
| a test says "not available in this build" | `throughput` and `path` arrive in M4+. |
| records with `outcome: error` | the probe could not run the test; `error` says why (no lease, namespace missing, no raw socket, curl missing). Never a network verdict. |
| `spool stat` shows growth and `dropped_total` > 0 | the collector was unreachable longer than the spool bounds allow. |

## Tests

```
.venv/bin/python -m pytest probe -q -m "not harness"     # unit tests: fake `ip`, fake clock, fake_collector over TLS
.venv/bin/ruff check probe
probe/tests/harness/run.sh                                # real veths/namespaces, udhcpc, dnsmasq and curl, in a privileged container
probe/tests/harness/run.sh -k measurements                # only the M1 measurement tests (about 2.5 min)
```
