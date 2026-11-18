# HPE EXM (Event network eXperience Monitor)

Synthetic clients on the event network answer one question every 10 seconds: *is the network up, are DHCP and DNS working, and is the internet experience good?* A NOC dashboard says it in one sentence, says where on the path a fault is, and lets you drag back in time to see what was failing. Alerts go to Slack or Teams.

```
   event network (test ports)                management network                         DC
 ┌──────────────────────────┐            ┌──────────────────┐ SSH (pull)  ┌──────────────────────────┐
 │ exm-probe VM             │            │                  │◄────────────│ exm-collector VM         │
 │  c01..cNN  one namespace │  results   │  sshd: exm-stream│ exm stream  │  exm-follow@<probe>      │
 │  per port: DHCP, DNS,    ├──────────► │  (forced command)├────────────►│  /var/lib/exm-collector  │
 │  apps, speed, heartbeats │  7 days    │                  │  results    │  exm-web   :80 dashboard │──► NOC screens
 │  s01..  Minis targets    │  local     └──────────────────┘             │  exm-alert  webhooks     │──► Slack / Teams
 └──────────────────────────┘                                            └──────────────────────────┘
        Mac on the event Wi-Fi (beta) ── SSH (pull, forced command) ──► collector: the board's Wi-Fi row
```

| Package | For | Docs |
|---|---|---|
| `exm-probe-<v>.tar.gz` | probe VMs (Linux): one management interface, one or more test interfaces | [docs/PROBE.md](docs/PROBE.md) |
| `exm-collector-<v>.tar.gz` | the collector VM in the DC: dashboard, alerts, the probes' streams | [docs/COLLECTOR.md](docs/COLLECTOR.md) |
| `exm-mac-probe-<v>-beta.tar.gz` | a Mac on the event Wi-Fi (beta) | [docs/MAC-PROBE-BETA.md](docs/MAC-PROBE-BETA.md) |

Download them from the GitHub release (with `SHA256SUMS`), or build them: `scripts/build-release.sh`.

## Quick start

```
# collector VM
tar xzf exm-collector-0.9.1.tar.gz && sudo exm-collector-0.9.1/install.sh
# each probe VM: edit /etc/exm/exm.toml ([[client]] per test interface) after the first install, then sudo exm apply
tar xzf exm-probe-0.9.1.tar.gz && sudo exm-probe-0.9.1/install.sh
# link them
sudo exm-collector probe add probe-01 --host <probe mgmt address>        # on the collector; prints a key
sudo exm authorize-collector '<that key>'                               # on the probe
sudo exm-collector probe trust probe-01 --yes && sudo exm-collector apply   # on the collector, fingerprint checked
```

Both installers are idempotent: re-run them to upgrade or repair. Both packages on one host (all-in-one) is supported: `exm-collector probe add NAME --local`.

**Upgrading from 0.9.0, when it was called UXM:** run the 0.9.1 installers over it. They migrate config, keys, users and all history in place (probe first on an all-in-one host); see [docs/PROBE.md](docs/PROBE.md#install) and [docs/COLLECTOR.md](docs/COLLECTOR.md#install).

## More

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): data flow, trust boundaries, the result schema, where correlation plugs in
- [docs/RELEASING.md](docs/RELEASING.md): versioning, building, GitHub releases
- [CHANGELOG.md](CHANGELOG.md)
- `deploy/lab-srv02/`: the lab's real probe config (12 Silicom ports, Minis targets)
- Tests: `test/unit.sh` (offline, about a minute), `test/harness.sh` (a probe in a container, ~10 min), `test/package.sh` (the release tarballs in systemd containers), `test/upgrade.sh` (0.9.0 tarballs upgraded in place to this version)
