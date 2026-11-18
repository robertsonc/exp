# HPE EXM collector

HPE EXM (Event network eXperience Monitor): the collector package.

The collector runs on one VM in the DC. It pulls each probe's results over SSH, serves the dashboard (one Pulse board per probe and an overview of them all), and pushes alerts. Probes keep 7 days of results themselves, so the collector can be restarted, upgraded or briefly unreachable without losing anything: each follower resumes from the last line it stored.

| Piece | What it does |
|---|---|
| `exm-follow@<probe>.service` | one per remote probe: an SSH session to the probe's management address that runs `exm stream` there (the only thing the collector's key can do), checks every line, and stores it under `/var/lib/exm-collector/probes/<probe>/` |
| `exm-web.service` | the dashboard, read-only, no login |
| `exm-alert.service` | webhook alerts (Slack, Teams, JSON); skipped until a webhook is configured |
| `exm-collector-prune.timer` | daily: streamed results older than `retention_days` (14) |
| `/etc/exm/collector.toml` | dashboard, alerts, retention |
| `/etc/exm/probes.d/<probe>.toml` | one file per probe (`exm-collector probe add` writes them) |

## Install

Needs Ubuntu 24.04 (or any Linux with systemd and Python 3.11+) and outbound SSH to the probes' management addresses.

```
tar xzf exm-collector-<version>.tar.gz && cd exm-collector-<version>
sudo ./install.sh
```

Idempotent: run it again to upgrade or repair. It keeps the config, probe files, keys, the alert webhook and all results. Then set `board_url` (this host's URL, used in alert links) and `timezone` under `[alerts]` in `/etc/exm/collector.toml`, and `sudo exm-collector apply`.

**Upgrading from 0.9.0 (UXM).** EXM was called UXM until 0.9.1. This installer migrates a UXM collector in place: it stops the `uxm-*` units, moves `collector.toml`, `probes.d`, the probe keys and the alert webhook from `/etc/uxm` to `/etc/exm` (paths inside follow, and linux probes are now reached as `exm-stream`), renames the `uxm-collector` user to `exm-collector` with the same uid and gid, and moves `/var/lib/uxm-collector` to `/var/lib/exm-collector` with every stored result, cursor and incident. Upgrade each probe too (in either order; a probe's board pauses until both ends are on 0.9.1, then catches up from where it stopped). On an all-in-one host, upgrade the probe first. Board URLs, including `?at=` links in old alerts, are unchanged.

## Add probes

A probe VM (exm-probe package), reached at its management address:

```
sudo exm-collector probe add hall-b --host 192.0.2.10 --label "Hall B registration"
#   prints the probe's SSH host key fingerprints and a key line; on the probe:
sudo exm authorize-collector 'ssh-ed25519 AAAA... exm-collector@dc-vm:hall-b'
#   back here, once the fingerprint matches the probe's own (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub there):
sudo exm-collector probe trust hall-b --yes
sudo exm-collector apply
```

Use the probe's `probe_id` as its name. The probe accepts the key only for the `exm-stream` user, only to run `exm stream`, with no shell, no pty and no forwarding; `--from` on `authorize-collector` pins it to the collector's address too. The collector pins the probe's host key, and the follower refuses to connect if it changes.

All-in-one (a probe on this same host): `sudo exm-collector probe add NAME --local`. Its results are read in place.

A Wi-Fi laptop (beta, see the Mac probe README): `sudo exm-collector probe add NAME --kind mac --host ADDR --user LOGIN --attach-to BOARD --ssid NETWORK`. Its results become the Wi-Fi row of that board.

`exm-collector probe list` shows each probe's follower and newest result; `probe remove NAME [--purge]` takes one out.

To test a probe's link by hand, use the followers' own identity (root's ssh refuses the group-readable key, by design): `sudo runuser -u exm-collector -- ssh -i /etc/exm/collector/keys/NAME_ed25519 -o UserKnownHostsFile=/etc/exm/collector/keys/known_hosts exm-stream@ADDR stream | head -3`.

## Operate

```
exm-collector status                 # every board's five lines right now, and where any fault is
exm-collector probe list
journalctl -u 'exm-follow@*' -f      # streams: connects, catch-up after an outage, refused lines
journalctl -u exm-web -u exm-alert -f
sudo exm-collector apply             # after any config change: followers, dashboard and alerts restart
```

A follower that loses its probe retries with backoff (5 s up to 60 s). On reconnect it asks for everything since the last line it stored (at most `backfill_hours`, 24), and drops what it already has.

## The dashboard

`exm-web.service` serves a read-only page, port 80 by default (`[web]` in `collector.toml`). There is no login. With one probe, `/` is its board; with several, `/` is the overview (one row per probe, worst first, with its five lines and where the fault is) and `/?probe=NAME` is each board.

The top of a board is the Pulse board: one sentence that answers "is it OK right now", over five heartbeat lines for the last 15 minutes (5 on a phone).

| Line | Beats from | Answer looks back |
|---|---|---|
| Network | `gateway`, every 10 s | 30 s |
| DHCP | `dhcp_hb` every 10 s, plus the full `dhcp` tests | 30 s |
| DNS | `dns_hb` every 10 s, plus the full `dns` tests for the resolver DHCP hands out | 30 s |
| Internet | `app` events (one beat per client run, lab servers excluded) and speed tests | 2 min |
| Wi-Fi | `wifi_hb` from a laptop attached to this board (beta), every 10 s | 30 s |

A line is failing when half or more of its recent results failed, partly working when any failed (or a third were slow), and "no data" when nothing arrived. A stretch with no results is drawn grey, never as a calm line. `harness_error` results never count. If only the Wi-Fi line has no data, the board says the wired network is fine and the test laptop isn't reporting. The sentence names the worst line and when it started. If no result has been written for 90 s, or the page loses its connection, the board goes grey and says nothing on it is current.

Under a line that isn't fine, one line of text says why:
- **Network:** the gateway each failing port could not reach and how many ports, plus any ports with no link.
- **Internet:** where a traceroute to `trace_target` stops. A `trace` heartbeat runs every 10 s from a rotating client: one ICMP echo per TTL, paced 20 ms apart, because Google's edge drops a simultaneous burst. It is diagnostic only and never colours a line.
- **Other lines:** the latest error.

Below the board, "What's failing" groups the errors behind each such line, with the clients and apps affected. For a traceroute, it shows the full path and the last complete path before it.

**Looking back.** The line marking when a problem started can be dragged:
- Drag it, or click any beat, and the sentence, icons, reasons and "What's failing" show that moment. What came after it is dimmed.
- Drag past the left edge to scroll further back.
- ← and → step 10 s (Shift: 1 min), and PageUp/PageDown jump 15 minutes.
- Esc or "Back to live" returns to live.
- The address keeps `?at=<UTC time>`, so a moment can be shared.

The page loads an hour of results, so "since" finds the start of a long problem. When the start is older than that, it says "since before HH:MM".

**Where.** Under the sentence, one more line says where on the path the fault is, with the path drawn as chips: Ports › Switch › Gateway › WAN edge › ISP › DNS › Apps. The break is red, the suspects are dashed, and everything past the break is grey. It triangulates signals the probe already has:
- **Control path:** the probe's `trace_ctl` heartbeat runs the same traceroute from the probe's management path, which reaches the ISP without the WAN edge. If it gets out and the ports' path doesn't, the fault is the edge. If neither gets out, it is upstream.
- **Alternate resolver:** `dns_hb` also asks `dns_alt` (1.1.1.1), and pings both resolvers. A dead resolver tells you to hand out another one; a dead path is a different problem; a resolver that answers ping but not DNS is a third.
- **Wi-Fi as a second view:** the Mac shares the gateway with the wired ports. If Wi-Fi reaches the gateway and the wired ports don't, it is the switch side. If neither does, it is the gateway or the link to it.
- **Rules:** they live in `static/pulse-core.js`, loaded by the page, and are mirrored in `lib/exm/pulse.py` for alerts. `test/parity.sh` replays real results through both and fails on any difference.

When a line comes back, the board says so for 15 minutes ("DNS was down for 51 minutes, 03:00:22–03:51:14"), so someone walking up to "All good" doesn't miss it.

**Voice.** By default a tired Unix admin writes the sentence; the facts in it are the same.
- **Incidents:** each one gets its own line, held for its whole length, and the line changes as it drags on ("It was DNS." becomes "Still DNS. It's always DNS.").
- **Context:** the time of night ("It's 3 a.m. Of course it's DNS."), Friday afternoons, flapping and recovery all have their own lines.
- **Plain:** set `voice = "plain"` under `[web]` in `collector.toml` for screens other people see, or add `?voice=plain` to the address.


## Alerts

`exm-alert.service` pushes to a chat webhook, so nobody has to be watching. Every probe is judged on its own with the board's rules; each message names the probe and links to its board at the moment it started:

| Message | When |
|---|---|
| down | a line has failed for 20 s: what failed, since when, where on the path, and a link to the board at that moment |
| again / flapping | it failed again within 5 minutes of recovering; from the third time, one "flapping" message, then quiet until it has been fine for 10 minutes |
| resolved | it has been fine for 60 s: how long it was down |
| silent | no results at all for 90 s |

Consequences fold into their cause:
- **Under Network:** DHCP, DNS and Internet ride along in its page ("Also failing: DNS"). So does Wi-Fi, while the laptop is on its own network.
- **Under DNS:** Internet.
- **Afterwards:** a line still failing when its cause recovers pages then.

A replay of the 2026-10-27 outage (the gateway down 43 minutes, then DNS, then the AP) gives 9 messages, each accurate. Open incidents are kept on disk, so `exm-collector apply` in the middle of an outage does not page twice.

Setup: create an incoming webhook in Slack (or a Teams Workflows webhook), then:

```
sudo install -m 600 /dev/null /etc/exm/alert-webhook
sudo nano /etc/exm/alert-webhook          # paste the URL, save
sudo exm-collector alert-test             # a sample down and resolved message, marked [TEST]
sudo exm-collector apply                  # starts exm-alert.service
```

The URL is a secret. It stays root-only on disk, and systemd hands it to the unprivileged service as a credential (`LoadCredential`); it is never logged. `[alerts]` in `collector.toml` sets the format (`slack`, `teams` or `json`), which lines page, the timezone used in messages, `board_url` for the links, and the holds. `exm-collector alert-test --dry-run` prints the messages without sending them. Without a webhook file, the unit is skipped rather than failed.


## API

| Path | Returns |
|---|---|
| `/` | the overview (several probes) or the only board |
| `/?probe=NAME` | a board; add `&at=2026-10-27T03:10:00Z` to open it at that moment |
| `/events?probe=NAME` | the live stream (Server-Sent Events) |
| `/api/history?probe=NAME&minutes=15` | recent results for the Pulse lines; `&at=` for a window ending then |
| `/api/summary?probe=NAME` | the details tables: the probe's own summary (published each minute) plus Wi-Fi |
| `/api/boards` | every board's lines and "where" right now (the overview, and `exm-collector status`) |

Every line the collector stores is untrusted input: test names must be plain identifiers (they name files), timestamps well formed and not in the future, nesting and sizes are bounded, numbers finite, and `probe_id` is overwritten with the configured name. A bad line costs only itself.

## Remove

`sudo ./uninstall.sh` stops and removes the services and code; `--purge` also deletes the config, keys, webhook, streamed results and the `exm-collector` user. A probe on the same host is left alone.
