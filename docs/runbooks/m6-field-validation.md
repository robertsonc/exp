# M6 field validation runbook

Everything in M6 was proven against fakes and a container harness. This runbook closes the gaps that only real gear can
close. Run it at a lab or a friendly venue before the first customer event, fill in the report template at the end, and
send it back: every "FAIL" or surprise becomes a fix or a change record.

| # | What | Why it is open | Needs |
|---|---|---|---|
| 1 | Raspberry Pi probe | Debian 12 / Pi OS support is new; arm64 tested in CI containers only | 1 Pi 4/5, 64-bit Pi OS |
| 2 | Mist connector | built from the Mist OpenAPI + fakes; never called a live org | read-only Mist org token, 1 site |
| 3 | EdgeConnect connector | built from pyedgeconnect 0.16.0a1; time-series column names are an assumption | read-only Orchestrator API key, 1 appliance |
| 4 | 2 Gb/s on-network leg | the 47.9 Gb/s A6.2 figure is veth in a sandbox, not a NIC | box with >= 2.5 GbE, 2-3 wired clients |
| 5 | Byte-counter cross-check on real Wi-Fi | CR-m6-speedtest-server item 28: in-flight bytes at an abort may trip `counters_disagree` on slow, deep-buffered links | 1 busy or weak AP, 1 phone |

Allow half a day for 1-3 and an hour each for 4-5.

## 0. Safety rules (read before anything else)

* **Vendor APIs are read-only.** Use credentials that *cannot* write: a Mist org token with a read-only role and an
  Orchestrator user with a read-only role (role names differ by version: check *Mist → Organization → Settings → API Token*
  and *Orchestrator → Administration → Users / Roles*). exp only calls the endpoints listed in sections 2 and 3; the one
  `POST` (`/alarm/appliance`) is a query that returns alarms and changes nothing.
* **Speed tests are real traffic.** Each test moves up to `limits.bytes_local` (200 MB default) across the venue core to
  the box, plus the internet leg to Cloudflare when it is enabled. Sections 4 and 5 generate deliberate load: run them in
  a lab, or at a venue only in an agreed window. Never point section 4 at a production core during an event.
* **Nothing in this runbook changes network configuration.** No VLAN, QoS, CoA or Orchestrator policy changes. If a step
  seems to need one, stop and record it instead.
* **Secrets stay out of argv and shell history.** The curl examples read keys with `read -rs` and pass headers through
  process substitution; do not paste keys into commands, tickets or this report.

## 1. Raspberry Pi probe

**Setup.** Raspberry Pi 4 or 5, **64-bit** Raspberry Pi OS (Bookworm, Debian 12), Lite is fine. 32-bit Pi OS (armv7l) is
not supported and the installer refuses it. Wired Ethernet into the VLAN the probe should test, NTP working
(`timedatectl` shows `System clock synchronized: yes`).

**Install.** Manager → Hosts → **Add host** → copy the enrol command, run it on the Pi:

```bash
curl -fsSL https://<manager>/install.sh | sudo bash -s -- <enrol token>
```

Assign the probe shape in the manager, then on the Pi:

```bash
cat /etc/os-release | grep -E '^(ID|VERSION_ID)='     # expect ID=debian VERSION_ID="12"
uname -m                                               # expect aarch64
python3 --version                                      # 3.11.x
systemctl status exp-agent exp-probe --no-pager
sudo exp-probe selftest          # components are linked into /usr/local/bin
sudo exp-probe health --json
```

**Pass.** Enrolment succeeds; `selftest` prints no `FAIL`; `health --json` reports `ok`; the probe's lines (DHCP, DNS,
gateway, internet, throughput if enabled) appear on the dashboard within two cycles; after 30 min `exp-probe` RSS is
stable (`systemctl status` memory) and the Pi is not throttling (`vcgencmd get_throttled` → `throttled=0x0`).

**Record.** Pi model, OS image date, throughput test result vs a laptop on the same port (the Pi 4 NIC tops out
below 1 Gb/s in practice; note the figure, do not tune for it).

## 2. Mist connector (live org)

**Configure.** Manager → Speedtest → *site* → **Connectors** → Juniper Mist (owner only): API base for your cloud (`https://api.mist.com`, `https://api.eu.mist.com`,
`https://api.gc1.mist.com`, ... as shown in your Mist portal URL) and the **read-only** org token. Runner component →
correlation → Mist: the site id(s) and a `zone_map` (AP name or site → exp zone). Leave `max_calls_per_test` at 6 (Mist
allows about 5,000 calls per hour per token).

**Sanity check the token (optional, read-only).**

```bash
read -rs MIST_TOKEN; echo
curl -sS -H @<(printf 'Authorization: Token %s\n' "$MIST_TOKEN") https://api.mist.com/api/v1/self | head -c 400; echo
```

Expect your user/token identity and the org privilege listed as read-only (`"role": "read"` or similar).

**Run.** From a phone on the venue SSID, scan the zone QR (or open the page) and run 3 tests: one near an AP, one at the
edge of coverage, one while walking between two APs. Also run one from a wired laptop on a Mist switch port.

**Check each test** in Dashboard → Speedtests → test → *What the network team sees*:

| Evidence | Pass |
|---|---|
| Identity | `mist`, correct client MAC (admins see it), zone from `zone_map` |
| Wi-Fi | AP name, band, channel/width, RSSI, SNR match the Mist client page for the same minute (±3 dB) |
| Roaming | the walking test shows the roam (from the client's own events) |
| Wired | switch name and port id match the Mist switch page |
| Diagnosis | edge-of-coverage test reads `wifi_signal` (or a plausible cause), the good one reads `none` |

Runner log (`journalctl -u exp-runner --since -10min`) must show no `auth`/`403`/`429` errors.

**Calls exp makes** (all `GET`, under `/api/v1`): `sites/{site}/clients/search`, `sites/{site}/wired_clients/search`,
`sites/{site}/stats/clients/{mac}`, `sites/{site}/stats/devices/{device}`, `sites/{site}/clients/{mac}/events`,
`sites/{site}/stats/ports/search`, `sites/{site}/devices/events/search` (best effort; a 404 is tolerated).

**Record.** Any evidence that is `partial`/`unavailable` with its reason text, any field that differs from the Mist UI.

## 3. EdgeConnect connector (live Orchestrator)

**Configure.** Manager → Speedtest → *site* → **Connectors** → HPE EdgeConnect Orchestrator (owner only): URL and the **read-only** API key. Runner component → correlation → EC:
the appliance(s) (`nePk`, e.g. `3.NE`) that carry the venue's WAN, `wan_util.enabled = true` for auto-pause.

**Capture raw shapes (read-only) for the one unverified part, the time-series columns.**

```bash
read -rs EC_KEY; echo
ORCH=https://<orchestrator>; NE=<nePk>
H() { printf 'X-Auth-Token: %s\n' "$EC_KEY"; }
END=$(date +%s); START=$((END-900))
curl -sS -H @<(H) "$ORCH/gms/rest/appliance?nePk=$NE" | head -c 600; echo
curl -sS -H @<(H) "$ORCH/gms/rest/interfaceState?nePk=$NE&cached=true" | head -c 600; echo
curl -sS -H @<(H) "$ORCH/gms/rest/stats/timeseries/interface?nePk=$NE&startTime=$START&endTime=$END&granularity=minute&trafficType=all_traffic" \
  > ec-timeseries.json
python3 -c "import json;d=json.load(open('ec-timeseries.json'));print(type(d).__name__, list(d)[:5] if isinstance(d,dict) else d[:1])"
```

If your Orchestrator rejects a parameter, record the error verbatim; do not guess alternatives against production.

**Run.** Two tests from a client behind that appliance: one idle, one while a large download is running through the WAN
(e.g. a 1 GB file from a CDN, *in an agreed window*).

**Check** in the test's evidence:

| Evidence | Pass |
|---|---|
| WAN (`wan`) | status `ok` (not `partial`), `util_pct` present and within ±10 points of Orchestrator's own interface chart for that minute; alarms listed if any are open |
| Flows (`flows`) | the client's flows listed with application, traffic class, bytes; numbers match Orchestrator → Flows for that client |
| Auto-pause (only if WAN util > 80 % during the busy test) | the internet leg reads *paused*, diagnosis `wan_saturation` or "internet check paused, venue network fine" |

`wan` = `partial` with "columns not identified" means the time-series column names differ from the assumption in
`runner/exp_runner/ec.py`: send back `ec-timeseries.json` **with appliance names and IPs redacted**.

**Calls exp makes** (under `/gms/rest`): `GET /flow`, `GET /appliance`, `GET /interfaceState`,
`GET /stats/timeseries/interface`, `GET /health/{latency,loss,jitter,mos}PeriodSummary`, `POST /alarm/appliance` (query only).

## 4. 2 Gb/s on-network leg (real NIC)

**Setup (lab).** The core box on a >= 2.5 GbE (ideally 10 GbE) port; 2-3 wired clients with >= 1 GbE each on the same
L2/L3 path users take; `limits.bytes_local` raised for the bench only (e.g. 2 GB) and restored afterwards.

**Baseline the path** with iperf3 (installed with the probe) so the result can be compared with what the wire carries:

```bash
# on the box
iperf3 -s -1
# on each client, one at a time, then together
iperf3 -c <box-ip> -P 4 -t 15
```

**Run.** Open the speed-check page on all clients and start the tests within a few seconds of each other; repeat 3 times.
During the runs, on the box:

```bash
top -b -d 2 -n 15 | grep -E 'exp-speedtest|Cpu'
sudo exp-speedtest health --json | python3 -m json.tool | grep -E 'local_leg_gbps_p95|status'
```

**Pass.** `local_leg_gbps_p95` >= 2.0 when the clients together can carry >= 2 Gb/s (iperf3); each client's Local down/up
within 15 % of its own iperf3 figure; `exp-speedtest` below 2 cores at 2 Gb/s; no `counters_disagree` on these wired runs.

**Record.** NIC, CPU model, iperf3 per client and aggregate, page figures per client, `local_leg_gbps_p95`, CPU.

## 5. Byte-counter cross-check on real Wi-Fi

This tests the open question in CR-m6-speedtest-server item 28: at the end of each direction the page aborts the requests
still in flight; the box now counts the bytes it put on the connection, which on a slow link with deep buffers may exceed
what reached the phone by more than the 20 % cross-check.

**Run.** 20 tests from one phone at the edge of coverage of a busy AP (or a 2.4 GHz-only SSID), internet leg on, normal
`limits.bytes_local`.

**Check.** Dashboard → Speedtests filtered to that phone: count tests flagged *counters disagree*. For two flagged and two
unflagged tests, export the detail (admin view) and note `legs.local.bytes` (the page's count) vs
`observed.local_bytes_down + observed.local_bytes_up` (the box's).

**Pass.** <= 1 of 20 flagged. More than that confirms the item 28 risk: send the four detail exports; the fix is to book
acknowledged instead of sent bytes, or to shorten the last requests of a direction.

## Report template

Copy, fill, send back. Redact customer names, IPs and MACs.

```text
Venue / lab:                Date:            exp version:
1 Pi probe      PASS/FAIL   Pi model + OS image:            throughput vs laptop:
2 Mist          PASS/FAIL   cloud:            evidence mismatches:
3 EdgeConnect   PASS/FAIL   Orchestrator ver:  wan status (ok/partial):   util_pct vs chart:
4 2 Gb/s        PASS/FAIL   NIC/CPU:          iperf3 agg:     local_leg_gbps_p95:   CPU:
5 Counters      PASS/FAIL   flagged N/20:     page vs box bytes (4 tests):
Other surprises:
```
