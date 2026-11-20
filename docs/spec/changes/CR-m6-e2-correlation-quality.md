# CR-m6-e2-correlation-quality — A6.4 A6.5 A6.6 A6.8 A6.10 A6.12 on the `core` layout (M6 step e2)

**From:** M6 step e2 (integrator, e2e). **Affects:** `test/harness/` (`lanctl nat-core`), `test/e2e/m6/`, `.github/workflows/e2e.yml`, `runner/` (one defect).
**Decision:** accepted; later steps must know the items marked (binding). Builds on `CR-m6-e1-core-layout.md` (same stack, session-scoped).

## What was added

| Test file | A6.x | How the ground truth is made (no M5 drills) |
|---|---|---|
| `test_a64_diagnosis.py` | A6.4 | `wifi_signal`: fake Mist `weak_rssi` (-83 dBm / SNR 9) + the phone's link throttled by CDP (stand-in for the airtime an attenuated radio costs; the harness has no radio). `internet_path`: `lanctl delay --at wan` + fake Cloudflare bandwidth cap, fake Orchestrator healthy. `wan_saturation`: same fault + fake Orchestrator `saturated_wan` (92.5 %), internet-leg auto-pause off for that run. `policy_block`: EdgeConnect-style firewall DENY syslog lines for the client sent to the runner (diagnosis cites `security data.events`, the event carries the rule and the client IP, `raw_refs` has `syslog:<id>`). `network_wide`: `lanctl block-dns core-tp0..2` (every probe port loses DNS) so the probe baseline fails at the same time. Also: with the default 80 % threshold the runner's EC WAN-utilization feed pauses the internet leg (asserted end to end). |
| `test_a65_identity.py` | A6.5 | Mist identity (IP -> MAC, `device_key` = HMAC(per-org secret, MAC), AP/SSID/band, zone through `zone_map`); DHCP-syslog fallback (ISC dhcpd and Kea) with the Mist API forced to 503; unresolved (Mist `no_client` -> fails closed `no_match`; and no connector + no subnet table + no QR hint) still stores a diagnosed test with every leg and the probe baseline. |
| `test_a66_scrub.py` | A6.6 | `scrub_after_diagnosis` on in collector, runner and speedtest; after the final diagnosis NO raw IP / MAC (7 spellings) / hostname in any table of `records.db`, `runner.db`, `syslog.db`, `speedtest.db` (query assertions, polled until the scrub job ran), `device_key` and zone kept, no name/email key in any stored document and no such column in any table. |
| `test_a68_aggregates.py` | A6.8 | Box VictoriaMetrics: label names of every `exp_st_*` series are a subset of `{site,zone,leg,ssid,band,ap,os_family,cause,vmrange}`, no label value looks like an IP/MAC/device key/test id or equals one stored, series count follows the label combinations (3) not the devices (34). Dashboard `speedtests/aggregate` (count by zone/ap/ssid/band/os_family/cause/hour, p50 down/up/score) equals an independent computation over the collector's SQLite rows; the dashboard list equals the table. |
| `test_a610_page_quality.py` | A6.10 | Capture of every request; gzip -9 weight of the page's own files (144 KB of 200 KB); fps under a CDP trace with 4x CPU throttle; reduced-motion run; per-section comparison with the prototype (below). |
| `test_a612_location.py` | A6.12 | Mist -> AP/zone/RSSI (wireless) and switch/port (wired); DHCP fallback IP -> MAC and subnet -> zone; no connector -> `zone: unresolved` with all legs; NAT guard (below). |

## Findings and decisions

1. **Defect (runner, fixed): the privacy scrub left device-naming lines in the syslog ring.** `Ring.delete_ip` removes the lines indexed by the
   client IP; a `DHCPDISCOVER from <MAC> (<hostname>)` line carries no lease IP (stored as an unparsed line), so after the final diagnosis the
   MAC and hostname were still in `syslog.db`, contradicting A6.6 / 12 section 9 ("no raw identifiers remain ... the syslog ring"). New
   `Ring.delete_mentions(tokens)` (case-insensitive substring over the ring, bounded by the ring's row cap) and `correlator.device_tokens`
   (the MAC in colon / dash / dotted / bare spelling + the hostname); the correlator calls both after `complete` when `scrub_after_diagnosis`.
   Regressions: `runner/tests/test_ring.py::test_delete_mentions_removes_lines_without_an_ip`,
   `runner/tests/test_correlator.py::test_scrub_also_drops_ip_less_lines_naming_the_device`. Found by `test_a66_scrub.py`.
2. **NAT path in the harness (binding for later gates).** `lanctl nat-core on|off`: the gateway masquerades attendee traffic towards the box
   (`-o gw-core -d 10.9.0.10`), so the box sees `10.9.0.1`. The suite also tells the fake Mist that this address belongs to a DIFFERENT device
   (the dangerous case: a confident wrong answer). Observed and asserted: `identity.resolved_by none`, `zone unresolved`, `nat_suspected true`,
   `nat_reason outside_subnets` (observed IP outside every `client_subnets` entry while `require_real_client_ip`), then with the gateway address
   added to `client_subnets` and `translated_addresses`: `translated_address`; an ambiguous Mist lookup (`nat_ambiguity`, two MACs on one IP):
   `ambiguous`; no MAC, `device_key`, AP, SSID or switch port is ever stored, neither the stranger's nor the phone's. With the translation gone
   the next test resolves normally. `restore` turns the NAT off.
3. **`no_match` is a fail-closed result, not a fallback trigger.** With Mist configured and healthy a lookup that returns zero MACs fails
   closed (`nat_suspected`, `no_match`); the DHCP-syslog and subnet fallbacks run only when Mist is absent or ERRORS (outage, 429, budget). The
   suite asserts both (A6.5 / A6.12). The spec's "no connector -> unresolved" is exercised by removing `sources.mist` from the runner config.
4. **A paused internet leg gives "looks healthy"** (score 80 on the on-network leg alone, `none`) although the WAN evidence shows 92.5 % utilization.
   Not changed: nothing in the spec says a paused leg is a fault of the user's test, and the NOC sees the saturation in the `wan` evidence and the
   pause itself (`internet_leg_paused`, flag `internet_paused`). Open question for the owner if "paused" should also read as `wan_saturation`.
5. **A6.10 fps, measured (4x CPU throttle, link emulated at 50 / 25 Mb/s, 4-core sandbox shared with the box and the fakes):** median second
   55-56 fps, mean 46-47, per phase: on-network download 55, upload 57-58, Cloudflare latency 61, internet download 50-54, **internet upload
   31-35**. Gate: median >= 50 and never > 2 consecutive seconds under 10 fps. The upload dip is the vendored Cloudflare engine, not the page: it posts
   each upload body as a JS string and `fetch()` encodes it on the main thread (a CDP CPU profile of the run: ~3.2 s of native `fetch` self time
   at 4x; capping the page's upload tiers at 10 MB did NOT remove the stalls and was reverted, nothing in the page was changed). On an unthrottled
   client the same phase is 40-58 fps. An unthrottled gigabit client is also not a mid-range phone: with the link unrestricted the 4x-slowed main
   thread spends its time on data delivery (19-30 fps in the speed phases), which is why the phone's link is emulated. The CDP trace
   (`a610-trace.json`, ~4500 frames) and the per-second series (`a610-fps.json`) are kept in the artifacts.
6. **A6.10 prototype comparison tolerance (documented, binding for re-runs).** The prototype is rendered at 390 px (a desktop-mode 390-px viewport:
   it has no viewport meta, a mobile emulation would lay it out at 980 px) with its own demo data and the product's woff2 fonts; Google Fonts
   requests are aborted. Both full-page screenshots are cropped per section at that section's own top and compared on a 16 x 16 device-pixel
   luminance grid: mean absolute difference <= 0.15 (0..1) per section (0.35 for the waterfall bar, whose segments are the data). Measured:
   top 0.06, stage 0.07, legs 0.05, result head 0.04, score 0.02, parts 0.01, speeds 0.03, waterfall 0.19, checks 0.06; document height ratio
   1.14. Geometry: same widths (+-2 px), same section order, section heights within [0.75, 1.30] of the prototype ([0.4, 1.6] for the header, which wraps for the
   prototype's demo chip, and the checks list, one line per piece of evidence). Screenshots: `shots/a610-03-final-390.png`, `shots/a610-prototype-390.png`.
7. **Page weight**: HTML 151 KB raw / 41.7 KB gzip -9 + three woff2 (104 KB) = 144 KB. The box serves the HTML uncompressed (plain HTTP, no
   `Content-Encoding`); the budget is asserted on the gzip -9 size, as `speedtest/README.md` and `test_page_build.py` define it.
8. **CI placement**: `e2e.yml` job `m6` (nightly / label `e2e` / dispatch; timeout 150 min, the suite takes about an hour: it builds a signed
   0.2.0 release, installs the all-in-one box and runs A6.1-A6.12 in file order against it, `test_a68` last). It is NOT added to the 45-minute
   `ci.yml` harness job (the M1 suite already uses most of that budget).
9. The harness helper `Core.db_hits` / `Core.columns` (SQLite scans on the box), `Core.syslog` (UDP 5514 to the runner from the host, inside
   the allowlist), `Core.identify`, `Core.final`, `Core.clean_slate` are the shared test helpers (`m6lib.py`); `ui/core_page.js` gained CDP knobs
   (`cpuThrottle`, `throttle`, `reducedMotion`, `tracePath`, `profilePath`), a frame recorder, a phase sampler and wire sizes;
   `ui/proto_diff.js` renders the prototype and compares.

## Not done / limits
* No SSE connector (decision 2 of the owner decisions); no drills (A6.4 ground truth is harness faults + vendor fakes).
* The "attenuated radio" is the fake Mist scenario plus a page-side link throttle; no RF is simulated.
* Per-device VM labels are proven absent for the 34 devices of the session; the collector's own label cap (`metric_label_limit`) is unit-tested in the collector.

7. **Cited fps run and log.** The figures in item 5 are re-captured in `e2e-artifacts/m6/e2-full-final4.log` (full suite, `-rA` so the passing tests' stdout is kept;
   e2e.yml uses `-rA` too): `33 passed`; A6.10 fps median 59.0, mean 49.2, p10 20, min 0 over 41 s; per phase 58.7 / 58.7 / 61.3 / 55.5 / **35.6 (internet upload)**;
   3 seconds under 10 fps, longest run 1 s. The internet-upload dip and the "no freeze over 2 s" gate are the deviation described above; the lead should review it.
8. **Flake fixed (test side).** In the full suite the two A6.4 cases after the saturated-WAN case could start while the runner's held WAN peak re-paused the internet leg,
   giving score 99 and the (correct) "healthy" short-circuit although the evidence held the deny lines / failing probe. The cases now wait for the leg to stay open
   for 25 s (`internet_leg_open`), the firewall lines go over TCP syslog, and a failed diagnosis case dumps its whole record to the artifacts. No guard was changed.

