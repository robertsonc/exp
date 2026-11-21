# 12 — Speedtest analytics (M6)

A **branded speedtest page** that attendees, exhibitors, and staff open on the event network. Every
result is cataloged in exp and **correlated with what the network saw for that user's device at that
moment**: wireless client stats (Mist), flows and path (EdgeConnect), security-policy logs (firewall /
SSE / syslog), the wired port, and exp's own synthetic probes nearby. The result is a one-sentence
diagnosis for the user ("Your Wi-Fi signal is weak — the internet is fine") and an **evidence bundle**
for the NOC.

Inspiration: Orb Custom (white-label web speedtest, results to your own endpoint, live share links for
support). What exp adds: **two-leg measurement** (local vs internet) and **network-side correlation**
per device, kept on-prem.

## 1. Goals and non-goals

Goals
- G1. Any user on the event network can run a test in ≤ 20 s from a phone or laptop with one tap,
  from a QR code or captive-portal link. No app or account.
- G2. Every test answers **"is it my device, the Wi-Fi/LAN, the venue WAN, or the internet?"** —
  by measuring two legs and correlating network data for that client.
- G3. The NOC sees every test with its evidence, and aggregates by zone, AP, SSID, band, device OS,
  and time — "user experience as reported by users", next to the synthetic probes.
- G4. **Always anonymous.** No name or email is ever collected. The box resolves the device only to
  diagnose the test, and raw identifiers are deleted shortly after (§9).
- G5. Same exp mantra: one more shape (`speedtest`) the manager deploys; no hand configuration.

Non-goals (v1)
- **Any app install or cloud deployment.** No native app, no app-store, no Worker or other cloud
  service of our own: the page is a **self-contained web page served by a dedicated exp box**
  (a probe + collector host) on the event network, and the internet leg uses Cloudflare's public
  speed-test endpoints directly from the browser.
- Background sensors on user devices (Orb Sensor equivalent).
- Packet-loss measurement in the browser (needs WebRTC/UDP; see §12 future).

## 2. Decision D15

**The speedtest is a self-contained page served by a single exp box at the venue core / data center
(the probe, collector, and runner shapes on one host). Attendees across every hall hit the same box;
**where they physically are is resolved by correlation** (Mist AP/zone, EC flows, DHCP), not by the
box's location. The browser measures its speed to that box ("on-network") and to Cloudflare's public
speed-test service ("internet"); DNS runs through the device's own resolver; the per-user Wi-Fi and
path breakdown comes from correlation.**
- **One box, no per-zone boxes and no steering.** This replaces the earlier per-zone/steering design
  (the old D16): simpler to deploy, and correlation already knows each client's AP, zone, switch, and
  WAN path. A per-zone QR is now only an optional *hint* that stamps a zone when Mist can't resolve one.
- **No app, no cloud component of ours.** Works stand-alone with a local config (M1-style install
  from tarballs); a manager, when present, deploys and configures it like any host.
- **Hard requirement — the box must see each client's real source IP (no NAT in between).** Correlation
  keys on that IP (IP → Mist → MAC/AP/zone). Place the box where attendee VLANs reach it **routed but
  un-NAT'd** (core, before any guest-NAT / internet edge). If the path NATs client addresses,
  correlation fails and the product degrades to bare speed numbers with no "where" (§13 Q8).
- **Correlation-dependent by design.** With Mist/EC connected, the single box localizes Wi-Fi vs
  switch vs WAN as well as a local box did (Mist reads the radio directly — better than a timing leg).
  Without Mist/EC, a DC box yields only device→box and device→internet speeds and the DNS leg, with no
  per-user location.
- **Works with the internet down** (Principle 2): page, on-network leg, DNS leg, and diagnosis keep
  working; the internet leg reports "unavailable". A core/box outage stops testing event-wide (the
  trade for one box); an event that needs hall-local resilience can still run more than one box.
- Correlation and the syslog receiver run on the **same box** (the runner shape,
  `10-drills-integrations.md`), holding the Mist/Orchestrator credentials.

## 3. Components and data flow

```
 phones in every hall ──QR / portal link──▶ http://speed.<event-domain>/   (plain HTTP, routed to core)
   │                              ┌──────── one exp box at the core / DC ──────────────────────────┐
   │ 1. page (one self file)  ◀───│ exp-speedtest (page, sessions, on-network endpoints)           │
   │ 2. on-network: ping/down/up ◀▶│  spans Wi-Fi+access+core — the "on-network" figure            │
   │ 3. DNS leg: http://<nonce>.t.speed…  │  tiny authoritative DNS — sees resolver IP, arrival     │
   │ 4. internet leg ───▶ speed.cloudflare.com (public; down/up/latency, colo)                     │
   │ 5. result ─────────────────▶ collector (records + VM aggregates)                              │
   │ 6. runner correlates by client IP: Mist AP/zone/RSSI · EC flow+WAN · syslog · nearest probe   │
   │ 7. diagnosis + where-you-were  ◀───── evidence → rules (≤ 5 min)                               │
   ▼                              └───────────────────────────────────────────────────────────────┘
 result: on-network vs internet speeds, DNS, then the per-user Wi-Fi/path breakdown from correlation
 (box must see the real client IP — no NAT between the halls and the core)
```

- **`exp-speedtest`** (component type `speedtest`) runs on the core box: serves the page and the
  on-network speed endpoints, issues sessions, runs the DNS-leg authoritative server and the (now
  shared, infrastructure-level) core→edge path timer, validates results, sends them to the collector
  on the same host. It must be reachable from attendee VLANs **routed and un-NAT'd** (D15).
- **Collector**: stores tests, evidence, and diagnoses (SQLite `speedtests`, `evidence`), writes
  low-cardinality aggregates to VictoriaMetrics, exposes the query API (§7.4), runs the diagnosis
  rules (server-side — D3).
- **Runner**: correlation connectors and syslog receiver (§5).
- **Dashboard** (optional on the kit or elsewhere): speedtest analytics views (§8).
- **Manager** (optional): branding/config, connector credentials as secrets, zone labels and
  optional QR signage, fleet health for the box. Without a manager the settings live in local config.

## 3.1 Where the user is: resolved by correlation, not by the box

Because one box at the core serves everyone, the attendee's **location is reconstructed after the
test from network data**, not from which box they reached (decision D15, which replaces the earlier
per-zone-steering design):

- **Primary:** the runner resolves `client_ip` + time → Mist client → **AP, zone, SSID, band, RSSI,
  switch/port** (§5.1). That is the user's real location and radio, independent of where the box sits.
- **Fallbacks:** DHCP-syslog or EC gives IP → MAC and the subnet → a coarse zone; failing that the
  test is `zone: unresolved` (still has both speed legs, the DNS leg, and a probe baseline).
- **Optional hint:** a per-zone QR (`/?z=hallb-row12`) or a captive-portal parameter stamps a zone on
  the test up front, used when Mist can't resolve one and to cross-check. It no longer steers the user
  to a box — there is one box.

This removes the zone directory, the redirect director, and DNS steering from the earlier design.
The only hard dependency is that the box sees the client's **real source IP** (D15): behind NAT, the
Mist-by-IP lookup resolves the wrong device or none. Verify the attendee→core path is un-NAT'd (§13 Q8).

## 4. The test

### 4.1 Page and UX
- One screen, event-branded (logo, colors, title, copy, languages — configured in the manager, like
  Orb Custom's configurator). Big **Start** button; ~15 s test; live gauges; results.
- Before the first test: a **consent panel** (configurable text) stating what is measured and that the
  network team will look at this device's Wi-Fi and traffic metadata to diagnose it; choices **Start
  test** / **Cancel**. Every test is anonymous — no name or email is collected — so there is only one
  path. The consent text version is stored with the test.
- **Zone**: not asked up front and not needed to run. It is resolved *after* the test from
  correlation (§3.1): Mist AP/zone by client IP, else subnet→zone, else `unresolved`. An optional QR
  `?z=` stamps a hint. Once resolved, the result shows it ("You were in Hall B") and the user can
  correct it.
- Results show the **path of legs** with each leg's time (§4.2), Download/Upload for the local and
  internet legs, **Responsiveness** (latency under load), the **exp score** (0–100), "where your time
  goes" (a waterfall of the latency each segment adds on the way to Cloudflare), "good for" (video
  calls, HD streaming, large uploads), a plain-language verdict, the **diagnosis** ("Your Wi-Fi is
  strong. The venue's internet link is busy, so uploads suffer."), and **what the network team sees**
  as correlation completes (Wi-Fi signal, venue internet, security policy, hall sensor). Network
  details (AP name, channel) are shown to the user only if the event enables it.
- **Report a problem**: optional free text (≤ 500 chars) attached to the test.
- **Share with support**: an unguessable link (`/st/r/{id}#k=…`, key in the fragment) the user can
  give to the help desk; operators open it in the dashboard with full evidence.
- Works on a 390-px phone, WCAG AA, keyboard reachable, `prefers-reduced-motion`; no third-party
  scripts, fonts, or analytics; CSP as the dashboard (`04-dashboard.md` §5); all user text rendered
  with `textContent`.

### 4.2 Legs and measurement method

The test runs ~18 s: latency legs first (≈ 4 s), then local download/upload, then internet
download/upload. Every leg is shown on the page as a node on the **path**
(device → Wi-Fi/LAN → DNS → gateway → edge → edge+1 → Cloudflare) and timed idle and, where it
matters, **loaded** (while the user's own download/upload is running — this is what exposes a
congested venue link).

| Leg | Measured by | Method |
|---|---|---|
| **On-network** (device ↔ core box) | browser | 20 × `GET /st/ping` on a warm HTTP connection to the box: median RTT and jitter, idle and loaded; on-network download/upload (below). From the core this spans **Wi-Fi + access + distribution + core**, so it is the "how fast on the venue network" figure, **not** a pure Wi-Fi/LAN isolation — that split comes from Mist (§5). |
| **DNS** (device's own resolver) | browser + box | The page fetches `http://<nonce>.t.speed.<event-domain>/st/px` for 2 fresh nonces (cold: resolver must recurse to the box's authoritative server) and 1 repeated name (warm: cached). Lookup time = Resource Timing `domainLookupEnd − domainLookupStart` (the box sends `Timing-Allow-Origin`). The box's DNS server sees the query arrive, which identifies the **resolver IP** and splits the cold time into device→resolver and resolver→authority. Requires only a delegated `t.speed.<event-domain>` (NS → box) — **no certificate**, since the page is plain HTTP. Without the delegation: fallback to the probe's own DNS line at that moment, labelled "measured by the hall sensor". |
| **Core → edge path** (gateway, edge, edge+1) | box | The box times its own path to the gateway, the EdgeConnect LAN side, and one hop past the edge (ICMP / TTL-limited trace, idle and loaded). From the core this is **venue-infrastructure health shared by all tests**, not the individual user's access path. The *user's own* path and WAN come from their EC **flow** record and Mist switch stats (§5), which is where the per-test waterfall is built. |
| **Internet** (device ↔ Cloudflare) | browser | Cloudflare's public speed-test endpoints (`speed.cloudflare.com` `__down?bytes=` / `__up`), the method of Cloudflare's own open-source speed-test library (MIT-licensed `@cloudflare/speedtest`, **vendored into the page** — no CDN): idle/loaded latency, download, upload; the serving location (colo) from `/cdn-cgi/trace`. Header and timing behaviour of these endpoints MUST be confirmed from a live recording during the build, not assumed. |
| **On-network speed** | browser + box | Parallel streams (start 4, up to 8) of `GET /st/down?bytes=N` (box uses `sendfile`) and `POST /st/up` (box discards and counts bytes); sizes ramp 100 kB → 25 MB until each request ≥ 1 s or 8 s elapsed; 90th percentile of 250-ms samples after the ramp (when the byte budget ends a direction before 8 such samples exist: bytes / duration of the steady window instead, `changes/CR-m6-speedtest-server.md` item 27). **This traffic crosses the core** from the DC box (§4.4), so caps are tighter. Box byte counters cross-check the browser's numbers. |

Box-measured legs stream to the page over `GET /st/api/v1/sessions/{id}/path` (every 500 ms or SSE)
so the page animates them with the browser-measured legs. From the core, **"where your time goes" is
built from correlation, not from the box's path**: the user's Wi-Fi RTT and retries (Mist), their
access switch/port, their flow's WAN path and QoS (EC), plus the measured device→box and
device→internet RTTs. The box's own core→edge path is shown as venue-infrastructure context. Until
correlation returns (≤ 5 min), the page shows on-network vs internet and the DNS leg, and fills the
per-user breakdown in when the evidence arrives. The whole breakdown is labelled an estimate.

Implementation uses `fetch` streams and the Resource Timing API; no WebSockets or WebRTC. Total
transfer is capped per test (default 200 MB on-network, 200 MB internet; the 400 MB of the first draft is superseded by §4.4) and adapts down on slow links.

**exp score** (0–100) = 40 × speed (min(down/target_down, 1) and min(up/target_up, 1), averaged) +
40 × responsiveness (100 % at ≤ 30 ms loaded latency, 0 % at ≥ 300 ms, linear) + 20 × stability
(CV and failures). Targets per event (default 25 / 10 Mb/s). Shown with its three parts.

### 4.3 The page: self-contained, mobile-first, and it has to look great

- **One self-contained file** served by the box over **plain HTTP by default** (D15): HTML with
  inline CSS/JS/SVG and locally served fonts (variable condensed display face for numerals + a text
  face, subset, ≤ 120 KB), no CDN or third-party script, no analytics. CSP
  `default-src 'self'; script-src 'sha256-…'` (hashes computed at build),
  `connect-src 'self' http://*.t.speed.<event-domain> https://speed.cloudflare.com`,
  `img-src 'self' data:`. (An HTTP page may call the HTTPS Cloudflare endpoints — that direction is
  not mixed content.) Page weight ≤ 200 KB gzip including fonts and the vendored library.
- **Degrades without a secure context:** copy-to-clipboard and the screen wake lock need HTTPS, so on
  plain HTTP they fall back (select-the-code, no wake lock). Everything measured — `fetch` streams,
  Resource Timing, the gauge — works over HTTP. If an event does provide a cert, serving over HTTPS
  restores those niceties with no other change.
- **Mobile first**: designed at 390 × 844 first; one-thumb layout (big start button in the lower
  half of the gauge), 44-px targets, safe-area insets, no horizontal scroll, portrait and landscape,
  dark and light themes following the device; two-column layout from 900 px.
- **Animation is part of the product**, not decoration:
  - the **gauge**: a 270° arc on a perceptual (piecewise-log) scale 0–1,000 Mb/s with a glowing
    leading tip, a counter that eases to each sample, green for download, violet for upload, pulse
    rings while running, and a live throughput trace under it;
  - the **path**: each leg is a node; the active leg pulses and "packets" run down the rail to the
    next node; each node settles to its time and a state colour (ok / slow) as it completes;
  - **results**: the score ring sweeps in, speed bars and the time waterfall grow from zero,
    correlation checks flip from "checking…" to their findings as the evidence arrives.
  - 60 fps on a mid-range phone (transform/opacity and SVG attribute updates only, one
    `requestAnimationFrame` loop); `prefers-reduced-motion` turns animation off and keeps every
    number; the screen wake lock is held during a test where allowed.
- **Reference prototype:** `docs/spec/prototypes/speed-check.html` (demo data) is the visual and
  interaction reference WP-10 builds to; the production page replaces its demo engine with the real
  legs above and loads fonts locally.

### 4.4 Abuse and capacity protection (an event WAN is shared)- Per client IP: ≤ 6 tests per 10 min, ≤ 1 concurrent; per site: ≤ `max_concurrent` internet legs
  (default 10) — extra users get the on-network and DNS legs immediately and a queue position for the
  internet leg (the page asks the box for an internet slot before calling Cloudflare).
- Admin switch **Pause internet leg** (e.g., during a keynote) and an automatic pause when the EC WAN
  utilization from the runner exceeds a threshold (default 80 %); the page then shows the on-network
  and DNS legs and says why the internet leg was skipped.
- The internet leg goes to Cloudflare's public service, which is ordinary internet use from the
  device; the box cannot technically stop a modified client calling Cloudflare directly, so the
  slot mechanism protects the event WAN from **well-behaved** pages at scale, and the volume caps
  keep each test bounded.
- On-network endpoints require the session's short-lived token (60 s, byte budget) so the box is not
  an open bandwidth sink.
- **Core bandwidth:** with one box at the core, every on-network download crosses the access and core
  links (unlike a per-hall box, where it stayed local). Keep the on-network cap tight (default lowered
  to 200 MB), bound total concurrency per box (default 20), and have the manager/box auto-shrink the
  on-network size when core-facing interface utilization (from fleet health / EC) is high.

## 5. Correlation (runner connectors)

On each new test (polled from the collector every 5 s, or SSE), the runner resolves the client and
pulls evidence for the window **[start − 5 min, end + 2 min]**. Each connector is optional; missing
connectors simply produce no evidence of that kind.

### 5.1 Identity resolution
This is the **primary location mechanism** for the single-box model (§3.1), not just an enrichment.
`client_ip` + time → **device** (MAC) → **zone/AP + user**:
1. Mist client search by IP at that time (wireless, and wired clients behind Mist-managed EX switches) →
   MAC, **AP, zone, SSID, band, RSSI, switch/port**, manufacturer, OS family, 802.1X/guest user if present.
2. Fallbacks: DHCP lease data from the runner's syslog receiver (ISC/Kea/Windows DHCP or EC DHCP
   logs) for IP → MAC, and the client **subnet → coarse zone** from the zone-label table.
3. If unresolved: `zone: unresolved` — the test still has the on-network, internet, and DNS legs and
   a probe baseline, but no per-user Wi-Fi/path breakdown.
**Requires the real client IP** (D15): behind NAT this step resolves the wrong device or none, so the
box must sit where attendee traffic reaches it un-translated.

Stored identifiers: `device_key` = HMAC-SHA256(per-org secret, MAC) — stable for aggregation, not
reversible without the secret. Raw MAC/IP/username are kept **only** per the privacy mode (§9).

### 5.2 Evidence sources
| Source | What is pulled (field names MUST come from the vendor API docs or recorded responses) | Evidence kind |
|---|---|---|
| **Mist (wireless)** | client stats at test time: AP, SSID, band, channel, channel width, RSSI, SNR, tx/rx rate, retries, idle time; AP stats: client count, channel utilization, interference; roam and auth events for the MAC in the window | `wifi` |
| **Mist (wired)** | switch, port, VLAN, port speed/duplex, errors, PoE, port events | `wired` |
| **EdgeConnect Orchestrator** | flows for the client IP in the window on the site's appliance(s): application, bytes in/out, duration, overlay/business intent, WAN path, QoS class, boost; appliance WAN utilization and loss/latency per WAN at test time; alarms | `flows`, `wan` |
| **Security-policy logs** | (a) EC firewall / zone-policy logs via syslog; (b) HPE Aruba SSE (Axis) policy decisions via its API; (c) any firewall sending syslog (RFC 5424 / CEF / LEEF / key=value). Matching denies, drops, URL/IPS blocks, and NAT/session-limit hits for the client IP | `security` |
| **exp probes** | state of the nearest probe(s) (same zone/AP/site) at test time: lines, verdict, throughput tests | `baseline` |
| **DNS** (optional) | resolver query logs for the client IP (syslog) — slow or failing lookups | `dns` |

- **Syslog receiver** (runner): UDP/TCP 5514 and TLS 6514 (no root port), source allowlist, rate
  limit, a 60-min ring buffer indexed by IP in SQLite (`/var/lib/exp/runner/syslog.db`). Lines are
  kept beyond 60 min **only** when attached to a test's evidence. Parsers: EdgeConnect, CEF, LEEF,
  RFC 5424 structured data, `key=value`; unknown formats kept as raw text (bounded) with timestamp and IP.
- **On-demand pulls**: Mist and Orchestrator are queried per test (not bulk-polled), within the
  existing rate budgets (Mist ~5,000 req/h/token: ≤ 6 calls per test; cached 30 s per AP/appliance).
- Evidence is normalized to `exp.evidence/1` (§7.2), bounded (≤ 256 KiB per test, top-50 flows by
  bytes, ≤ 200 log lines), and posted to the collector with the runner's identity-bound token.

### 5.3 Diagnosis rules (collector, server-side)
Rules run on the quick result (legs only) and again when evidence is final. Output: `cause`
(ordered list, each with confidence and the evidence it cites), user text, NOC text. Initial rules:

| Cause | Fires when (defaults, tunable) |
|---|---|
| `wifi_signal` | RSSI < −72 dBm or SNR < 20 dB, and local leg < 50 % of the band/width expectation |
| `wifi_congestion` | AP channel utilization > 70 % or > 60 clients, local leg slow, RSSI fine |
| `wifi_roaming` | ≥ 2 roams or an auth failure during the test |
| `wired_port` | wired client and port errors/half duplex/100 Mb/s |
| `device_limit` | local leg slow with good RSSI/SNR, AP not congested (old radio, 1×1, power save, VPN) |
| `wan_saturation` | EC WAN utilization > 85 % or WAN loss/latency high, local leg fine |
| `internet_path` | internet leg slow, local leg fine, WAN not saturated (ISP / peering / Cloudflare) |
| `policy_block` | security logs show denies/blocks or session limits for the client in the window |
| `qos_shaping` | flows classified into a rate-limited class/intent for the client |
| `dns` | resolver logs show failures/slow answers, or probe DNS line is failing |
| `network_wide` | nearest probe shows the same degradation at the same time ("it is not just you") |
| `none` | score ≥ 80 |

Like line verdicts, the user text is plain and blame-free; the NOC text names the evidence
("hallb-ap-12 ch 44/80 MHz, util 81 %, 74 clients; RSSI −61 dBm").

## 6. Storage and metrics
- Collector SQLite: `speedtests` (one row per test, §7.1), `evidence` (per kind, JSON), `diagnoses`.
  Retention: tests, device metadata and evidence 30 days by default (aggregates forever in VM); raw identifiers per §9.
- VictoriaMetrics (low cardinality — Principle 8; **no per-user or per-device labels**):
  `exp_st_down_mbps`, `exp_st_up_mbps`, `exp_st_loaded_latency_ms`, `exp_st_score` as histograms
  (`vmrange`) with labels `site`, `zone`, `leg`, `ssid`, `band`, `ap` (bounded by AP count), `os_family`;
  `exp_st_tests_total{site,zone,cause}`.
- Fleet health (`01-contracts.md` §8.1) gains a `speedtest` row: `tests_per_hour`, `active_tests`,
  `internet_leg_paused` (0/1), `queue_depth`, `local_leg_gbps_p95`, `rejected_per_hour`.

## 7. Contracts

> **Moved (M6 contracts step).** The normative contracts are `01-contracts.md` §14 and `shared/schemas/`
> (`speedtest`, `speedtest.submission`, `evidence`, `speedtest.config`, plus additions to `common`, `runner.config`,
> `collector.config`, `desired`, `health`), `shared/openapi/speedtest.yaml` (and the `speedtests` additions to
> `collector.yaml` / `admin.yaml`) and `shared/python/exp_common/speedtest.py`. The subsections below are the original design
> sketch; where they disagree with §14 or `changes/CR-m6-spec-resolutions.md` (transport, byte caps, retention, NAT guard,
> D16 wording, A6.4 ground truth), **those win**. In particular: §3.1's "decision D16" means D15; §4.2/§7.5's 400 MB
> on-network cap is 200 MB (§4.4); §6's 90-day test retention is 30 days (§9); §7.3's "HTTPS 443" is TCP 80 (plain HTTP)
> unless `tls.mode = provided`.

### 7.1 `exp.speedtest/1` (result, client → speedtest → collector)
`legs` also carries `dns` (`cold_ms`, `warm_ms`, `resolver_ip`, `source: browser|probe`) and `path`
(`gateway_ms`, `edge_ms`, `edge1_ms` each `{idle, loaded, samples}`, `edge1_addr`, `device_icmp_ms`)
filled in by the box.
```json
{"schema": "exp.speedtest/1", "id": "st_01JDF…", "site": "hall-b", "zone": "hallb-row12",
 "started": "2026-11-18T14:02:11.120Z", "ended": "2026-11-18T14:02:27.540Z",
 "client": {"ip": "10.60.14.77", "ua": {"os_family": "iOS", "os_version": "18.1", "browser": "Safari",
            "device_class": "phone"}, "connection_hint": "wifi"},
 "consent": {"text_version": 3},
 "legs": {
   "local":    {"down_mbps": 212.4, "up_mbps": 88.1, "idle_ms": 6.2, "jitter_ms": 1.1,
                "loaded_down_ms": 41.0, "loaded_up_ms": 55.3, "rpm": 1150, "cv": 0.12, "bytes": 310000000,
                "server": "spd-hallb"},
   "internet": {"down_mbps": 184.0, "up_mbps": 61.7, "idle_ms": 18.9, "jitter_ms": 2.4,
                "loaded_down_ms": 96.0, "loaded_up_ms": 120.4, "rpm": 520, "cv": 0.21, "bytes": 190000000,
                "server": "cloudflare:FRA"}},
 "score": {"total": 74, "speed": 92, "responsiveness": 55, "stability": 80},
 "comment": "video calls freeze at my booth"}
```
Validation: the speedtest server **overwrites** `client.ip`, `site`, `server`, timestamps it can
observe, and recomputes the score; client-reported numbers are bounded (≤ 100 Gb/s, ≤ 60 s) and
checked against server-side byte counters for the local leg (> 20 % disagreement → flagged).

### 7.2 `exp.evidence/1` (runner → collector)
`{"schema":"exp.evidence/1","test_id","kind":"wifi|wired|flows|wan|security|baseline|dns|identity",
"source":"mist|ec|syslog|sse|exp","collected_at","window":{"from","to"},"status":"ok|partial|unavailable|error",
"data":{…kind-specific, bounded…},"raw_refs":[…source ids…]}`. Kind-specific `data` schemas are
fixed in WP-0 from the vendor docs/recordings.

### 7.3 Public speedtest API (`exp-speedtest`, plain HTTP TCP 80 on the event network by default, unauthenticated)
| Route | Purpose |
|---|---|
| `GET /` | the page (one box; no redirect) |
| `GET /st/r/{id}` | result page (the `#k=` fragment key authorizes the full view) |
| `GET /st/api/v1/where` | best-effort `{zone, source: qr\|subnet\|mist\|unresolved}` echoed to the page so it can show "You're in Hall B" (Mist lookup, cached) |
| `POST /st/api/v1/sessions` | consent + zone → `{session_id, leg_token, limits, dns_nonces, internet_leg: "ok|queued|paused"}` |
| `GET /st/api/v1/sessions/{id}/path` | box-timed legs so far: gateway, edge, edge+1 (idle/loaded, samples), resolver seen by the DNS leg, device ICMP RTT |
| `POST /st/api/v1/sessions/{id}/internet-slot` | ask for / release an internet-leg slot (queue position) |
| `GET http://<nonce>.t.speed.<domain>/st/px` | DNS-leg target (204, `Timing-Allow-Origin`), answered by the box |
| `GET /st/ping` · `GET /st/down?bytes=` · `POST /st/up` | local leg endpoints (token required) |
| `POST /st/api/v1/sessions/{id}/result` | submit `exp.speedtest/1` |
| `GET /st/api/v1/sessions/{id}` | status: quick diagnosis, evidence progress, final diagnosis (user-safe fields only) |
| `POST /st/api/v1/sessions/{id}/comment` | report-a-problem text |

There is no cloud component: the internet leg calls Cloudflare's public speed-test endpoints directly.

### 7.4 Collector query API additions (`01-contracts.md` §5 style, `expd_` tokens)
`GET speedtests?site&zone&ap&ssid&cause&from&to&min_score&max_score&q&limit&cursor` ·
`GET speedtests/{id}` (test + evidence + diagnosis) · `GET speedtests/aggregate?group_by=zone|ap|ssid|band|os_family|hour|cause&metric=down_p50|up_p50|loaded_p50|score_p50|count&leg&from&to` ·
`POST speedtests/{id}/evidence` (runner only) · `GET speedtests/stream` (SSE, new tests).

### 7.5 `exp.speedtest.config/1` (desired state for the shape)
`{site, zones:[{id,name}], branding:{title, logo_artifact, colors, languages, copy}, consent:{text, version,
show_network_details:false, targets:{down_mbps:25, up_mbps:10},
limits:{tests_per_10min_per_ip:6, max_concurrent_internet:10, max_concurrent_tests:20, bytes_local:200e6, bytes_internet:200e6},
internet_leg:{enabled:true, provider:"cloudflare", auto_pause_wan_util_pct:80},
serve:{placement:"core", hostname:"speed.summit.example", listen_ip:"10.0.0.9", require_real_client_ip:true},
zone_labels:{subnets:[{cidr, zone}]}, dns_leg:{zone:"t.speed.summit.example", enabled:true},
path:{gateway:"auto", edge:"10.60.0.2", edge1:"auto|<ip>", note:"infrastructure context, not per-user"},
tls:{mode:"none|provided"}, collector:{…}}`.
**Transport (D15): plain HTTP by default (`tls.mode = none`).** The page is anonymous and carries no
user credentials, the data plane is the event LAN, and plain HTTP avoids a per-event certificate and
the DNS-leg wildcard entirely — and it shows only a mild "Not secure" label, not the full-page
interstitial a self-signed cert triggers. Set `tls.mode = provided` with a real certificate for
`speed.` and `*.t.speed.<event-domain>` to serve over HTTPS where one is available (restores clipboard
and wake lock). **Avoid a hostname whose parent domain is HSTS-preloaded**, which would force HTTPS;
prefer a dedicated event domain or the box IP. Self-signed is not offered — its browser interstitial
is worse than plain HTTP for a user-facing page.

### 7.6 Runner config additions (`exp.runner.config/1`)
`correlation: {enabled, window_before_s: 300, window_after_s: 120, sources: {mist:{sites:[…]},
ec:{appliances:[…]}, syslog:{listen:["udp:5514","tcp:5514","tls:6514"], allow:["10.0.0.0/8"]},
sse:{enabled:false}}}`; credentials in `integrations.json` (`ec`, `mist`; **no `sse`**: no vendor documentation, CR-m6-spec-resolutions), never in config.

## 8. Analytics UI (dashboard, read by NOC; config in the manager)
- **Speedtests overview**: tests/hour, median down/up/responsiveness by leg, score distribution, top
  causes, map of zones colored by p50 score, "users vs probes" chart (user-test score against the
  nearest probe's line state over time).
- **Breakdowns**: by zone, AP, SSID, band, OS family, hour; worst-10 APs by p50 score with ≥ N tests.
- **Test detail**: the two legs side by side, score parts, diagnosis with cited evidence, and an
  **evidence timeline** (Wi-Fi RSSI/roams, AP utilization, top flows and apps, WAN utilization,
  security hits, probe beats) across the window; "share link" support view.
- **Manager**: Speedtest settings (branding preview like Orb's configurator, consent text with
  versioning, zone labels, optional per-zone QR signage, limits, targets, connectors). With one box
  there is no steering directory; the manager supplies the subnet→zone label table used as the
  correlation fallback (§5.1) and the Mist/EC connector credentials. The shape appears in fleet
  health. The manager never receives test results or evidence (Principle 2, SR-20).

## 9. Privacy and data kept (requirements)

**Anonymous means no person, not no device.** The page collects **no name and no email** and shows
the user nothing about themselves. The network record we *do* keep, because it is the whole point, is
**device and network metadata**: MAC, IP, hostname, manufacturer/OS family, 802.1X or guest-portal
username when the network already has one, AP/SSID/band/RSSI, switch/port, flow metadata (5-tuple,
app, bytes, QoS), security-policy verdicts, and the matching syslog lines. This is operational data
for the network team, not identity we attach a person to.

- **Retention:** tests, device metadata, and evidence are kept for the configured window
  (default 30 days), then purged; VM aggregates (no per-device labels) persist. There is **no**
  automatic raw-identifier scrub — keeping MAC/IP is intended. An event MAY set a shorter window or
  enable a scrub (drop raw IP/MAC/username after the final diagnosis, keep `device_key`) if its
  privacy sign-off calls for it; both are config, not default.
- **`device_key`** = HMAC-SHA256(per-org secret, MAC) is kept alongside the raw MAC as the
  low-cardinality join/aggregation key (raw MAC is never a VM label — Principle 8).
- The help-desk code (§4.1) identifies the **test**; there is no name to look anyone up by.
- **Legal note (for the owner):** MAC and IP are still "personal data" under GDPR/▮PIPEDA-style
  regimes even with no name attached. The consent text (versioned, admin-changed) states that device
  and traffic metadata are recorded for network diagnostics; the owner's privacy sign-off (§13 Q4)
  should cover the 30-day metadata retention, not just a deletion window.
- **Purge / data-subject request:** `exp-collector speedtest purge --device-key|--mac|--ip|--test`
  and a dashboard admin action; audited. Retention and purge are tested (end state: the rows are gone).
- Flow and security evidence is metadata (5-tuple, app, bytes, verdict) — no payloads, no full URLs
  (host only) unless the event explicitly enables URL detail.

## 10. Security requirements (added to `07-security.md` as SR-21 … SR-26)
- **SR-21** Public speedtest endpoints are unauthenticated by design: strict input validation, size
  and rate limits (§4.3), no reflection of internal data except to the test's own key holder.
- **SR-22** Local-leg endpoints require a short-lived session token with a byte budget; the box is
  not an open download/upload service. The box-side path timer only probes the configured gateway,
  edge, and edge+1 addresses and the requesting client — never a target chosen by the client. The
  DNS-leg authoritative server answers only its own zone (no recursion, no zone transfer, rate-limited).
- **SR-23** User-entered text (the problem comment) is untrusted: stored as text, rendered only with
  `textContent`, length-bounded; never used in log formats or queries without parameterization.
- **SR-24** The syslog receiver accepts only allowlisted sources, is rate-limited, bounds line
  length, and never executes or follows anything from a log line; raw lines expire after 60 min
  unless attached to a test.
- **SR-25** No user identity (name/email) is ever collected. Device/network metadata (IP, MAC,
  username, flows, security logs) is operational data kept per §9 (default 30 d, configurable purge);
  `device_key` uses a per-org secret
  distributed as a secret; exports exclude raw identifiers unless the operator has the admin role.
- **SR-26** Plain HTTP is the default transport (D15): the page carries no user credentials; the
  session leg token is short-lived (60 s), single-session, and byte-budgeted, so its exposure on the
  LAN is low-value; results are validated and bound server-side by observed client IP, never trusted
  from the wire. Page integrity over HTTP is a residual risk accepted for the event LAN and reduced by
  serving only from the box and embedding no secrets in the page; an event that needs integrity sets
  `tls.mode = provided`.

## 11. Acceptance (A6.x)
1. A phone on a lab SSID runs a test from a zone QR code; both legs reported; result page shows
   score and diagnosis in ≤ 20 s; 390-px layout, no horizontal scroll; CSP present; XSS test on
   comment passes.
2. Local-leg server sustains ≥ 2 Gb/s aggregate download on a 4-core host (bench) with ≤ 1 core
   per Gb/s; byte counters agree with client numbers within 5 %.
3. Rate limits and internet-leg slots/queue/pause work; local-leg endpoints refuse requests
   without or with expired/over-budget tokens; the path timer refuses client-chosen targets.
9. Legs: on the harness, added delay on the gateway, the edge, and the WAN side each moves only the
   matching leg (and the right waterfall segment); the DNS leg reports the resolver IP and cold/warm
   times via the delegated zone, and falls back to the probe measurement without it.
10. Page quality: self-contained (no request leaves for any host but the box, its DNS-leg names, and
    Cloudflare — asserted by capture); ≤ 200 KB gzip; 60 fps animation on a reference mid-range
    phone (CDP trace); reduced-motion mode shows the same numbers with no animation; matches the
    reference prototype's layout at 390 px.
11. Transport: over plain HTTP the page loads, the internet leg still reaches HTTPS Cloudflare, and
    clipboard/wake-lock fall back cleanly; the DNS leg works with no certificate; over `tls.mode =
    provided` HTTPS all of it still works. No name/email field exists anywhere; a purge by MAC/IP/test
    removes the device metadata (end-state asserted).
12. Location by correlation (§3.1, single box): against the fake Mist connector, a test from a given
    client IP resolves to that client's AP/zone/RSSI and switch/port; the DHCP-syslog fallback gives
    IP→MAC and subnet→zone; with no connector the test is `zone: unresolved` but still carries
    on-network, internet, and DNS legs. **NAT guard:** when the box is given a translated source IP,
    resolution fails closed (`zone: unresolved`, flagged) rather than binding the test to the wrong
    device.
4. Drills as ground truth (M5 harness): with RSSI attenuated → `wifi_signal`; with `local.netem` on
   the WAN side → `wan_saturation` or `internet_path`; with a firewall deny for the client →
   `policy_block` citing the matching syslog line; with a probe failing at the same time →
   `network_wide`. Each verified against fakes built from vendor docs/recordings.
5. Identity resolution via the fake Mist API and via DHCP syslog fallback; unresolved path still
   produces a result.
6. Anonymous mode: after the final diagnosis job, no raw identifiers remain in any table or the
   syslog ring (asserted by query). There is no identified mode and no name/email field anywhere.
7. Internet down: the page and local leg work, the internet leg reports "unavailable", diagnosis says
   so; results reach the dashboard on the LAN.
8. Aggregates in VM have no per-device/user labels (cardinality test); dashboard breakdowns match
   SQLite ground truth.

## 12. Future options
- WebRTC data channel to the local server for loss/jitter under UDP (call-quality MOS like netvitals).
- Live "share with support" (results streaming while the user re-tests, like Orb's live links).
- Aruba Central / other WLAN connectors; IPFIX/sFlow ingestion for non-EC sites.
- Native sensor mode (a probe running the same test on a schedule = synthetic user test parity).

## 13. Open questions for the owner (defaults assumed)
1. Domain and DNS delegation of `t.speed.<event-domain>` to the **core box** (default: a dedicated
   event name or the box IP, plain HTTP, no certificate; HTTPS only if a cert exists; never under an
   HSTS-preloaded parent).
2. Which security log sources exist at your events (default: EC firewall syslog + generic CEF; SSE
   via API if credentials are configured).
3. Identity: is 802.1X / guest-portal identity available via Mist (default: use it when present)?
4. Legal/privacy sign-off on the consent text and the **30-day device-metadata retention** (MAC/IP
   are personal data even without a name). Tests are always anonymous; no name/email is collected.
5. Wireless platforms beyond Mist (default: Mist only in v1).
8. **Does the attendee→core path preserve the client source IP (no NAT)?** This is required for
   correlation-based location (D15/§3.1). Default assumption: routed, un-NAT'd internal core. If an
   event NATs guest traffic, either place the box inside the un-NAT'd segment or accept speed-only
   results with no "where".
