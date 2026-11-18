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
- G4. Privacy by default: consent first, anonymous by default, raw identifiers kept briefly.
- G5. Same exp mantra: one more shape (`speedtest`) the manager deploys; no hand configuration.

Non-goals (v1)
- Native apps or background sensors (Orb App / Orb Sensor equivalents). Web only.
- Packet-loss measurement in the browser (needs WebRTC/UDP; see §12 future).
- Public-internet hosting of the page. It is served **on the event network** (see D15).

## 2. Decision D15

**The speedtest is an on-prem shape with two legs; correlation runs asynchronously in the runner;
results and evidence stay on-prem.**
- Served on-prem because the server must see the client's **real LAN IP** (behind any NAT) — the key
  that joins the test to Wi-Fi, flow, and security data — and because it must keep working when the
  internet is down (Principle 2).
- **Local leg** (browser ↔ `exp-speedtest` on the LAN) isolates the Wi-Fi/LAN; **internet leg**
  (browser ↔ Cloudflare edge, a Worker route of the manager's own account) measures the venue WAN +
  ISP. The difference between the legs localizes the problem.
- Correlation is done by the **runner**, which already holds the Mist/Orchestrator credentials and
  pullers (`10-drills-integrations.md`). It attaches evidence to the test after the fact (≤ 5 min).

## 3. Components and data flow

```
 attendee phone ──(QR / portal link)──▶ https://speed.<event>/        exp-speedtest (on-prem shape)
   │  1. GET page, POST /st/api/v1/sessions  (consent, zone)  ─────────▶  issues session + leg tokens
   │  2. local leg:   down/up/latency ◀─────────────────────────────▶   same host (sendfile / discard)
   │  3. internet leg: down/up/latency ◀──── Cloudflare Worker /st/* (manager account, token-checked)
   │  4. POST /st/api/v1/sessions/{id}/result ─────────────────────▶   validates, quick diagnosis
   │  5. GET /st/r/{id} (poll) ◀── diagnosis + evidence status         → collector ingest (records + VM)
   │                                                                       │
   │                                     runner: on new test ◀──────────────┘ (collector API)
   │                                       Mist client stats · EC flows · syslog/SSE policy hits ·
   │                                       wired port · nearest probe state  → POST evidence
   ▼                                       → final diagnosis (rules) → collector → dashboard
 result page shows final diagnosis (≤ 5 min)
```

- **`exp-speedtest`** (new component type `speedtest`, usually co-located with a collector): serves the
  page and the local-leg endpoints, issues sessions, validates results, sends them to its collector.
- **Collector**: stores tests, evidence, and diagnoses (SQLite `speedtests`, `evidence`), writes
  low-cardinality aggregates to VictoriaMetrics, exposes the query API (§7.4), runs the diagnosis
  rules (server-side, like line rules — D3).
- **Runner**: correlation connectors (§5).
- **Dashboard**: Speedtest analytics views (§8).
- **Manager**: branding/config, connector credentials as secrets, the internet-leg Worker routes,
  QR signage, fleet health for the new component.

## 4. The test

### 4.1 Page and UX
- One screen, event-branded (logo, colors, title, copy, languages — configured in the manager, like
  Orb Custom's configurator). Big **Start** button; ~15 s test; live gauges; results.
- Before the first test: a **consent panel** (configurable text) stating what is measured and that the
  network team will look at this device's Wi-Fi and traffic metadata to diagnose it; choices **Run
  anonymously** (default) / **Run and share my contact** (optional fields the event chooses: name,
  email, company/booth, seat/row) / **Cancel**. The choice is stored with the test.
- **Zone**: from the QR code (`/?z=hallb-row12`, zones defined per site in the manager) or a picker;
  unknown if skipped.
- Results show Download, Upload, **Responsiveness** (latency under load), idle latency, jitter, the
  **exp score** (0–100), a plain-language verdict ("Good for video calls and uploads"), and the
  **diagnosis** ("Weak Wi-Fi signal near you. The internet connection is fine.") with what to try.
  Network details (AP name, channel) are shown to the user only if the event enables it.
- **Report a problem**: optional free text (≤ 500 chars) attached to the test.
- **Share with support**: an unguessable link (`/st/r/{id}#k=…`, key in the fragment) the user can
  give to the help desk; operators open it in the dashboard with full evidence.
- Works on a 390-px phone, WCAG AA, keyboard reachable, `prefers-reduced-motion`; no third-party
  scripts, fonts, or analytics; CSP as the dashboard (`04-dashboard.md` §5); all user text rendered
  with `textContent`.

### 4.2 Measurement method (both legs; ported ideas from `reference/perf` and Cloudflare's method)
| Metric | Method |
|---|---|
| Idle latency, jitter | 20 × small HTTP GET (`/st/ping`) over a warm connection; median and mean absolute successive difference |
| Download | Parallel streams (start 4, grow to 8 while throughput rises) of `GET /st/down?bytes=N`; size ramps (100 kB → 25 MB) until each request ≥ 1 s or 8 s elapsed; report the 90th percentile of 250-ms throughput samples after the ramp |
| Upload | Same with `POST /st/up` (server discards); browser generates random payloads once and reuses them |
| Responsiveness (loaded latency) | `/st/ping` every 100 ms *during* download and upload; report median loaded latency and the increase over idle (bufferbloat); also as RPM (round trips per minute, IETF responsiveness draft) |
| Stability | coefficient of variation of throughput samples; aborted/failed requests |

Implementation is the Resource Timing API + `fetch` streams; no WebSockets needed. Total transfer
is capped per test (default 400 MB local, 200 MB internet) and adapts down on slow links.

**exp score** (0–100) = 40 × speed (min(down/target_down, 1) and min(up/target_up, 1), averaged) +
40 × responsiveness (100 % at ≤ 30 ms loaded latency, 0 % at ≥ 300 ms, linear) + 20 × stability
(CV and failures). Targets per event (default 25 / 10 Mb/s). Shown with its three parts.

### 4.3 Abuse and capacity protection (an event WAN is shared)
- Per client IP: ≤ 6 tests per 10 min, ≤ 1 concurrent; per site: ≤ `max_concurrent` internet legs
  (default 10) — extra users get the local leg immediately and a queue position for the internet leg.
- Admin switch **Pause internet leg** (e.g., during a keynote) and an automatic pause when the EC WAN
  utilization from the runner exceeds a threshold (default 80 %).
- Leg tokens: the session endpoint issues a short-lived HMAC token (60 s, single session, byte budget);
  the Worker refuses requests without a valid token (key = per-site secret shared by manager and
  speedtest). The Worker is therefore not an open bandwidth sink; Cloudflare Rate Limiting backs it.

## 5. Correlation (runner connectors)

On each new test (polled from the collector every 5 s, or SSE), the runner resolves the client and
pulls evidence for the window **[start − 5 min, end + 2 min]**. Each connector is optional; missing
connectors simply produce no evidence of that kind.

### 5.1 Identity resolution
`client_ip` + time → **device** (MAC) → **user** (optional):
1. Mist client search by IP at that time (wireless, and wired clients behind Mist-managed EX switches) →
   MAC, hostname, manufacturer, OS family, 802.1X identity/guest-portal user if present.
2. Fallbacks: DHCP lease data from the runner's syslog receiver (ISC/Kea/Windows DHCP or EC DHCP
   logs), then the EC ARP table for the LAN segment.
3. If unresolved: `identity: unresolved` — the test still has both legs and probe context.

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
  Retention: tests 90 days (aggregates forever in VM), evidence 30 days; raw identifiers per §9.
- VictoriaMetrics (low cardinality — Principle 8; **no per-user or per-device labels**):
  `exp_st_down_mbps`, `exp_st_up_mbps`, `exp_st_loaded_latency_ms`, `exp_st_score` as histograms
  (`vmrange`) with labels `site`, `zone`, `leg`, `ssid`, `band`, `ap` (bounded by AP count), `os_family`;
  `exp_st_tests_total{site,zone,cause}`.
- Fleet health (`01-contracts.md` §8.1) gains a `speedtest` row: `tests_per_hour`, `active_tests`,
  `internet_leg_paused` (0/1), `queue_depth`, `local_leg_gbps_p95`, `rejected_per_hour`.

## 7. Contracts (to be moved into `01-contracts.md` and `contracts/` by WP-0 at M6)

### 7.1 `exp.speedtest/1` (result, client → speedtest → collector)
```json
{"schema": "exp.speedtest/1", "id": "st_01JDF…", "site": "hall-b", "zone": "hallb-row12",
 "started": "2026-11-18T14:02:11.120Z", "ended": "2026-11-18T14:02:27.540Z",
 "client": {"ip": "10.60.14.77", "ua": {"os_family": "iOS", "os_version": "18.1", "browser": "Safari",
            "device_class": "phone"}, "connection_hint": "wifi"},
 "consent": {"mode": "anonymous|identified", "text_version": 3, "contact": {"name": "…", "email": "…"}},
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

### 7.3 Public speedtest API (`exp-speedtest`, HTTPS 443 on the event network, unauthenticated)
| Route | Purpose |
|---|---|
| `GET /` · `GET /st/r/{id}` | page; result page (the `#k=` fragment key authorizes the full view) |
| `POST /st/api/v1/sessions` | consent + zone → `{session_id, leg_tokens, limits, internet_leg: "ok|queued|paused"}` |
| `GET /st/ping` · `GET /st/down?bytes=` · `POST /st/up` | local leg endpoints (token required) |
| `POST /st/api/v1/sessions/{id}/result` | submit `exp.speedtest/1` |
| `GET /st/api/v1/sessions/{id}` | status: quick diagnosis, evidence progress, final diagnosis (user-safe fields only) |
| `POST /st/api/v1/sessions/{id}/comment` | report-a-problem text |

The Worker exposes the same `ping/down/up` routes for the internet leg under `https://<manager>/st/*`.

### 7.4 Collector query API additions (`01-contracts.md` §5 style, `expd_` tokens)
`GET speedtests?site&zone&ap&ssid&cause&from&to&min_score&max_score&q&limit&cursor` ·
`GET speedtests/{id}` (test + evidence + diagnosis) · `GET speedtests/aggregate?group_by=zone|ap|ssid|band|os_family|hour|cause&metric=down_p50|up_p50|loaded_p50|score_p50|count&leg&from&to` ·
`POST speedtests/{id}/evidence` (runner only) · `GET speedtests/stream` (SSE, new tests).

### 7.5 `exp.speedtest.config/1` (desired state for the shape)
`{site, zones:[{id,name}], branding:{title, logo_artifact, colors, languages, copy}, consent:{text, version,
contact_fields:[…], default_mode}, show_network_details:false, targets:{down_mbps:25, up_mbps:10},
limits:{tests_per_10min_per_ip:6, max_concurrent_internet:10, bytes_local:400e6, bytes_internet:200e6},
internet_leg:{enabled:true, auto_pause_wan_util_pct:80}, tls:{mode:"provided|self_signed"}, collector:{…}}`.
TLS: a publicly trusted certificate for `speed.<event-domain>` is **strongly recommended** (a browser
warning on a user-facing page defeats the purpose); `self_signed` is allowed for labs.

### 7.6 Runner config additions (`exp.runner.config/1`)
`correlation: {enabled, window_before_s: 300, window_after_s: 120, sources: {mist:{sites:[…]},
ec:{appliances:[…]}, syslog:{listen:["udp:5514","tcp:5514","tls:6514"], allow:["10.0.0.0/8"]},
sse:{…}}}`; credentials in `integrations.json` (adds `sse`), never in config.

## 8. Analytics UI (dashboard, read by NOC; config in the manager)
- **Speedtests overview**: tests/hour, median down/up/responsiveness by leg, score distribution, top
  causes, map of zones colored by p50 score, "users vs probes" chart (user-test score against the
  nearest probe's line state over time).
- **Breakdowns**: by zone, AP, SSID, band, OS family, hour; worst-10 APs by p50 score with ≥ N tests.
- **Test detail**: the two legs side by side, score parts, diagnosis with cited evidence, and an
  **evidence timeline** (Wi-Fi RSSI/roams, AP utilization, top flows and apps, WAN utilization,
  security hits, probe beats) across the window; "share link" support view.
- **Manager**: Speedtest settings (branding preview like Orb's configurator, consent text with
  versioning, zones and printable QR signage per zone, limits, targets, connectors), and the shape in
  fleet health. The manager never receives test results or evidence (Principle 2, SR-20).

## 9. Privacy (requirements)
| Mode | What is kept |
|---|---|
| **anonymous** (default) | Evidence is collected for diagnosis. After the final diagnosis (≤ 24 h), raw IP, MAC, hostname, username, and syslog lines naming them are **deleted**; the test keeps `device_key`, zone/AP/SSID, results, causes. |
| **identified** | User-provided contact and raw identifiers kept for the test retention (default 30 d), visible to operators only. |
- Consent text is versioned; the version is stored with each test; changing it requires an admin.
- Contact fields are optional and event-chosen; email is never required.
- Data subject requests: `exp-collector speedtest purge --device-key|--email|--test` and a dashboard
  admin action; audited.
- Retention, modes, and purge jobs are tested (verify the end state: the rows are gone).
- Flow and security evidence is metadata (5-tuple, app, bytes, verdict) — no payloads, no full URLs
  (host only) unless the event explicitly enables URL detail.

## 10. Security requirements (added to `07-security.md` as SR-21 … SR-25)
- **SR-21** Public speedtest endpoints are unauthenticated by design: strict input validation, size
  and rate limits (§4.3), no reflection of internal data except to the test's own key holder.
- **SR-22** The internet-leg Worker requires a valid short-lived HMAC leg token; it is not usable as
  an open download/upload service; budgets are enforced server-side.
- **SR-23** User-entered text (comment, contact) is untrusted: stored as text, rendered only with
  `textContent`, length-bounded; never used in log formats or queries without parameterization.
- **SR-24** The syslog receiver accepts only allowlisted sources, is rate-limited, bounds line
  length, and never executes or follows anything from a log line; raw lines expire after 60 min
  unless attached to a test.
- **SR-25** Personal data (IP, MAC, username, contact) follows §9; `device_key` uses a per-org secret
  distributed as a secret; exports exclude raw identifiers unless the operator has the admin role.

## 11. Acceptance (A6.x)
1. A phone on a lab SSID runs a test from a zone QR code; both legs reported; result page shows
   score and diagnosis in ≤ 20 s; 390-px layout, no horizontal scroll; CSP present; XSS test on
   comment and contact passes.
2. Local-leg server sustains ≥ 2 Gb/s aggregate download on a 4-core host (bench) with ≤ 1 core
   per Gb/s; byte counters agree with client numbers within 5 %.
3. Rate limits and internet-leg concurrency/queue/pause work; the Worker refuses requests without or
   with expired/over-budget tokens.
4. Drills as ground truth (M5 harness): with RSSI attenuated → `wifi_signal`; with `local.netem` on
   the WAN side → `wan_saturation` or `internet_path`; with a firewall deny for the client →
   `policy_block` citing the matching syslog line; with a probe failing at the same time →
   `network_wide`. Each verified against fakes built from vendor docs/recordings.
5. Identity resolution via the fake Mist API and via DHCP syslog fallback; unresolved path still
   produces a result.
6. Anonymous mode: after the final diagnosis job, no raw identifiers remain in any table or the
   syslog ring (asserted by query); identified mode keeps them for the retention only.
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
1. Domain and certificate for `speed.<event-domain>` (default: provided cert per event; DNS on the
   event resolver).
2. Which security log sources exist at your events (default: EC firewall syslog + generic CEF; SSE
   via API if credentials are configured).
3. Identity: is 802.1X / guest-portal identity available via Mist (default: use it when present)?
4. Legal/privacy sign-off on the consent text and the anonymous-mode deletion window (default 24 h).
5. Wireless platforms beyond Mist (default: Mist only in v1).
