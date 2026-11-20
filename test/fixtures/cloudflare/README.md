# Cloudflare speed-test endpoints: live recording (M6)

`recording-2026-11-20.json` is a **live recording** of Cloudflare's public speed-test endpoints exactly as the exp
speedtest page uses them (12-speedtest-analytics.md section 4.2: "header and timing behaviour of these endpoints MUST be
confirmed from a live recording, not assumed"). It is the ONLY place in the repo that talks to the public internet on
purpose, it was made once by the M6 contracts step, and tests never touch the internet: the speedtest page's tests run
against a fake that replays the headers recorded here.

## What was asked, and when

Recorded 2026-11-20 (UTC) by `record.py`, through the sandbox's HTTPS agent proxy (`via_proxy: true`: the first connect
figure includes the proxy tunnel, and latencies include the proxy hop, so use them only for shape, not as venue
numbers). Every request carried `Origin: http://speed.summit.example` (the page is plain HTTP by default, D15; the origin
is a placeholder). Only **cookie** headers were stripped; every other response header is kept, in the order received
(some are sent twice, e.g. both `Server-Timing` and `server-timing`).

| # | Request | Why |
|---|---|---|
| 1 | `GET https://speed.cloudflare.com/__down?bytes=0` | the library's **latency probe** (idle) |
| 2 | `GET .../__down?bytes=0&during=downloadload` | latency **under load**: the library adds `during=` |
| 3 | `GET .../__down?bytes=100000` | a download sample |
| 4 | `POST .../__up?bytes=1000` (body: 1000 x `0`, `Content-Type: text/plain;charset=UTF-8`) | an upload sample (a string body, so no custom headers and no preflight) |
| 5 | `GET https://speed.cloudflare.com/cdn-cgi/trace` | serving location (`colo=`) |
| 6 | `OPTIONS .../__up?bytes=1000` with `Access-Control-Request-Method: POST` | CORS preflight as the library *would* send it (it does not, see below) |
| 7 | `OPTIONS .../__up?bytes=1000` + `Access-Control-Request-Headers: authorization,content-type` | preflight if the library's `authorizationToken` option were enabled (exp does not enable it) |
| 8 | `OPTIONS .../__down?bytes=0` + `Access-Control-Request-Method: GET` | for completeness |

plus 8 more `__down?bytes=0` requests in `idle_latency_ttfb_ms_samples` (time to first byte after send, ms).

To re-record: `python3 test/fixtures/cloudflare/record.py --out recording-YYYY-MM-DD.json` (needs the public internet;
honours `HTTPS_PROXY` / `SSL_CERT_FILE`). Do it when Cloudflare changes the endpoints or the library is bumped, diff the
two recordings, and update the page fake, this README and `CR-m6-contracts.md` if behaviour moved.

## What the vendored library actually uses

Library: `@cloudflare/speedtest` **1.16.0** (MIT, tarball sha256
`08e3c0b4e69a2533dc0f4bca3e88e063c4fbc3c3b4e5c301557c1dcf767e866e`, pinned, more than 14 days old), read from
`dist/speedtest.js`.

**Endpoints** (defaults in `defaultConfig`):

| Config key | URL | Used for | exp decision |
|---|---|---|---|
| `downloadApiUrl` | `https://speed.cloudflare.com/__down` | download samples **and** latency probes (`bytes=0`) | keep |
| `uploadApiUrl` | `https://speed.cloudflare.com/__up` | upload samples (and parallel upload latency) | keep |
| `logAimApiUrl` | `https://speed.cloudflare.com/__results` | POSTs the *results* to Cloudflare after a run (`logAimResults`) | **set to `null`**: nothing about a user's test is sent to Cloudflare beyond the measurement traffic itself |
| `logMeasurementApiUrl` | `null` | adds a `measId` query parameter and posts per-measurement logs | keep `null` |
| `rpkiInvalidHost` | `https://invalid.rpki.cloudflare.com` | a reachability measurement type (`rpki`) | not in exp's measurement list: unused |
| `turnServerUri` / `turnServerCredsApiUrl` | `null` | packet loss over WebRTC | out of scope (12 section 1: no packet loss in the browser) |
| (not in the library) | `https://speed.cloudflare.com/cdn-cgi/trace` | serving location | the **page** fetches it itself (`colo=` line) |

**Query parameters:** `bytes` (every request), `during` = `idle | downloadload | uploadload` on latency probes
(`qsParams.during`, set to `<dir>load` while a throughput measurement runs), `measId` only when `logMeasurementApiUrl`
is set.

**Request headers:** none of its own. A download is a plain `GET`; an upload is `POST` with a **string** body
(`"0".repeat(bytes)`), so fetch sends `Content-Type: text/plain;charset=UTF-8` and the request is CORS-"simple": **no
preflight is sent**. `Authorization: Bearer <token>` is added only when `authorizationToken` is configured (exp: never).
No cookies (`includeCredentials: false`).

**Timing data it reads:**

* **Resource Timing** (`performance.getEntriesByName(url)`): `requestStart`, `responseStart`,
  `finalResponseHeadersStart` (falls back to `responseStart`), `responseEnd`, `transferSize`, `nextHopProtocol`,
  `connectStart`, `connectEnd`, `secureConnectionStart`. TTFB = final response start - request start; download payload
  time = `responseEnd` - final response start. It **requires** the cross-origin detail fields, i.e. a
  `Timing-Allow-Origin` response header, and discards a sample (and after 3 misses stops with a fatal error) when no
  entry exists; the page must not clear or overfill the Resource Timing buffer (the library raises it to 10,000).
* **`Server-Timing` response header**, through `fetch` (`r.headers.get('server-timing')`): `cfReqDur` /
  `cfRequestDuration`, or the **sum of every `cfSpeed*` entry** (`cfSpeedEdge` + `cfSpeedWorker`), to subtract server
  processing time from TTFB (latency = TTFB - server time - a calibrated delta). Without it the library falls back to an
  estimate (`estimatedServerTime`, default 0).
* `cf-meta-request-time` is read only by the optional measurement-logging engine (off in exp).

## What the recording shows (observed behaviour, 2026-11-20)

* **CORS from an `http://` origin works.** `__down`, `__up` and the preflights answer
  `Access-Control-Allow-Origin: *` (with `Vary: Origin`); a plain-HTTP page can call these HTTPS endpoints (not mixed
  content), so D15's plain-HTTP page is viable.
* **`Timing-Allow-Origin: *` is present** on `__down`, `__up` and the preflights, so cross-origin Resource Timing detail
  is available to the library.
* **`Access-Control-Expose-Headers`** on `__down` lists `server-timing, content-length, cf-meta-ip,
  cf-meta-request-time, cf-meta-colo, cf-meta-asn, cf-meta-country, cf-meta-city, cf-meta-postalCode,
  cf-meta-latitude, cf-meta-longitude, cf-meta-timezone`; on `__up`: `server-timing, cf-meta-colo,
  cf-meta-request-time, cf-meta-upload-bytes`. `Server-Timing` is therefore readable cross-origin.
* **Server-Timing format:** two `Server-Timing` header lines per response: `cfSpeedEdge;dur=<n>, cfSpeedWorker;dur=<n>`
  (what the library sums) and `cfL4;desc="?proto=TCP&rtt=...&min_rtt=..."` (TCP stats, ignored by the library). No
  `cfReqDur` was sent.
* **Preflight:** `204`, `Access-Control-Allow-Methods: GET, POST, OPTIONS`, `Access-Control-Allow-Headers:
  authorization, content-type`, `Access-Control-Max-Age: 86400`. Preflights are not sent for the library's own requests.
* `__down?bytes=0` answers `200`, `Content-Length: 0`, `Cache-Control: no-store, no-transform`, `Content-Type:
  application/octet-stream`; `__up` answers `200` with `Content-Type: text/plain;charset=UTF-8` and an empty body.
* `GET /cdn-cgi/trace` answers `text/plain` `key=value` lines including `colo=<IATA>` and `loc=<country>`; the page takes
  the serving location (`server: cloudflare:<colo>`) from here.

## Things the design depends on that are **missing or different** (stated plainly)

1. **The colo is not readable from `__down` responses.** `__down` returns the location in a header literally named
   `colo` (plus `city`, `country`, `latitude`, ...), but `Access-Control-Expose-Headers` advertises `cf-meta-colo` etc.
   and **does not list `colo`**, and the `__down` recording contains **no `cf-meta-colo` header at all** (only `__up`
   has it). So a cross-origin page cannot read the colo from `__down`. Use `/cdn-cgi/trace` (the body is CORS-readable:
   `Access-Control-Allow-Origin: *`). The page therefore makes one extra request to `/cdn-cgi/trace` per test.
2. **`/cdn-cgi/trace` has no `Timing-Allow-Origin`.** Irrelevant for its body, but its timing must not be used as a
   latency sample (cross-origin Resource Timing detail is zeroed); latency comes from `__down?bytes=0` only.
3. **`Server-Timing`'s `cfSpeedWorker` is noisy** (4 ms to 207 ms across the recorded requests, the 207 ms on a cold
   preflight). The library subtracts it, which is correct but means individual latency samples can swing; exp reports
   the median of 20 and shows idle/loaded as estimates.
4. **Cloudflare sends the requester's public egress IP and rough location in `cf-meta-ip` / `city` / `latitude` ...** on
   `__down`. The page must not read, display or store them (privacy; they describe the venue NAT, not the user). The
   recording contains the sandbox's egress values; they are unrelated to any exp deployment.
5. **No explicit documentation of these endpoints** exists in the library beyond its source; behaviour above is observed
   and may change. Re-record on a library bump (see above); the page fake in the speedtest build is generated from this
   file so a change shows up as a test diff.
6. The proxy hop in this recording inflates `connect_incl_tunnel_tls` (about 300 ms) and `ttfb_after_send`; treat the
   numbers as shape only.
