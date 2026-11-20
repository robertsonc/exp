# CR-m6-runner-connectors — correlation connectors (Mist, EdgeConnect, baseline, SSE placeholder)

**From:** M6 step r2. **Affects:** WP-9 (runner), WP-10/WP-11 (collector rule inputs, manager compile). **Decision:** accepted by the
step that wrote it. No `shared/` change: everything fits `evidence.schema.json` and `runner.config.schema.json` as written by c0.

## Decisions (later steps must know)

1. **Vendor fields** only from the local references (Mist OAS in `mistapi` 0.64.1, `pyedgeconnect` 0.16.0a1); each module lists its
   calls and schema/function names. **SSE (Axis) has no local documentation: no connector.** `SseConnector` is a placeholder that
   reports `unavailable` + reason (health fact `sse`) when `sources.sse.enabled` is set; SSE decisions can still arrive via syslog.
2. **Mist budget**: <= `max_calls_per_test` (6) calls per test *including retries and the identity step* (one `CallBudget`
   `ctx.budgets["mist"]` shared by identity and the connector). A typical wireless test uses 5: wireless search, wired search, client
   stats, AP stats (30 s cache per AP, shared by neighbouring tests), one per-client events call. Cache hits cost nothing. The
   event-type constants (`GET /const/client_events`) are reference data refreshed hourly **outside** the per-test budget.
   Pagination: searches ask `limit=5` (two hits already mean ambiguity), events one page of 100: bounded, never followed.
3. **Identity lookup**: wireless **and** wired search for every site in `sources.mist.sites` until a site has any hit; the union of
   MACs decides (one binds; zero = `no_match`; more = `ambiguous`; a wireless and a wired client sharing the IP is ambiguous). A budget,
   timeout, 429 or 5xx *before the answer is complete* is `mist_status: error` — never `no_match`/`ambiguous`; the DHCP / subnet
   fallbacks apply. Lookups are cached 30 s per (IP, window bucket) so the where-cache loop does not burn the quota.
4. **Mist events are the client's own (`getSiteEventsForClient`).** `GET /sites/{site_id}/clients/{client_mac}/events?start&end&limit=100`
   (OAS operationId `getSiteEventsForClient`, response schema `response_client_events_search` / `events_client`; `client_mac` is
   the 12 lower-case hex form, put in the path unchanged as mistapi's `clients.py` does) returns only that client's events, so the
   earlier AP-level `searchSiteWirelessClientEvents` (no MAC filter: another client's roam or auth failure on the same AP was
   attributed to the test) is **no longer called**; no AP-level event context is kept. Events are filtered to the client's SSID,
   kept only when classified at runtime from the event constants' key/display text as a roam or an authentication failure.
   `roams`, `roam_count`, `auth_failures` and `events` come **only** from this one call (a roam event = one roam; no multi-AP gating
   is needed any more). Budget: one events call per test instead of <= 2, so a typical test is 4-5 calls. Evidence schema: only
   description strings changed (no field added or renamed). Collector input: `rule_wifi_roaming` reads `wifi.roams`, `wifi.events`
   and `wifi.auth_failures` (`collector/exp_collector/speedtest/diagnosis.py:320-346`), exactly the client-specific fields.
   The c1 fake implements the route (`page`-based pagination, 404 for an unknown client) and a `roaming_other_client` scenario.
5. **Mist stats are current state.** `stats_wireless_client` is read after the window closed: a client that left (404) yields
   `wifi.status = partial` carrying the search-record fields (SSID, band, AP). Mist zones (`zones`) are map zones and not used; the
   exp zone is `sources.mist.zone_map` then the subnet table.
6. **EdgeConnect**: API-key auth (`X-Auth-Token`), REST root `/gms/rest`. Flows: `GET /flow?nePk&ip1=<client>&ipEitherFlag=false&uptime=
   anytime|term<N>`, narrowed to the window client-side (the documented custom time filters apply to active and terminated flows
   separately), parsed from the positional rows by the documented indexes, top-50 by `bytes_total`. `ipEitherFlag=False` = both
   directions (per the docstring wording for `True`). WAN: appliance state, interface state, interface time series, four health
   summaries (dict or list accepted), alarms in the window. Per-test budget 32 (`ec.CALLS_PER_TEST`; the `ec` config block is closed,
   so it is a constant), interface/health/alarm reads cached 30 s.
7. **Time-series columns are not documented** ("COLUMN_DEF ... and DATA"): the interface/time/rx/tx byte columns are located by name at
   runtime; values are read as bytes per `minute` bucket (assumption, stated: bps = bytes * 8 / 60; utilization = peak(rx, tx) /
   `scalars.maxWanBandwidth`). Unidentifiable columns keep the raw series, omit utilization and mark `wan` `partial`. Both documented
   response shapes (list, `{COLUMN_DEF, DATA}`) are accepted. Health `max` units are passed through unconverted.
8. **Auto-pause**: `WanUtilMonitor` (the `PausePublisher` source, enabled by `sources.ec.wan_util.enabled`, every `interval_s`) publishes
   the **held peak** utilization of the two latest minute buckets across the configured appliances. The speedtest owns the threshold
   (`internet_leg.auto_pause_wan_util_pct`) and the 90 s fail-open staleness rule; the runner's hold is the hysteresis on the way down
   (a spike keeps the leg paused ~2 min). Any failure publishes nothing (fail open).
9. **Cross-kind merge**: the client's own flows with `drop_reason` 1 or 2 become `security.ec_dropped_flows` (the `policy_block` rule
   reads it); with no syslog security evidence an `ec`-sourced `security` document carries that figure (`partial`).
10. **Baseline**: `BaselineConnector` uses the correlator's own collector client (pinned TLS, `expr_` token); it passes the resolved zone
    (never `unresolved`), the AP name and the test end time; the answer is re-bounded to the closed `data_baseline` shape. 404/none =
    `unavailable`; transport failure = `error`. The probe DNS fallback (`dns.probe_dns`) is not produced by the runner (the baseline
    carries the probe's `dns` line; the collector sets `dns_fallback`).
11. **Failure behaviour**: `429` pauses the whole connector (`Retry-After` or 30 s, max 300 s) and never retries inside the test;
    in the EdgeConnect connector credential refusal, transport failure, timeout or deadline skip the rest of the chain (Mist stops at its first failed call within each step and its budget bounds the rest); 5xx/timeouts retry once with
    backoff on idempotent GETs (the alarm query is a read-only POST and is treated as idempotent). Every vendor string is control-
    character-stripped, bounded and type-coerced before it reaches an evidence document (SR-24); credentials are never logged.
12. **TLS to Mist/EC**: system trust store (`SSL_CERT_FILE` adds a private CA for an on-prem Orchestrator); verification is never
    disabled; plain http only for loopback hosts (test fakes).
13. **No device scrub in the connectors**: `identity.mac` / `wifi.client.mac` are written as evidence; the privacy scrub is the
    collector's (A6.6) and the runner's ring deletion (`privacy.scrub_after_diagnosis`).

## Not done / limits
* HPE Aruba SSE API connector (no local documentation) and Mist `fast_roam` (`listSiteRoamingEvents`): the c1 Mist fake does not
  implement it and roam counts come from the client's own events (decision 4); switch-port events (`searchSiteDeviceEvents`) are requested best
  effort (a 404 is tolerated, the fake has no such route).

## Privacy-scrub precision (p3)
`Ring.delete_mentions(tokens, ip=None)` no longer deletes on a bare case-insensitive substring (it over-deleted other devices' DHCP
lines, breaking the DHCP-fallback identity of concurrent tests, A6.5). The parameterized, escaped LIKE stays as a prefilter; every
candidate is verified in Python:
* MAC spellings (colon, dash, Cisco dotted, bare) must not be adjacent to a hex digit or to the spelling's own separator, so a bare MAC
  inside a longer hex string (session id, hash) is kept. *[Superseded 2026-11-20: see "A6.6 follow-up" below; a MAC inside a longer
  run is now deleted.]*
* A hostname token matches the whole name, case-insensitively, not adjacent to `[0-9A-Za-z_-]` ("johns-iphone.local" matches
  "johns-iphone"; "johns-iphone" does not match "iphone").
* A line matched only by the hostname is deleted only if it names no other device: no MAC in any spelling other than this device's, and
  no indexed IP (ring `ips` table) other than the device's client IP (the correlator passes `test.client_ip`).
Still one bounded pass per call under the same Ring lock. A separator adjoining the MAC only blocks the match when a hex digit lies beyond it, so "addr:f0:18:..." (the device's own line) is deleted
while a longer MAC-like run is kept. *[Superseded 2026-11-20, see below.]*

Follow-up (p3 validator): a word glued to the MAC by its own separator ("mac:f0:18:..", whose "ac" looks like a hex pair) is the
device's own line and is deleted; only an octet-like pair standing alone ("id 11:f0:18:..:01:22") marks a longer MAC and keeps the line.
Residual: a standalone two-hex-digit word directly before a MAC separator (e.g. "ab:" + MAC) is indistinguishable from a 7th octet and is
kept *[superseded 2026-11-20: now deleted]*. The ring SQL has no interpolated statement at all (constant `PRAGMA user_version=1`; deletes
bind one JSON array to `json_each(?)`), so `grep "execute(f"` on ring.py is empty (guarded by test_ring_sql_has_no_interpolated_execute).
*[Corrected 2026-11-20: this was not true when written. `Ring.query()` built its `kinds` filter as an IN-list of `?` placeholders joined
into the SQL text (values were bound, but the statement text varied), and the guard's regex did not see it. It is true since the
follow-up below.]*

## A6.6 follow-up (2026-11-20): scrub misses found in review
A review reproduced privacy misses of the p3 rules (the previous plain substring scrub deleted all of these). With the device MAC
`f0:18:98:aa:bb:01`, hostname `Johns-iPhone` and IP `10.1.2.3`, these lines stayed in the ring after the final diagnosis and are now
deleted (`runner/tests/test_ring.py::test_scrub_removes_every_identifier_of_this_device_only`, via `parse_line` + `insert_many` and the
correlator's `delete_ip` + `delete_mentions(device_tokens(...))`):
DHCPv6 DUID-LLT `00:01:00:01:2c:3d:4e:5f:<MAC>` and DUID-LL `00:03:00:01:<MAC>`, option-61 client-id `01:<MAC>`, a netfilter
`MAC=<dst>:<MAC>:86:dd` header of an IPv6 packet (so `delete_ip` never reaches it), a bare DUID `000100012c3d4e5f<bare MAC>`,
hostapd `STA <MAC>:deauth`, `<30>Nov 20 10:00:00 10.1.0.1 dnsmasq-dhcp[412]: ... client provides name: Johns-iPhone` and
`Added reverse map from 3.2.1.10.in-addr.arpa. to Johns-iPhone.example.com`.

Changes (`runner/exp_runner/ring.py`; one accessor in `syslog_parse.py`):
1. **MAC: the "longer MAC = another device" rule is removed** (owner's decision: the privacy rule wins over over-deletion). A 6-octet
   MAC of this device embedded in a longer octet run is this device's identifier (DUID, client-id, `MAC=` header); another device
   colliding on the same 48 bits is negligible. A colon, dash or dotted spelling matches wherever it is not glued to another hex
   **digit** on either side (a separator followed by more octets, or a word, is fine); the bare 12-hex spelling matches as a plain
   case-insensitive substring. The special handling of a word glued by the separator (`mac:`, `addr:`) is gone with the rule it
   served. Tests that encoded the old rule were replaced: `test_bare_mac_inside_longer_hex_is_kept` -> `test_bare_mac_is_a_plain_substring`
   (`deadf01898aabb01beef` is now deleted), `test_mac_after_its_own_separator_char_is_deleted_but_longer_mac_kept` ->
   `test_mac_inside_a_longer_octet_run_is_deleted`, and the `id 11:<MAC>:22` / `ab:<MAC>` cases are now deleted.
2. **Hostname-only lines: which indexed IP names another device.** For an unknown format `parse_line` indexes every dotted quad in the
   first 300 characters, including the RFC 3164/5424 header HOSTNAME (often the sending router's IP) and the labels of a reverse-DNS
   name. An indexed IP now counts as "another device" only if it is not this device's IP, not the reversed form of it, not the line's
   syslog header host (read with the parser's own envelope logic, new `syslog_parse.envelope_host(line)`), and not a label of an
   `in-addr.arpa`/`ip6.arpa` name. The protection is kept: `DHCPACK(br0) 10.1.2.9 aa:bb:cc:dd:ee:ff iPhone` (another client's IP or MAC)
   stays when this device's hostname is `iPhone`.
3. **Unicode hostnames.** SQLite `lower()` folds ASCII only, so the LIKE prefilter never found `BÜRO-PC` for the token `büro-pc`. A
   token with non-ASCII characters is now prefiltered with `exp_lower(raw)`, a deterministic Python `str.lower` registered on the ring's
   own connection (`create_function(..., deterministic=True)`, never used in the schema, so the file stays readable without it); ASCII
   tokens keep the native `lower(raw)` scan. Verification compares the lower-cased line; the hostname boundary is `[\w-]` (Unicode
   aware), so `büro-pc` does not match `Großbüro-pc`.
4. **SQL text.** `Ring.query()`'s `kinds` filter binds one JSON array to `l.kind IN (SELECT value FROM json_each(?))` (with
   `? IS NULL` for no filter), so every ring statement is now a constant string. `test_ring_sql_has_no_interpolated_execute` now also
   parses ring.py and requires the first argument of every `execute`/`executemany`/`executescript` to be a string literal (or a name only
   ever bound to literals, or a conditional between two literals); the old `query()` fails that check. A bare string `kinds` is one kind.

Kept: hostname boundary rule (`iphone` does not delete `Johns-iPhone`; `Johns-iPhone` deletes `Johns-iPhone.example.com`, `"Johns-iPhone"`,
`'JOHNS-IPHONE'`, `(johns-iphone)`), tokens shorter than 3 characters ignored, one bounded scan per token under the Ring lock, chunked
deletes in one transaction. The e2e assertion `test/e2e/m6/test_a66_scrub.py` needed no change (it encodes none of the removed rules).

Residual limits (stated, not fixed):
* A MAC written with a separator or grouping other than colon/dash pairs, Cisco dotted quads or bare hex (e.g. HP `f01898-aabb01`,
  `f0 18 98 aa bb 01`, or one glued directly to a hex letter, `idf0:18:...`) is not recognised, nor an IPv6 address derived from the
  MAC (EUI-64 `...f218:98ff:feaa:bb01`).
* Hostname-only lines are still kept when they name another IP or MAC, also when that IP is this device's *previous* lease
  (`forward map from Johns-iPhone.example.com to 10.1.2.7`): the price of not deleting other devices that share a generic name.
  Conversely a generic-name line whose only IP is the header host or an arpa label is deleted, even if it was about another device.
* Another device's MAC inside a longer octet run (its DUID) does not count as "another device" for a hostname-only line, so such a line
  is deleted (privacy-safe direction); a bare 12-digit number on a hostname-only line reads as another device's bare MAC and keeps it.
