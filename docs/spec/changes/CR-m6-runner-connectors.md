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
