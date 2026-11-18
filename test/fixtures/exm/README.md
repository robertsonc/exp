# Converted EXM outage (golden data for the collector rules/alert engine)

`outage-2026-10-27.ndjson.gz` is the real EXM outage fixture
(`reference/exm/test/fixtures/outage-2026-10-27.jsonl.gz`: 6,537 EXM events, 02:40 to 04:30 UTC on 2026-10-27, lab
probe `t430-srv-02`) converted to `exp.measurement/1` NDJSON by `../convert_exm.py`
(13,792 records, gzip with mtime 0, byte-reproducible: `python test/fixtures/convert_exm.py`).
`docs/spec/03-collector.md` section 13 (acceptance test 4, golden rules) replays this file.

Identity: `probe = t430-srv-02`, `site = lab`. Every record is ordered by `ts`. `id` is a ULID whose time part is `ts` and whose
random part is `sha256("<input line>:<sub-index>")[:10]`, so ids are unique per probe and stable across reruns.

## Mapping

| EXM `test` | exp `test` | Notes |
|---|---|---|
| `gateway` (one record, all ports) | `gateway`, **one record per port** | labels `port`, `iface`; metrics `link_up` (carrier), `rtt_ms`, `loss_pct` (0 or 100), `carrier_changes`; outcome `ok`/`fail` per port; detail `gateway_ip`; `error` = the port's error. `iface` comes from the other EXM records of the same port; the target ports `s01..s03` never appear elsewhere so they get the synthetic name `eth-s01`. |
| `dhcp_hb` | `dhcp_hb` | labels `port`, `server` (`none` when no offer); `offer_ms`, `offers` (1/0); detail `offered_ip`, `mac`, `resent`. |
| `dns_hb` | `dns_hb` | labels `port`, `resolver` (server IP), `resolver_kind`: `alternate` when the server is 1.1.1.1 (EXM's default alternate), else `dhcp` (8.8.8.8 is the DHCP-given resolver); `rtt_ms`, `rcode`, `answers`; detail `name`. |
| `trace` | `trace` | labels `port`, `path=test` (the fixture has no control-path trace); `reached`, `hops`, `last_ttl`, `rtt_ms`; detail `hops[]` as `[ttl, ip, rtt]`, `last_ip`, `target`, `dest_ttl`. |
| `dhcp` | `dhcp` | labels `port`, `server`; `discover_offer_ms`, `request_ack_ms` (EXM `request_reply`), `total_ms`, `lease_s`, `offers`; detail `ip`, `router`, `dns`, `options` (scalars only), `mode`, `gateway_mac`, ... |
| `dns` | `dns` | EXM aggregates 24 queries per record. labels `port`, `resolver` (the IP, EXM's resolver name goes to detail `resolver_name`); `rtt_ms` = p50, `answers` = answered count, `rcode` = 0 when only NOERROR, else the most frequent non-NOERROR code (absent when nothing answered); detail keeps `queries`, `answered`, `timeouts`, `errors`, `p95_ms`, `max_ms`, `rcodes`, `per_type`, `rows`. |
| `app` | `app` | label `app` = EXM target name; metrics from the slowest successful step (`dns_ms`, `connect_ms`, `tls_ms`, `ttfb_ms`, `total_ms`, `status_code`); `apdex` from `apdex_class` (satisfied 1.0, tolerating 0.5, frustrated 0.0); `duration_ms` = EXM `sample_ms`; detail `url`, `ip`, `http_version`, `apdex_t_ms`, `steps[]` summary. |
| `speedtest` (cloudflare) | `throughput` | label `provider=cloudflare`; `down_mbps`, `up_mbps`, `latency_idle_ms`, `latency_loaded_ms`, `jitter_ms`; EXM `harness_error` becomes outcome `error`. The 5 `fastcom` records are **dropped**: that provider is not in the catalog (`cloudflare` or `iperf3`). |
| `wifi_hb` from `corey-mac` | `wifi_hb` on the same probe | The Wi-Fi laptop was a separate EXM probe attached to the board. In exp it is port `wifi` of `t430-srv-02`, so the Wi-Fi line and the gateway verdict share one board. labels `port=wifi`, `ssid`, `band` (channel <= 14 is `2.4`, else `5`); `link_up` (always 1: the fixture has no association loss), `rssi_dbm`, `noise_dbm`, `snr_db`, `tx_rate_mbps`, `channel`, `gw_rtt_ms` (**absent** when the gateway did not answer over Wi-Fi; this is EXM's `gk`); detail `target_ssid` (when EXM recorded one) and `on_target` (true when no target is recorded or the ssid equals it), `security`, `ip`, `gateway`, `dns_server`, ... |

Dropped fields with no exp equivalent: `config_ver`, `hw_class`, `zone`, `vlan`, `source`, `emitted` (exp orders by `ts`), `phase_ms` keys other than
those mapped. Large values are kept in `detail` within the bounds (depth <= 4, <= 256 items, strings <= 1024 chars, <= 8 KiB serialized);
anything that does not fit is dropped largest-key-first. Outcomes map `ok|degraded|fail` 1:1, `portal` to `fail`, `harness_error` to `error`.

Record counts: gateway 7,920 (660 beats x 12 ports), dns_hb 659, dhcp_hb 660, trace 100, dhcp 197, dns 1,091, app 2,499, throughput 6, wifi_hb 660.

## Timeline and expected verdicts (UTC; Chicago is CDT = UTC-5)

Produced by replaying the EXM alert engine over the original fixture (the 9 pages in `reference/exm/test/unit.py`). Times are the incident
start/end the engine reports; the first failing record is a second or two earlier.

| # | Page | Line | Starts | Ends | Expected `where` | Cause |
|---|---|---|---|---|---|---|
| 1 | down | Network | 03:00:21 | | `gateway` 10.1.0.1 (12 of 12 ports; wired and Wi-Fi both fail) | the 43-minute gateway outage: every `gateway` record has `outcome=fail`, `link_up=1`, `loss_pct=100`, `error="no reply from 10.1.0.1"` from 03:00:20.114 to 03:43:00.105 |
| 2 | resolved | Network | | 03:43:22 | | gateway back |
| 3 | down | DNS | 03:00:22 | | none (folded under Network: "Also failing, probably because of this: DNS, Wi-Fi") | `dns_hb` fails for 8.8.8.8 from 03:00:22 to 03:51:02 |
| 4 | resolved | DNS | | 03:51:14 | | DNS back (8 minutes after the gateway) |
| 5 | down | Wi-Fi | 03:56:34 | | `ssid` (laptop on `MistiFi`, wants `ACME_CORP`) | AP outage: `wifi_hb` fails from 03:56:30 to 04:29:50 and does not recover in the fixture (no resolved page); `labels.ssid=MistiFi` with `detail.on_target=false` |
| 6 | down | DNS | 04:05:32 | | none | 1.1.1.1 (alternate) silent for ~1 minute, 04:05:32 to 04:06:22 |
| 7 | resolved | DNS | | 04:06:34 | | |
| 8 | down | DNS | 04:21:32 | | `wan`: path stops after 10.1.0.2 (hop 1) toward 8.8.8.8 | 04:21:32 to 04:23:22: `trace` fails on all 12 ports **and** the alternate resolver is silent. EXM names this `edge` only when a control-path trace also succeeds; this fixture has no control-path trace (`path=control`), so the expected seg is `wan` |
| 9 | resolved | DNS | | 04:23:42 | | |

Minor failures that must **not** page (they stay under the hold-down): a 1m50s `dns_hb` failure on 8.8.8.8 at 02:45:02 to 02:46:52 (12 records);
`dhcp_hb` failures between 03:29 and 03:36 (inside the gateway outage) and two 30-60 s blips at 03:49:53 and 04:02:33; scattered single Wi-Fi
failures. Expected page sequence for the rules/incident replay: `down Network, resolved Network, down DNS, resolved DNS, down Wi-Fi,
down DNS, resolved DNS, down DNS, resolved DNS`.

Other golden cases from `reference/exm/test/unit.py` ("where" for every class: link, switch, gateway, lan, edge, isp, resolver, dns_path, apps,
dhcp, ssid; one lost traceroute does not blame the edge; both resolvers silent plus a lost trace does) are synthetic in EXM and are not part of this
file; WP-2 builds them from small hand-made inputs.
