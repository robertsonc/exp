# CR-wp1-test-options — per-test options the probe reads that `exp.probe.config/1` does not declare

**What.** `01-contracts.md` section 3 says outcome thresholds are "configurable per probe in
`tests.<test>.thresholds`", but `shared/schemas/probe.config.schema.json` declares no `thresholds` object (and no
other knobs below). The schema does not set `additionalProperties: false` on the `tests.*` objects, so the probe
reads these optional keys without any schema change:

| key | meaning | default |
|---|---|---|
| `tests.dhcp.thresholds.offer_ms` / `.total_ms` | `dhcp_hb` first offer / `dhcp` total above this is `degraded` | 1000 / 1500 |
| `tests.dhcp.allowed_servers` | list of DHCP server ids; an offer from another server sets `rogue_suspect` | none |
| `tests.dns.thresholds.rtt_ms` | `dns_hb`/`dns` answer slower than this is `degraded` | 250 |
| `tests.trace.thresholds.rtt_ms` / `tests.ping.thresholds.rtt_ms` | reached-but-slow / mean rtt `degraded` | 250 / 250 |
| `tests.app.thresholds.slow_factor` / `.apdex_min` | `total_ms > slow_factor * apdex_t_ms` or `apdex < apdex_min` is `degraded` | 4 / 0.85 |
| `tests.app.targets[].expect_status` / `.expect_body` | what a connectivity-check endpoint always returns; a mismatch is reported as a captive portal | built-in for generate_204, gen_204, captive.apple.com, msftconnecttest.com, detectportal.firefox.com |

Note that `tests.trace` and `tests.ping` are not declared at all (only `heartbeat.trace` / `heartbeat.ping` are).

**Why.** The catalog promises configurable thresholds and a rogue/captive-portal feature set that needs per-site
expectations. Unknown fields are ignored by readers (01-contracts section 1), so this is forward compatible.

**Request.** Declare the keys above (all optional) in `probe.config.schema.json` so the manager UI/compiler can
validate and edit them; until then the manager may pass them through verbatim.

**Interpretations recorded (no contract change).**
* `gateway` sends 4 echoes (not 2 tries): with two samples `loss_pct` could only be 0/50/100 and the contract's
  "degraded when 0 < loss_pct < 50" could never fire. `loss_pct >= 50` is `fail`.
* `dhcp_hb` labels the record with the first responding server and lists every server in `detail.servers`.
* A `dns_hb` record is emitted per resolver; interception (NXDOMAIN canary answered) makes the record `degraded`.
* `app` apdex is computed on `total_ms`; the TLS version comes from curl's verbose log (the `%{json}` has none).

**Affected WPs.** WP-0 (schema), WP-5/WP-4 (manager config compiler/UI, optional).

**Compatibility.** Additive, optional keys only.
