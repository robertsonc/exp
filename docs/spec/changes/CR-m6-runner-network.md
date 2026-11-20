# CR-m6-runner-network — NAT-guard and subnet inputs in `exp.runner.config/1`

**From:** M6 step r1 (runner core). **Affects:** WP-9 (runner), WP-5/WP-11 (manager compile). **Decision:** accepted by the step
that wrote it (additive to `shared/`, sanctioned by the M6 rules).

## Problem
`CR-m6-spec-resolutions` A6 and `01-contracts.md` 14.6 make the **runner** evaluate the fail-closed NAT guard (outside
`serve.client_subnets` while `require_real_client_ip`, equals `serve.translated_addresses`, Mist ambiguity) and the
subnet -> coarse-zone fallback (`zone_labels.subnets`). Those inputs exist only in `exp.speedtest.config/1`; the runner
config had no place for them, and the collector feed item carries neither flags nor the subnet table.

## Change
Optional `correlation.network` in `runner.config.schema.json`:
`{require_real_client_ip (default true), client_subnets[], translated_addresses[], zone_subnets[{cidr, zone}]}`.
Mirrors of the speedtest fields; the manager compiles both from the same site speedtest settings (WP-11 / WP-5 follow-up).
An absent block means: no subnet knowledge (NAT guard condition 1 cannot fire because no subnet list is configured;
conditions 2 and 3 still apply only if their inputs are configured) and no subnet zone fallback.

## Compatibility
Additive and optional; existing configs are unchanged.

## Other r1 decisions recorded here
* The runner's own `syslog` connector supplies `security` and `dns` evidence (from the ring); `wifi/wired/flows/wan/baseline`
  are `unavailable` until the r2 connectors register (a registered connector replaces the placeholder).
* The collector URL stays `https` + pin (`exp_common.tlspin`); plain `http://` is accepted by the client only for loopback
  hosts (dev/tests), never by the config schema.
* Health is a snapshot file `<run>/health.json` written every 5 s by the daemon (same pattern as the collector).

## Second change in this CR: `kind=baseline` may be `unavailable` / `error` with empty data
`evidence.schema.json#/$defs/data_baseline` required `probe` and `severity` unconditionally, so the explicit
`status: unavailable|error` document with `data: {}` that the envelope description promises (and that every other kind accepts)
was invalid for `baseline` only: the collector would answer 400. `required` became `anyOf: [{required: [probe, severity]},
{maxProperties: 0}]`. A populated baseline is validated exactly as before; only the empty form is newly accepted. Backwards
compatible for every reader and writer. (Found by the r1 pipeline test that posts all eight kinds.)
