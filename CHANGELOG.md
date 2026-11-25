# Changelog

All notable changes to exp are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-25

Heartbeat cadence, and fixes found bringing up the cr-lab containerlab lab.

### Added
- Heartbeat cadence (CR-heartbeat-cadence): the collector measures each line's beat spacing and judges state on a
  window of at least 2.5 beats (never below the spec window, capped at 180 s), so a slow heartbeat no longer reads
  `unknown` between beats; 5 s and 10 s are unchanged. Window texts and the incident hold use the effective window.
  `exp.state/1` gains `cadence_s` and `lines[].window_s`; the probe list gains `cadence_s`.
- Dashboard: beat width, playhead step and staleness (3 beats, at least 30 s) follow the probe's real cadence.
- Manager: per-site probe heartbeat, Standard 10 s or Fast 5 s (site page; `POST /sites/{site}/probe-heartbeat`, one
  audited batch for every probe of the site).
- Manager: a **Test ports** panel on the probe's component page (the wizard's port picker, prefilled).
- `lab/cr-lab`: a containerlab topology exercising every exp role, and a multi-gig speed-test bench kit.

### Changed
- Manager: throughput, path and Wi-Fi tests, and the target and Wi-Fi port roles (milestone M4) are shown but cannot be
  switched on, since the probe does not run them yet; existing settings can still be switched off.

### Fixed
- `install.sh`: a site without a release is named as the cause, with the command that finishes the install.
- Runner: `correlation.network` (attendee subnets, translated addresses, zone subnets, `require_real_client_ip`) is
  compiled from the same site settings as the speed-test box, so the NAT guard and the subnet-zone fallback work in
  managed deployments.

## [0.2.0] - 2026-11-21

M6: speedtest to the core/DC box, correlated with network evidence (acceptance A6.1-A6.12, 33/33 on the core layout).

### Added
- `exp-speedtest` component: the speed-check page served from the core/DC box (local download/upload legs, DNS leg,
  per-segment path timing, optional internet leg to Cloudflare), internet slots with queue and auto-pause from EdgeConnect
  WAN utilisation, NAT guard (fails closed), per-IP limits, view-proof share links, problem reports. The vendored
  `@cloudflare/speedtest` 1.16.0 engine and the on-network transfers run in dedicated Web Workers with a main-thread fallback.
- `exp-runner` component: per-test correlation with Juniper Mist (client, AP/zone/RSSI, roams, switch port), HPE EdgeConnect
  Orchestrator (flows, WAN utilisation, health, alarms), DHCP syslog fallback and baseline probes; syslog ring with an optional
  privacy scrub after the final diagnosis.
- Collector: speedtest ingest, storage and diagnosis (spec 5.3 rules); aggregates to VictoriaMetrics without per-device labels.
  Result flag `internet_off` (operator switched the internet leg off; not an outage).
- Dashboard: speedtest list/detail and breakdowns; identifiers and purge for SSO admins.
- Manager: speedtest and runner shapes, settings, connectors and QR signage.
- Hosts: Debian 12 / Raspberry Pi OS 64-bit supported alongside Ubuntu 22.04/24.04 (probes on Raspberry Pi 4/5).
- CI: browser suites, Mist OpenAPI conformance, arm64 Debian 12 install job. Field validation runbook
  (`docs/runbooks/m6-field-validation.md`).
- M6 packaging: `exp-runner` and `exp-speedtest` are released components (noarch tarballs in the signed manifest).
  `exp-speedtest` bundles the pinned dnspython wheel (one `vendor.lock` pin shared with the probe; the build fails if a
  component imports `dns` without vendoring it) and, when `speedtest/page/build.py` exists, the deterministically built
  page (run twice, byte-identical output required).
- Agent: `runner` and `speedtest` component types (reconcile order collector, runner, speedtest, dashboard, probe;
  users `exp-runner` / `exp-speedtest`). The speedtest unit holds `CAP_NET_BIND_SERVICE` only (ports 80/443/53 on
  `serve.listen_ip`); its ICMP path timer uses unprivileged ICMP sockets, for which the agent manages one scoped,
  reversible sysctl drop-in (`/etc/sysctl.d/60-exp-speedtest-ping.conf`, written only when `net.ipv4.ping_group_range`
  does not already cover the service group; decommission restores the original range). Branding logo assets from the
  desired state are downloaded, sha256- and content-checked and installed as `/etc/exp/speedtest/assets/logo`.
- Agent: `health --json` `facts.url` may be `http://` (plain-HTTP speedtests).

### Fixed
- `deploy.sh`: a relative `--release-pubkey` is resolved against the caller's directory (the script changes into
  `manager/`); the forged-JWT smoke check is retried like the others (`workers.dev` can answer a transient 404 right
  after it is enabled); if the run stops for any reason after `wrangler deploy`, an exit trap still disables the
  `workers.dev` route; version preview URLs (`preview_urls`) are never enabled.

## [0.1.1] - 2026-11-19

### Added
- `manager/deploy.sh --embed-ui`: bundle the admin UI into the Worker (no Static Assets binding) for deploy hosts
  behind a proxy that rewrites `Authorization` to `api.cloudflare.com`.
- Production deployment record and key-rotation runbook (`docs/deployments/exp-control.md`).
- M3 acceptance suites (`test/e2e/m3`): two-site, three-collector harness; A3.1 federation (partial results when a
  collector is lost), A3.2 Slack/Teams/JSON webhook alerts (holds, again, flapping, folding, payload escaping), A3.3
  manager unreachable (no record lost or duplicated, edits made during the outage applied after), A3.4 site internet
  outage (local login, NOC token, board and SSE keep working; packet capture proves nothing leaves the LAN). Nightly
  `e2e.yml` runs M1–M3; `lanctl cut-internet`; `test/harness/pktwatch.py`.
- Manager: `EXP_MASTER_KEY` rotation with re-encryption (key ids, `EXP_MASTER_KEY_PREVIOUS`, cron re-sealing in batches,
  `GET settings/master-key`, Settings card, `scripts/rotate-master-key.sh`; migration `0003`).
- Manager: provided dashboard TLS certificates (`GET/PUT dashboards/{id}/tls`; validated, stored encrypted, delivered to
  the dashboard host).
- Manager: fleet-API gaps (per-probe rows, per-interface and error/drop history, per-test history,
  `Issue.component_type`; migration `0004`).
- CI: the dashboard offline-netns test runs as root in the harness job and fails if skipped.

### Fixed
- `deploy.sh` smoke test retries the enrol check on transient edge errors right after a deploy.
- Agent: a running probe's test ports (moved into their `exp-<port id>` namespaces) are reported in host facts again, so
  config edits of a running probe are no longer refused with `422 unknown_interface` (`CR-m3-facts-netns-ports`).
- Manager: `PATCH sites/{site}/release` returns the documented 422/409 codes. Agent prunes old version directories.

### Changed
- Manager Worker tests run on `@cloudflare/vitest-plugin` (was `@cloudflare/vitest-pool-workers`).

## [0.1.0] - 2026-11-18

### Added
- M1/M2: probe, collector (VictoriaMetrics, rules engine, incidents, query API, SSE), dashboard (SSO, local users,
  NOC tokens, federation, Pulse board), Cloudflare manager (Access JWT verification, agent API, desired-state
  compiler, AES-GCM secrets, releases, rollout, fleet roll-ups, issues) and admin UI, agent + `install.sh`,
  reproducible signed packaging, CI, container harness and M1/M2 acceptance suites.
- WP-0 contracts and foundation: JSON Schemas (`shared/schemas/`), `exp_common` Python package,
  OpenAPI specs (`shared/openapi/`), fixtures and fakes (`test/`).
- WP-0 root tooling: Makefile, pytest/ruff configuration, `.editorconfig`, `VERSION`.
- Shared UI design tokens, base stylesheet and icon set (`shared/ui/`).
- Skeleton CI workflow (lint + unit).
