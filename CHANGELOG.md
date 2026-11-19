# Changelog

All notable changes to exp are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

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
