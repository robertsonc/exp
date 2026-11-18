# Changelog

All notable changes to exp are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `manager/deploy.sh --embed-ui`: bundle the admin UI into the Worker (no Static Assets binding) for deploy hosts
  behind a proxy that rewrites `Authorization` to `api.cloudflare.com`.
- Production deployment record and key-rotation runbook (`docs/deployments/exp-control.md`).

### Fixed
- `deploy.sh` smoke test retries the enrol check on transient edge errors right after a deploy.

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
