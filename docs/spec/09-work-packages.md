# 09 — Work packages (parallel build plan)

Designed for a multi-agent build: **one builder + one reviewer per work package**, disjoint file
ownership, contracts frozen up front, and an **integrator** who owns everything shared and signs off
milestones.

## 1. Ground rules

1. **Read first:** `SPEC.md`, `docs/spec/01-contracts.md`, your component spec, `07-security.md`.
2. **Own your paths only.** A WP never edits files outside its owned paths (§2). Shared files
   belong to the integrator.
3. **Contracts are frozen after WP-0.** Need a change? File a change request (§5); do not diverge locally.
4. **Port, don't reinvent.** Where `reference/` has proven logic, port it and cite the source in a
   comment (`# ported from reference/exm/lib/exm/pulse.py:where_of`). Never import from `reference/`.
5. **Build against fakes.** Every WP can run its tests without the other components, using the fakes
   and fixtures from WP-0.
6. **Tests prove end states** and every enforcement control is tested by attempting the bad thing.
   Never weaken a guard to make a test pass.
7. **No secrets in the repo**, no real credentials in fixtures, no tests that need the public
   internet unless marked `@pytest.mark.internet` (excluded in CI).
8. **Milestone order inside each WP:** build M1 scope first, then M2…M5 (each component spec marks scope).

## 2. Ownership

| WP | Name | Owns | Milestones |
|---|---|---|---|
| WP-0 | Contracts & foundation (integrator) | `shared/`, `test/fixtures/`, `test/fakes/` (except `test/fakes/orchestrator/`), root files (`Makefile`, `VERSION`, `README.md`, `CHANGELOG.md`, `pyproject.toml`, `ruff.toml`, `.editorconfig`), `docs/spec/` (via CRs) | M0 |
| WP-1 | Probe | `probe/` | M1, M4, M5 (local drills) |
| WP-2 | Collector (+ reflector, iperf3 unit) | `collector/` | M1, M3, M4, M5 (drill reports/control) |
| WP-3 | Dashboard | `dashboard/` | M1, M3, M5 (drills view) |
| WP-4 | Manager backend | `manager/worker/`, `manager/migrations/`, `manager/wrangler.toml`, `manager/deploy.sh`, `manager/scripts/` | M2, M3, M5 |
| WP-5 | Manager UI | `manager/ui/` | M2, M3, M5 |
| WP-6 | Agent + bootstrap | `agent/` (incl. `agent/install/install.sh`) | M2 |
| WP-7 | Packaging, release, CI | `packaging/`, `.github/workflows/`, `test/package/` | M1 (tarballs), M2 (signing/release/CI) |
| WP-8 | Integration & e2e (integrator) | `test/harness/`, `test/e2e/`, `test/load/` | every milestone gate |
| WP-9 | Runner: drills & correlation | `runner/`, `test/fakes/orchestrator/` | M5, M6 (correlation connectors, syslog receiver) |
| WP-10 | Speedtest shape + page | `speedtest/`, `manager/worker/src/speedtest/` (internet-leg routes, by CR with WP-4) | M6 |
| WP-11 | Speedtest analytics | collector `speedtests` storage/rules/API (in `collector/exp_collector/speedtest/`), dashboard views (`dashboard/static/speedtest/`), `test/fakes/mist/` | M6 |

## 3. Dependency graph and waves

```
            ┌──────────── WP-0 contracts, exp_common, fakes, fixtures ────────────┐
            ▼        ▼        ▼        ▼        ▼        ▼        ▼              ▼
          WP-1     WP-2     WP-3     WP-4     WP-5     WP-6     WP-7          WP-9 (M5)
          probe   collector dashboard mgr-api  mgr-ui   agent  packaging      runner
            └────────┴────────┴────────┴────────┴────────┴────────┘
                                       ▼
                         WP-8 harness + e2e (milestone gates)
```

- **Wave 0:** WP-0 alone. Gate: schemas, OpenAPI, `exp_common`, fakes, and fixtures reviewed and merged.
- **Wave 1:** WP-1 … WP-7 in parallel (each implementing its M1/M2 scope against contracts and fakes), WP-8 building the harness.
- **Gates:** M1 (WP-1/2/3/7 + harness), then M2 (adds WP-4/5/6/7), then M3, M4, M5 (adds WP-9), M6 (adds WP-10/11), each run by WP-8 and signed off by the integrator.

## 4. Work package details

### WP-0 — Contracts & foundation (integrator) · size M
Deliverables:
- `shared/schemas/`: JSON Schemas for `exp.measurement/1` (with the `id` + `detail` delta), `exp.desired/1`,
  `exp.status/1`, `exp.state/1`, `exp.beats/1`, `exp.manifest/1`, `exp.{probe,collector,dashboard,runner}.config/1`.
- `shared/openapi/`: `ingest.yaml`, `collector.yaml`, `agent.yaml`, `admin.yaml` (admin objects from
  `05-manager.md` §3).
- `shared/python/exp_common/`: `schema` (moved from `shared/exp_schema.py`, delta applied, tests kept),
  `ids` (ULID), `tlspin` (pinned HTTPS client), `config` (load + JSON-Schema-subset validation without
  deps), `creds` (read from `$CREDENTIALS_DIRECTORY`), `atomic` (atomic writes, `O_NOFOLLOW`),
  `log` (structured journald-friendly logging with secret scrubbing), `reflector_proto`.
- `shared/ui/tokens.css` + icon set (HPE design language).
- `test/fixtures/`: sample measurements per test type, desired/status docs, configs, and
  `convert_exm.py` + the converted outage fixture.
- `test/fakes/`: `fake_collector.py` (ingest + query API from fixtures), `fake_manager.py` (agent API),
  `mock_admin/` (admin API mock for the UI).
- Root tooling: `Makefile` (`lint`, `test`, `build`, `dev`), Python tooling config, CI skeleton stub.
DoD: every fixture validates against its schema; fakes conform to the OpenAPI files; `exp_common`
unit tests green; reference schema tests still green.

### WP-1 — Probe · size L
Scope: `02-probe.md` (M1: netns/host modes, preflight, lease, heartbeats, dhcp/dns/app tests, spool,
shipper, TLS pin, CLI; M4: throughput, path, target ports, Wi-Fi; M5: local drills).
DoD: `02-probe.md` §11 on the harness; SR-1/3/18 tests.

### WP-2 — Collector · size L
Scope: `03-collector.md` (M1: server, auth, ingest, storage, VM writer, rules engine, verdict,
incidents (log), query API, SSE, TLS identity, CLI; M3: webhooks, folding/flapping completeness;
M4: reflector, iperf3 unit, summary tables; M5: drill control/reports).
DoD: `03-collector.md` §13 including the **golden EXM outage tests**; SR-1/2/3/4/5/14/15.

### WP-3 — Dashboard · size M-L
Scope: `04-dashboard.md` (M1: server, local users, sessions, federation, overview, Pulse board,
incidents; M2: SSO handoff, NOC tokens; M3: partial-failure UX, kiosk; M5: drills view).
DoD: `04-dashboard.md` §7; SR-13.

### WP-4 — Manager backend · size L
Scope: `05-manager.md` §1–9, §11–14 (M2: auth, data model, agent API, compiler, secrets, releases,
rollout, cron, deploy.sh, **fleet roll-ups, fleet API, fleet issues**, demo seeder; M3: alerts settings,
NOC tokens, dashboard users, platform webhook; M5: drills/integrations API).
DoD: `05-manager.md` §15 items 1–7 and 9–11; SR-6/7/8/9/14/16.

### WP-5 — Manager UI · size L
Scope: **`11-manager-ui.md`** (fleet overview, issues, hosts table, host/component views, design
system, refresh model) and the administration flows of `05-manager.md` §10 — against `mock_admin`
and the demo seed, then the real backend.
DoD: `05-manager.md` §15 item 8 and `11-manager-ui.md` §11; performance budget (§9); SR-13.

### WP-6 — Agent + bootstrap · size L
Scope: `06-agent.md` (including host/process metrics, §3.1).
DoD: `06-agent.md` §9; SR-8/14/17.

### WP-7 — Packaging, release, CI · size M
Scope: `08-operations.md` §2, §3, §10; systemd unit templates per component are authored by each
component WP inside its own tree (`<component>/systemd/`) and collected by `packaging/build.sh`.
DoD: reproducible builds (two builds, identical bytes); signature verify; vendored hashes checked;
CI workflows green; package tests (`test/package/`) install each tarball in systemd containers.

### WP-8 — Integration & e2e (integrator) · size M
Scope: `test/harness/` (port `reference/exm/test/harness.sh`: bridge with pinned MAC, dnsmasq,
veth ports, NAT, local HTTP/DNS targets so tests do not need the internet), `test/e2e/` acceptance
suites A1–A5 from `SPEC.md` §9, `test/load/`.
DoD: each milestone's acceptance suite green in CI.

### WP-9 — Runner · size M (M5)
Scope: `10-drills-integrations.md` (EC drills, correlation pullers, allowlist enforcement, revert
intents) + `test/fakes/orchestrator/` built from the Orchestrator API documentation.
DoD: `10-drills-integrations.md` §8; SR-12/15. M6: `12-speedtest-analytics.md` §5 connectors and
syslog receiver, fakes built from vendor docs/recordings; A6.4–A6.6; SR-24.

### WP-10 — Speedtest shape + page · size M (M6)
Scope: `12-speedtest-analytics.md` §3–4, §7.3, §7.5 — server (sessions, tokens, local-leg endpoints
with `sendfile`, validation, limits/queue/pause), the branded page, the internet-leg Worker routes
(manager CR), agent unit + fleet-health metrics.
DoD: A6.1–A6.3, A6.7; SR-21/22/23.

### WP-11 — Speedtest analytics · size M (M6)
Scope: `12-speedtest-analytics.md` §5.3, §6, §7.4, §8, §9 — collector storage, VM aggregates,
diagnosis rules, query API, privacy jobs; dashboard views; manager settings pages (with WP-5 by CR).
DoD: A6.4, A6.6, A6.8; SR-25.

## 5. Contract change requests

A WP that needs a contract change writes `docs/spec/changes/CR-<n>-<slug>.md`: what changes, why,
affected WPs, backward compatibility. The integrator accepts or rejects; on accept, the integrator
updates `docs/spec/01-contracts.md`, `shared/` (schemas, OpenAPI, `exp_common`), fixtures, and fakes in
one merge and notifies affected WPs. Additive changes are preferred.

## 6. Branches, reviews, merges

- Branch per WP: `wp-<n>-<name>`; small PRs into `main`.
- **Reviewer checklist:** contract conformance (schemas/OpenAPI); security requirements for the WP
  (`07-security.md` SR list); tests assert end states and include enforcement tests; no edits outside
  owned paths; lint/type clean; no secrets; ported code cites its source; component README updated.
- CI must pass; reviewer approval required; the integrator merges in dependency order and runs the
  milestone gate after each wave.

## 7. Definition of done (every WP)

- All acceptance tests in its component spec pass in CI.
- Conforms to the frozen contracts; fixtures and fakes still pass.
- Security requirements for the WP have passing enforcement tests.
- Component `README.md` (what it is, CLI, config, troubleshooting).
- No TODOs that hide missing MUST requirements.
