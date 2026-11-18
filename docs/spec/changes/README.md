# Change requests

Change requests (CRs) are raised by work packages when a contract or spec is silent, inconsistent or too narrow.
Each CR is one file `CR-<wp>-<slug>.md` in this directory. The integrator decides each one; the decision and where
it was applied are recorded here. "Applied" means the frozen contracts, spec text, fixtures and fakes were updated;
the component implementations already followed the CR (they were written against it).

Decisions: **accepted** (applied), **deferred** (accepted in principle, scheduled for a later milestone),
**rejected** (none so far).

| File | From | Affects | Decision | Where applied |
|---|---|---|---|---|
| `CR-wp0-exm-fixture-readme-notes.md` | WP-2 | WP-0 fixture docs | accepted | `test/fixtures/exm/README.md` (times, replay window, resolver kind notes); `03-collector.md` §12 |
| `CR-wp1-allow-shared.md` | WP-1 | probe config, manager compiler/UI | accepted | `probe.config.schema.json` (`allow_shared`); `01-contracts.md` §9.1; `02-probe.md` §9; fixture `configs/probe.test-options.json` |
| `CR-wp1-health-exit.md` | WP-1 | all components, agent | accepted | `01-contracts.md` §8.1 (`degraded` exits 0, `fail` exits 1); `02-probe.md` §9; `06-agent.md` §3 step 8 |
| `CR-wp1-test-options.md` | WP-1 | probe config, manager compiler/UI | accepted | `probe.config.schema.json` (`tests.{dhcp,dns,app,trace,ping}.thresholds`, `dhcp.allowed_servers`, `app.targets[].expect_status/expect_body`); `01-contracts.md` §9.1; fixtures `configs/probe.test-options.json`, `invalid/configs/probe-apdex-min-over-1.json` |
| `CR-wp2-cred-rotation-loadcredential.md` | WP-2 | agent, packaging | accepted, **modified**: the agent restarts the unit when credential files change (option 1; no `--creds-dir` mirror, no reliance on reload/SIGHUP) | `01-contracts.md` §11; `06-agent.md` §3 step 7; `03-collector.md` §2 |
| `CR-wp2-hold-vs-fixture-0245.md` | WP-2 | fixture docs, 03 §5 | accepted (documentation only; the hold is not weakened) | `test/fixtures/exm/README.md`; `03-collector.md` §12 |
| `CR-wp2-incident-line-probe.md` | WP-2 | `incident.schema.json`, collector.yaml, dashboard | accepted | `incident.schema.json` (`line` = `line_key` or `probe`); `01-contracts.md` §5; `03-collector.md` §6; `04-dashboard.md` (renders "Probe"); fixture `incidents/probe-silent.json`, `invalid/incidents/bad-line.json` |
| `CR-wp2-state-layout-and-wrappers.md` | WP-2 | agent, packaging | accepted | `01-contracts.md` §11 (collector state layout, `vm-exec`/`iperf3-exec` wrappers); `06-agent.md` §3 step 4 |
| `CR-wp2-summary-and-query-extras.md` | WP-2 | dashboard, harness | accepted | `01-contracts.md` §5 (summary row shapes, `query_range` extra errors, ack 403, SSE ids); `shared/openapi/collector.yaml`; `03-collector.md` §7 |
| `CR-wp2-webhook-allowlist.md` | WP-2 | collector config, manager, agent | accepted | `collector.config.schema.json` (`alerts.webhook_allow`); `01-contracts.md` §9.2; fixtures `configs/collector.webhook-allow.json`, `invalid/configs/collector-webhook-allow-*.json` |
| `CR-wp3-dashboard-runtime-paths.md` | WP-3 | agent, packaging, manager | accepted | `04-dashboard.md` §1 (runtime paths, health socket, HSTS, credential re-read, NOC `expires`, per-site collector entries); `01-contracts.md` §11. Item 2 (dashboard `degraded` exits 1) is superseded by the health-exit convention (`degraded` exits 0), so the dashboard CLI must change (see conformance notes) |
| `CR-wp4-admin-api-clarifications.md` | WP-4 | UI, agent, harness | accepted | `shared/openapi/admin.yaml` (`EnrolToken.command`, host metric keys, `t` seconds); `05-manager.md` §8 |
| `CR-wp4-desired-404.md` | WP-4 | agent.yaml, agent | accepted | `shared/openapi/agent.yaml` (`GET /desired` 404); `01-contracts.md` §6; `05-manager.md` §8; `06-agent.md` §8 |
| `CR-wp4-manager-url.md` | WP-4 | deploy docs, UI | accepted | `05-manager.md` §1; `01-contracts.md` §6 |
| `CR-wp4-rotate-409-code.md` | WP-4 | fake_manager | accepted | `test/fakes/fake_manager.py` (`rotation_not_requested`) + regression assertion in `test/fakes/tests/test_manager.py` |
| `CR-wp4-status-component-facts.md` | WP-4 | agent | accepted | `05-manager.md` §8; `06-agent.md` §3 step 8 (agent drops malformed wiring facts) |
| `CR-wp4-token-overlap.md` | WP-4 | collector, dashboard | accepted | `01-contracts.md` §9.2 (`str` or `[current, previous]`); `03-collector.md` §2; `05-manager.md` §8; `test/fakes/fakes_common.match_token` (and `fake_collector --ingest-tokens` files) + test |
| `CR-wp5-admin-ui-intent.md` | WP-5 | manager compiler/API, dashboard | accepted | `05-manager.md` §8 (admin-UI intent bullet); NOC URL `#t=` in `test/fakes/mock_admin/server.py` |
| `CR-wp5-fleet-api-gaps.md` | WP-5 | Worker fleet API, mock_admin | **item 1 accepted**; **items 2-6 deferred to M3** | Item 1: `test/fakes/mock_admin/seed.py` (`collector_metrics`: full `exp.health/1` collector set; `days_to_full` 5.4 d on `hb-col-01`, 1.6 d on `kn-col-01`, 41 d on `hc-col-01`) + test. Items 3-4 were answered by `CR-wp4-admin-api-clarifications` (host keys documented). Deferred (M3): 2 per-probe rows for the collector view, 3 per-interface history and error/drop series endpoint, 5 per-test history series, 6 `Issue.component_type` |
| `CR-wp5-metric-t-units.md` | WP-5 | mock_admin, Worker | accepted | `test/fakes/mock_admin/seed.py` emits epoch seconds (existing test corrected); `admin.yaml` `MetricSeries` text; UI keeps its tolerance |
| `CR-wp6-enrol-token-not-argv.md` | WP-6 | agent, packaging docs | accepted | `06-agent.md` §8 (`exp-agent enrol [--manager URL] [--token-file PATH\|-]`, `$EXP_ENROL_TOKEN`); `01-contracts.md` §6 |
| `CR-wp6-health-and-reload.md` | WP-6 | all components, packaging | accepted, **modified**: credential changes restart the unit; `ExecReload=` only for config-only reloads; health gate `ok`/`degraded` pass, `fail`/timeout/unparsable fail | `01-contracts.md` §8.1, §11; `06-agent.md` §3 steps 7-8, unit layout in §8 |
| `CR-wp6-install-sh-serving.md` | WP-6 | manager, packaging | accepted | `06-agent.md` §8 (validated template, three tokens, headers); `05-manager.md` §1; `01-contracts.md` §6 |
| `CR-wp6-shapes-converge-deferral.md` | WP-6 | packaging, harness | accepted (acceptance-test ownership moves to WP-7/WP-8) | `06-agent.md` §9 item 2 |
