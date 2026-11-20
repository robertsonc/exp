# CR-m6-manager: speedtest + runner shapes, speedtest settings, secrets and fleet health in the manager (M6 p1)

**From:** M6 p1 (manager). **Affects:** manager Worker (compiler, admin API, secrets, fleet), manager UI, `mock_admin`,
`shared/openapi/admin.yaml` (additive), `shared/schemas/status.schema.json` (additive), WP-6 (agent: assets), WP-9/10/11
(consumers of the compiled documents). **Decision:** accepted; applied by the step that wrote it. Builds on
`CR-m6-contracts.md` and `CR-m6-spec-resolutions.md` (binding).

## 1. What the manager now does

| Area | Behaviour |
|---|---|
| Component types | `speedtest` is an addable shape (admin API + add-host wizard + fleet filters); `S` badge. A host may carry `probe + collector + runner + speedtest` (the all-in-one profile). |
| Compiler: speedtest | `exp.speedtest.config/1` = the site's speedtest settings + the host's `serve` addresses (the component's own `config.serve` overrides the site's). `serve.hostname` defaults to `serve.listen_ip`; `serve.client_subnets` defaults to the zone-label subnets (NAT-guard input, A.6); `tls.mode` (`none` default, `provided` needs the stored pair); `local_channel.listen = 127.0.0.1:8480`; `internet_leg.paused` = the admin switch; consent text + version; `branding.logo_artifact` + `assets[]`. Not compiled (warning, nothing broken) until: the collector reported listen + pin, the `exps_` token exists, `serve.listen_ip` is set, and (provided TLS) the pair exists. Creds: `collector_token` (`exps_`), `runner_channel_token_sha256` (sha256 of the runner's `expl_`), `tls.crt` / `tls.key` when provided. |
| Compiler: runner | `exp.runner.config/1` gains `correlation` only when the site runs speedtest analytics (a speedtest component or saved settings): connector sources come from the runner component's own `config.correlation` (Mist sites + zone map, EC appliances + WAN util, syslog allow list); `sources.sse` is forced `{enabled:false}`; `privacy.scrub_after_diagnosis` is the site's org privacy setting; `speedtest_channel.url` = `http://127.0.0.1:8480/local/v1` when a speedtest shares the host. A plain M3/M5 runner is byte-for-byte as before. Creds: `ingest_token` (`expi_`), `collector_token` (`expr_`), `device_key_secret` (`expk_`), `speedtest_channel_token` (`expl_`), `integrations.json` (`{ec:{url,api_key}, mist:{api_base,token}}` built from the existing integrations settings; only complete connectors). With correlation on, a missing token/key means the runner is not compiled (never half-configured). |
| Compiler: collector | gains `speedtests {enabled, speedtests[], runners[], retention_days, scrub_after_diagnosis, targets}` **only when a speedtest reports to it**, and creds `speedtest_tokens.json`, `runner_tokens.json` (sha256 maps, `[current, previous]` during a rotation overlap) and the optional `device_key_secret`. |
| Port collisions | `compile/speedtest.ts::portConflicts` models the listeners of a host (collector api/reflector/iperf3, dashboard 443/80, speedtest 80 or 443+80 and DNS 53 on `listen_ip`, runner syslog, channel 8480; `0.0.0.0` overlaps every address). Admission: `POST/PATCH components` on a host with a speedtest answers `422 port_collision` (also for a dashboard that would take the speedtest's port 80). The compiler fails closed if one slips through (the speedtest is left out with the reason). |
| Secrets | new generated kinds: `speedtest_token` (`exps_`), `runner_token` (`expr_`), `channel_token` (`expl_`, owner `<runner cmp>:<speedtest cmp>`), all sha256 at rest and rotated with the existing overlap (`POST components/{id}/rotate`: a runner rotates `ingest_token` + `runner_token` + `channel_token`, a speedtest `speedtest_token` + `channel_token`; the channel needs no overlap, both ends are on one host); `device_key` (`expk_`, owner `org`, **no hash**) created once when a runner exists (or by `POST settings/speedtest-device-key`), sealed with the master-key keyring (rotation-aware), never returned by any API, never in audit, never in D1 plaintext; `speedtest_tls` (pair, write-only). |
| Settings | `speedtest_settings` + `speedtest_consent_history` (migration `0005_speedtest.sql`). Consent text: an edit bumps the version (the client's `version` is ignored), every version is kept. The logo is an artifact (`component = speedtest-logo`, named `exp-speedtest-0.0.0-logo.<sha12>-noarch.tar.gz` only to satisfy `artifact_name`; the bytes are the raw image; version `0.0.0-logo.<sha12>`), referenced by the desired state so SR-6 lets the host download it, replaced and garbage-collected on re-upload / removal, deleted with the site. |
| Fleet | `runner` and `speedtest` health metric keys (01 §8.1) are stored (`LATEST_COMPONENT_KEYS`), rolled up (`COMPONENT_KEYS`) and charted; host rows list the `speedtest` shape and `work.tests_per_hour`; `?type=speedtest`. The status zod mirror accepts `facts.url` over `http://` and `facts.tls_mode`. |
| SR-20 | There is no admin or agent route for results, evidence, sessions or tests, asserted by tests in the Worker, the mock and the UI. |

## 2. Contract changes (all additive)

* `admin.yaml`: `GET /sites/{site}/speedtest/consent-history` (admin), `GET|PUT /sites/{site}/speedtest/tls` (admin; write-only
  pair, same validation as the dashboard's, needed only for `tls.mode: provided`), schemas `SpeedtestConsentHistory`,
  `SpeedtestTls`, `SpeedtestTlsPut`; `Shape` and `Release.artifacts[].component` gain `speedtest` (the host `shapes` badge was
  P/C/D/R). `test_openapi.py` lists the three operations and the two admin-only GETs; `mock_admin/admin_schemas.json` regenerated.
* `status.schema.json` component `facts.url` is now `http_url` (a superset of `https_url`) and `facts.tls_mode` is declared: the
  health schema (c0) already allowed `http://` for the speedtest, the status schema it is carried in did not. Without this an agent
  report with a speedtest endpoint would have been refused.
* Error contract of the settings PUT: all validation failures are `400 invalid_request` (the documented set); layout failures of
  components (`port_collision`, bad component config) are `422` like the other component errors.

## 3. Decisions later steps must know

1. **Where settings live.** Everything the admin API owns (branding, zones, limits, privacy, serve, TLS, DNS leg, path, core guard)
   is per **site**; the component only carries host-level overrides (`collector_id`, `serve`, `tls`, `dns_leg`). `serve.listen_ip`
   must be a unicast address (never `0.0.0.0`/loopback) and, when the speedtest host has reported its interfaces, one of them.
2. **Connectors.** Credentials stay in the org-wide integrations settings (`PUT integrations/{ec|mist}`, owner). The runner
   receives them in `integrations.json`. Saving an integration now recompiles the fleet. The Speedtest page has write-only Mist /
   EdgeConnect cards; there is no SSE connector (CR-m6-spec-resolutions A.8): the page says so.
3. **QR codes** are drawn in the browser with `qrcode-generator` 1.4.4 (MIT, pinned with its npm integrity hash in
   `manager/ui/package-lock.json`, published 2019). Chosen over an in-repo encoder because no decoder exists in this repo to verify a
   hand-written one; the tests pin the structure (finder/timing patterns, version, determinism). The signage is a printable dialog
   (`@media print`), no server-side image. ASCII URLs only (`?z=<slug>`).
4. **Logo preview** uses a `data:` URL (the SPA's CSP is `img-src 'self' data:`); the stored artifact is served to the agent only.
5. **Not yet possible from the manager:** a provided syslog TLS pair for the runner (`syslog_tls.crt/.key`; the editor offers only
   `self_signed`), per-runner `speedtest` channel tuning, DNS-leg port overrides. Add by CR when needed.
6. **A release must contain `exp-speedtest-<v>-noarch.tar.gz`.** A host with a speedtest component is *held* (existing rule for a
   missing artifact) when the site's release has none; `seedRelease` / packaging must add it (WP-10 / packaging).
7. **Seed (`mock_admin`).** `hb-run-01` is now the all-in-one box: shapes `runner + speedtest`, interface `eno2` (`10.0.0.9/24`),
   hall-b speedtest settings from `test/fixtures/configs/speedtest.json` (consent version 3, 3 versions of history), device key set.
   `test_mock_admin.py` was updated for the new shape and component count (26 -> 27).

## 4. Tests

`worker/test/workers/speedtest.test.ts` (settings API, roles, CSRF, consent versioning, all-in-one compile, token placement,
device_key sealing, collisions, rotation, logo, QR, TLS, fleet), `worker/test/node/speedtest-compile.test.ts` (the all-in-one
document and the compiled speedtest/runner configs validated against `shared/schemas`, equality with the contract fixtures, zod
mirrors vs fixtures, SVG scan), `manager/ui/tests/speedtest.test.ts` (form, QR, runner sources, page), `manager/ui/e2e/speedtest-tests.mjs`,
`test/fakes/tests/test_mock_admin.py`.
