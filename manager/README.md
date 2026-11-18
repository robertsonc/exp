# exp/manager - `exp-manager`

Cloudflare Workers central manager: `worker/` (WP-4), `ui/` (WP-5). Spec: [docs/spec/05-manager.md](../docs/spec/05-manager.md).

The manager holds the organisation's **intent**, compiles it into per-host **desired state**
(`exp.desired/1`), distributes signed releases and secrets, and audits every change. It never touches
the data plane.

## Status (WP-4)

| Step | Scope | State |
|---|---|---|
| 1 | foundation, Access auth, agent API, secrets, compiler, audit | **done** (this tree) |
| 2 | releases import/upload (Ed25519 verify), admin API routes, fleet roll-ups, issues, cron | **done** (this tree) |
| 3 | fleet API, demo seed, drills/integrations, deploy rehearsal | pending |

Every admin endpoint of `shared/openapi/admin.yaml` is implemented except **drills** (`/drills*` answers
`501 not_implemented` until step 3). Roles follow `x-exp-min-role` in the OpenAPI file; every mutation writes
exactly one audit event in the same D1 batch.

## Layout

```
manager/
  wrangler.toml          bindings: DB (D1), ARTIFACTS (R2), RL_ENROL/RL_AGENT/RL_ADMIN, ASSETS, crons, vars
  deploy.sh              one-command deploy (idempotent)
  migrations/0001_init.sql
  scripts/               prepare.mjs (bundles install.sh), dev.mjs, build-check.mjs, seed-demo.mjs (step 3)
  worker/src/
    index.ts             hono app, error envelope, /healthz, /install.sh, scheduled()
    auth/access.ts       Cloudflare Access JWT verification (RS256, JWKS cache), roles
    agent/               enrol, desired (304 hot path), manifest, artifacts, status, rotate, decommissioned
    admin/               routes.ts (all endpoints), service.ts + intent.ts (audited intent mutations),
                         read.ts (rows -> contract objects), sso.ts (dashboard handoff form)
    releases/            verify.ts (Ed25519 verify, GitHub import, multipart upload), rollout.ts (canary)
    fleet/               rollup.ts (5-min upserts, hourly compaction, pruning), query.ts (fleet API reads)
    issues/              rules.ts (section 14 rules), engine.ts (open / hysteresis / suppression / staleness),
                         store.ts (list, snooze), notify.ts (platform webhook), thresholds.ts
    notify/              webhook.ts (SSRF-safe outbound webhooks)
    compile/             compile.ts (pure), wiring.ts, load.ts (rows -> World), recompile.ts (persist, serve)
    secrets/             AES-256-GCM, token generation, secret rows with rotation overlap
    audit/               one event per mutation, scrubbing
    install/             /install.sh substitution
    cron/                */5 (tokens, staleness, canary, grace, history), hourly (compaction), daily (audit, R2)
  worker/test/
    workers/             vitest-pool-workers: local D1 / R2 / rate limit bindings
    node/                pure compiler goldens validated with ajv against shared/schemas
```

## Commands

```
npm ci            # .npmrc sets legacy-peer-deps: @cloudflare/vitest-pool-workers peers on vitest ^4.1
npm test          # vitest: workers project (D1/R2) + node project (compiler goldens)
npm run build     # tsc --noEmit + wrangler bundle dry-run (size, no Node built-ins)
npm run dev       # local wrangler dev (creates .dev.vars with a random EXP_MASTER_KEY)
./deploy.sh --check
```

`UPDATE_GOLDEN=1 npx vitest run --project node` rewrites `worker/test/node/golden/*.json`; review the diff.

## Configuration

Vars (`wrangler.toml [vars]`, filled by `deploy.sh`): `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `EXP_OWNER_EMAIL`,
`RELEASE_PUBKEY_PEM`, `RELEASES_REPO`, `ORG_NAME`, `MANAGER_URL` (optional; otherwise learned from the first
authenticated admin request and stored in `settings.manager_url`).
Secrets: `EXP_MASTER_KEY` (base64 of 32 bytes; **back it up offline**), `GITHUB_TOKEN` (optional).
A missing or malformed `EXP_MASTER_KEY` makes every operation that stores or reads a secret fail with
`503 unavailable` and a clear message; nothing falls back to plaintext.

## Behaviour worth knowing

* **Admin auth fails closed.** Every `/api/admin/v1/*` request needs a valid `Cf-Access-Jwt-Assertion`
  (RS256, `aud`, `iss`, `exp`/`nbf`); the email comes from the verified JWT only. Missing config -> 401.
* **Agent auth**: bearer `expa_`; the current secret or the previous one within 10 min of a rotation. The
  `GET desired` 304 path is one indexed read (credentials + desired version in one query) and writes nothing.
  Auth failures from an IP draw from a per-IP budget (10/min) and then answer 429.
* **Enrol** consumes the token with `UPDATE ... WHERE used_at IS NULL`; zero rows changed means 410.
* **Compiler**: `compile(world, host_id)` is pure. `version` only increases when the canonical-JSON hash of
  the document (without `version`/`generated_at`) changes. When a needed artifact or release is missing the
  host is **held** on its current document (never told to remove components). A component whose inputs are
  not known yet (e.g. no management address) is left out and reported as a warning.
* **Credentials inside `desired_docs`** are individually AES-GCM sealed (`enc1:`), decrypted only when
  served to the owning agent.
* **Rotation overlap**: collectors' `ingest_tokens.json` / `dashboard_tokens.json` carry `[current, previous]`
  hashes during the 10-min overlap (see `docs/spec/changes/CR-wp4-token-overlap.md`).
* **Audit**: every mutation adds exactly one event in the same batch as the change; details are scrubbed of
  token patterns, URLs and secret-looking keys.

## Troubleshooting

* `503 EXP_MASTER_KEY ...`: set the Worker secret (`wrangler secret put EXP_MASTER_KEY`, base64 of 32 bytes).
* `401 unauthenticated` on every admin call: `ACCESS_TEAM_DOMAIN`/`ACCESS_AUD` unset, or the request did not
  come through Access.
* `GET /install.sh` -> 503: `RELEASE_PUBKEY_PEM` is not a public-key PEM (it is substituted into a script piped to `sh`, so it is validated).
* A host stays on an old version: look at the compile warnings (`recompile()` outcome) - usually a release
  without an artifact for that component/arch.

## Step 2 behaviour worth knowing

* **Releases** (`worker/src/releases/verify.ts`): the Ed25519 signature is verified over the exact manifest bytes
  with WebCrypto against `RELEASE_PUBKEY_PEM` *before* any artifact is fetched; each artifact is streamed to R2
  (`FixedLengthStream` + `DigestStream`) and its sha256 and size compared with the signed manifest. Rows are
  written in one batch only after everything verified; any failure deletes every R2 object written so far and
  records nothing. GitHub import follows redirects manually, only to GitHub hosts, and never sends
  `GITHUB_TOKEN` anywhere but `api.github.com`. Multipart upload is buffered in memory and capped at 64 MiB
  (larger releases use the streaming GitHub import). Error codes: `signature_invalid`, `artifact_hash_mismatch`,
  `manifest_invalid`, `artifact_missing`, `artifact_unexpected` (422), `release_exists` (409).
* **Rollout**: `PATCH sites/{site}/release {version, canary_host_id}` compiles the target for the canary host
  only. Cron promotes it once the canary applied its document and every component stayed `ok` for 10 minutes
  (`canary_state`: `pending` -> `healthy_waiting` -> `promoted`). A rolled-back / failed reconcile, a `fail`
  component after applying, or an offline canary sets `failed` (halts, audited as `site.canary_failed`).
  Rollback or manual promotion = PATCH again without a canary host.
* **Roll-ups**: every status report upserts its 5-minute bucket with one statement per table (host row, host
  interfaces via `json_each`, component metrics via `json_each`). Per-metric sample counts (`cpu_n`, `net_n`, ...)
  mean a null value is skipped, never stored as zero. Cron compacts completed hours (idempotent REPLACE from the
  5-minute rows) and prunes 5-minute data > 48 h and hourly data > 30 d. Host metric keys served by the API:
  `cpu_pct mem_pct disk_pct load1 net_rx_pps net_tx_pps net_rx_bps net_tx_bps net_errors net_drops disk_write_kbps`.
* **Issues**: all 20 kinds of 05-manager.md section 14. Duration rules keep a `since` in `issue_state`;
  windowed rules (`cpu_high`, `iface_errors`, `collector_rejects`) read the roll-ups and need 80 % sample coverage;
  an issue resolves after two consecutive clean evaluations; an open `host_offline` hides the host's other issues
  (they stay recorded, nothing new opens). Snoozes (`1h`, `24h`, `resolved`) hide a kind per host from the lists and
  the platform webhook. The platform webhook fires on crit open (incl. warn -> crit) and on resolve of an announced
  crit issue, nothing else. Thresholds: `GET/PUT settings/fleet-thresholds`.
* **Write-only secrets**: webhook URLs (site alerts, platform), integration credentials are encrypted at rest and
  read back as `{"set": true, "updated_at"}`. Webhook URLs must be https and not private / loopback / link-local /
  CGNAT / IPv6 literal (SR-15); redirects are never followed; errors never echo the URL.
* **SSO handoff**: `POST dashboards/{id}/sso` returns an HTML page with an auto-submitting POST form (HS256 JWT,
  `exp = iat + 120`, `jti` uuid, key = the 32 bytes of the dashboard `sso_secret`). The CSP allows the one inline
  script by hash only and pins `form-action` to the dashboard origin.

Optional var: `AUDIT_RETENTION_DAYS` (default 365, minimum 30).
