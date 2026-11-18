# 05 — Central manager (`exp-manager`, Cloudflare Workers)

The single place an admin signs in. It holds the organization's **intent** (sites, hosts, shapes,
configs, releases, users, alert settings, drills), compiles it into per-host **desired state**,
distributes software and secrets, and records everything in an audit log. It never touches the
data plane: telemetry stays on-prem. Contracts: `01-contracts.md` §6–8, §10, §12–13.

## 1. Stack and bindings

| Item | Choice |
|---|---|
| Runtime | Cloudflare Workers, TypeScript `strict`, ES modules. Router: `hono`. Validation: `zod` (schemas generated from/aligned with `shared/schemas`). |
| UI | `manager/ui/`: TypeScript + Preact + Vite → static files served by the Workers **Static Assets** binding. |
| Storage | **D1** (`DB`) for all state; **R2** (`ARTIFACTS`) for release manifests and artifacts. No KV, no Durable Objects in v1 (decision D4). |
| Abuse control | Workers **Rate Limiting** bindings: `RL_ENROL` (10/min per IP), `RL_AGENT` (120/min per agent id), `RL_ADMIN` (600/min per identity). |
| Schedules | Cron Triggers: `*/5 * * * *` (housekeeping), `0 3 * * *` (daily). |
| Secrets (Wrangler secrets) | `EXP_MASTER_KEY` (base64, 32 bytes — AES-256-GCM for secrets at rest), `GITHUB_TOKEN` (optional, private release repo). |
| Vars | `ACCESS_TEAM_DOMAIN` (`<team>.cloudflareaccess.com`), `ACCESS_AUD`, `EXP_OWNER_EMAIL`, `RELEASE_PUBKEY_PEM`, `RELEASES_REPO` (`owner/repo`), `ORG_NAME`. |
| Plan | Workers Paid recommended (CPU time for release import and compilation); must run on Free for ≤ 20 hosts. |

Layout: `manager/worker/src/{index.ts, auth/, agent/, admin/, compile/, secrets/, releases/, audit/, cron/, db/}`,
`manager/migrations/*.sql`, `manager/ui/`, `manager/wrangler.toml`, `manager/deploy.sh`.
`install.sh` is authored by WP-6 (`agent/install/install.sh`) and bundled as a static asset at build time.

## 2. Routes

| Prefix | Protection | Purpose |
|---|---|---|
| `/` (UI assets) | Cloudflare Access | admin SPA |
| `/api/admin/v1/*` | Access **+ Worker-side JWT verification** (§5) | admin API (`01-contracts.md` §13) |
| `/api/agent/v1/*` | Access **bypass**; per-agent bearer secret; rate limits | agent API (`01-contracts.md` §6) |
| `/install.sh` | Access bypass; public; static | bootstrap script |
| `/healthz` | public | `ok` |

## 3. Data model (D1)

All tables carry `org_id TEXT NOT NULL DEFAULT 'default'` (future multi-tenancy) and
`created_at`/`updated_at` (ISO). Secrets are never stored in plaintext (§6).

| Table | Key columns |
|---|---|
| `settings` | `org_name`, `drills_enabled` (0), `default_retention_*`, `release_channel` |
| `admins` | `email` (unique), `role` (`owner\|admin\|operator\|viewer`), `disabled`, `last_seen` |
| `sites` | `site` (slug pk), `name`, `timezone`, `release_version`, `canary_host_id`, `alerts_json` (no secrets), `edge_label` |
| `hosts` | `host_id` (pk `h_…`), `name`, `site`, `state` (`pending\|enrolled\|stale\|offline\|decommissioning\|removed`), `facts_json`, `last_seen`, `agent_version`, `desired_version`, `applied_version`, `desired_hash` |
| `components` | `component_id` (pk), `host_id`, `type`, `slug` (probe_id/collector_id/…; unique per type), `config_json`, `enabled`, `facts_json` (from status: TLS fingerprint, listen, health) |
| `enrol_tokens` | `token_hash` (pk), `host_id`, `expires_at`, `used_at`, `created_by` |
| `agent_creds` | `host_id`, `secret_hash`, `previous_hash`, `previous_valid_until`, `revoked_at` |
| `desired_docs` | `host_id` (pk), `version`, `doc_json` (creds **encrypted** inside, decrypted at serve time), `content_hash` |
| `status_latest` / `status_history` | `host_id`, `received_at`, `report_json` (bounded); history keeps the last 100 per host |
| `releases` | `version` (pk), `manifest_bytes` (R2 key), `signature` , `verified_at`, `source`, `notes_url` |
| `artifacts` | `artifact_id` (pk), `version`, `name`, `component`, `arch`, `sha256`, `size`, `r2_key` |
| `secrets` | `secret_id` (pk), `owner_ref` (component/dashboard/site/integration), `kind`, `ciphertext`, `nonce`, `version`, `previous_ciphertext`, `previous_valid_until`, `hash` (sha256 of plaintext when the consumer only needs a verifier) |
| `dashboard_users` | `usr_id`, `dashboard_slug`, `username`, `role`, `hash` (PBKDF2 string, computed in the browser — §6) |
| `noc_tokens` | `noc_id`, `dashboard_slug`, `label`, `hash`, `expires_at`, `revoked_at` |
| `webhooks` | `webhook_id`, `site`, `format`, `secret_id` (URL is a secret) |
| `integrations` | `kind` (`ec\|mist`), `config_json` (non-secret), `secret_id`, `allowlist_json` (drill targets) |
| `drills` / `drill_runs` | see `10-drills-integrations.md` |
| `audit` | `evt_id`, `ts`, `actor` (email or `agent:h_…` or `system`), `action`, `resource`, `details_json` (no secrets), `ip` |

Migrations are forward-only SQL files applied by `deploy.sh` (`wrangler d1 migrations apply`).

## 4. Roles

| Capability | owner | admin | operator | viewer |
|---|---|---|---|---|
| View everything (no secret values) | ✓ | ✓ | ✓ | ✓ |
| Sites, hosts, components, configs, releases | ✓ | ✓ | | |
| Rotate credentials, decommission | ✓ | ✓ | | |
| Dashboard users / NOC tokens, open dashboard via SSO | ✓ | ✓ | SSO only | SSO only |
| Integrations credentials, drills enable, admins | ✓ | | | |
| Create/approve drills | ✓ | ✓ (approve requires a second admin if `drills_two_person`) | | |
| Start approved drill / abort | ✓ | ✓ | ✓ | |
| Audit log | ✓ | ✓ | | |

## 5. Admin authentication (fail closed)

1. Cloudflare Access protects `/` and `/api/admin/*` (policy: allowed emails; default one-time PIN).
2. The Worker **independently verifies** `Cf-Access-Jwt-Assertion` on every admin request:
   RS256 signature against `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs` (JWKS cached 1 h,
   refetched on unknown `kid`), `aud` contains `ACCESS_AUD`, `iss` = `https://<ACCESS_TEAM_DOMAIN>`,
   `exp`/`nbf` valid. Missing config, missing header, or any failure → `401`. Never trust
   `Cf-Access-Authenticated-User-Email` alone.
3. The JWT `email` maps to `admins`. The first sign-in of `EXP_OWNER_EMAIL` creates the owner.
   Everyone else must be added by an owner/admin; an authenticated but unknown email gets `403`.
4. Enforcement test (A2.2): a direct request to the Worker with a forged or absent JWT is refused.

## 6. Secrets

- **At rest:** AES-256-GCM with `EXP_MASTER_KEY`; random 96-bit nonce per write; AAD =
  `secret_id|kind|version`. Plaintext exists only in memory while compiling or serving a desired state.
- **Generated by the manager:** probe ingest tokens (`expi_`), dashboard→collector tokens (`expd_`),
  dashboard `sso_secret`, NOC tokens (`expn_`, shown once, then only the hash is kept), enrol tokens
  (`expe_`, hash only), agent secrets (`expa_`, hash only; plaintext returned once at enrol/rotate).
- **Provided by admins (write-only in the UI/API):** webhook URLs, integration credentials, Wi-Fi
  credentials, provided TLS certs/keys. The API never returns them; it returns `{"set": true,
  "updated_at": …}`.
- **Dashboard local-user passwords never reach the manager:** the admin UI computes
  `pbkdf2_sha256$600000$<salt>$<hash>` in the browser (WebCrypto) and sends only that string.
- **Verifier-only delivery:** collectors receive `sha256` hashes of ingest/dashboard tokens; probes
  and dashboards receive plaintext only of their own tokens.
- **Rotation with overlap:** a rotated token keeps the previous value valid for 10 min
  (`previous_valid_until`): the collector accepts both hashes; the probe/dashboard switches; then
  the previous one is dropped. Agent secret rotation follows the same pattern via `POST rotate`.

## 7. Desired-state compiler

`compile(host_id)` builds `exp.desired/1` (`01-contracts.md` §7) from D1 state. It runs on any
change to the host, its site, its components, related components (wiring below), release targets,
credentials, or relevant status facts (a collector's `listen` or TLS fingerprint).

Wiring rules:
- **Probe → collector:** the probe's `config.collector_id` (default: the site's first collector).
  The URL is `https://<collector listen>`; the pin is the collector's reported
  `tls_fingerprint_sha256`. Until the collector has reported both, the probe's `collector` is
  `null` and the probe spools.
- **Collector:** `probes` = every probe pointing at it; `ingest_tokens.json` = their token hashes
  (+ the runner's); `dashboards` + `dashboard_tokens.json` = dashboards federating it.
- **Dashboard:** `collectors` = its configured collector ids (default: all collectors of its
  sites), each with URL, pin, and its own `expd_` token; `local_users.json`, `noc_tokens.json`,
  `sso_secret`. Its `url` (admin-set, default the host's mgmt IP) is the SSO handoff target and the
  default `alerts.board_url` of every collector it federates.
- **Path/iperf3 peers:** a probe's `path`/`iperf3` peer defaults to a target port with
  `serve.reflector` in the same site; the collector reflector is used only when the admin marks the
  site's event network as able to reach the management network.
- **Release:** component and agent versions = the site's `release_version`, except the canary host
  gets the new version first. Artifact chosen by component + host `arch` (`noarch` fallback).
- **Version:** the canonical-JSON hash of the doc (excluding `version`/`generated_at`) is compared
  with `desired_hash`; only a real change increments `version`. Agents therefore see no churn.

Compilation is a pure function over D1 rows (unit-testable with fixtures). Fan-out on a collector
change recompiles all its probes and dashboards.

## 8. Agent API behaviour

- **enrol:** rate limit by IP → look up `sha256(token)` → reject unknown (401), used or expired (410).
  Mark used **atomically** (`UPDATE … SET used_at=? WHERE token_hash=? AND used_at IS NULL`; zero rows → 410)
  so concurrent reuse yields exactly one success. Create `agent_creds`, store facts, host →
  `enrolled`, audit, return the secret (once) and `RELEASE_PUBKEY_PEM`.
- **desired:** auth (current or previous-within-grace secret, constant time) → if
  `If-None-Match` equals `"<host_id>:<version>"` → `304` (one indexed read; this is the hot path) →
  else decrypt creds into the doc and return it with `ETag`.
- **artifacts:** only artifacts referenced in this host's current desired doc (`403` otherwise);
  streamed from R2 with `Content-Length` and `ETag` = sha256.
- **status:** ≤ 256 KiB, validated against `exp.status/1`; stored in `status_latest`/`status_history`;
  host `last_seen`/versions updated; component facts merged; recompile if wiring facts changed.
- **rotate**, **decommissioned:** as in the contract; both audited.
- Every agent request is rate limited per agent; repeated auth failures from one IP are throttled.

## 9. Releases and rollout

- **Import** (`POST releases/import`): fetch `exp-<v>-manifest.json` and `.sig` from GitHub Releases
  of `RELEASES_REPO` (with `GITHUB_TOKEN` if private) → **verify the Ed25519 signature with WebCrypto**
  against `RELEASE_PUBKEY_PEM` over the exact bytes → fetch each artifact, stream to R2, and check its
  sha256 against the manifest → record rows. Any mismatch → nothing is recorded, error returned.
- **Upload** (`POST releases/upload`): the same verification for a manifest + signature + artifacts
  uploaded from the UI (for air-gapped or private builds).
- **Rollout:** `PATCH sites/{site}/release {version, canary_host_id?}` → the canary host compiles
  first; it is promoted automatically after its components report healthy for 10 min (or manually);
  a failed canary halts the rollout and alerts the admin in the UI. Rollback = set the previous
  version (agents also roll back on failed health checks and failed self-updates, `06-agent.md` §3–4).

## 10. Admin UI (`manager/ui`)

HPE design language (`shared/ui/tokens.css`), keyboard accessible, works at 390 px. Pages:

| Page | Key interactions |
|---|---|
| **Overview** | Sites with health counts (probes/collectors/dashboards ok/warn/fail/offline), version drift, recent audit events, failing canaries. |
| **Sites** | Create/edit (name, slug, timezone, edge label), release version, alert settings (webhook URLs write-only + "Send test"), retention. |
| **Add host wizard** | 1) name, site, shapes → 2) the one-liner with a copy button and a 1-h countdown, live "waiting for the host…" (polls every 3 s) → 3) the host's facts appear; for a probe, an **interface picker** (name, MAC, link, speed, addresses; the management/default-route interface is disabled with the reason) assigning `client`/`target`/`wifi` roles and target addresses → 4) Apply; progress until every component reports healthy. |
| **Host detail** | Components with health, desired vs applied version, last reconcile result and events, actions: restart component, rotate credentials, new enrol token, decommission. |
| **Component editors** | Probe: heartbeat targets, tests and intervals, app targets, DNS names, path peers, thresholds, labels. Collector: retention, alerts. Dashboard: title, collectors, local users (password hashed in-browser), NOC tokens (show once + copy NOC URL), **Open dashboard** (SSO handoff form), TLS mode + fingerprint. |
| **Releases** | Imported versions, import by version / upload, per-site target, canary status, rollback. |
| **Drills / Integrations** | `10-drills-integrations.md`. |
| **Audit** | Filter by actor/resource/time. |
| **Settings** | Org name, admins (invite by email + role), drills enabled, two-person approval, defaults. |

## 11. Cron

Every 5 min: expire enrol tokens; host `stale` after 3 × poll interval without status, `offline`
after 10 min; canary promotion; drop `previous_*` secrets past their grace; prune `status_history`.
Daily: prune audit > 1 year (configurable), report orphaned R2 objects.

## 12. `deploy.sh` (one-command manager deployment)

Prerequisites: Node 20+, a Cloudflare account, an API token with Workers Scripts:Edit, D1:Edit,
R2:Edit, Access: Apps and Policies:Edit (+ Zone:DNS:Edit for a custom domain). Steps (idempotent;
re-running upgrades):
1. Create (or reuse) the D1 database and R2 bucket; write their ids into `wrangler.toml`.
2. Apply migrations.
3. Generate `EXP_MASTER_KEY` if absent and set it as a secret (print a warning to back it up offline —
   losing it makes stored secrets unrecoverable).
4. Build the UI; deploy the Worker (custom domain if given, else `*.workers.dev`).
5. Create/update the Access application for the hostname (allow `EXP_OWNER_EMAIL`), and bypass
   applications for `/api/agent/*`, `/install.sh`, `/healthz`; write `ACCESS_AUD`/`ACCESS_TEAM_DOMAIN` vars.
6. Smoke test: `/healthz` ok; an unauthenticated `/api/admin/v1/me` → 401 *from the Worker* (direct
   request) — proving enforcement, not just configuration.
7. Print the URL and "sign in as <owner email>".

## 13. Acceptance tests (WP-4/WP-5 definition of done)

Vitest with `@cloudflare/vitest-pool-workers` (local D1/R2), plus UI tests:
1. Admin auth: absent JWT, bad signature, wrong `aud`, expired, unknown email → 401/403; valid → 200.
2. Enrol: single use under 20 concurrent attempts (exactly one 201), expiry, rate limit (11th/min → 429).
3. Compiler golden tests: intent fixtures → expected desired docs (probe/collector/dashboard wiring,
   pins, token hashes vs plaintext, canary, no version churn on no-op changes).
4. Agent auth: wrong/old secret outside grace → 401; artifact not in desired → 403; 304 hot path.
5. Release import: tampered manifest, bad signature, artifact sha mismatch → refused, nothing stored.
6. Secrets: D1 dump contains no plaintext token/URL (scan for `exp[aeidn]_` and `https://hooks`);
   decrypt round-trip; rotation overlap works end to end.
7. Every mutation writes exactly one audit event without secret values.
8. UI: the add-host wizard end to end against a fake agent; interface picker disables the mgmt
   interface; password hashing happens client-side (no plaintext in the request).
