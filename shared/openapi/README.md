# shared/openapi — HTTP contracts (WP-0)

OpenAPI **3.1.0** (`jsonSchemaDialect` 2020-12) for every HTTP interface in `docs/spec/01-contracts.md`.
Changing these files after WP-0 needs a change request to the integrator.

| File | Contract | Base path (`servers[0]`) | Auth |
|---|---|---|---|
| `ingest.yaml` | §4 probe -> collector | `https://{collector}:8443/ingest/v1` | `ingestToken` (`expi_`) |
| `collector.yaml` | §5 dashboard -> collector, drills | `https://{collector}:8443/api/v1` | `dashboardToken` (`expd_`); `GET /drills/control` uses `ingestToken` |
| `agent.yaml` | §6 agent -> manager | `https://{manager}/api/agent/v1` | `agentSecret` (`expa_`); `enrol` takes `expe_` in the body |
| `admin.yaml` | §13 UI -> manager (data model: `05-manager.md` §3; fleet/issues: `11-manager-ui.md`) | `https://{manager}/api/admin/v1` | `accessJwt` (`Cf-Access-Jwt-Assertion`) |

Paths in each file are relative to that base (`/measurements`, `/state`, `/desired`, `/hosts/{id}` ...).
Root-level routes live in the same file with an operation-level `servers` override of the bare host:
collector `GET /healthz`; agent `GET /install.sh` and `GET /healthz`.

## Conventions

- **Security schemes** (all four defined in every file): `ingestToken`, `dashboardToken`, `agentSecret`
  (http bearer; prefixes `expi_`, `expd_`, `expa_`; 43 base64url chars after the prefix) and `accessJwt`
  (apiKey, header `Cf-Access-Jwt-Assertion`). Public operations declare `security: []` explicitly.
- **Document schemas are referenced, not copied**: `../schemas/<name>.schema.json` (one of the 13 agreed
  files, optionally with a `#/$defs/...` or `#/properties/...` fragment). Inline schemas use only the agreed
  JSON Schema keyword subset (see `test_openapi.py`), so a stdlib validator can implement them.
- **Errors**: every non-2xx body is `{"error":{"code","message","details"}}` (`common.schema.json#/$defs/error_envelope`).
  Each response documents its error codes as named `examples`. 429 and 503 carry `Retry-After`.
- **Lists**: `{items,next_cursor}`, `limit` 1..1000 default 100, opaque `cursor`.
- **Roles (admin)**: `x-exp-min-role` (`viewer|operator|admin|owner`) on every operation; `x-exp-audited: true`
  on every mutation (exactly one audit event, never with secret values). Insufficient role -> `403 insufficient_role`.
- **Fleet endpoints** return `ETag` and `Cache-Control: private, max-age=15` and accept `If-None-Match` (-> 304).
- **Agent `GET /desired`**: `ETag: "<host_id>:<version>"`, `If-None-Match` -> 304 (hot path).
- **Ingest limits** (`x-exp-limits`): <= 1000 lines, <= 4 MiB wire, <= 16 MiB decompressed (413), <= 64 KiB per line.
- **NDJSON / SSE** are described with vendor extensions because OpenAPI 3.1 has no item schema:
  `x-exp-line-schema` (ingest body) and `x-exp-sse-events` (collector `/stream`: `beat`, `state`, `incident`).
- **Secrets**: write-only fields read back as `{"set": true, "updated_at": ...}`; plaintext `expe_`/`expn_`
  tokens appear only in the response that creates them (`Cache-Control: no-store`).

## Tests

`/home/user/exp/.venv/bin/python -m pytest shared/openapi -q` validates each file with
`openapi_spec_validator` (external refs resolved relative to the file), checks that every contract endpoint
(and no extra one) exists, the 13-file `$ref` allowlist, the keyword subset, operationId/4xx hygiene,
the role matrix against `05-manager.md` §4, and the ETag/limits/SSE documentation.
