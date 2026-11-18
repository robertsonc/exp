# exp/shared — contracts (integrator-owned)

Machine-readable contracts and the Python reference implementation every component builds against.
Spec: [docs/spec/01-contracts.md](../docs/spec/01-contracts.md). Changes after WP-0 need a change
request to the integrator; no work package edits `shared/` directly.

```
shared/
  schemas/            JSON Schema 2020-12 documents (restricted keyword subset, see config.py)
  openapi/            OpenAPI 3.1 for ingest / collector / agent / admin
  python/
    exp_common/       stdlib-only reference package (Python 3.10+)
      schema.py         Measurement (exp.measurement/1): id, detail, series mapping   [SCHEMA.md]
      ids.py            ULIDs, prefixed ids (h_ cmp_ ...), expX_ tokens, token_hash, slugs
      config.py         strict JSON loading, subset JSON-Schema validator, load_config
      tlspin.py         HTTPS client pinned to a leaf-cert SHA-256 fingerprint
      creds.py          systemd credentials ($CREDENTIALS_DIRECTORY), symlink/size-safe
      atomic.py         atomic, symlink-safe file writes
      log.py            journald-friendly logging + secret-scrubbing filter
      reflector_proto.py  UDP/TCP wire protocol for `path` tests (probe <-> reflector)
    tests/            pytest suite (incl. differential test against `jsonschema`)
  exp_schema.py       compatibility shim -> exp_common.schema (moved in WP-0)
  SCHEMA.md           human documentation of the measurement record
```

Use: `sys.path` must include `shared/python` (or install the packaged copy). Schemas are found via
`exp_common.schemas_dir()`: `$EXP_SCHEMAS_DIR`, else a packaged `exp_common/schemas/`, else
`shared/schemas/`. `exp_common.__version__` comes from `<repo>/VERSION` (or `0.1.0`).

Dev only (never imported by product code): `.venv` with pytest, hypothesis, ruff, jsonschema.

```
.venv/bin/python -m pytest shared/python -q
.venv/bin/ruff check shared/python --target-version py310
```

Key behaviours: `config.validate(doc, "probe.config")` raises `ConfigError` (a `ValueError`) listing
every problem with JSON-pointer paths; `config.iter_errors` returns them. A schema using a keyword
outside the subset raises `SchemaError`; it is never ignored.
