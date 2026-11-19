# CR-m3-provided-tls: dashboard "provided" TLS certificates (upload endpoint)

Raised by: M3 step p2 (provided TLS). Affects: manager Worker (admin API, compiler), `shared/openapi/admin.yaml`, mock admin, manager UI (dashboard editor). Resolves item 6 of `CR-wp5-admin-ui-intent` and the note in `05-manager.md` §8.

## What (additive; applied by the step)

1. **`GET` / `PUT /api/admin/v1/dashboards/{dashboard_id}/tls`** (admin role; PUT is CSRF-guarded, audited as `dashboard.tls` without values).
   - `PUT {"mode": "self_signed"}` deletes any stored pair. `PUT {"mode": "provided", "cert_pem", "key_pem"}` stores a pair.
   - `GET` (and the PUT answer) return `{mode, set, updated_at, cert}` with `cert = {subject, issuer, not_before, not_after, sha256, san[]}` parsed from the leaf certificate; `sha256` is the upper-case colon fingerprint the dashboard reports as `tls_fingerprint_sha256`. The key and the PEM are never returned.
2. **Validation (422 `invalid_config`, clear message):** PEM structure; every `CERTIFICATE` block is parsed as X.509 DER (bounded reader, no new dependency); the leaf is not expired (and not valid only in the far future); at most 5 certificates, `cert_pem` <= 32 KiB, `key_pem` <= 8 KiB (bodies far over the cap fail the schema with 400); exactly one private key, unencrypted, `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` or `EC PRIVATE KEY`; RSA and ECDSA P-256/P-384/P-521 keys; and the key must match the leaf: both are imported with WebCrypto and a signature over a random 32-byte challenge made with the key must verify with the certificate's public key (proof of possession). The chain beyond the leaf is not path-validated (the admin owns trust).
3. **Storage:** one encrypted secret (`secrets`, kind `dashboard_tls`, owner = the dashboard component, JSON `{cert_pem, key_pem}`, AES-GCM with the master key, covered by key rotation). No schema change, so migration `0005_dashboard_tls.sql` is **not** needed and was not created. The mode is derived from the secret's existence (config `tls.mode` is not authoritative: a config saying `provided` without a pair compiles to `self_signed` with a warning).
4. **Compiler:** a dashboard with a stored pair compiles to `tls.mode = "provided"` plus creds `tls.crt` / `tls.key` (01-contracts §9.3) in that dashboard host's desired document only. The agent already skips self-signed generation for `provided` and restarts the unit when the creds change; the dashboard serves `creds/tls.crt` + `creds/tls.key` and reports the provided certificate's fingerprint (checked by `dashboard/tests/test_provided_tls.py`).
5. **Defect fixed on the way:** `DELETE components/{id}` left the component's secrets (tokens, SSO secret, and now the TLS key) in D1; it now deletes them as `deleteHost` already did.
6. **UI:** the dashboard editor's TLS panel has its own form (mode, PEM paste or file choose, parsed details after save, expiry warning under 30 days, never re-displays the key); `config.tls` is no longer edited by the config form.

## Why

`provided` was selectable but unusable (`05-manager.md` §8 "no upload endpoint yet (M3)"); real deployments need an organisation-issued certificate on the dashboard.
