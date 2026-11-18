# CR-wp4-token-overlap: collector token files carry two hashes during a rotation overlap

**From:** WP-4 (manager) **Affects:** WP-2 (collector), WP-3 (dashboard, indirectly) **Status:** proposed, implemented compatibly

## What
`01-contracts.md` §9.2 defines `ingest_tokens.json` as `{probe_id: sha256}` and `dashboard_tokens.json` as
`{dashboard_id: sha256}` (one hash per identity). `05-manager.md` §6 requires that a rotated token keeps the
previous value valid for 10 minutes ("the collector accepts both hashes"). The two cannot both hold with
single-string values.

## Proposal (what the manager does today)
A value is either a hex string (the normal case, exactly as in the contract) **or, only during the overlap
window, a JSON array `[current_sha256, previous_sha256]`**. After the grace period (or after cron drops
`previous_*`) the value is a plain string again.

## Why
Rotation without a flag day: the collector accepts both until the probe/dashboard has fetched the new
plaintext; no restart, no downtime.

## Compatibility
* Collectors that only understand strings would mis-handle (or reject) the array form for at most 10 minutes
  after an admin-initiated rotation. Recommended collector behaviour: accept `str | list[str]` per key, and
  keep ignoring unknown shapes (do not crash; log once).
* `shared/schemas` do not describe the creds files (they are opaque strings in `exp.desired/1`), so no schema
  change is needed; `docs/spec/01-contracts.md` §9.2 should gain one sentence.
* Fallback if WP-2 refuses the array form: the manager can instead publish two entries per identity under
  derived keys; tell WP-4 and it will switch (one function, `hashMap` in `compile/compile.ts`).
