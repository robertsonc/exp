# CR-wp5-metric-t-units: metric point timestamps are milliseconds in mock_admin, seconds in the contract

**Raised by:** WP-5 (manager UI)  **Affects:** WP-0 fake (`test/fakes/mock_admin/seed.py`), WP-4 (real Worker must follow the contract)

## What
`shared/openapi/admin.yaml` `MetricPoint.t` is documented as "Bucket start, epoch seconds (UTC)". The mock admin API
(`seed.py: series_points`) returns `t * 1000`, i.e. epoch milliseconds, for both `/fleet/hosts/{id}/metrics` and
`/fleet/components/{id}/metrics`.

## Why it matters
A UI written strictly to the contract would plot every mock series 1000x too far in the future; a UI written to the
mock would break against the real Worker.

## Workaround in WP-5 (forward compatible)
`manager/ui/src/charts/align.ts: toSeconds()` accepts both: any value above 1e11 is treated as milliseconds (1e11 s is the
year 5138, 1e11 ms is 1973), everything else as seconds. Covered by `tests/misc.test.ts`. No behaviour change is needed
on the UI side whichever way this is resolved.

## Proposed resolution
Fix the mock to emit seconds (the contract is authoritative) and keep the UI tolerance until WP-8 confirms the Worker.

## Compatibility
Fixing the mock is backwards compatible with the UI (it accepts both). No schema change.
