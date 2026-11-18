# CR-wp1-health-exit — what `health` exit codes mean when a component is `degraded`

**What.** `01-contracts.md` section 8.1 says "exit 0 = healthy" and `status` is `ok|degraded|fail`;
`02-probe.md` section 9 says the probe is *healthy* when "the collector is down and the spool is accepting".
The fixture `test/fixtures/health/probe-degraded.json` shows exactly that situation as `degraded`.

**WP-1 reading (most conservative that satisfies both).** `exp-probe health` exits **0 for `ok` and `degraded`**
and **1 for `fail`**. `degraded` is used only for states the spec defines as healthy: collector unreachable or not
configured while the spool accepts writes, throttling (429), or a client port without a lease that a recent error
record explains. `fail` covers: invalid config, daemon not running (no fresh status), a missing namespace or
port, a client port without a lease and without an explanation, spool write failures, a shipper that has not
pushed for more than 120 s with a backlog, and the two security-relevant shipper states `auth_failed` (401) and
`tls_pin_mismatch` (data cannot be delivered and an operator must act).

**Request.** State in 8.1 that `degraded` exits 0 for every component, so the agent maps exit code to
"process healthy" and `status` to severity. Components must not use exit 1 for `degraded`.

**Additive facts.** The probe adds `shipper_state`, `tls_pin_mismatch`, `auth_failed` to `facts` (the health schema
allows additional facts) and `dropped_total` to `metrics`; consumers must ignore unknown keys.

**Affected WPs.** WP-6 (agent exit-code handling), WP-2/WP-3/WP-9 (same convention), WP-0 docs.

**Compatibility.** No schema change.
