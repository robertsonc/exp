# CR-wp2-cred-rotation-loadcredential

**From:** WP-2 (collector) - **Affects:** WP-6 (agent), WP-7 (packaging) - **Status:** proposed

## What
`03-collector.md` section 2 says the collector re-reads `ingest_tokens.json` / `dashboard_tokens.json` /
`webhooks.json` when the agent updates them (inotify or 10-s mtime poll) so rotation needs no restart.
`01-contracts.md` section 11 / the packaging convention deliver those files with `LoadCredential=`.

systemd copies a `LoadCredential=` file into `$CREDENTIALS_DIRECTORY` (a private tmpfs) **once, when the unit
starts**. Rewriting `/etc/exp/collector/creds/*` afterwards is not visible to the running service, so the
mtime poll alone cannot see an agent-side rotation.

## Why it matters
Token rotation (`POST components/{id}/rotate`, SR incident procedure "rotate the site's ingest and API tokens")
would silently not take effect until the next restart, leaving the OLD (possibly leaked) token valid.

## What the collector does (shipped in step 1)
`CredStore` polls the credentials directory every 5 s (<= 10 s, enforced) by `(mtime_ns, size, inode)` and
swaps in a new immutable token table atomically; a bad file keeps the previous good set and is logged without
its content. This works whenever the directory content changes (dev, tests, or if the agent refreshes it).

## Requested of WP-6 (agent) / WP-7
After writing changed credential files the agent MUST make them visible to the unit, by one of:
1. `systemctl restart exp-collector` (simplest; a restart costs about 2 s, probes spool meanwhile), or
2. (preferred, no restart) running the collector with a root-maintained credential mirror: render the creds to
   `@RUN@/creds/` (owner `exp-collector`, mode `0600`, atomic replace) and start the service with
   `--creds-dir @RUN@/creds` instead of `LoadCredential=`. The collector accepts `--creds-dir` today.

Until the agent does one of these, rotation takes effect on the next restart. The acceptance test for
rotation without restart (`collector/tests/test_server_auth.py::test_rotation_takes_effect_without_restart`)
exercises the collector side only.

## Compatibility
No contract change. The collector supports both delivery modes; the unit template ships with
`LoadCredential=` as the packaging convention requires.
