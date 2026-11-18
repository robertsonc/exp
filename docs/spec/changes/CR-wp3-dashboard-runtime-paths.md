# CR-wp3-dashboard-runtime-paths

Status: informational (no contract file changes required). Raised by WP-3 (dashboard), step 1.

## What

1. **State, runtime and credential directories are not in `exp.dashboard.config/1`.** The dashboard
   takes them from the systemd environment: `STATE_DIRECTORY` (default `/var/lib/exp/dashboard`),
   `RUNTIME_DIRECTORY` (default `/run/exp/dashboard`), `CREDENTIALS_DIRECTORY` (default
   `/etc/exp/dashboard/creds`). The unit uses `StateDirectory=exp/dashboard` and
   `RuntimeDirectory=exp/dashboard`. Dev/test overrides are CLI flags (`--state-dir`, `--creds-dir`,
   `--run-dir`, `--tls-cert`, `--tls-key`).
2. **`health --json` talks to the running service over a unix socket** `@RUN@/health.sock` (mode 0600,
   owned by `exp-dashboard`; root, i.e. the agent, can connect). It never opens a TCP port for health
   and never needs credentials. When the service is down it prints `status: fail` (with the facts it
   can compute offline) and exits 1. Exit code is 0 **iff `status` is `ok`**; `degraded` (a collector is
   unreachable, the dashboard itself is serving) exits 1 so callers must read the JSON, not only the
   exit code, to tell "dashboard down" from "a collector is down".
3. **HSTS only when `tls.mode = provided`** (04-dashboard.md section 5). The task text for this step said
   "HSTS on https"; HSTS on a self-signed certificate would remove the browser's click-through for the
   certificate warning that the manager UI tells users to expect, so the more conservative spec wording
   was followed.
4. **Credential reload.** systemd credential directories are snapshots; the service additionally
   re-reads `CREDENTIALS_DIRECTORY` (stat stamp, every 5 s) so a re-rendered directory, or the dev/test
   layout, invalidates sessions within the 30 s required by 04-dashboard.md section 2. Production should
   still restart the unit on credential rotation (sessions.db survives restarts and is reconciled at
   start-up).
5. **NOC token `expires` is mandatory.** An entry of `noc_tokens.json` without a parsable timezone-aware
   `expires` is ignored (never non-expiring). `role` is ignored: NOC sessions are always `viewer`.
6. **Upstream SSE scope.** The collector `stream` takes `probes` xor `site`; the dashboard subscribes
   with `site=<collectors[].site>` once per collector, so one collector entry must cover exactly the
   site(s) it serves (a collector serving several sites needs one config entry per site/URL).

## Affected WPs

WP-6 agent (render units, create empty credential files, call `health`), WP-7 packaging (static files
live in `exp_dashboard/static/`), WP-5 manager (config rendering: one `collectors[]` entry per site).

## Compatibility

Additive; nothing in `shared/` changes.
