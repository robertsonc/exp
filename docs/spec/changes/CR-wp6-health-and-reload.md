# CR-wp6-health-and-reload

Status: informational (no contract file changes required). Raised by WP-6 (agent), step 1.

## What

1. **Health gate during reconcile.** `06-agent.md` section 3 says "`exp-<c> health` must succeed within 60 s".
   `01-contracts.md` section 8.1 says "exit 0 = healthy" and `health.schema.json` also has `degraded`.
   The agent runs `<prefix>/bin/exp-<c> health --json --config <config>` (5 s timeout, `CREDENTIALS_DIRECTORY`
   set to the component creds dir) and treats **`status` `ok` or `degraded` as passing, `fail` (or no
   parsable JSON with a non-zero exit, or a timeout) as failing**. This follows `CR-wp3-dashboard-runtime-paths`
   (a dashboard whose collector is down exits 1 with `degraded`) and avoids rolling a healthy dashboard or a
   probe without a collector address back. Components that want a rollback must report `fail`.
   `status: fail` with exit 0 is a contradiction and counts as failing. The component's own `status`, `detail`,
   `metrics` and `facts` are copied into the status report either way (a timeout is `degraded`,
   `detail: "health timeout"`).
2. **Declaring reload support.** `06-agent.md` section 3 step 7 says a creds-only change sends `SIGHUP` "if the
   component declares reload support". The packaging convention does not say how a component declares it.
   The agent treats a service unit that contains an **`ExecReload=` line** as declaring it and runs
   `systemctl reload <unit>` (the unit decides what that does, normally `ExecReload=/bin/kill -HUP $MAINPID`).
   Components without `ExecReload=` are restarted on a creds-only change (the safe default).
3. **Restart order inside a component.** Units with `netns` in their name are (re)started first, then template
   instances (`exp-probe-lease@<port>`, `exp-probe-target@<port>`), then the remaining units that have an
   `[Install]` section. Units without `[Install]` are never enabled or started directly (dependencies pull them in).
   Template instances come from the probe config: `client` ports get `exp-probe-lease@<id>`, `target` ports
   `exp-probe-target@<id>`, `wifi` ports none; only if the artifact ships the matching template.
4. **Agent unit layout.** `exp-agent.service` runs `/opt/exp/agent/current/bin/exp-agent run --config
   /etc/exp/agent.json` (the agent keeps `agent.json` at the contract path `/etc/exp/agent.json`, not
   `/etc/exp/agent/config.json` as the generic `--config` default of the other components suggests).
   Self-update maintains `/opt/exp/agent/previous` (a symlink to the version being replaced) and
   `/var/lib/exp/agent/pending.json`; `exp-agent-rollback.service` runs the **previous** tree's
   `exp-agent rollback-check` under `ConditionPathExists=/var/lib/exp/agent/pending.json`, so a broken new agent
   cannot prevent its own rollback. `install.sh` (WP-6 step 2) must create `/opt/exp` and `/etc/exp` before the
   first start (the service unit declares them in `ReadWritePaths=`; `StateDirectory=exp`/`RuntimeDirectory=exp`
   create the other two).

## Affected WPs

WP-1 probe, WP-2 collector, WP-3 dashboard, WP-4 runner (health exit codes and `ExecReload=` in their unit
templates), WP-7 packaging (agent tarball ships the three units under `systemd/`, `requirements.apt` for the agent).

## Compatibility

Backwards compatible: stricter components that exit non-zero with `ok` are not a thing; components that already
exit 0 only when `ok` keep working (their `degraded` simply no longer blocks a deployment).
