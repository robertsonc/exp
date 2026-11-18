# 06 — Host agent (`exp-agent`) and bootstrap (`install.sh`)

The agent turns a plain Ubuntu host into whatever the manager says it should be, and keeps it that
way. It is **declarative and bounded**: it applies desired state through a fixed set of operations
and never runs arbitrary commands from the manager (Principle 4). Contracts: `01-contracts.md`
§6–8, §10–11.

Package: `agent/exp_agent/{config,client,facts,desired,verify,artifacts,install,units,creds,health,
selfupdate,decommission,cli}.py`, `agent/install/install.sh`, tests in `agent/tests/`. Python 3.10+
stdlib only; uses `openssl`, `systemctl`, `apt-get`, `ip`, `tar` via argv (never `shell=True`).

## 1. Bootstrap — `install.sh`

Served by the manager at `/install.sh` with three values substituted at serve time (no secrets):
`MANAGER_URL`, the current agent version, and `RELEASE_PUBKEY_PEM`.

```
curl -fsSL https://<manager>/install.sh | sudo bash -s -- expe_XXXXXXXX…
```
(With no argument it prompts for the token with echo off.)

Steps — stop with a clear message on any failure, change nothing before step 3:
1. **Preflight:** root; Ubuntu 22.04 or 24.04; `amd64`/`arm64`; systemd PID 1; `python3` ≥ 3.10;
   `curl`, `openssl`, `tar` present (install `ca-certificates curl openssl` if missing); HTTPS to the
   manager works (honours `HTTPS_PROXY`); time sync active (warn if not — timestamps depend on it).
2. **Enrol:** `POST /api/agent/v1/enrol` with the token and minimal facts (hostname, machine-id, os,
   arch). The response secret is written straight to `/etc/exp/agent.json` (`0600` root) — never
   echoed.
3. **Fetch and verify the agent:** `GET desired` → release manifest + signature → verify with
   `openssl pkeyutl -verify -rawin` against the pinned public key → download the agent artifact →
   check its sha256 against the manifest.
4. **Install:** safe-unpack (§6) to `/opt/exp/agent/<ver>/`, link `current`, install
   `exp-agent.service` and `exp-agent-rollback.timer`, start the agent.
5. Print: enrolled host name, site, "components will be installed by the agent; watch progress in
   the manager". Exit 0.

Re-running with a new token on an enrolled host re-enrols it (replacing credentials). Re-running
without a token repairs the agent installation.

## 2. Main loop

- Poll `GET desired` with `If-None-Match` every `poll_interval_s` (30 s) ± 20% jitter. For 2 min
  after enrolment or after applying a change, poll every 5 s (fast convergence).
- On a new desired state → **reconcile** (§3) → `POST status`. Otherwise `POST status` every
  `agent.status_interval_s` (default 60 s, 30–300) — the fleet-health heartbeat (§3.1).
- Manager unreachable → keep the last applied state (cached at `/var/lib/exp/agent/desired.json`),
  back off 30 s → 5 min, keep reporting locally (`exp-agent status`). Components are never stopped
  because the manager is unreachable.
- `401` from the manager → stop polling for 5 min, log once (credentials revoked or rotated wrongly);
  do not uninstall anything.

## 3. Reconcile (idempotent, ordered)

1. Validate the doc against `exp.desired/1`; refuse invalid docs (report, keep the current state).
2. Verify the release manifest signature (cache verified manifests per version).
3. **Self-update** first if `agent.version` differs (§4).
4. For each component in order **collector → runner → dashboard → probe**:
   1. Apt requirements: install only packages that are in **both** the artifact's `requirements.apt`
      and the agent's built-in allowlist (`busybox`, `busybox-static`, `iproute2`, `iputils-ping`,
      `iperf3`, `curl`, `openssl`, `ca-certificates`, `ethtool`, `iw`, `wpasupplicant`, `tcpdump`).
      Anything else → refuse the component and report.
   2. Ensure the service user (`exp-collector`, `exp-vm`, `exp-dashboard`, `exp-runner`).
   3. Install the artifact version if missing: download → sha256 against the manifest → safe-unpack
      into a staging dir → atomic rename to `/opt/exp/<c>/<ver>/`.
   4. Render `config.json` (atomic write, `0644`) and every `creds` entry (atomic, root `0600` in
      `creds/`, which is `0700`); remove creds files no longer present; create any credential file
      the units reference but desired state left empty (missing files stop units from starting).
   5. Type hooks: collector/dashboard → ensure TLS key + self-signed cert (`03-collector.md` §8);
      probe → run `exp-probe preflight` against the new config and **refuse port changes that fail
      it**, keeping the previous config.
   6. Render units from the artifact's `systemd/` templates into `/etc/systemd/system/` (names
      must match `exp-*.service|timer`); `daemon-reload`.
   7. Flip `current` if the version changed; restart units whose version, config, or creds changed
      (creds-only change → `SIGHUP` if the component declares reload support, else restart).
   8. **Health:** `exp-<c> health` must succeed within 60 s (poll every 2 s).
   9. **On failure:** restore the previous version, config, and creds (kept in
      `/var/lib/exp/agent/previous/<c>/`), restart, re-check, report `rolled_back` with the error,
      and do not retry this desired version until it changes.
5. Remove components no longer desired: stop/disable units, remove unit files and
   `/opt/exp/<c>/`; **keep data** under `/var/lib/exp/<c>/` (decommission purges it — §5). For a
   probe, stopping `exp-probe-netns` returns every port to the host.
6. Execute `actions` once per action id (ids remembered in `/var/lib/exp/agent/actions.json`):
   `rotate_agent_secret` (call `POST rotate`, swap the secret atomically), `restart_component`,
   `collect_diagnostics` (sanitized journal excerpts and versions; never creds).
7. Report status (`01-contracts.md` §8), including each component's `health` facts (collector TLS
   fingerprint and listen address, dashboard fingerprint, probe port states).

### 3.1 Metrics (fleet health)

Each status report carries host metrics and per-component process and work metrics exactly as
defined in `01-contracts.md` §8–8.1: CPU, load, memory, disks (`/` and `/var/lib/exp` mounts),
disk I/O, host-namespace interface pps/bps/errors/drops, uptime, temperature; per component, systemd
cgroup CPU/memory/restarts/uptime plus `exp-<c> health --json` metrics and facts (probe per-port
counters come from the probe, which can see inside its namespaces). Rates are computed from counter
deltas between reports (first report and counter resets → `null`). Collection is cheap (< 50 ms CPU,
reads from `/proc` and `/sys`) and a health command that exceeds 5 s is reported as `degraded`
with `detail: "health timeout"`.

**Facts:** hostname, machine-id, `/etc/os-release`, kernel, arch, CPUs, memory, free disk under
`/var/lib`, Python, time sync (`timedatectl show`), interfaces (`ip -j link/addr/route`, speed and
driver from `/sys/class/net`), default-route interface, and `in_use_by` derived from current config.

## 4. Self-update

Download and verify the new agent → unpack to `/opt/exp/agent/<new>/` → write a `pending` marker
with the previous version → flip `current` → `systemctl --no-block restart exp-agent`. The new
agent, on start with a `pending` marker, must poll and report successfully within 5 min, then clear
the marker. Otherwise `exp-agent-rollback.timer` (every 5 min, installed by `install.sh`) flips
`current` back and restarts the old agent, which reports `agent_rollback`. An agent version is
never downgraded below the manifest's `min_agent_version`.

## 5. Decommission and uninstall

- `decommission: true` → remove all components **including** their data, creds, and configs →
  `POST decommissioned` → remove `/etc/exp/agent.json`, the agent units, and `/opt/exp/agent/`.
- `exp-agent uninstall --local` (manager unreachable): the same local cleanup without the call;
  the host stays listed in the manager until an admin removes it.
- Never removes anything outside the paths in §6.

## 6. Safety rules (enforced in code, tested)

- **Allowed roots only:** `/opt/exp/`, `/etc/exp/`, `/var/lib/exp/`, `/run/exp/`, and
  `/etc/systemd/system/exp-*`. Any computed path outside them → refuse.
- **Safe unpack:** reject absolute paths, `..`, symlinks or hardlinks pointing outside the target,
  device/FIFO files, and setuid/setgid bits; unpack only after signature + sha256 verification.
- **No shell:** every subprocess uses an argv list; config values are never interpolated into
  shell text or unit `ExecStart` lines (units take `--config <path>` only).
- **No ownership changes through service-writable paths:** root creates directories and changes
  ownership only on paths it created and that no service user can write; never recursive `chown`
  and never through symlinks (`O_NOFOLLOW`, `lchown`).
- **TLS to the manager:** system CA store, hostname verification, TLS ≥ 1.2. Only `MANAGER_URL` is
  ever contacted for control traffic.
- **Secrets:** never logged, never in status, never in argv (`/proc` exposure); journald messages
  scrubbed of `exp[aeidn]_` patterns as a backstop.
- **Fail closed:** any verification failure leaves the host as it was and reports why.

## 7. Units

`exp-agent.service`: root, `Restart=always`, `RestartSec=5`, `ProtectHome=yes`, `PrivateTmp=yes`,
`ReadWritePaths=/opt/exp /etc/exp /var/lib/exp /run/exp /etc/systemd/system`.
`exp-agent-rollback.service` + `.timer`: oneshot rollback check (§4).

## 8. CLI

`exp-agent run` · `status` (local summary: desired/applied versions, components, last error) ·
`reconcile --once` · `facts` · `enrol <token> [--manager URL]` · `uninstall [--local]` · `version` · `selftest`.

## 9. Acceptance tests (WP-6 definition of done)

In systemd containers (pattern: `reference/exm/test/package.sh`) against the manager under
`wrangler dev` or a contract-faithful fake:
1. `install.sh` on fresh 22.04 and 24.04 images enrols and starts the agent; the secret is never
   printed; re-running is idempotent.
2. All shapes converge (collector, dashboard, probe with veth ports) and report healthy; probe
   data reaches the collector through the wiring the manager compiled.
3. Tampered manifest, bad signature, wrong sha256 → refused, nothing changed.
4. A release whose `health` fails → automatic rollback, reported `rolled_back`; the same desired
   version is not retried.
5. Self-update succeeds; a new agent that cannot report → the rollback timer restores the old one.
6. Manager down 30 min → components unaffected; the agent recovers and reports.
7. Decommission removes everything; `uninstall --local` works offline.
8. Tar-slip artifact, symlink escape, unknown component type, apt package off the allowlist,
   unit name not `exp-*`, path outside allowed roots → each refused.
9. `creds/` files are root `0600`; a journal scan after a full run finds no token patterns.
