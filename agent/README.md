# exp/agent — `exp-agent` + `install.sh`

Enrols a host with one command and keeps it converged. Spec: [docs/spec/06-agent.md](../docs/spec/06-agent.md). Work package WP-6.
Python 3.10+, standard library only; uses `openssl`, `systemctl`, `apt-get`, `ip`, `useradd`, `journalctl` through argv lists
(never a shell). The agent is **declarative and bounded**: it applies the desired state it fetched from the manager through a
fixed set of operations and never runs a command the manager sends.

Status: complete (steps 1 and 2) — agent core, `install/install.sh` bootstrap, self-update with rollback timer, decommission /
uninstall, and the acceptance tests in systemd containers (`tests/container/`).

## Bootstrap: `install/install.sh`

```
curl -fsSL https://<manager>/install.sh | sudo bash -s -- expe_XXXXXXXX…      # enrol (or re-enrol with a new token)
curl -fsSL https://<manager>/install.sh | sudo bash                           # no token, enrolled host: repair
```
The manager serves it with `@@MANAGER_URL@@`, `@@AGENT_VERSION@@`, `@@RELEASE_PUBKEY_PEM@@` substituted (the script refuses to
run while any is left; see `docs/spec/changes/CR-wp6-install-sh-serving.md`). With no argument and no `/etc/exp/agent.json` it
asks for the token with echo off, from `/dev/tty`. Behind a proxy use `sudo -E` with `HTTPS_PROXY` set.

1. **Preflight, nothing changed** (except `apt-get install ca-certificates curl openssl` when one is missing): root, Ubuntu
   22.04/24.04 or Debian 12 (incl. 64-bit Raspberry Pi OS bookworm; not the 32-bit armv7l image), amd64/arm64, systemd as PID 1, python3 >= 3.10, tar/curl/openssl, HTTPS to the manager (system CA store),
   time sync (warning only). Any failure stops with the reason; the token is not used up.
2. **Enrol:** `POST /api/agent/v1/enrol`. The token travels only on a pipe into `curl --data @-`; the answer's secret goes
   straight into `/etc/exp/agent.json` (0600, atomic); later requests get the bearer header through `curl -K -`. Neither is
   ever in argv, a URL, the output or (xtrace is switched off) a trace.
3. **Verify:** `GET desired` -> signed manifest + signature -> `openssl pkeyutl -verify -rawin` against the *pinned* key ->
   agent artifact -> size and sha256 against the signed manifest -> `min_agent_version`.
4. **Install:** strict unpack (regular files and directories only; no absolute paths, `..`, links, devices, setuid/setgid;
   bounded) into `/opt/exp/agent/.staging-*`, atomic rename to `/opt/exp/agent/<ver>`, flip `current`, `/usr/local/bin/exp-agent`,
   units, `systemctl enable` + `restart exp-agent`, `enable exp-agent-rollback.timer`.
5. Prints the host, the site and "components will be installed by the agent; watch progress in the manager".

If verification fails after the enrolment, nothing is installed or started, but `/etc/exp/agent.json` stays (the token is
spent): fix the cause and re-run **without** a token to repair. A verification failure never leaves partial state under
`/opt/exp` or `/etc/systemd/system`.

## CLI

```
exp-agent run                      poll the manager, converge the host, report status (the systemd service)
exp-agent status                   local summary: desired/applied versions, components, last error, pending update
exp-agent reconcile --once         fetch the desired state once and apply it (prints "reconcile: ok|error|rolled_back")
exp-agent facts                    host facts as JSON (what enrol sends)
exp-agent enrol [--manager https://host] [--token-file PATH|-]   one-time enrolment; token from $EXP_ENROL_TOKEN or stdin
                                   (never argv: /proc exposure); writes /etc/exp/agent.json (0600)
exp-agent uninstall [--local]      remove all components, their data and the agent (--local: do not contact the manager)
exp-agent health [--json]          exp.health/1 for the agent itself (exit 0 iff healthy)
exp-agent version | selftest       selftest: python, openssl Ed25519 round trip, schemas, path guard, safe unpack, tools
exp-agent rollback-check           (timer) roll back an agent update that never confirmed itself
```
`--config PATH` (default `/etc/exp/agent.json`) is accepted before or after the subcommand. The agent refuses to start on a
missing, unreadable, symlinked, group/other-accessible, wrongly owned or invalid config and says why (exit 78).

## Config: `/etc/exp/agent.json` (root, 0600)

```json
{"manager_url": "https://exp-control.example.com", "agent_id": "h_…", "agent_secret": "expa_…", "release_pubkey_pem": "-----BEGIN PUBLIC KEY-----…"}
```
`manager_url` is an `https://host[:port]` origin (no path, userinfo or query). The secret is never logged, printed, put in
argv, status reports or diagnostics (`AgentConfig.__repr__` hides it too).

## What it does (06-agent.md §2–3)

* **Poll** `GET desired` with `If-None-Match` every 30 s ±20 % (5 s for 2 min after enrolment or after applying a change);
  `304` is the hot path. A status report goes out right after each reconcile and every `status_interval_s` (60 s).
* **Manager unreachable / 5xx / 429:** keep the applied state, back off 30 s → 5 min (honouring `Retry-After`); components are
  never stopped. **401:** pause 5 min, log once, uninstall nothing. TLS: system CA store, hostname verification, ≥ TLS 1.2,
  `HTTPS_PROXY` honoured; only `MANAGER_URL` is ever contacted and redirects are never followed.
* **Reconcile** (idempotent, order collector → runner → speedtest → dashboard → probe): validate `exp.desired/1` → verify the signed release
  manifest (`openssl pkeyutl -verify -pubin -rawin`, cached per version, `min_agent_version` enforced) → self-update if the agent
  version differs → per component: download + sha256 against the *signed manifest* → safe unpack into staging → `requirements.apt`
  ∩ allowlist (anything else refuses the component) → service users → atomic rename to `/opt/exp/<c>/<ver>/` → render
  `config.json` (0644) and creds (root 0600 in `creds/` 0700, stale files removed, referenced-but-empty files created) → TLS key and
  self-signed cert for collector/dashboard (P-256, SAN = listen IP, key `lchown`ed to the service user, never regenerated while valid)
  → probe `exp-probe preflight --config <new>` (a refusal keeps the previous config) → render units (only `@VERSION@ @PREFIX@
  @CONFIG@ @CREDS@ @STATE@ @RUN@`; names must match `exp-*.service|timer`) → flip `current` and `/usr/local/bin/exp-<c>` →
  enable/restart only what changed (a changed credential file always restarts the unit: systemd re-reads `LoadCredential=` only at unit start; a config-only change gets `systemctl reload` when the unit has `ExecReload=`, else a restart) →
  `exp-<c> health --json` within 60 s (poll 2 s; the document's `status` decides: `ok`/`degraded` pass whatever the exit code, `fail`, a timeout or unparsable output fail) → **on failure restore the previous version, config and creds from
  `/var/lib/exp/agent/previous/<c>/`**, report `rolled_back`, and never retry that desired version.
* Components no longer desired are stopped, disabled and removed (data under `/var/lib/exp/<c>` is kept). Actions run once per id
  (`actions.json`): `rotate_agent_secret`, `restart_component`, `collect_diagnostics` (sanitized, `/var/lib/exp/agent/diagnostics/<id>.txt`).
  Unknown component types are ignored and reported.
* **Self-update:** verified download → `/opt/exp/agent/<new>/` → `pending.json` → flip `current` (and `previous`) →
  `systemctl --no-block restart exp-agent`. The new agent clears the marker after its first successful poll + report; otherwise
  `exp-agent-rollback.timer` (every 5 min, runs the standalone `/opt/exp/agent/rollback-check`, independent of both agent versions) flips back, and the old agent reports `agent_rollback` and
  refuses that version until the manager asks for another.
* **Decommission:** remove every component incl. data, creds and config → `POST decommissioned` → remove `agent.json`, the agent
  units, `/opt/exp/agent/` and `/var/lib/exp/agent/`.

## Safety (06-agent.md §6, SR-8, SR-14, SR-17) — all enforced in code and tested

| Rule | Where |
|---|---|
| Allowed roots only (`/opt/exp`, `/etc/exp`, `/var/lib/exp`, `/run/exp`, `/etc/systemd/system/exp-*`, `/usr/local/bin/exp-*` links); `..`, relative paths and symlinks leaving the roots refused | `pathguard.py` — the only place that decides; every mutation goes through `SafeFS` |
| Release signature, sha256 vs the signed manifest, arch, `min_agent_version`; nothing unpacked before verification | `verify.py`, `artifacts.py` |
| Safe unpack: absolute paths, `..`, symlink/hardlink escapes, symlink chains, devices/FIFOs, setuid/setgid/sticky, duplicates | `artifacts.safe_unpack` |
| Apt allowlist, no shell, no secrets in argv | `install.py`, `runner.py` |
| `lchown`/`fchown` only on objects root just created or opened with `O_NOFOLLOW`; never recursive | `pathguard.SafeFS.lchown/fchown`, `tls.py` |
| Secrets never logged / in status / in diagnostics | `exp_common.log` scrubber on every handler; leak scan in `tests/test_security_logs.py` |

## Layout

```
agent/bin/exp-agent            entry point (tarball layout <prefix>/{bin,lib,vendor} or the dev tree)
agent/exp_agent/               config client facts metrics desired verify artifacts install units creds tls health
                               reconcile selfupdate decommission loop status state runner pathguard context cli
agent/install/install.sh       bootstrap (served by the manager)
agent/systemd/                 exp-agent.service  exp-agent-rollback.service  exp-agent-rollback.timer
agent/requirements.apt         ca-certificates curl iproute2 openssl
agent/tests/                   unprivileged tests in a tmp root against test/fakes/fake_manager.py
agent/tests/container/         acceptance tests: systemd containers + TLS fake manager (opt-in, Docker)
agent/Makefile                 test | lint | container-test
```
All paths come from one `Paths(root)` object, so the tests run as a normal user in a tmp directory with a scripted command
runner. (`--root DIR` exists on the CLI for the same purpose; never use it on a real host.)

## Troubleshooting

* `exp-agent status` — last reconcile result and error, versions, a pending update, desired versions that are *not retried*.
* A desired version that failed (rolled back or refused) is not retried until the manager publishes a new version; fix the cause,
  then change anything in the host's configuration (or re-publish) to bump the version.
* `refusing to start: …/agent.json: mode 0644 is too open; must be 0600` — `chmod 600 /etc/exp/agent.json`.
* `release manifest signature verification FAILED` — the manifest was not signed by the pinned release key (`release_pubkey_pem`);
  nothing was changed. Re-enrol only if the key legitimately rotated.
* `requirements.apt lists packages outside the agent allowlist` — the artifact asks for a package the agent will not install.
* Manager unreachable (network down, DNS, 5xx, 429): the agent logs it and retries with back-off from 30 s up to 5 min;
  installed components are left untouched and keep running. Check `exp-agent status` (last error) and the `manager_url` in
  `/etc/exp/agent.json`, then `curl -sS <manager_url>/api/agent/v1/desired` for a 401/TLS answer from the host itself.
* Credentials revoked (401): the agent logs once and pauses 5 minutes at a time; re-enrol with a new token
  (`echo "$TOKEN" | exp-agent enrol`), components keep running meanwhile.
* Logs: `journalctl -u exp-agent`; secrets are scrubbed (`exp[aeidn]_…` → `[REDACTED]`).

## Tests

```
.venv/bin/python -m pytest agent -q          # unit tests (+ install.sh and its embedded helper, unprivileged); container tests skip
.venv/bin/ruff check agent
make -C agent container-test                 # 06-agent.md section 9 in systemd containers (Docker, privileged; ~15-25 min)
```
`container-test` (sets `EXP_CONTAINER_TESTS=1`, marker `harness`) builds `exp-agent-systemd:<22.04|24.04|debian12>`
from `tests/container/Dockerfile` (`--build-arg BASE=ubuntu:<v>|debian:12`), runs the TLS fake manager on the docker host, generates a throwaway CA (installed into the
container trust store for the test only), a throwaway Ed25519 release key and signed releases containing the **real** agent
artifact built from this checkout plus tiny fake component artifacts; nothing is written into the repo. `EXP_CONTAINER_UBUNTU=24.04`
limits the OS matrix (default `24.04,22.04,debian12`; `debian12` is the 64-bit Raspberry Pi OS userland). If systemd cannot run as PID 1 (cgroups, privileges) or an image cannot be built, the affected tests
skip with the exact reason. `EXP_DIST_DIR=<dist>` (+ `EXP_RELEASE_PUBKEY`) additionally runs the "all shapes converge" test
against real built tarballs (§9 item 2).

| §9 | Test |
|---|---|
| 1 | `test_container_lifecycle.py` 01-06: install.sh on Ubuntu 22.04, 24.04 and Debian 12, secret never printed / never in argv, repair, used token, re-enrol, `exp-agent enrol` |
| 2 | `test_container_shapes.py` (needs `EXP_DIST_DIR`) |
| 3, 8 | `test_container_verify.py`: tampered manifest, wrong key, wrong sha256, tar-slip, symlink, device, setuid -> refused, nothing installed |
| 5 | lifecycle 09-10: self-update (+ component), a new agent that cannot report -> rollback timer restores the old one (timer shortened) |
| 6 | lifecycle 08: manager down -> component untouched (same PID), agent restart from cache, recovery |
| 7 | lifecycle 11 (decommission), `test_container_uninstall_local.py` (offline) |
| 9 | lifecycle 07 (creds modes) and 12 (journal + reports scan for token patterns) |
| prompt | `test_container_prompt.py`: no argument -> token read from /dev/tty with echo off (pty-driven) |
| preflight | `test_container_refusals.py`: no systemd, non-root, wrong OS, bad token, placeholders, unreachable manager, untrusted certificate |


## State layout (CR-wp2-state-layout-and-wrappers)

The collector and dashboard units use `StateDirectory=exp/<c>`, which chowns the directory to the service user and
recurses only when the top-level owner differs. The agent therefore creates the layout itself, as root, before the first
start, through `O_NOFOLLOW` directory descriptors (a service user that owns its state dir can never turn a path into a
link under the agent), so systemd never needs to recurse into `exp-vm`'s data:

| path | owner | mode |
|---|---|---|
| `/var/lib/exp/collector/` | `exp-collector` | 0755 (= `StateDirectoryMode`) |
| `/var/lib/exp/collector/tls/` | `exp-collector` | 0700; `key.pem` 0600, `cert.pem` 0644 |
| `/var/lib/exp/collector/vm/` | `exp-vm` | 0700 |
| `/var/lib/exp/dashboard/` | `exp-dashboard` | 0700 (= `StateDirectoryMode`) |
| `/var/lib/exp/dashboard/tls/` (self-signed mode only) | `exp-dashboard` | 0700; `key.pem` 0600, `cert.pem` 0644 |

New key pairs are generated in a root-only temp directory under `/var/lib/exp/agent/` and renamed into the pinned `tls/`
descriptor (a planted symlink is replaced, never followed). `records.db`/`sessions.db` are created by the services.

## Other behaviour worth knowing

* `GET desired` -> `404 not_found` means "nothing compiled for this host yet": the applied state is kept, the next poll is
  at the normal cadence (no backoff), and one info event is logged (CR-wp4-desired-404).
* Before a status report each component's wiring facts (`tls_fingerprint_sha256`, `listen`, `url`) are validated against
  `status.schema.json`; an invalid one is dropped and one warn event names the component and fact (never the value).
* `POST rotate` returns `grace_s`; the agent stores the new secret atomically, proves it with an authenticated call and, if
  the manager refuses it, restores the old one (still valid for the grace) and reports the failure.
* Package lists: when an allowlisted package is missing, `apt-get update` runs once per reconcile, then `apt-get install`;
  an apt failure is reported once per desired version (retries continue with backoff; other components still converge).
