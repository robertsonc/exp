# 08 — Operations: packaging, releases, deployment, testing, CI

## 1. Platforms and sizing

Hosts: Ubuntu 22.04 / 24.04 LTS, amd64 or arm64, systemd, python3 ≥ 3.10, NTP active.

| Shape | Minimum | Notes |
|---|---|---|
| Probe | 2 vCPU, 2 GB RAM, 10 GB disk per 16 test ports | 1 mgmt NIC + test NICs (or VLAN sub-interfaces); Wi-Fi probe needs an `nl80211` adapter |
| Collector | 4 vCPU, 8 GB RAM, 100 GB SSD for 50 probes / 30 days | VictoriaMetrics storage dominates |
| Dashboard | 1 vCPU, 1 GB RAM | can share a host with a collector |
| Runner | 1 vCPU, 512 MB RAM | needs reachability to Orchestrator/Mist APIs |
| All-in-one | 4 vCPU, 8 GB RAM | small events |

Network requirements:

| From | To | Port | Why |
|---|---|---|---|
| every host | manager | 443/tcp outbound | control plane |
| probe (mgmt) | collector | 8443/tcp | ingest |
| probe (test ports) | collector reflector / iperf3 | 8862 udp+tcp, 5201 | path and throughput tests (only where those tests are configured) |
| dashboard | collector | 8443/tcp | queries + SSE |
| operators | dashboard | 443/tcp (80 redirect) | UI |
| collector | webhook endpoints | 443/tcp outbound | alerts (optional) |
| runner | Orchestrator / Mist | 443/tcp | drills, correlation |
| every host | NTP | 123/udp | time |

## 2. Build and packaging (`packaging/`, WP-7)

`make release VERSION=x.y.z` → `packaging/build.sh`:
1. For each component, assemble the tarball layout (`01-contracts.md` §10): code, a pinned copy of
   `shared/python/exp_common`, `bin/` entry point, `systemd/` templates, `requirements.apt`, licenses.
2. Vendor dependencies from `packaging/vendor.lock` (name, version, URL, **sha256**): `dnspython`
   wheel (pure Python) for the probe; VictoriaMetrics `victoria-metrics-linux-{amd64,arm64}` for the
   collector, checked against upstream checksums pinned in the lock file.
3. Byte-compile check (`python3 -m compileall -q`), then pack reproducibly (sorted entries,
   owner 0:0, mtime = commit time, `gzip -n`).
4. Write `exp-<v>-manifest.json`; sign it: `openssl pkeyutl -sign -rawin -inkey $EXP_RELEASE_KEY
   -in manifest.json -out manifest.sig.bin` → base64 `.sig`. The key comes from the environment or a
   file outside the repo; the build refuses to run if the key file is inside the repo.
5. Verify the signature with `packaging/keys/release-pub.pem` before finishing.

Two builds of the same commit must produce identical bytes (checked in CI).

## 3. Releases

- Semver, one version for all components (`VERSION` file). `CHANGELOG.md` per release.
- Tag `vX.Y.Z` → `.github/workflows/release.yml`: run the full test suite, build amd64 + arm64,
  sign (environment `release` with required reviewers holds `EXP_RELEASE_KEY`), publish a GitHub
  Release with all artifacts, the manifest, and the signature.
- Admins then import the version in the manager (or upload for private/air-gapped builds) and roll
  it out per site with a canary (`05-manager.md` §9).

## 4. Deploying the manager

`manager/deploy.sh` (`05-manager.md` §12). Recommendations:
- Use a custom domain on a Cloudflare zone (e.g. `exp.example.com`) for a stable Access application.
- Enforce MFA in the Access identity provider.
- **Back up `EXP_MASTER_KEY` offline** at deploy time (printed once); without it, stored secrets
  cannot be recovered (hosts keep running; tokens would need rotation).
- D1 backups: Time Travel (point-in-time restore) plus an optional nightly `wrangler d1 export`
  (`manager/scripts/backup.sh`) to an operator-controlled location.
- Upgrading the manager: re-run `deploy.sh` (migrations are forward-only and applied first).

## 5. Day-1 runbook (admin guide content)

1. Deploy the manager, sign in as the owner, add other admins.
2. Import the current release; set it on the site.
3. Create a site (timezone, edge label).
4. Add the collector host first (it must report its TLS fingerprint before probes can be wired),
   then dashboards, then probes (pick test ports in the interface picker).
5. Open the dashboard via SSO; create local users and a NOC token for wall screens.
6. Optional: webhook URLs per site → "Send test".

## 6. Day-2 runbook

| Task | How |
|---|---|
| Upgrade | Import release → set site version with a canary host → watch → auto-promote |
| Roll back | Set the previous version (agents also roll back on failed health) |
| Rotate credentials | Component → Rotate (overlap window, no data loss); host → Rotate agent secret |
| Move a probe to another collector | Edit the probe's collector; the agent rewires; the spool covers the switch |
| Replace a failed collector | Add a new collector host to the site, repoint probes; history on the old host is lost unless restored from a snapshot |
| Snapshot collector data | `exp-collector snapshot` → VictoriaMetrics `/snapshot/create` + SQLite online backup into `/var/lib/exp/collector/snapshots/` |
| Decommission a host | Host → Decommission |
| Manager lost | Redeploy, restore D1 from export/Time Travel, restore `EXP_MASTER_KEY`; hosts keep running meanwhile |

## 7. Observing the platform itself

- Manager overview: stale/offline hosts, failed reconciles, version drift, failing canaries.
- Collector: self-metrics (`03-collector.md` §9); `probe silent` incidents; the dashboard banner
  when a collector is unreachable.
- Probe: `probe_self` measurements (spool depth, push lag, clock offset).

## 8. Troubleshooting guide (to write)

No carrier on all test ports (NIC in bypass/disconnect mode, not cables); port refused by preflight
(and why); probe waiting for collector fingerprint; time not synced; Access `401`/`403`; enrol token
expired/used; artifact signature refused; collector `429` back-pressure; webhook test failing.

## 9. Testing strategy

| Layer | Tooling | Where |
|---|---|---|
| Unit | `pytest` (dev only), `vitest` | `<component>/tests/`, `manager/worker/test/` |
| Contract | JSON Schema validation of every fixture and of live responses; OpenAPI conformance | `shared/` + each component's tests |
| Golden | EXM outage fixture → verdicts and alert messages | `collector/tests/golden/` |
| Component integration | container LAN harness: bridge with pinned MAC, dnsmasq, veth ports, NAT (from `reference/exm/test/harness.sh`) | `test/harness/` |
| Package | release tarballs in systemd containers (`--privileged --cgroupns=host`, from `reference/exm/test/package.sh`) | `test/package/` |
| End-to-end | manager under `wrangler dev` + agent containers enrolling and converging; acceptance tests per milestone (`SPEC.md` §9) | `test/e2e/` |
| Load | ingest 50 probes × 20 rec/s; manager 500 agents polling | `test/load/` |
| Security | `07-security.md` §5 | CI |

Rules for tests (Principle 7): assert the end state (the record is in SQLite, the port is in the
namespace, the request was refused, the incident fired), and validate any diagnostic against a
known-good subject before trusting it. Never weaken a guard to make a test pass.

## 10. CI (`.github/workflows/`)

- `ci.yml` (every PR): lint + types, unit, contract, golden, harness (Docker privileged on
  `ubuntu-latest`), package build + reproducibility check, `gitleaks`, dependency audit.
- `e2e.yml` (nightly and on `e2e` label): full milestone acceptance suites.
- `release.yml` (tags): §3.
- Required checks gate merges to `main`.

## 11. Developer environment

`make dev` on an Ubuntu VM with Docker: VictoriaMetrics + collector + dashboard + a probe in the
netns harness, and the manager under `wrangler dev` with local D1/R2. Python dev dependencies
(`pytest`, `hypothesis`, `ruff`) live in a virtualenv only — never in shipped artifacts.

## 12. Documentation deliverables

`README.md` (overview + quick start), `docs/admin-guide.md` (deploy, add hosts, upgrades, rotation,
incident response), `docs/operator-guide.md` (reading the board, incidents, NOC mode, drills),
`docs/troubleshooting.md`, per-component `README.md`, `CHANGELOG.md`.
