# packaging — reproducible build, vendoring, signing (WP-7)

`make release VERSION=x.y.z` → `packaging/build.sh --release x.y.z`. Spec: `docs/spec/08-operations.md`
§2–3, `docs/spec/01-contracts.md` §10, `docs/spec/07-security.md` SR-10/SR-11.

| File | Purpose |
|---|---|
| `build.sh` | Orchestrates fetch → assemble → byte-compile → pack → manifest → sign → verify |
| `pack.py` | Stdlib helper: assemble a tarball tree, reproducible tar.gz, canonical manifest, key checks |
| `vendor.lock` | Pinned third-party artifacts (version **and** sha256, plus sources) |
| `vendor.py`, `fetch-vendor.sh` | Fetch pinned artifacts into `packaging/.cache` (gitignored); always verify sha256 |
| `verify-release.sh DIST PUBKEY` | Verify manifest signature and every artifact's size + sha256 (CI and operators) |
| `gen-release-key.sh PRIV` | Generate an Ed25519 keypair outside the repo (0600), prints only the public path |
| `keys/` | `release-pub.pem` (the real public key, supplied by the owner) — see `keys/README.md` |

## Building

```
packaging/build.sh                      # dev build of ./VERSION into dist/, UNSIGNED (clearly labelled)
EXP_RELEASE_KEY=/secure/path/release.pem make release VERSION=0.1.0     # signed release into dist/
packaging/verify-release.sh dist packaging/keys/release-pub.pem
```

Options (`build.sh --help`): `--out DIR` (or `EXP_DIST_DIR`), `--repo DIR`, `--lock FILE`, `--cache DIR`
(or `EXP_VENDOR_CACHE`), `--components probe,collector`, `--pubkey FILE` (or `EXP_RELEASE_PUBKEY`),
`--min-agent-version`, `--notes-url`, `--unsigned`, `--no-fetch`. `SOURCE_DATE_EPOCH` overrides the
HEAD-commit-time default.

Components are those of `agent probe collector dashboard runner speedtest` that have code (`bin/` or `exp_<c>/`);
a directory with only a README is skipped with a note. A component that has code but violates the
convention **fails the build** with the reason (missing `bin/exp-<c>`, not executable, shebang not
`#!/usr/bin/python3`, no `exp_<c>/__init__.py`, no/foreign `systemd/exp-*.service|timer`, missing
`requirements.apt`, apt package outside the agent allowlist, symlinks, byte-compile errors).

### Tarball layout (per convention, `01-contracts.md` §10)

```
exp-<c>-<v>/{VERSION, bin/exp-<c>, lib/exp_<c>/, lib/exp_common/ (+ schemas/ = shared/schemas),
             vendor/, systemd/, requirements.apt, LICENSES/}
```
`tests/` directories, `__pycache__` and `*.pyc` are never packaged. `LICENSES/` contains
`THIRD-PARTY.txt` (name, version, license, sha256 of each bundled third-party file), the vendored
license files, and the root `LICENSE` if the repo has one. Artifacts: `exp-<c>-<v>-noarch.tar.gz`; the
collector is built per arch (`amd64`, `arm64`) because `vendor/victoria-metrics` (upstream file `victoria-metrics-prod`, installed under the name the collector expects) is a native
binary.

### Reproducibility

Entries sorted; uid/gid 0, `root`/`root`; dirs 0755, files 0755 if executable in the source (and `bin/*`,
the VM binary) else 0644; mtime = `SOURCE_DATE_EPOCH`; the gzip header is written by hand (mtime 0, no
name, fixed OS byte) so output does not depend on the Python version's gzip defaults. The compressed
bytes depend on the zlib build, so reproduce on the same OS image (CI compares two builds on the same
runner). The manifest is serialized **once** (compact JSON, fixed key order, trailing newline) and
those exact bytes are signed; Ed25519 signatures are deterministic, so even `.sig` is identical.

### Signing (SR-10)

`openssl pkeyutl -sign -rawin -inkey $EXP_RELEASE_KEY` → base64 → `exp-<v>-manifest.json.sig`, then
`verify-release.sh` against `keys/release-pub.pem` (or `EXP_RELEASE_PUBKEY`) before the build reports
success; a signature that does not verify is deleted and the build fails. The build **refuses to run** if
the key file's realpath is inside the repo (or the source tree) or if it is accessible by group/others
(stricter than "not world-readable"). Key material is never printed. In CI the key is an
environment-protected secret written to `$RUNNER_TEMP` (see `.github/workflows/release.yml`).

## Vendored dependencies (SR-11) and the GitHub/Docker deviation

`vendor.lock` pins, per item, a **version and the sha256 of the file that is used**:

* `dnspython 2.9.2` pure-Python wheel from PyPI (probe) → unpacked into `vendor/`. 2.9.x declares Python ≥ 3.11; it is vendored on 3.10 (Ubuntu 22.04) on purpose to fix GHSA-45c3-73f7-pv4m, guarded by a 3.10 import smoke test — see the note in `vendor.lock`. The caveat is Ubuntu 22.04 only: Debian 12 (and 64-bit Raspberry Pi OS bookworm) ships python3.11 and Ubuntu 24.04 python3.12, both inside dnspython's declared range.
* `VictoriaMetrics v1.106.1` `victoria-metrics-prod` for linux/amd64 and linux/arm64 (collector).
  The canonical `sha256` is the binary inside the **upstream GitHub release archive**
  (`victoria-metrics-linux-<arch>-v1.106.1.tar.gz`; the archive hash is pinned too as `archive_sha256`);
  both values match upstream's published `*_checksums.txt`, which is how "verified against upstream
  checksums" is met.

**Deviation / fallback.** Some build hosts (including the agent sandbox this was authored in) block GitHub
downloads, so each VM item also lists the official Docker image **pinned by digest**
(`victoriametrics/victoria-metrics:v1.106.1@sha256:…`, per-arch manifest digests; arm64 is extracted with
`docker create`/`docker cp` without running it). The image's binary is a *different build* of the same
release, so it has its **own** pinned sha256 on the source and is **non-canonical**: it is cached under its own
hash, `fetch-vendor.sh` warns loudly, and `build.sh` refuses to use it unless `EXP_ALLOW_FALLBACK_VENDOR=1`
(local builds only). `build.sh --release` refuses the fallback outright: it dies if
`EXP_ALLOW_FALLBACK_VENDOR=1` is set and `vendor.py` ignores the opt-in when `EXP_RELEASE_BUILD=1`, so official
releases only ever use the upstream file whose sha256 is pinned in `vendor.lock`.

`fetch-vendor.sh` tries sources in order; an unreachable source falls through, but a **sha256 mismatch aborts
immediately** and nothing is cached. A cached file is re-hashed at every use; a mismatching cache file aborts
the build (it is never silently refetched). Cache layout:
`packaging/.cache/<name>-<version>-<arch>/<sha256>/<file>`. `EXP_VENDOR_SOURCES=url` or `=docker` restricts
sources.

Updating a pin: edit `vendor.lock` (version, URLs, sha256 from the vendor's checksum file or PyPI JSON,
docker digest from `docker buildx imagetools inspect`) in a reviewed PR.

## Verifying a release (operators)

```
packaging/verify-release.sh DIST packaging/keys/release-pub.pem
```
Checks the Ed25519 signature over `exp-<v>-manifest.json` (exact bytes) and every artifact's size and sha256
against the manifest. The manager does the same on import and the agent again on download (SR-10); a
failed check is a refusal, never a warning. By hand: `openssl pkeyutl -verify -rawin -pubin -inkey PUB -sigfile <(base64 -d SIG) -in MANIFEST`.

## CI and the release process

Workflows live in `.github/workflows/`; every action is pinned to a full commit SHA (version in the trailing
comment) and every workflow defaults to `permissions: contents: read`.

| Workflow | Trigger | What |
|---|---|---|
| `ci.yml` | PR, push to main | `lint` (ruff, tsc for manager and manager/ui), `unit` (Python 3.10 and 3.12; `make test`), `unit-manager` (`npm ci`, `npm test`; ui also `npm run build`), `contract` (fixtures, OpenAPI, fakes, golden), `package` (two unsigned builds must be byte-identical; a signed build with a throwaway key generated in the job must verify; stub-tree packaging tests), `package-install` (tarballs from `package` installed into systemd containers), `harness` (`make -C test/harness ci` only if that Makefile exists), `gitleaks` (v8.21.2, image pinned by digest, full history), `audit` (pip-audit of vendored wheels blocks; `npm audit --omit=dev` is a non-blocking report) |
| `release.yml` | tag `vX.Y.Z` | full tests, build + sign in environment `release`, independent verify + container install of the signed tarballs, publish |
| `e2e.yml` | nightly, label `e2e`, manual | `test/e2e` if present |

Required checks gating `main`: `lint`, `unit`, `contract`, `package`, `package-install`, `gitleaks`.

While components land in separate work packages, the CI `package` job builds only the components that already
satisfy the convention (`packaging/ready-components.sh`) and prints a warning for the rest. `release.yml`
has no such leniency: `EXP_PACKAGE_STRICT=1` makes `build.sh` refuse to skip any of the five components (a component with no code aborts the build) and makes the install tests
fail instead of skip when a component cannot be built.

**Cutting a release**

1. Bump `VERSION`, update `CHANGELOG.md`, merge to `main` with green required checks.
2. `git tag vX.Y.Z && git push origin vX.Y.Z` (the tag must equal `v$(cat VERSION)`; the job refuses otherwise).
3. `release.yml` runs the full tests; `build-sign` waits for approval by the required reviewers of the
   `release` environment, then builds amd64 and arm64 (the collector bundles a per-arch VictoriaMetrics), signs,
   and verifies against `packaging/keys/release-pub.pem`.
4. `verify-release` re-verifies from the uploaded artifact and installs the signed tarballs in systemd
   containers; only then does `publish` (the only job with `contents: write`) create the GitHub Release with
   artifacts, manifest and `.sig`.
5. Import the version in the manager and roll it out with a canary (`docs/spec/05-manager.md` section 9).

## Key rotation and compromise (SR-10)

The private key exists only as the `EXP_RELEASE_KEY` secret of the protected `release` environment (required
reviewers, restricted to `v*` tags) and in the owner's offline backup. It is never in the repo, in a log or in an
unprotected job; the build refuses a key inside the checkout or readable by group/others, and CI uses
throwaway keys generated per run.

Rotate (scheduled, or immediately on suspected exposure):

1. `packaging/gen-release-key.sh /secure/new-release.pem` on an offline machine; keep the private file there.
2. Add the new private key as `EXP_RELEASE_KEY` in the `release` environment (replace the old secret).
3. Commit the new `packaging/keys/release-pub.pem` in a reviewed PR (reviewed PR; the repository owner should add a CODEOWNERS rule for `packaging/keys/` since `.github/CODEOWNERS` is outside this package's paths).
4. Release a new version signed with the new key. The manager's trusted public key and each agent's
   `@@RELEASE_PUBKEY_PEM@@` (substituted into `install.sh` at serve time) are updated from the same file; agents
   verify an update with the key they hold, so ship the key change as a version signed by the OLD key whose
   agent carries the new key, then retire the old key.
5. On compromise: revoke the old secret first, rotate as above, and publish a notice. Artifacts signed by the
   compromised key must not be trusted again; remove them from the manager's release list.

## Tests

`.venv/bin/python -m pytest test/package -q`

* `test_package.py` - stub component trees in tmp dirs, a throwaway key and a pre-seeded cache (no network):
  reproducibility, layout, modes, signing/verification and every refusal. `-m internet` additionally fetches
  the real pinned artifacts.
* `test_install.py` (marker `harness`; needs Docker with privileged containers) - for each component tarball
  (from `$EXP_DIST_DIR`, else built `--unsigned` into a tmp dir): unpack to `/opt/exp/<c>/<v>` in an
  ubuntu:24.04 and a debian:12 systemd container (image from `Dockerfile.systemd`, `--build-arg BASE=<image>`;
  `EXP_PACKAGE_OS=debian:12` limits the matrix; CI also runs the debian:12 case on an arm64 runner), render the unit templates by placeholder
  substitution, `systemctl daemon-reload`, then assert `exp-<c> version` prints the version, `selftest`
  passes (with the fixture config, empty credential files and a generated TLS pair that the agent would
  provision), `health --json` is valid `exp.health/1`, and every unit passes `systemd-analyze verify`.
  Negative controls prove the schema check and the unit check can fail. If systemd containers cannot run the
  tests skip with the exact reason; a component that cannot be built is skipped with the build error, or fails
  with `EXP_PACKAGE_STRICT=1`.

## Troubleshooting

* `refusing to run: the release key file is inside the repository` — move the key outside the checkout.
* `SHA-256 MISMATCH … cache file` — the cache entry was modified/corrupted; inspect, then delete that file.
* `no usable source` offline — pre-seed the cache, or use a host with GitHub or Docker Hub access.
* `malformed component …` — fix the component to match the packaging convention; the message names the file.

## M6 additions (`CR-m6-agent-packaging`)

* `speedtest` is a `noarch` component. It imports dnspython (DNS-leg authority), so `vendor.lock` carries the SAME pinned
  wheel for `component: speedtest` as for `probe` (the lock key is name + version + arch + component; one cache entry).
  `pack.py assemble` fails if a component imports `dns` and `vendor/dns/` is absent.
* **Page build hook.** If `speedtest/page/build.py` exists, `assemble` runs it twice (`python3 -I build.py --out DIR`,
  fixed env: `SOURCE_DATE_EPOCH`, `PYTHONHASHSEED=0`, no network assumed, 300 s) and requires both outputs to be
  byte-identical, then overlays DIR onto `lib/exp_speedtest/static/` (so `index.html`, `csp-hashes.json`, fonts under
  `assets/` come from the build; regular files only, at most 64 files / 16 MiB). Without the script, the committed
  `speedtest/exp_speedtest/static/` tree is shipped as it is.
* `ready-components.sh`, `build.sh` (strict mode), `test/package` know both new components.
