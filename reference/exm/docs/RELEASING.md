# Releasing

The version lives in one place: `VERSION`. Probes and the collector report it (`exm version`, `exm-collector version`, every result's `agent_ver`).

1. Update `VERSION` and `CHANGELOG.md`; commit.
2. Run the tests: `test/unit.sh` (offline, about a minute) and, before a release, `test/harness.sh`, `test/package.sh` and `test/upgrade.sh` (Docker with privileged containers; ~25 minutes together). `test/upgrade.sh <dir with the 0.9.0 tarballs>` checks the in-place upgrade from 0.9.0 (UXM); a later release whose upgrade needs more than re-running the installers puts that in the installers and extends this test.
3. Tag and push: `git tag -a v0.9.1 -m "exm 0.9.1" && git push origin main v0.9.1`.
4. GitHub Actions (`.github/workflows/release.yml`) runs the unit tests, builds the tarballs with `scripts/build-release.sh v0.9.1` (it refuses a tag that doesn't match `VERSION`), and publishes a GitHub release with the three tarballs and `SHA256SUMS`.

To build by hand: `scripts/build-release.sh` writes `dist/`. Tarballs are reproducible for a commit (sorted, root-owned, the commit's timestamp). The probe tarball carries supercronic, downloaded once and checked against the sha256 pinned in `packaging/probe/install.sh`, so probes install without internet access.

Install on a host: `curl -LO .../exm-probe-<v>.tar.gz && sha256sum -c --ignore-missing SHA256SUMS && tar xzf ... && sudo ./install.sh`.

Versioning: semantic. 0.x while the event deployment settles; a change to the result schema or the stream protocol bumps the minor version, and the collector should be upgraded before (or with) its probes.
