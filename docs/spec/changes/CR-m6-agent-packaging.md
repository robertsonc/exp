# CR-m6-agent-packaging — agent units, host setup and packaging for `runner` and `speedtest` (M6 step p2)

**From:** M6 agent/packaging step (p2). **Affects:** WP-6 (agent), WP-7 (packaging), the page build (s2), the harness.
**Decision:** accepted; binding on later M6 steps. Companions: `CR-m6-contracts.md`, `CR-m6-speedtest-server.md`.

## Agent

1. **Types.** `desired.ORDER` is `collector, runner, speedtest, dashboard, probe`; `install.SERVICE_USERS` gains
   `speedtest: (exp-speedtest,)` (`runner: (exp-runner,)` already existed). The agent creates no state directory for the two:
   the units use `StateDirectory=exp/<c>` (systemd creates and chowns it), so the agent's tls/state layout code is not involved.
2. **Capabilities.** `exp-speedtest.service`: `AmbientCapabilities=CapabilityBoundingSet=CAP_NET_BIND_SERVICE` and nothing else
   (80/443/53 on `serve.listen_ip`; the justification is a comment in the unit). `exp-runner.service`: empty capability sets.
   No `CAP_NET_RAW`: ICMP uses unprivileged datagram sockets.
3. **Unprivileged ICMP = one scoped sysctl drop-in.** Needs `net.ipv4.ping_group_range` to include the gid of `exp-speedtest`.
   `agent/exp_agent/pingsys.py`: when the live range already covers the gid (the systemd default `0 2147483647`) nothing is
   written. Otherwise `/etc/sysctl.d/60-exp-speedtest-ping.conf` widens the range minimally (an empty range `1 0` becomes
   exactly the group) with the ORIGINAL range recorded in its header (`# exp-original: lo hi`), applied with `sysctl -w`.
   Removing the speedtest component or decommissioning deletes the file and writes the original value back. Failure is
   non-fatal (agent event; the speedtest falls back to `ping` and reports `degraded`).
   **Path guard exception:** exactly that one path (`/etc/sysctl.d/60-exp-speedtest-ping.conf`) is allowed outside the
   roots; the directory and every other file in it stay refused.
4. **Branding assets** (`desired.components[speedtest].assets[]`, CR-m6-contracts item 6) are implemented in
   `agent/exp_agent/assets.py`: downloaded through the existing artifact route, size <= 256 KiB, sha256 compared with the
   DESIRED STATE's value (a user-uploaded logo is not in the signed release manifest), content sniffed against the declared
   type (PNG/JPEG magic; SVG with script, handlers, foreign objects, entities or non-fragment references is refused),
   installed atomically root `0644` as `/etc/exp/speedtest/assets/logo`; removed when no longer desired. A bad asset is
   skipped with an agent event (the box serves without a logo); it never fails the reconcile.
5. **Health facts.** `facts.url` is validated as `http_url` (plain HTTP by default, D15); `tls_mode` passes through.
6. **Decommission** removes both components like the others (units, `/opt`, `/etc`, `/var/lib`, `/run`, bin links, creds),
   plus the sysctl drop-in and the assets, and restores the original `ping_group_range`.
7. **Test-fake fix (SR-6).** `test/fakes/fake_manager.py referenced_artifacts` now includes `assets[].artifact.id` (the
   Worker already did, `compile/recompile.ts`), so the fake serves logo artifacts the desired state references.

## Packaging

8. `pack.COMPONENTS` gains `speedtest` (noarch); `build.sh` strict-mode loop, `ready-components.sh`, and `test/package` list it.
9. **dnspython for the speedtest**: `vendor.lock` gets a second item (`component: speedtest`) for the SAME wheel and sha256 as
   the probe's. `vendor.load_lock`'s duplicate key is now (name, version, arch, component). `pack.py` fails the build if a
   component's `exp_<c>/*.py` imports `dns` while `vendor/dns/` is absent.
10. **Page build hook (contract for s2).** If `speedtest/page/build.py` exists, packaging runs `python3 -I build.py --out DIR`
    twice and requires identical output; DIR is overlaid onto `lib/exp_speedtest/static/`. The script must write the whole
    static tree it owns (`index.html`, `csp-hashes.json`, fonts under `assets/`), deterministically (honour `SOURCE_DATE_EPOCH`),
    with no network and no symlinks, at most 64 files / 16 MiB. A non-zero exit, nondeterminism or a symlink fails the release.
