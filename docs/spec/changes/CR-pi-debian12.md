# CR-pi-debian12 — Debian 12 and 64-bit Raspberry Pi OS (Raspberry Pi 4/5) as supported host OSes

**What changed.** `agent/install/install.sh` preflight accepts `ID=debian VERSION_ID=12` in addition to Ubuntu
22.04 and 24.04. Both refusal messages now name the supported set: "Ubuntu 22.04/24.04 or Debian 12 (incl.
Raspberry Pi OS 64-bit)". The architecture gate (amd64/arm64), the systemd-as-PID-1 check and the python3 >= 3.10
check are unchanged. Nothing else in the installer or the agent was Ubuntu-specific: they use `/etc/os-release`
only to report facts, and they rely on `apt-get`/`dpkg-query`, `useradd`, `/usr/sbin/nologin`,
`/etc/ssl/certs/ca-certificates.crt`, `update-ca-certificates` and `/etc/sysctl.d`, which Debian 12 has at the
same paths. They do not use `lsb_release`. The manager does not gate on the OS.

**Why.** Probes are deployed on Raspberry Pi 4/5 boards. 64-bit Raspberry Pi OS (bookworm) is Debian 12 with the
Raspberry Pi kernel and firmware. Its `/etc/os-release` reports `ID=debian`, `VERSION_ID="12"`, it runs on aarch64,
and it ships python3.11.

**Spec text updated.** `SPEC.md` D7 and §8 Platforms; `06-agent.md` §1 step 1 (preflight) and §9 item 1
(acceptance); `08-operations.md` §1; `agent/README.md`; `packaging/README.md` (the dnspython 3.10 caveat applies
to Ubuntu 22.04 only); `docs/admin-guide.md` (manual install); and the Add-host page text in the admin UI.

**What is tested, and where.**

| Test | OS | Arch | Where |
|---|---|---|---|
| `agent/tests/test_agent_install_sh.py::test_preflight_os_gate_accepts_exactly_the_supported_set` (the preflight OS gate run against fake os-release files: Ubuntu 22.04/24.04 and Debian 12 accepted; Ubuntu 20.04, Debian 11, Debian 13, raspbian 12 and an empty file refused) | n/a | any | `make test-agent`, CI `unit` |
| `agent/tests/container/` (`make -C agent container-test`): `install.sh` enrols and starts the agent, repair, re-enrol, self-update, rollback, decommission | Ubuntu 22.04, 24.04, **Debian 12** (default matrix `24.04,22.04,debian12`) | amd64 | locally (Docker); not in CI |
| `test_container_refusals.py::test_refuses_an_unsupported_os` | fake Ubuntu 20.04, Debian 11, raspbian 12 | amd64 | locally |
| `test/package/test_install.py`: every release tarball unpacked into a systemd container; `version`, `selftest`, `health --json`, `systemd-analyze verify`; runner and speedtest started under real systemd | ubuntu:24.04, **debian:12** | amd64 | locally and CI `package-install` |
| the same, `EXP_PACKAGE_OS=debian:12`: the noarch tarballs and the arm64 collector, on a real arm64 runner; the agent and probe cases must pass | debian:12 | **arm64** | CI `package-install-arm64` (`ubuntu-24.04-arm`) |

The Debian images use the `debian:12` tag, just as the Ubuntu images use the `ubuntu:24.04` tag. Neither is pinned
by digest.

**Package check.** Every package named in a component's `requirements.apt` exists in bookworm `main`, and so does
the rest of the agent allowlist. Checked with `apt-cache policy` in `debian:12` in Nov 2026:

| Package | Candidate | Package | Candidate |
|---|---|---|---|
| busybox | 1:1.35.0-4+deb12u1+b1 | busybox-static | 1:1.35.0-4+deb12u1+b1 |
| iproute2 | 6.1.0-3 | iputils-ping | 3:20221126-1+deb12u1 |
| curl | 7.88.1-10+deb12u15 | openssl | 3.0.22-1~deb12u2 |
| iperf3 | 3.12-1+deb12u2 | ca-certificates | 20250419~deb12u2 |
| ethtool | 1:6.1-1 | iw | 5.19-1 |
| wpasupplicant | 2:2.10-12+deb12u3 | tcpdump | 4.99.3-1 |

Differences from Ubuntu, none of which needs code:

* The `debian:12` container image has no `curl`, `openssl` or `ca-certificates`. The preflight already installs
  them when they are missing. A full Raspberry Pi OS image has them.
* Debian's `busybox` has the `udhcpc` applet, and the probe passes its own hook (`-s`). Debian ships no default
  udhcpc script, and the probe does not need one.
* systemd 252 on Debian 12. Ubuntu 22.04 has 249 and Ubuntu 24.04 has 255. Every unit passes
  `systemd-analyze verify` on 252.
* python3.11 on Debian 12, so the vendored dnspython 2.9.x is within its declared `requires_python`.

**Not supported.** These hosts are refused:

* 32-bit Raspberry Pi OS (`ID=raspbian`, armv7l). Both the OS gate and the arch gate refuse it.
* Raspberry Pi OS Lite 32-bit, for the same reason. The 64-bit Lite image is Debian 12 arm64 and is supported.
* Debian 11 (bullseye) and older.
* Debian 13 (trixie). It is not yet tested, so the OS gate refuses it.

**Not verified here (no hardware).**

* A physical Raspberry Pi 4/5 booting the Raspberry Pi kernel. The arm64 CI job runs debian:12 userland on a
  generic arm64 kernel, so Raspberry Pi kernel specifics are covered only by reasoning:
  * The Pi 5's 16K-page `kernel_2712`.
  * Whether the cgroup memory controller is enabled. Without it, `Memory*=` limits in units are ignored, which
    is not fatal.
  * NetworkManager owning the uplink.
* Clock at boot. A Pi has no battery-backed RTC by default, so the clock is wrong until `systemd-timesyncd`
  syncs. Preflight only warns about an unsynchronised clock, but TLS to the manager and token expiry fail until
  the clock is right. Run the installer after NTP has synced.

**Compatibility.** Additive. No schema, contract or unit change.
