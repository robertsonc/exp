"""Namespaces and host mode (02-probe.md sections 1-2).

netns mode: one namespace ``exp-<port_id>`` per port. `up` runs preflight over ALL ports first; if any
port is refused nothing at all is changed (fail closed). Then, per port: create the namespace, write
the per-namespace resolv.conf placeholder, move the port in, bring it up. `down` stops whatever still
runs in the namespaces, takes the ports down and MOVES EVERY PORT BACK to the host namespace
explicitly -- verifying each is visible on the host -- before it deletes any namespace (deleting a
namespace destroys virtual ports such as veth/VF otherwise; the EXM lesson). A namespace whose port
could not be returned is left in place and reported, never deleted.

Both directions are idempotent. host mode: tests run in the host namespace bound to the test interface
(SO_BINDTODEVICE); `up`/`down` only run preflight and change nothing.

Ported from reference/exm/lib/exm/netns.py (`up`, `down`, `remove_stale`, `write_inplace`, `guard`).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import preflight
from .config import Paths, Port, ProbeConfig
from .runner import NS_PREFIX

log = logging.getLogger(__name__)

PLACEHOLDER_RESOLV = "# exp: no DHCP lease yet; resolvers appear here when one is bound\n"
Sleeper = Callable[[float], None]


class PreflightRefused(Exception):
    """`up` refused: nothing was changed. `.result` holds the per-port reasons."""

    def __init__(self, result: preflight.PreflightResult) -> None:
        self.result = result
        super().__init__("; ".join(result.reasons_text()) or "preflight refused")


class TeardownIncomplete(Exception):
    """`down` could not return every port; the listed namespaces were left in place."""


def write_inplace(path: Path, text: str) -> None:
    """Rewrite a file keeping its inode (``ip netns exec`` bind-mounts the file over /etc/resolv.conf;
    a rename would leave running processes on the old inode). Port of exm netns.write_inplace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, text.encode())
    finally:
        os.close(fd)


def guard(runner: Any, paths: Paths, iface: str) -> str | None:
    """Reason this host interface must not be moved, or None if it is safe (EXM `guard`)."""
    return preflight.guard(runner, paths, iface)


def netns_names(runner: Any) -> set[str]:
    r = runner.run(["ip", "netns", "list"], 10)
    if not r.ok:
        return set()
    return {ln.split()[0] for ln in r.stdout.splitlines() if ln.strip()}


def iface_present(runner: Any, iface: str, ns: str | None = None) -> bool:
    argv = ["ip"] + (["-n", ns] if ns else []) + ["link", "show", "dev", iface]
    return bool(runner.run(argv, 10).ok)


def wait_for_ports(cfg: ProbeConfig, runner: Any, wait_s: float, sleep: Sleeper = time.sleep) -> None:
    """At boot a port may still be getting its udev name: wait (bounded) for missing ports."""
    deadline = wait_s
    waited = 0.0
    names = netns_names(runner)
    while True:
        missing = [p for p in cfg.ports
                   if not iface_present(runner, p.iface)
                   and not (p.ns in names and iface_present(runner, p.iface, p.ns))]
        if not missing or waited >= deadline:
            return
        sleep(1.0)
        waited += 1.0


def up(cfg: ProbeConfig, runner: Any, paths: Paths | None = None, *, wait_s: float = 0.0,
       sleep: Sleeper = time.sleep) -> list[str]:
    """Bring the probe's ports into their namespaces. Raises PreflightRefused (nothing changed).
    Returns human-readable progress lines."""
    paths = paths or Paths()
    if wait_s > 0:
        wait_for_ports(cfg, runner, wait_s, sleep)
    res = preflight.check(cfg, runner, paths)
    if not res.ok:
        raise PreflightRefused(res)
    lines: list[str] = []
    if cfg.mode == "host":
        lines.append(f"host mode: {cfg.ports[0].iface} stays in the host namespace (nothing changed)")
        return lines
    present = netns_names(runner)
    for port in cfg.ports:
        lines.append(_up_port(runner, paths, port, port.ns in present))
    return lines


def _must(runner: Any, argv: list[str], what: str) -> None:
    r = runner.run(argv, 20)
    if not r.ok:
        raise OSError(f"{what} failed: {(r.stderr or 'rc ' + str(r.rc)).strip()[:300]}")


def _up_port(runner: Any, paths: Paths, port: Port, ns_exists: bool) -> str:
    ns, iface = port.ns, port.iface
    if not ns_exists:
        _must(runner, ["ip", "netns", "add", ns], f"creating {ns}")
    resolv = paths.resolv_path(port.id)
    if not resolv.exists():
        write_inplace(resolv, PLACEHOLDER_RESOLV)
    if not iface_present(runner, iface, ns):
        _must(runner, ["ip", "link", "set", "dev", iface, "netns", ns], f"moving {iface} into {ns}")
    _must(runner, ["ip", "-n", ns, "link", "set", "lo", "up"], f"bringing lo up in {ns}")
    r = runner.run(["ip", "netns", "exec", ns, "sysctl", "-qw", f"net.ipv6.conf.{iface}.disable_ipv6=1"], 10)
    if not r.ok:
        log.warning("%s: could not disable IPv6 on %s: %s", port.id, iface, r.stderr.strip()[:200])
    if port.vlan and not iface_present(runner, port.lease_iface, ns):
        _must(runner, ["ip", "-n", ns, "link", "add", "link", iface, "name", port.lease_iface,
                       "type", "vlan", "id", str(port.vlan)], f"creating VLAN {port.vlan} in {ns}")
    _must(runner, ["ip", "-n", ns, "link", "set", "dev", iface, "up"], f"bringing {iface} up in {ns}")
    if port.vlan:
        _must(runner, ["ip", "-n", ns, "link", "set", "dev", port.lease_iface, "up"],
              f"bringing {port.lease_iface} up in {ns}")
    return f"{port.id}: {iface} up in {ns}"


def _kill_ns_pids(runner: Any, ns: str, sleep: Sleeper, kill: Callable[[int, int], None]) -> None:
    """Stop anything still running in the namespace (it would pin it open)."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        r = runner.run(["ip", "netns", "pids", ns], 10)
        pids = [int(p) for p in r.stdout.split() if p.isdigit()] if r.ok else []
        if not pids:
            return
        for pid in pids:
            try:
                kill(pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
        sleep(1.0 if sig == signal.SIGTERM else 0.2)


def down(cfg: ProbeConfig, runner: Any, paths: Paths | None = None, *, sleep: Sleeper = time.sleep,
         kill: Callable[[int, int], None] = os.kill, include_stale: bool = True) -> list[str]:
    """Return every port to the host namespace, THEN delete the namespaces.

    Phase 1 (per port): stop processes, delete the VLAN sub-interface, set down, move back, verify.
    Phase 2: delete only the namespaces whose port is verified back on the host (and stale exp-*
    namespaces, whose every non-lo link is moved back first). Raises TeardownIncomplete listing
    the namespaces that were kept."""
    paths = paths or Paths()
    lines: list[str] = []
    if cfg.mode == "host":
        return ["host mode: nothing to tear down"]
    present = netns_names(runner)
    returned: list[Port] = []
    kept: list[str] = []
    for port in cfg.ports:
        if port.ns not in present:
            _host_admin_down(runner, port, lines)
            returned.append(port)
            continue
        _kill_ns_pids(runner, port.ns, sleep, kill)
        if port.vlan:
            runner.run(["ip", "-n", port.ns, "link", "del", "dev", port.lease_iface], 10)
        if iface_present(runner, port.iface, port.ns):
            runner.run(["ip", "-n", port.ns, "link", "set", "dev", port.iface, "down"], 10)
            # Hand the port back explicitly: a physical NIC would return when the namespace goes, but a
            # virtual one (veth, some hypervisor NICs) would be destroyed with it.
            runner.run(["ip", "-n", port.ns, "link", "set", "dev", port.iface, "netns", "1"], 20)
        if _wait_on_host(runner, port.iface, sleep):
            _host_admin_down(runner, port, lines)
            returned.append(port)
        else:
            kept.append(port.ns)
            lines.append(f"{port.id}: {port.iface} did NOT return to the host; {port.ns} kept")
    for port in returned:
        if port.ns in present:
            runner.run(["ip", "netns", "del", port.ns], 10)
        _remove_resolv_dir(paths, port.id)
    if include_stale:
        for ns in remove_stale(cfg, runner, paths, sleep, kill, present):
            lines.append(f"{ns}: removed (no longer in the config); its port returns to the host")
    if kept:
        raise TeardownIncomplete("ports not returned, namespaces kept: " + ", ".join(kept))
    return lines


def _wait_on_host(runner: Any, iface: str, sleep: Sleeper, tries: int = 20) -> bool:
    for i in range(tries):
        if iface_present(runner, iface):
            return True
        if i < tries - 1:
            sleep(0.25)
    return False


def _host_admin_down(runner: Any, port: Port, lines: list[str]) -> None:
    if iface_present(runner, port.iface):
        runner.run(["ip", "link", "set", "dev", port.iface, "down"], 10)
        lines.append(f"{port.id}: {port.iface} returned to the host, admin down")
    else:
        lines.append(f"{port.id}: {port.iface} not visible on the host after teardown")


def _remove_resolv_dir(paths: Paths, port_id: str) -> None:
    d = paths.resolv_path(port_id).parent
    if d.is_dir() and not d.is_symlink():
        for f in d.iterdir():
            if f.is_file() or f.is_symlink():
                f.unlink()
        try:
            d.rmdir()
        except OSError:
            log.warning("could not remove %s", d)


def remove_stale(cfg: ProbeConfig, runner: Any, paths: Paths, sleep: Sleeper = time.sleep,
                 kill: Callable[[int, int], None] = os.kill, present: set[str] | None = None) -> list[str]:
    """Delete exp-* namespaces whose port is no longer in the config, returning their links first."""
    configured = {p.ns for p in cfg.ports}
    names = netns_names(runner) if present is None else present
    gone: list[str] = []
    for ns in sorted(n for n in names if n.startswith(NS_PREFIX) and n not in configured):
        _kill_ns_pids(runner, ns, sleep, kill)
        r = runner.run(["ip", "-n", ns, "-j", "link", "show"], 10)
        try:
            links = json.loads(r.stdout) if r.ok and r.stdout.strip() else []
        except json.JSONDecodeError:
            links = []
        stuck = False
        for lk in links:
            name = lk.get("ifname") if isinstance(lk, dict) else None
            if not name or name == "lo":
                continue
            runner.run(["ip", "-n", ns, "link", "set", "dev", name, "netns", "1"], 20)
            if not _wait_on_host(runner, name, sleep, tries=4):
                stuck = True
        if stuck:
            log.error("%s: a port did not return to the host; namespace kept", ns)
            continue
        runner.run(["ip", "netns", "del", ns], 10)
        d = paths.etc_netns / ns
        if d.is_dir() and not d.is_symlink():
            for f in d.iterdir():
                f.unlink()
            d.rmdir()
        gone.append(ns)
    return gone
