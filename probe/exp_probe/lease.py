"""DHCP lease holder (02-probe.md section 1): busybox ``udhcpc -f -R`` inside the port's namespace.

`exp-probe lease <port>` (unit exp-probe-lease@<port>.service) builds the argv below and execs it, so
systemd supervises udhcpc directly and SIGTERM makes it send DHCPRELEASE (-R). udhcpc calls the
hook (`hooks/udhcpc-hook` -> `exp-probe udhcpc-hook <event>`), which configures the namespace and
writes ``/run/exp/probe/<port>/lease.json`` atomically.

The DHCP identity (hostname, vendor class, client id) comes from the config and never contains
personal data (SR-20). Ported from reference/exm/lib/exm/lease.py (`udhcpc_argv`, `hook`).
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from exp_common.atomic import atomic_write_json
from exp_common.schema import utcnow

from .config import Paths, Port, ProbeConfig
from .netns import PLACEHOLDER_RESOLV, netns_names, write_inplace
from .runner import ns_exec_argv

log = logging.getLogger(__name__)

HOOK_PATH = Path(__file__).resolve().parent / "hooks" / "udhcpc-hook"
LEASE_SCHEMA = "exp.probe.lease/1"
_HEX = re.compile(r"[0-9a-fA-F]+\Z")


def udhcpc_argv(cfg: ProbeConfig, port: Port, paths: Paths, hook: Path | str = HOOK_PATH) -> list[str]:
    d = cfg.dhcp_params(port)
    argv = ns_exec_argv(port.id, [
        "busybox", "udhcpc",
        "-f",                                   # foreground, supervised by systemd
        "-i", port.lease_iface,
        "-s", str(hook),
        "-p", str(paths.pid_file(port.id)),
        "-R",                                   # DHCPRELEASE on exit: lease hygiene
        "-t", "4", "-T", "4", "-A", "15",       # 4 discovers 4 s apart, then retry after 15 s
        "-x", f"hostname:{d['hostname']}",
        "-V", d["vendor_class"],
        "-O", "mtu", "-O", "114",               # interface MTU and captive-portal URI
    ])
    if d["client_id"] == "hostname":
        # RFC 4361 style: type 0 (string) + hostname. "mac" is busybox's default (type 1 + MAC).
        argv += ["-x", "0x3d:00" + d["hostname"].encode().hex()]
    return argv


def hook_env(config_path: str, port: Port, paths: Paths, entry: str) -> dict[str, str]:
    """Environment the hook needs; exported by `exp-probe lease` before exec (merged over os.environ)."""
    return {"EXP_PROBE_BIN": entry, "EXP_PROBE_CONFIG": str(config_path), "EXP_PROBE_PORT": port.id,
            "EXP_PROBE_RUN_DIR": str(paths.run_dir), "EXP_PROBE_STATE_DIR": str(paths.state_dir)}


def run_lease(cfg: ProbeConfig, port_id: str, runner: Any, paths: Paths, config_path: str, entry: str,
              exec_fn: Callable[[str, list[str], Mapping[str, str]], Any] = os.execvpe) -> int:
    """Prepare run state and exec udhcpc. Returns an exit code only when it cannot start."""
    port = cfg.port(port_id)
    if cfg.mode == "host":
        print("exp-probe: host mode has no lease holder (DHCP is the host's own)", file=sys.stderr)
        return 0
    if port.role not in ("client", "wifi"):
        print(f"exp-probe: port {port_id} has role {port.role}; only client and wifi ports hold a lease",
              file=sys.stderr)
        return 2
    if port.ns not in netns_names(runner):
        print(f"exp-probe: namespace {port.ns} does not exist (is exp-probe-netns.service up?)", file=sys.stderr)
        return 3
    rd = paths.port_run_dir(port.id)
    rd.mkdir(parents=True, exist_ok=True)
    write_lease(paths, port, {"state": "none"})
    argv = udhcpc_argv(cfg, port, paths)
    env = {**os.environ, **hook_env(config_path, port, paths, entry)}
    log.info("exec %s", " ".join(argv))
    exec_fn(argv[0], argv, env)
    return 0          # only reached by a test double


# ----------------------------------------------------------------------------------------- state

def write_lease(paths: Paths, port: Port, doc: dict[str, Any]) -> None:
    body = {"schema": LEASE_SCHEMA, "port": port.id, "iface": port.lease_iface, "ts": utcnow(), **doc}
    paths.port_run_dir(port.id).mkdir(parents=True, exist_ok=True)
    atomic_write_json(paths.lease_file(port.id), body, mode=0o644)


def read_lease(paths: Paths, port_id: str) -> dict[str, Any] | None:
    try:
        with open(paths.lease_file(port_id), encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def has_lease(doc: dict[str, Any] | None) -> bool:
    return bool(doc) and doc.get("state") == "bound" and bool(doc.get("ip"))


# ------------------------------------------------------------------------------------------ hook

def _hexopt_text(value: str | None) -> str | None:
    if not value:
        return None
    if _HEX.match(value) and len(value) % 2 == 0:
        return bytes.fromhex(value).decode("utf-8", "replace")[:512]
    return value[:512]


def _ips(text: str, limit: int = 8) -> list[str]:
    out: list[str] = []
    for tok in text.split():
        try:
            out.append(str(ipaddress.IPv4Address(tok)))
        except ValueError:
            continue            # the lease comes from the network: ignore junk, never trust it blindly
    return out[:limit]


def _clean_text(v: str | None, limit: int = 253) -> str | None:
    if not v:
        return None
    v = "".join(ch for ch in v if ch.isprintable())[:limit]
    return v or None


def hook(cfg: ProbeConfig, event: str, env: Mapping[str, str], runner: Any, paths: Paths) -> int:
    """udhcpc event handler. Always returns 0 (a hook failure must not kill the lease holder)."""
    iface = env.get("interface", "")
    try:
        port = cfg.port_by_iface(iface)
    except Exception as exc:
        print(f"udhcpc-hook: {exc}", file=sys.stderr)
        return 0
    resolv = paths.resolv_path(port.id)

    if event == "deconfig":
        runner.run(["ip", "-4", "addr", "flush", "dev", iface, "scope", "global"], 10)
        runner.run(["ip", "link", "set", "dev", iface, "up"], 10)
        write_inplace(resolv, PLACEHOLDER_RESOLV)
        write_lease(paths, port, {"state": "none"})
        print(f"dhcp_lease {port.id} deconfig", flush=True)
        return 0

    ip = env.get("ip", "")
    try:
        ip = str(ipaddress.IPv4Address(ip)) if ip else ""
    except ValueError:
        ip = ""
    prefix = env.get("mask", "")
    if ip and not prefix.isdigit() and env.get("subnet"):
        try:
            prefix = str(ipaddress.IPv4Network(f"0.0.0.0/{env['subnet']}").prefixlen)
        except ValueError:
            prefix = ""
    if event in ("bound", "renew") and ip and prefix.isdigit() and 1 <= int(prefix) <= 32:
        _apply_bound(cfg, port, event, ip, int(prefix), env, runner, paths, resolv)
        return 0

    if event in ("leasefail", "nak"):
        prev = read_lease(paths, port.id) or {}
        if event == "leasefail" and prev.get("state") == "leasefail":
            # An unplugged port fails every ~31 s; record the transition, not every retry.
            prev["retries_since"] = int(prev.get("retries_since", 0)) + 1
            write_lease(paths, port, {k: v for k, v in prev.items() if k not in ("schema", "port", "iface", "ts")
                                      } | {"first_failed": prev.get("first_failed") or prev.get("ts")})
            print(f"dhcp_lease {port.id} leasefail (retry {prev['retries_since']})", flush=True)
            return 0
        write_lease(paths, port, {"state": "leasefail" if event == "leasefail" else "nak",
                                  "retries_since": 0, "message": _clean_text(env.get("message"), 200)})
        print(f"dhcp_lease {port.id} {event}", flush=True)
    return 0


def _apply_bound(cfg: ProbeConfig, port: Port, event: str, ip: str, prefix: int, env: Mapping[str, str],
                 runner: Any, paths: Paths, resolv: Path) -> None:
    iface = env.get("interface", port.lease_iface)
    routers = _ips(env.get("router", ""))
    dns = _ips(env.get("dns", ""))
    lease_s = env.get("lease", "")
    mtu = env.get("mtu", "")
    cmd = ["ip", "addr", "replace", f"{ip}/{prefix}", "dev", iface]
    if env.get("broadcast"):
        try:
            cmd += ["broadcast", str(ipaddress.IPv4Address(env["broadcast"]))]
        except ValueError:
            pass
    if lease_s.isdigit():
        cmd += ["valid_lft", lease_s, "preferred_lft", lease_s]
    # drop a previous address first so a changed lease does not leave the old one behind
    runner.run(["ip", "-4", "addr", "flush", "dev", iface, "scope", "global"], 10)
    runner.run(cmd, 10)
    if routers:
        runner.run(["ip", "route", "replace", "default", "via", routers[0], "dev", iface], 10)
    else:
        runner.run(["ip", "route", "del", "default"], 10)
    if mtu.isdigit() and 576 <= int(mtu) <= 9216:
        runner.run(["ip", "link", "set", "dev", iface, "mtu", mtu], 10)
    search = _clean_text(env.get("search") or env.get("domain"))
    lines = [f"# exp: from DHCP lease on {iface}, server {_ips(env.get('serverid', ''), 1) or '?'}, {event} {utcnow()}"]
    lines += [f"nameserver {d}" for d in dns]
    if search and re.fullmatch(r"[A-Za-z0-9. _-]+", search):
        lines.append(f"search {search}")
    write_inplace(resolv, "\n".join(lines) + "\n")
    write_lease(paths, port, {
        "state": "bound", "event": event, "ip": ip, "prefix": prefix, "router": routers, "dns": dns,
        "domain": _clean_text(env.get("domain")), "search": _clean_text(env.get("search")),
        "serverid": (_ips(env.get("serverid", ""), 1) or [None])[0],
        "lease_s": int(lease_s) if lease_s.isdigit() else None,
        "mtu": int(mtu) if mtu.isdigit() else None,
        "captive_portal_uri": _clean_text(_hexopt_text(env.get("opt114")), 512),
        "hostname_sent": cfg.dhcp_params(port)["hostname"]})
    print(f"dhcp_lease {port.id} {event} ip={ip}/{prefix} gw={routers[:1]} dns={dns} lease={lease_s}s", flush=True)
