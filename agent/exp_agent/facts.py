"""Host facts (06-agent.md section 3.1): hostname, machine-id, os-release, kernel, arch, CPUs, memory, free
disk under /var/lib, Python, time sync, interfaces (ip -j link/addr/route via argv, speed and driver from
/sys/class/net), default-route interface and `in_use_by` derived from the current component config."""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import socket
from pathlib import Path
from typing import Any

from exp_common import config as exp_config

from .context import Context

log = logging.getLogger(__name__)

_IFACE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,15}\Z")
_MAC_RE = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def read_text(path: Path, limit: int = 65536) -> str | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit).decode("utf-8", "replace")
    except OSError:
        return None


def parse_kv(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k and not k.startswith("#"):
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _ip_json(ctx: Context, what: str) -> list[dict[str, Any]]:
    res = ctx.runner.run(
        ["ip", "-j", what, "show"] if what != "route" else ["ip", "-j", "route", "show"], timeout=10
    )
    if res.rc != 0 or not res.stdout.strip():
        return []
    try:
        doc = json.loads(res.stdout)
    except ValueError:
        return []
    return [d for d in doc if isinstance(d, dict)] if isinstance(doc, list) else []


def probe_usage(ctx: Context) -> tuple[str | None, dict[str, str]]:
    """(mgmt_iface, {iface: port_id}) from the applied probe config; tolerant of absence/garbage."""
    raw = ctx.fs.read_bytes(ctx.paths.config("probe"), 1024 * 1024)
    if raw is None:
        return None, {}
    try:
        cfg = exp_config.parse_json(raw, "probe config")
    except exp_config.ConfigError:
        return None, {}
    if not isinstance(cfg, dict):
        return None, {}
    mgmt = cfg.get("mgmt_iface") if isinstance(cfg.get("mgmt_iface"), str) else None
    ports: dict[str, str] = {}
    for p in cfg.get("ports", []) if isinstance(cfg.get("ports"), list) else []:
        if (
            isinstance(p, dict)
            and isinstance(p.get("iface"), str)
            and isinstance(p.get("id"), str)
            and _SLUG_RE.match(p["id"])
        ):
            ports[p["iface"]] = p["id"]
    return mgmt, ports


def default_route_iface(routes: list[dict[str, Any]]) -> str | None:
    best: tuple[int, str] | None = None
    for r in routes:
        if r.get("dst") == "default" and isinstance(r.get("dev"), str):
            metric = r.get("metric") if isinstance(r.get("metric"), int) else 0
            if best is None or metric < best[0]:
                best = (metric, r["dev"])
    return best[1] if best else None


def in_use_by(iface: str, mgmt: str | None, ports: dict[str, str], default_if: str | None) -> str:
    if iface in ports:
        return f"probe:{ports[iface]}"
    if iface == mgmt or iface == default_if:
        return "mgmt"
    return "none"


def interface_facts(ctx: Context) -> tuple[list[dict[str, Any]], str | None, dict[str, str]]:
    """(interfaces, default_route_iface, roles{iface: in_use_by})"""
    links = _ip_json(ctx, "link")
    addrs = _ip_json(ctx, "addr")
    routes = _ip_json(ctx, "route")
    default_if = default_route_iface(routes)
    mgmt, ports = probe_usage(ctx)
    addr_by: dict[str, list[str]] = {}
    for a in addrs:
        name = a.get("ifname")
        if isinstance(name, str):
            lst = addr_by.setdefault(name, [])
            for ai in a.get("addr_info", []) if isinstance(a.get("addr_info"), list) else []:
                if (
                    isinstance(ai, dict)
                    and isinstance(ai.get("local"), str)
                    and isinstance(ai.get("prefixlen"), int)
                    and ai.get("scope") != "link"
                ):
                    lst.append(f"{ai['local']}/{ai['prefixlen']}"[:64])
    out: list[dict[str, Any]] = []
    roles: dict[str, str] = {}
    sysnet = ctx.paths.sys / "class" / "net"
    for link in links:
        name = link.get("ifname")
        if not isinstance(name, str) or name == "lo" or not _IFACE_RE.match(name):
            continue
        oper = str(link.get("operstate", "")).upper()
        item: dict[str, Any] = {"name": name, "state": {"UP": "up", "DOWN": "down"}.get(oper, "unknown")}
        mac = str(link.get("address", "")).lower()
        if _MAC_RE.match(mac):
            item["mac"] = mac
        sp = read_text(sysnet / name / "speed", 32)
        try:
            speed = int((sp or "").strip())
            item["speed_mbps"] = speed if speed >= 0 else None
        except ValueError:
            item["speed_mbps"] = None
        try:
            item["driver"] = os.path.basename(os.readlink(sysnet / name / "device" / "driver"))[:64]
        except OSError:
            item["driver"] = None
        item["addrs"] = addr_by.get(name, [])[:32]
        item["default_route"] = name == default_if
        item["in_use_by"] = roles[name] = in_use_by(name, mgmt, ports, default_if)
        out.append(item)
    return out[:256], default_if, roles


def _time_facts(ctx: Context) -> dict[str, Any]:
    res = ctx.runner.run(["timedatectl", "show"], timeout=10)
    kv = parse_kv(res.stdout) if res.rc == 0 else {}
    source = "unknown"
    if (ctx.paths.host("/run/systemd/timesync")).exists():
        source = "systemd-timesyncd"
    elif (ctx.paths.host("/run/chrony")).exists():
        source = "chrony"
    return {"synced": kv.get("NTPSynchronized", "no") == "yes", "source": source, "offset_ms": None}


def _disk_free_mb(ctx: Context) -> int:
    p = ctx.paths.host("/var/lib")
    while not p.exists() and p != p.parent:
        p = p.parent
    try:
        st = os.statvfs(p)
    except OSError:
        return 0
    return int(st.f_bavail * st.f_frsize // (1024 * 1024))


def collect_facts(ctx: Context) -> dict[str, Any]:
    osr = parse_kv(read_text(ctx.paths.host("/etc/os-release")) or "")
    mem_kb = 0
    for line in (read_text(ctx.paths.proc / "meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            try:
                mem_kb = int(line.split()[1])
            except (IndexError, ValueError):
                pass
    interfaces, _default_if, _roles = interface_facts(ctx)
    facts: dict[str, Any] = {
        "hostname": socket.gethostname()[:253],
        "machine_id": (read_text(ctx.paths.host("/etc/machine-id"), 64) or "").strip()[:64],
        "os": {"id": osr.get("ID", "")[:32], "version": osr.get("VERSION_ID", "")[:32]},
        "kernel": platform.release()[:128],
        "arch": ctx.arch,
        "cpus": max(1, os.cpu_count() or 1),
        "mem_mb": mem_kb // 1024,
        "disk_free_mb": _disk_free_mb(ctx),
        "python": platform.python_version()[:32],
        "time": _time_facts(ctx),
        "interfaces": interfaces,
    }
    if not facts["machine_id"]:
        del facts["machine_id"]
    return facts
