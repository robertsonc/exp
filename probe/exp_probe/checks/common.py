"""Helpers shared by the measurement tests: port state, link state, thresholds, error records.

Outcome semantics (02-probe.md 5, 01-contracts.md 3): ``ok | degraded | fail`` are NETWORK verdicts;
``error`` means the probe could not run the test (no lease, no namespace, no raw socket, tool crash)
and always carries a reason. A test never answers `fail` for its own problems.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from exp_common.schema import Measurement

from ..config import Port
from ..lease import has_lease, read_lease
from ..wifi import joining as wifi_joining

log = logging.getLogger(__name__)

DETAIL_STR = 1000


def clip(v: Any, n: int = DETAIL_STR) -> str:
    return "".join(ch for ch in str(v) if ch.isprintable())[:n]


def num(v: float | None, nd: int = 2) -> float | None:
    return None if v is None else round(float(v), nd)


def thresholds(ctx: Any, test: str, key: str, default: float) -> float:
    """`tests.<test>.thresholds.<key>` from the probe config (01-contracts.md 3), else the default."""
    try:
        v = ((ctx.cfg.tests.get(test) or {}).get("thresholds") or {}).get(key)
    except AttributeError:
        v = None
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else default


def test_option(ctx: Any, test: str, key: str, default: Any) -> Any:
    v = (ctx.cfg.tests.get(test) or {}).get(key)
    return default if v is None else v


def error_record(ctx: Any, test: str, reason: str, *, port: Port | None = None, labels: dict[str, str] | None = None,
                 target: str | None = None, detail: dict[str, Any] | None = None) -> Measurement:
    """An `error` measurement: the probe could not run the test."""
    lab = dict(labels or {})
    p = port or ctx.port
    if p is not None:
        lab.setdefault("port", p.id)
    kw: dict[str, Any] = {"labels": lab, "error": clip(reason, 500)}
    if target:
        kw["target"] = target
    if detail:
        kw["detail"] = detail
    return ctx.measure(test, "error", **kw)


def is_ipv4(v: str) -> bool:
    try:
        ipaddress.IPv4Address(v)
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------------------------ port state

@dataclass
class PortInfo:
    bound: bool = False
    ip: str | None = None
    prefix: int | None = None
    gateway: str | None = None
    dns: list[str] = field(default_factory=list)
    server_id: str | None = None
    lease_s: int | None = None
    captive_portal_uri: str | None = None
    source: str = "lease"


def _first_json(r: Any) -> Any:
    try:
        doc = json.loads(r.stdout)
    except (ValueError, TypeError):
        return None
    return doc


def _resolv_servers(path: str = "/etc/resolv.conf") -> list[str]:
    out: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                parts = ln.split()
                if len(parts) >= 2 and parts[0] == "nameserver" and is_ipv4(parts[1]) \
                        and not parts[1].startswith("127.") and parts[1] not in out:
                    out.append(parts[1])
    except OSError:
        pass
    return out[:4]


def port_info(ctx: Any, port: Port) -> PortInfo:
    """Address / gateway / resolvers of a client port. netns mode: the lease holder's state file.
    host mode: the host's own state for the test interface."""
    if ctx.cfg.mode != "host":
        doc = read_lease(ctx.paths, port.id)
        if not has_lease(doc):
            return PortInfo()
        assert doc is not None
        return PortInfo(True, doc.get("ip"), doc.get("prefix"), (doc.get("router") or [None])[0],
                        list(doc.get("dns") or []), doc.get("serverid"), doc.get("lease_s"),
                        doc.get("captive_portal_uri"))
    iface = port.lease_iface
    info = PortInfo(source="host")
    a = _first_json(ctx.runner.run(["ip", "-j", "-4", "addr", "show", "dev", iface, "scope", "global"], 5))
    for ent in a if isinstance(a, list) else []:
        for ai in ent.get("addr_info", []):
            if ai.get("local") and is_ipv4(ai["local"]):
                info.ip, info.prefix = ai["local"], ai.get("prefixlen")
                if ai.get("valid_life_time") not in (None, 4294967295):
                    info.lease_s = ai.get("valid_life_time")
    r = _first_json(ctx.runner.run(["ip", "-j", "-4", "route", "show", "default", "dev", iface], 5))
    for ent in r if isinstance(r, list) else []:
        if ent.get("gateway") and is_ipv4(ent["gateway"]):
            info.gateway = ent["gateway"]
            break
    info.dns = _resolv_servers()
    info.bound = bool(info.ip)
    return info


@dataclass
class LinkState:
    up: bool
    carrier_changes: int | None = None
    mac: str | None = None
    raw_state: str = ""


_CHANGES = re.compile(r"\s*(\d+)\s*\Z")


def link_state(ctx: Any, port: Port) -> LinkState | None:
    """Carrier and carrier_changes of the port's interface, read INSIDE its namespace (`ip netns exec`
    re-mounts /sys; the daemon's own /sys shows the host namespace). None when it cannot be read."""
    iface = port.iface
    r = ctx.runner.run(ctx.ns_argv(["ip", "-j", "link", "show", "dev", iface]), 5)
    doc = _first_json(r) if r.ok else None
    if not isinstance(doc, list) or not doc or not isinstance(doc[0], dict):
        return None
    flags = doc[0].get("flags") or []
    up = "UP" in flags and "NO-CARRIER" not in flags and "LOWER_UP" in flags
    st = LinkState(up, None, doc[0].get("address"), str(doc[0].get("operstate", "")))
    c = ctx.runner.run(ctx.ns_argv(["cat", f"/sys/class/net/{iface}/carrier_changes"]), 5)
    if c.ok and (m := _CHANGES.match(c.stdout)):
        st.carrier_changes = int(m.group(1))
    return st


# ----------------------------------------------------------------------------- choosing a client

def candidate_ports(ctx: Any, roles: tuple[str, ...] = ("client", "wifi")) -> list[Port]:
    """ctx.port first, then the other eligible ports in configuration order (wrapping)."""
    ports = ctx.cfg.ports_with_role(*roles)
    if ctx.port is None or ctx.port not in ports:
        return ports
    i = ports.index(ctx.port)
    return ports[i:] + ports[:i]


def pick_port(ctx: Any, roles: tuple[str, ...] = ("client", "wifi")) -> tuple[Port | None, PortInfo | None, list[str]]:
    """The port a rotating test runs on: ctx.port when it holds a lease; otherwise (heartbeats only,
    never `exp-probe test`) the next port that does. Returns (port, info, why-not list)."""
    why: list[str] = []
    cands = [ctx.port] if ctx.explicit and ctx.port is not None else candidate_ports(ctx, roles)
    for p in cands:
        if p.role == "wifi" and not ctx.explicit and wifi_joining(p.id):
            why.append(f"{p.id} is running a Wi-Fi join test")
            continue
        info = port_info(ctx, p)
        if info.bound:
            return p, info, why
        why.append(f"{p.id} has no lease")
    return None, None, why
