"""Preflight (02-probe.md section 3): decide, read-only, whether each test port may be taken over.

Fails closed: if the state of the host cannot be read, nothing is approved. Nothing here ever
modifies a link -- it only runs ``ip ... show`` queries (so it also works unprivileged, except for
looking inside a namespace). A port is REFUSED when it

* is the management interface or holds the default route (v4 or v6);
* carries a global address in the host namespace;
* is enslaved to a bond/bridge/team, is such a device, or has VLAN/macvlan children on the host;
* does not exist (unless it is already inside its ``exp-<port>`` namespace -- the upgrade case);
* is a Wi-Fi interface assigned a non-``wifi`` role.

Guard logic ported from reference/exm/lib/exm/netns.py:guard (extended with the checks above).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .config import Paths, Port, ProbeConfig
from .runner import ns_name

log = logging.getLogger(__name__)

NOT_ALLOWED_KINDS = frozenset({"bond", "bridge", "team", "vlan", "macvlan", "macvtap", "ipvlan", "ipvtap",
                               "openvswitch", "vrf"})
CHILD_KINDS = frozenset({"vlan", "macvlan", "macvtap", "ipvlan", "ipvtap"})
NO_CARRIER_HINT = ("no carrier on any test port at once: check the NIC (bypass or disconnect-mode "
                   "cards, driver, firmware), not the cables")

OK, REFUSED, IN_NAMESPACE = "ok", "refused", "in_namespace"


@dataclass
class PortCheck:
    port_id: str
    iface: str
    verdict: str                                   # ok | refused | in_namespace
    reasons: list[str] = field(default_factory=list)
    carrier: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"port": self.port_id, "iface": self.iface, "verdict": self.verdict,
                "reasons": list(self.reasons), "carrier": self.carrier}


@dataclass
class PreflightResult:
    checks: list[PortCheck] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)    # could not evaluate -> nothing approved

    @property
    def ok(self) -> bool:
        return not self.errors and all(c.verdict != REFUSED for c in self.checks)

    @property
    def refused(self) -> list[PortCheck]:
        return [c for c in self.checks if c.verdict == REFUSED]

    def exit_code(self) -> int:
        """0 all ports approved; 1 at least one port refused; 2 the host state could not be read."""
        if self.errors:
            return 2
        return 0 if self.ok else 1

    def reasons_text(self) -> list[str]:
        lines = [f"preflight error: {e}" for e in self.errors]
        for c in self.checks:
            for r in c.reasons:
                lines.append(f"{c.verdict.upper()} {c.port_id} ({c.iface}): {r}")
        lines += [f"hint: {h}" for h in self.hints]
        return lines

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "exit_code": self.exit_code(), "ports": [c.to_dict() for c in self.checks],
                "hints": self.hints, "errors": self.errors}


class HostView:
    """Snapshot of the host namespace taken with read-only `ip` queries (via the injected runner)."""

    def __init__(self, runner: Any, paths: Paths) -> None:
        self.runner = runner
        self.paths = paths
        self.errors: list[str] = []
        self.links = self._json(["ip", "-j", "-d", "link", "show"], "link list")
        self.addrs = self._json(["ip", "-j", "addr", "show"], "address list")
        self.default_devs = self._default_route_devs()
        self.netns = self._netns_list()

    def _json(self, argv: list[str], what: str, *, required: bool = True) -> list[dict[str, Any]]:
        r = self.runner.run(argv, 10)
        if not r.ok:
            if required:
                self.errors.append(f"cannot read the {what}: {(r.stderr or 'rc ' + str(r.rc)).strip()[:200]}")
            return []
        try:
            doc = json.loads(r.stdout) if r.stdout.strip() else []
        except json.JSONDecodeError:
            self.errors.append(f"cannot parse `{' '.join(argv)}` output")
            return []
        return [x for x in doc if isinstance(x, dict)] if isinstance(doc, list) else []

    def _default_route_devs(self) -> set[str]:
        devs: set[str] = set()
        for argv in (["ip", "-j", "route", "show", "default"], ["ip", "-6", "-j", "route", "show", "default"]):
            for r in self._json(argv, "default route", required=argv[1] != "-6"):
                if r.get("dev"):
                    devs.add(r["dev"])
                for nh in r.get("nexthops") or []:
                    if isinstance(nh, dict) and nh.get("dev"):
                        devs.add(nh["dev"])
        return devs

    def _netns_list(self) -> set[str]:
        r = self.runner.run(["ip", "netns", "list"], 10)
        if not r.ok:
            return set()
        return {ln.split()[0] for ln in r.stdout.splitlines() if ln.strip()}

    def link(self, iface: str) -> dict[str, Any] | None:
        for lk in self.links:
            if lk.get("ifname") == iface:
                return lk
        return None

    def global_addrs(self, iface: str) -> list[str]:
        out = []
        for e in self.addrs:
            if e.get("ifname") != iface:
                continue
            for a in e.get("addr_info") or []:
                if a.get("scope") in ("global", "site"):
                    out.append(f"{a.get('local')}/{a.get('prefixlen')}")
        return out

    def children(self, iface: str) -> list[str]:
        return [lk["ifname"] for lk in self.links
                if lk.get("link") == iface and lk.get("ifname") != iface
                and (lk.get("linkinfo") or {}).get("info_kind") in CHILD_KINDS]

    def is_wifi(self, iface: str) -> bool:
        base = self.paths.sys_class_net / iface
        return (base / "wireless").is_dir() or (base / "phy80211").exists()

    def in_namespace(self, port: Port) -> dict[str, Any] | None:
        """The port's link if it is already inside its own exp-* namespace, else None."""
        if port.ns not in self.netns:
            return None
        r = self.runner.run(["ip", "-n", port.ns, "-j", "link", "show", "dev", port.iface], 10)
        if not r.ok:
            return None
        try:
            doc = json.loads(r.stdout)
        except json.JSONDecodeError:
            return None
        return doc[0] if isinstance(doc, list) and doc and isinstance(doc[0], dict) else None


def _carrier(link: dict[str, Any] | None) -> bool | None:
    if not link:
        return None
    flags = link.get("flags") or []
    if "NO-CARRIER" in flags:
        return False
    if "LOWER_UP" in flags:
        return True
    return None       # administratively down: carrier unknown


def host_reasons(view: HostView, iface: str) -> list[str]:
    """Why `iface` (visible in the host namespace) must not be moved; [] when it is safe."""
    reasons: list[str] = []
    link = view.link(iface)
    if link is None:
        return [f"{iface} does not exist"]
    info = link.get("linkinfo") or {}
    if link.get("master"):
        reasons.append(f"enslaved to {link['master']} ({info.get('info_slave_kind') or 'master device'})")
    kind = info.get("info_kind")
    if kind in NOT_ALLOWED_KINDS:
        reasons.append(f"is a {kind} device")
    if view.children(iface):
        reasons.append(f"has {'/'.join(view.children(iface))} stacked on it in the host namespace")
    addrs = view.global_addrs(iface)
    if addrs:
        reasons.append(f"carries address {', '.join(addrs)} in the host namespace")
    if iface in view.default_devs:
        reasons.append("holds the host's default route")
    return reasons


def guard(runner: Any, paths: Paths, iface: str) -> str | None:
    """Reason this host interface must not be moved, or None if it is safe (EXM `guard`)."""
    view = HostView(runner, paths)
    if view.errors:
        return "host state unreadable: " + "; ".join(view.errors)
    r = host_reasons(view, iface)
    return "; ".join(r) if r else None


def check(cfg: ProbeConfig, runner: Any, paths: Paths | None = None) -> PreflightResult:
    """Evaluate every configured port. Read-only; never raises for host-state problems (fails closed)."""
    paths = paths or Paths()
    res = PreflightResult()
    view = HostView(runner, paths)
    res.errors.extend(view.errors)
    if res.errors:
        return res            # fail closed: nothing can be approved on an unreadable host
    for port in cfg.ports:
        res.checks.append(_check_port(cfg, view, port))
    if res.checks and all(c.carrier is False for c in res.checks):
        res.hints.append(NO_CARRIER_HINT)
    return res


def _check_port(cfg: ProbeConfig, view: HostView, port: Port) -> PortCheck:
    pc = PortCheck(port.id, port.iface, OK)
    in_ns = view.in_namespace(port)
    if in_ns is not None:                       # already ours (upgrade/restart case)
        pc.verdict = IN_NAMESPACE
        pc.carrier = _carrier(in_ns)
        return pc
    link = view.link(port.iface)
    pc.carrier = _carrier(link)
    reasons: list[str] = []
    if port.iface == cfg.mgmt_iface:
        if not cfg.allow_shared:
            reasons.append("is the management interface (mgmt_iface is never touched)")
    elif link is None:
        reasons.append(f"{port.iface} does not exist on the host and is not inside {ns_name(port.id)}")
    if link is not None:
        reasons += [r for r in host_reasons(view, port.iface)
                    if not (cfg.allow_shared and port.iface == cfg.mgmt_iface
                            and (r == "holds the host's default route" or r.startswith("carries address")))]
        if view.is_wifi(port.iface) and port.role != "wifi":
            reasons.append(f"is a Wi-Fi interface but is assigned role {port.role!r} (use role wifi)")
    if reasons:
        pc.verdict = REFUSED
        pc.reasons = reasons
    return pc
