"""Probe configuration (exp.probe.config/1) and filesystem locations.

`load_probe_config` validates with `exp_common.config` and then applies the cross-field rules the
JSON Schema cannot express (unique port ids/interfaces, no port on `mgmt_iface`, host mode rules).
The probe refuses to start on any problem and says why (01-contracts.md section 9).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from exp_common import config as exp_config
from exp_common.config import ConfigError

from .runner import ns_name

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/exp/probe/config.json"
DEFAULT_STATE_DIR = "/var/lib/exp/probe"
DEFAULT_RUN_DIR = "/run/exp/probe"
SCHEMA_NAME = "probe.config"

DEFAULT_DNS_NAMES = ["google.com", "apple.com", "microsoft.com", "cloudflare.com"]
DEFAULT_TRACE = {"target": "8.8.8.8", "pace_ms": 20, "max_hops": 30, "timeout_s": 2.0, "control_path": True}
DEFAULT_VENDOR_CLASS = "exp-probe"
_HOSTNAME_BAD = re.compile(r"[^A-Za-z0-9-]")


@dataclass(frozen=True)
class Paths:
    """Every filesystem location the probe touches; tests point them at tmp dirs."""
    state_dir: Path = Path(DEFAULT_STATE_DIR)
    run_dir: Path = Path(DEFAULT_RUN_DIR)
    etc_netns: Path = Path("/etc/netns")
    sys_class_net: Path = Path("/sys/class/net")
    proc: Path = Path("/proc")

    @property
    def spool_db(self) -> Path:
        return self.state_dir / "spool.db"

    @property
    def rotation_file(self) -> Path:
        return self.state_dir / "rotation.json"

    @property
    def status_file(self) -> Path:
        return self.run_dir / "status.json"

    def port_run_dir(self, port_id: str) -> Path:
        return self.run_dir / port_id

    def lease_file(self, port_id: str) -> Path:
        return self.port_run_dir(port_id) / "lease.json"

    def pid_file(self, port_id: str) -> Path:
        return self.port_run_dir(port_id) / "udhcpc.pid"

    def resolv_path(self, port_id: str) -> Path:
        return self.etc_netns / ns_name(port_id) / "resolv.conf"


@dataclass(frozen=True)
class Port:
    id: str
    iface: str
    role: str                      # client | target | wifi
    vlan: int | None = None
    dhcp: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ns(self) -> str:
        return ns_name(self.id)

    @property
    def lease_iface(self) -> str:
        """Interface carrying the DHCP lease inside the namespace (the VLAN sub-interface if any)."""
        return f"vlan{self.vlan}" if self.vlan else self.iface


@dataclass(frozen=True)
class Collector:
    url: str
    fingerprint: str
    fallback: tuple[str, ...] = ()

    @property
    def urls(self) -> list[str]:
        return [self.url, *self.fallback]


class ProbeConfig:
    """Validated config with defaults applied. `raw` is the validated document."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.raw = raw
        self.probe_id: str = raw["probe_id"]
        self.site: str = raw["site"]
        self.mode: str = raw["mode"]
        self.mgmt_iface: str = raw["mgmt_iface"]
        # `allow_shared` is not in the frozen schema (unknown fields are ignored by readers); the probe
        # honours it at the top level in host mode only. See docs/spec/changes/CR-wp1-allow-shared.md.
        self.allow_shared: bool = bool(raw.get("allow_shared")) and self.mode == "host"
        self.ports: list[Port] = [
            Port(id=p["id"], iface=p["iface"], role=p["role"], vlan=p.get("vlan"),
                 dhcp=dict(p.get("dhcp") or {}), raw=p) for p in raw["ports"]]
        c = raw.get("collector")
        self.collector: Collector | None = None if not c else Collector(
            c["url"].rstrip("/"), c["tls_fingerprint_sha256"],
            tuple(u.rstrip("/") for u in c.get("fallback") or ()))
        hb = dict(raw.get("heartbeat") or {})
        self.heartbeat: dict[str, Any] = {
            "interval_s": int(hb.get("interval_s", 10)),
            "gateway": bool(hb.get("gateway", True)),
            "dhcp": bool(hb.get("dhcp", True)),
            "dns": bool(hb.get("dns", True)),
            "trace": {**DEFAULT_TRACE, **(hb.get("trace") or {})},
            "ping": list(hb.get("ping") or []),
            "dns_names": list(hb.get("dns_names") or DEFAULT_DNS_NAMES),
            "alternate_resolver": hb.get("alternate_resolver"),
        }
        self.tests: dict[str, Any] = {k: v for k, v in (raw.get("tests") or {}).items() if v}
        sp = raw.get("spool") or {}
        self.spool_max_mb: int = int(sp.get("max_mb", 500))
        self.spool_max_days: int = int(sp.get("max_days", 7))
        self.labels: dict[str, str] = dict(raw.get("labels") or {})

    # ---- selectors
    def port(self, port_id: str) -> Port:
        for p in self.ports:
            if p.id == port_id:
                return p
        raise ConfigError(f"unknown port {port_id!r} (configured: {', '.join(p.id for p in self.ports)})")

    def ports_with_role(self, *roles: str) -> list[Port]:
        return [p for p in self.ports if p.role in roles]

    def port_by_iface(self, iface: str) -> Port:
        for p in self.ports:
            if iface in (p.iface, p.lease_iface):
                return p
        raise ConfigError(f"no configured port uses interface {iface!r}")

    @property
    def control_path(self) -> bool:
        """Traceroute from the management interface; disabled when the test NIC is shared with mgmt."""
        return bool(self.heartbeat["trace"].get("control_path") and not self.allow_shared)

    def dhcp_params(self, port: Port) -> dict[str, str]:
        """DHCP identity sent by the port: no personal data (SR-20) -- derived from probe/port ids."""
        d = port.dhcp
        hostname = d.get("hostname") or _HOSTNAME_BAD.sub("-", f"exp-{self.probe_id}-{port.id}")
        hostname = hostname[:63].strip("-") or "exp-probe"
        return {"hostname": hostname, "vendor_class": d.get("vendor_class") or DEFAULT_VENDOR_CLASS,
                "client_id": d.get("client_id") or "mac"}


def check_cross_fields(doc: dict[str, Any]) -> list[str]:
    """Rules beyond the JSON Schema; returns human-readable problems."""
    problems: list[str] = []
    ports = doc.get("ports") or []
    ids = [p.get("id") for p in ports]
    ifaces = [p.get("iface") for p in ports]
    for i in sorted({x for x in ids if ids.count(x) > 1}):
        problems.append(f"ports: duplicate port id {i!r}")
    for i in sorted({x for x in ifaces if ifaces.count(x) > 1}):
        problems.append(f"ports: interface {i!r} is used by more than one port")
    mode = doc.get("mode")
    shared = bool(doc.get("allow_shared")) and mode == "host"
    for p in ports:
        if p.get("iface") == doc.get("mgmt_iface") and not shared:
            problems.append(f"ports[{p.get('id')}]: iface {p.get('iface')!r} is the management interface "
                            "(mgmt_iface is never touched)")
    if mode == "host":
        if len(ports) != 1:
            problems.append("mode host supports exactly one port")
        for p in ports:
            if p.get("role") != "client":
                problems.append(f"ports[{p.get('id')}]: host mode supports role client only")
    return problems


def parse_config(doc: Any) -> ProbeConfig:
    """Validate an already-parsed document."""
    errs = exp_config.iter_errors(doc, SCHEMA_NAME)
    if errs:
        raise ConfigError("invalid probe config", errs)
    problems = check_cross_fields(doc)
    if problems:
        raise ConfigError("invalid probe config: " + "; ".join(problems))
    return ProbeConfig(doc)


def load_probe_config(path: str | Path = DEFAULT_CONFIG_PATH) -> ProbeConfig:
    """Load + validate. Raises ConfigError (callers must refuse to start)."""
    doc = exp_config.load_json(path)
    try:
        return parse_config(doc)
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc.summary}", exc.errors) from exc
