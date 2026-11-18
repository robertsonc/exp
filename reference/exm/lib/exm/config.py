"""Probe configuration (/etc/exm/exm.toml) and constants shared by the probe and the collector.

The collector's own configuration is collector.py."""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import tomllib

from .version import version

AGENT_VER = version()
LEGACY_SECTIONS = ("web", "alerts", "remote")     # moved to the collector in 0.9.0
DEFAULT_CONFIG = "/etc/exm/exm.toml"
EXM_HOME = os.environ.get("EXM_HOME", "/opt/exm")
NS_PREFIX = "exm-"
RUN_DIR = "/run/exm"
ETC_NETNS = "/etc/netns"

# Outcome classes are fixed by the spec. harness_error is our own failure and is
# never counted against the network.
OK, DEGRADED, FAIL, HARNESS, PORTAL = "ok", "degraded", "fail", "harness_error", "portal"


class ConfigError(Exception):
    pass


def load(path: str | None = None) -> dict:
    path = path or os.environ.get("EXM_CONFIG", DEFAULT_CONFIG)
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        cfg = tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    cfg["_path"] = path
    cfg["_ver"] = hashlib.sha256(raw).hexdigest()[:12]

    for key in ("probe_id",):
        if key not in cfg:
            raise ConfigError(f"{path}: missing top-level '{key}'")
    cfg.setdefault("hw_class", "unknown")
    cfg.setdefault("results_dir", "/var/lib/exm/results")
    cfg.setdefault("state_dir", "/var/lib/exm/state")
    cfg.setdefault("retention_days", 7)
    for section in ("schedule", "dhcp", "dns", "speedtest", "apps"):
        cfg.setdefault(section, {})

    clients = cfg.setdefault("client", [])
    seen_ids, seen_ifaces = set(), set()
    for c in clients:
        for key in ("id", "iface"):
            if not c.get(key):
                raise ConfigError(f"{path}: every [[client]] needs '{key}'")
        if c["id"] in seen_ids:
            raise ConfigError(f"{path}: duplicate client id {c['id']}")
        if c["iface"] in seen_ifaces:
            raise ConfigError(f"{path}: interface {c['iface']} used by two clients")
        seen_ids.add(c["id"])
        seen_ifaces.add(c["iface"])
        c.setdefault("vlan", "")
        c.setdefault("zone", "")
        c.setdefault("ipv6", False)
        c.setdefault("expect_subnet", "")
        c.setdefault("role", "client")
        if c["role"] not in ("client", "server"):
            raise ConfigError(f"{path}: client {c['id']}: role must be 'client' or 'server'")
        if c["role"] == "server":
            # A server port is hard-coded: no DHCP, a fixed address Minis can target.
            try:
                iface_addr = ipaddress.IPv4Interface(c.get("address", ""))
            except ValueError as exc:
                raise ConfigError(f"{path}: server {c['id']} needs address = \"a.b.c.d/len\": {exc}") from exc
            if iface_addr.network.prefixlen == 32 or iface_addr.ip in (iface_addr.network.network_address,
                                                                       iface_addr.network.broadcast_address):
                raise ConfigError(f"{path}: server {c['id']}: {iface_addr} is not a usable host address")
            gw = c.get("gateway", "")
            if gw and ipaddress.IPv4Address(gw) not in iface_addr.network:
                raise ConfigError(f"{path}: server {c['id']}: gateway {gw} is outside {iface_addr.network}")
            c.setdefault("dns", [])
    seen_addrs = [c["address"].split("/")[0] for c in clients if c["role"] == "server"]
    if len(seen_addrs) != len(set(seen_addrs)):
        raise ConfigError(f"{path}: two server ports share an address")

    # Before 0.9.0 the probe also served the dashboard, sent alerts and followed remote probes.
    # Those sections now live on the collector; an old config still loads, with a warning.
    cfg["_legacy"] = [k for k in LEGACY_SECTIONS if k in cfg]
    return cfg


def clients(cfg: dict) -> list[dict]:
    """Ports that act as emulated clients (DHCP, tests)."""
    return [c for c in cfg["client"] if c.get("role", "client") == "client"]


def servers(cfg: dict) -> list[dict]:
    """Ports hard-coded as test servers (Marvis Minis targets)."""
    return [c for c in cfg["client"] if c.get("role") == "server"]


def ns_name(client_id: str) -> str:
    return NS_PREFIX + client_id


def client(cfg: dict, client_id: str) -> dict:
    for c in cfg["client"]:
        if c["id"] == client_id:
            return c
    raise ConfigError(f"no client '{client_id}' in {cfg['_path']}")


def client_by_iface(cfg: dict, iface: str) -> dict:
    for c in cfg["client"]:
        if c["iface"] == iface:
            return c
    raise ConfigError(f"no client uses interface '{iface}'")


def state_path(cfg: dict, name: str) -> str:
    os.makedirs(cfg["state_dir"], exist_ok=True)
    return os.path.join(cfg["state_dir"], name)
