"""Identity resolution with the fail-closed NAT guard (12 section 5.1; CR-m6-spec-resolutions A6; 01 section 14.6).

``client_ip`` + time -> device (MAC) -> zone / AP. The test is **never bound to a device on ambiguity**: it stays zone
``unresolved`` with ``nat_suspected`` and a reason when

1. the observed IP is outside every configured attendee subnet while ``require_real_client_ip`` (reason ``outside_subnets``;
   not evaluable when no subnet is configured), or
2. it equals a configured translated/edge address (``translated_address``), or
3. the Mist lookup in the window yields more than one client MAC (``ambiguous``) or none (``no_match``).

Order: guard 1+2 (no lookup at all) -> Mist provider (when one is registered and answers) -> DHCP-syslog IP -> MAC (more than one
MAC in the window = ``ambiguous``) -> subnet -> coarse zone -> the speedtest's own zone (QR hint) -> ``unresolved``.
Mist unavailable/error/not configured is *not* ambiguity: the DHCP and subnet fallbacks apply.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import logging
from collections.abc import Callable
from typing import Any

from exp_common import speedtest as st_helpers

from .config import NetworkCfg, RunnerConfig
from .connectors import CallBudget, ClientCandidate, IdentityProvider, SpeedtestRef, Window
from .ring import Ring

log = logging.getLogger(__name__)


@dataclasses.dataclass
class Identity:
    ip: str
    resolved_by: str = "none"              # mist | dhcp | ec | subnet | qr | none
    zone: str = "unresolved"
    zone_source: str = "unresolved"        # mist | dhcp | subnet | qr | unresolved
    mac: str | None = None
    device_key: str | None = None
    hostname: str | None = None
    username: str | None = None
    manufacture: str | None = None
    os_family: str | None = None
    wired: bool | None = None
    site_id: str | None = None
    ap_mac: str | None = None
    ap_name: str | None = None
    ssid: str | None = None
    band: str | None = None
    switch_mac: str | None = None
    switch_port: str | None = None
    vlan: int | None = None
    candidates: int = 0
    nat_suspected: bool = False
    nat_reason: str | None = None
    source: str = "exp"                    # the evidence source: mist | syslog | exp
    raw_refs: list[str] = dataclasses.field(default_factory=list)
    mist_status: str = "unavailable"       # what the Mist step reported (ok | unavailable | error)

    @property
    def resolved(self) -> bool:
        return self.resolved_by != "none" or self.zone != "unresolved"

    def evidence_status(self) -> str:
        if self.nat_suspected:
            return "partial"
        if self.resolved_by == "mist":
            return "ok"
        if self.resolved_by == "none" and self.zone == "unresolved":
            return "unavailable"
        return "partial"

    def evidence_data(self) -> dict[str, Any]:
        d: dict[str, Any] = {"resolved_by": self.resolved_by, "ip": self.ip, "zone": self.zone, "zone_source": self.zone_source,
                             "candidates": min(self.candidates, 64), "nat_suspected": self.nat_suspected}
        for k in ("mac", "device_key", "hostname", "username", "manufacture", "os_family", "site_id", "ap_mac", "ap_name", "ssid", "band",
                  "switch_mac", "switch_port", "vlan", "nat_reason"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        if self.wired is not None:
            d["wired"] = self.wired
        return d

    def where_item(self, ttl_s: int = 60) -> dict[str, Any]:
        """The ``PUT /local/v1/where`` answer: no MAC, no username, nothing per-person (the speedtest never learns it)."""
        zs = self.zone_source if self.zone_source in ("mist", "dhcp", "subnet", "unresolved") else "unresolved"
        zone = self.zone if zs != "unresolved" else "unresolved"
        return {"ip": self.ip, "zone": zone, "zone_source": zs, "ap_name": self.ap_name, "ssid": self.ssid, "band": self.band,
                "nat_suspected": self.nat_suspected, "ttl_s": ttl_s}


def _addr(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def subnet_zone(net: NetworkCfg, ip: str) -> str | None:
    """Longest-prefix match of the client subnet -> coarse zone."""
    a = _addr(ip)
    if a is None or a.version != 4:
        return None
    best: tuple[int, str] | None = None
    for cidr, zone in net.zone_subnets:
        if a in cidr and (best is None or cidr.prefixlen > best[0]):
            best = (cidr.prefixlen, zone)
    return best[1] if best else None


def nat_guard(net: NetworkCfg, ip: str) -> str | None:
    """Reasons 1 and 2 (no lookups): ``translated_address`` / ``outside_subnets`` / None."""
    a = _addr(ip)
    if ip in net.translated_addresses or (a is not None and str(a) in net.translated_addresses):
        return "translated_address"
    if net.require_real_client_ip and net.client_subnets:
        if a is None or a.version != 4 or not any(a in n for n in net.client_subnets):
            return "outside_subnets"
    return None


def map_zone(cfg: RunnerConfig, cand: ClientCandidate) -> str | None:
    """Mist AP / site -> exp zone via ``sources.mist.zone_map`` (first match wins)."""
    zmap = (cfg.mist or {}).get("zone_map") or []
    ap_mac = (cand.ap_mac or "").lower()
    for z in zmap:
        if z.get("site_id") and cand.site_id and z["site_id"] != cand.site_id:
            continue
        macs = [m.lower() for m in z.get("ap_macs", [])]
        prefix = z.get("ap_name_prefix")
        if macs and ap_mac in macs:
            return z["zone"]
        if prefix and cand.ap_name and cand.ap_name.startswith(prefix):
            return z["zone"]
        if not macs and not prefix and z.get("site_id") and cand.site_id == z["site_id"]:
            return z["zone"]
    return None


class IdentityResolver:
    def __init__(self, cfg: RunnerConfig, ring: Ring, secret: str | Callable[[], str | None] | None,
                 provider: IdentityProvider | None = None) -> None:
        self.cfg = cfg
        self.ring = ring
        self._secret = secret                  # a callable is re-read per resolution (credentials may appear later)
        self.provider = provider

    @property
    def secret(self) -> str | None:
        return self._secret() if callable(self._secret) else self._secret

    def _device_key(self, mac: str | None) -> str | None:
        secret = self.secret
        if not mac or not secret:
            return None
        try:
            return st_helpers.device_key(secret, mac)
        except ValueError:
            log.warning("device_key_secret is malformed; device_key omitted")
            return None

    def _fail_closed(self, ident: Identity, reason: str, candidates: int = 0) -> Identity:
        ident.nat_suspected, ident.nat_reason, ident.candidates = True, reason, candidates
        ident.resolved_by, ident.zone, ident.zone_source = "none", "unresolved", "unresolved"
        for k in ("mac", "device_key", "hostname", "username", "manufacture", "os_family", "wired", "site_id", "ap_mac", "ap_name",
                  "ssid", "band", "switch_mac", "switch_port", "vlan"):
            setattr(ident, k, None)
        return ident

    def resolve(self, test: SpeedtestRef, window: Window, budget: CallBudget | None = None) -> Identity:
        ip, net = test.client_ip, self.cfg.network
        ident = Identity(ip=ip)
        reason = nat_guard(net, ip)
        if reason:
            return self._fail_closed(ident, reason)
        # --- Mist (the registered identity provider)
        if self.provider is not None:
            try:
                limit = int((self.cfg.mist or {}).get("max_calls_per_test", 6))
                look = self.provider.lookup_client(ip, window, budget or CallBudget(limit))
            except Exception as exc:  # noqa: BLE001 - a connector failure is "unavailable", not a crash
                log.warning("identity provider failed: %s", type(exc).__name__)
                ident.mist_status = "error"
            else:
                ident.mist_status = look.status
                if look.status == "ok":
                    if len(look.candidates) > 1:
                        return self._fail_closed(ident, "ambiguous", len(look.candidates))
                    if not look.candidates:
                        return self._fail_closed(ident, "no_match", 0)
                    return self._from_candidate(ident, look.candidates[0], test)
        # --- DHCP-syslog fallback
        events = self.ring.dhcp_events(ip, window.from_ts, window.to_ts)
        macs = list(dict.fromkeys(e["mac"] for e in events if e["event"] == "ack" and e["mac"]))
        chosen: dict[str, Any] | None = None
        if len(macs) > 1:
            return self._fail_closed(ident, "ambiguous", len(macs))
        if macs:
            chosen = [e for e in events if e["mac"] == macs[0]][-1]
        else:
            prev = self.ring.last_dhcp_before(ip, window.from_ts)
            if prev is not None and prev["event"] == "ack" and prev["mac"]:
                chosen = prev
        if chosen is not None and chosen["event"] == "ack" and chosen["mac"]:
            ident.mac = chosen["mac"]
            ident.device_key = self._device_key(ident.mac)
            ident.hostname = chosen["fields"].get("hostname")
            ident.candidates = 1
            ident.resolved_by, ident.source = "dhcp", "syslog"
            ident.raw_refs = [f"syslog:dhcp:{chosen['id']}"]
            z = subnet_zone(net, ip)
            if z:
                ident.zone, ident.zone_source = z, "subnet"
            return ident
        # --- subnet -> coarse zone, then the speedtest's own (QR) zone
        z = subnet_zone(net, ip)
        if z:
            ident.zone, ident.zone_source, ident.resolved_by = z, "subnet", "subnet"
            return ident
        if test.zone_hint and test.zone_source == "qr" and test.zone != "unresolved":
            ident.zone, ident.zone_source, ident.resolved_by = test.zone, "qr", "qr"
        return ident

    def _from_candidate(self, ident: Identity, c: ClientCandidate, test: SpeedtestRef) -> Identity:
        try:
            mac = st_helpers.normalize_mac(c.mac)
        except ValueError:
            return self._fail_closed(ident, "no_match", 1)
        ident.resolved_by, ident.source, ident.candidates = "mist", "mist", 1
        ident.mac, ident.device_key = mac, self._device_key(mac)
        for k in ("hostname", "username", "manufacture", "os_family", "site_id", "ap_mac", "ap_name", "ssid", "band", "switch_mac",
                  "switch_port", "vlan"):
            setattr(ident, k, getattr(c, k))
        ident.wired = bool(c.wired)
        if c.ref:
            ident.raw_refs = [c.ref[:128]]
        zone = map_zone(self.cfg, c)
        if zone:
            ident.zone, ident.zone_source = zone, "mist"
        else:
            z = subnet_zone(self.cfg.network, ident.ip)
            if z:
                ident.zone, ident.zone_source = z, "subnet"
        return ident
