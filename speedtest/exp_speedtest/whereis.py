"""Where is this client? Best-effort zone for the OBSERVED source address (12 section 3.1, CR-m6-spec-resolutions A6/B6).

Order: NAT guard (fails closed) > the runner's cached Mist/DHCP answer > ``zone_labels.subnets`` > the ``?z=`` hint >
``unresolved``. The speedtest evaluates the first two NAT conditions itself (it knows the address and its config); the
runner evaluates the third (a Mist lookup with zero or several client MACs) and publishes ``nat_suspected`` in its answer.
An answer never contains a MAC or username: the box does not learn raw device identity.

``where`` never blocks (a pure in-memory lookup), well inside the 300 ms budget; an address with no cached answer is
queued in ``wanted`` for the runner, which resolves it and PUTs the answer for the next call.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from .config import SpeedtestConfig

CACHE_MAX = 4096
WANTED_MAX = 100
WANTED_TTL_S = 300.0
DEFAULT_CACHE_TTL_S = 60


@dataclasses.dataclass
class Where:
    zone: str = "unresolved"
    zone_name: str | None = None
    source: str = "unresolved"        # qr | subnet | mist | dhcp | unresolved
    nat_suspected: bool = False
    zone_hint_conflict: bool = False
    ap_name: str | None = None
    ssid: str | None = None
    band: str | None = None

    def public(self) -> dict[str, Any]:
        return {"zone": self.zone, "zone_name": self.zone_name, "source": self.source, "nat_suspected": self.nat_suspected}


class ZoneResolver:
    def __init__(self, cfg: SpeedtestConfig, clock: Callable[[], float] = time.time) -> None:
        self.cfg = cfg
        self.clock = clock
        self._cache: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
        self._wanted: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------------------------------- NAT guard
    def nat_suspected(self, ip: str) -> bool:
        """Conditions 1 and 2 of the fail-closed guard. With no ``client_subnets`` configured the first condition has
        nothing to compare against and does not apply (the operator has not said where attendees live)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if addr in self.cfg.translated_addresses:
            return True
        subnets = self.cfg.client_subnets
        return bool(self.cfg.require_real_client_ip and subnets and not any(addr in n for n in subnets))

    def subnet_zone(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, zone in self.cfg.subnet_zones:
            if addr in net:
                return zone
        return None

    def zone_name(self, zone: str) -> str | None:
        return self.cfg.zones.get(zone)

    def valid_hint(self, hint: str | None) -> bool:
        return hint is not None and hint in self.cfg.zones

    # ------------------------------------------------------------------------------------ runner's cache
    def put(self, items: list[dict[str, Any]]) -> int:
        now = self.clock()
        with self._lock:
            for it in items:
                ttl = int(it.get("ttl_s") or DEFAULT_CACHE_TTL_S)
                self._cache[it["ip"]] = (now + ttl, it)
                self._cache.move_to_end(it["ip"])
                self._wanted.pop(it["ip"], None)
            while len(self._cache) > CACHE_MAX:
                self._cache.popitem(last=False)
        return len(items)

    def _cached(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            hit = self._cache.get(ip)
            if hit is None:
                return None
            if hit[0] <= self.clock():
                del self._cache[ip]
                return None
            return hit[1]

    def note_asked(self, ip: str) -> None:
        """Remember an address the page asked about that the cache cannot answer yet (the runner polls this list)."""
        now = self.clock()
        with self._lock:
            if ip in self._cache and self._cache[ip][0] > now:
                return
            self._wanted[ip] = self._wanted.get(ip, now)
            while len(self._wanted) > WANTED_MAX:
                self._wanted.popitem(last=False)

    def wanted(self) -> list[tuple[str, float]]:
        now = self.clock()
        with self._lock:
            for ip in [k for k, since in self._wanted.items() if now - since > WANTED_TTL_S]:
                del self._wanted[ip]
            return list(self._wanted.items())

    # ------------------------------------------------------------------------------------------ resolve
    def resolve(self, ip: str, hint: str | None = None, ask: bool = True) -> Where:
        valid_hint = hint if self.valid_hint(hint) else None
        if self.nat_suspected(ip):
            return Where(nat_suspected=True)             # fail closed: never bind on ambiguity, never trust a hint
        if ask:
            self.note_asked(ip)
        hit = self._cached(ip)
        sub = self.subnet_zone(ip)
        if hit is not None and hit.get("nat_suspected"):
            return Where(nat_suspected=True)
        if hit is not None and hit.get("zone_source") in ("mist", "dhcp") and hit.get("zone") not in (None, "unresolved"):
            z = hit["zone"]
            return Where(z, self.zone_name(z), hit["zone_source"], False, bool(valid_hint and valid_hint != z),
                         hit.get("ap_name"), hit.get("ssid"), hit.get("band"))
        if sub is not None:
            return Where(sub, self.zone_name(sub), "subnet", False, bool(valid_hint and valid_hint != sub))
        if valid_hint is not None:
            return Where(valid_hint, self.zone_name(valid_hint), "qr")
        return Where()
