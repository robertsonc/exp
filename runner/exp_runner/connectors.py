"""Connector interface (r1) and the runner's own syslog connector.

A *connector* turns a test + window + resolved identity into one or more evidence results of the kinds it declares.
Mist, EdgeConnect and the probe baseline plug in at r2 by subclassing :class:`Connector` (and, for Mist, implementing
:class:`IdentityProvider` for the identity step); the pipeline needs nothing else. A connector must bound its own network
calls (timeouts); the pipeline additionally enforces a per-connector deadline and records ``error`` when it is exceeded.
"""
from __future__ import annotations

import abc
import dataclasses
import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .config import RunnerConfig
from .ring import Ring

if TYPE_CHECKING:  # pragma: no cover
    from .identity import Identity

log = logging.getLogger(__name__)

SECURITY_MAX_EVENTS = 200
DNS_MAX_QUERIES = 200
DNS_FAIL_RCODES = frozenset({"SERVFAIL", "REFUSED", "TIMEOUT", "FORMERR", "NOTIMP"})
DNS_SLOW_MS = 500.0
FMT_MAP = {"rfc5424": "rfc5424", "cef": "cef", "leef": "leef", "kv": "kv", "raw": "raw", "dns": "raw", "dhcp": "raw"}


@dataclasses.dataclass(frozen=True)
class Window:
    from_ts: float
    to_ts: float
    from_iso: str
    to_iso: str

    def as_dict(self) -> dict[str, str]:
        return {"from": self.from_iso, "to": self.to_iso}


@dataclasses.dataclass(frozen=True)
class SpeedtestRef:
    id: str
    site: str
    started: float
    ended: float
    client_ip: str
    window: Window
    zone_hint: str | None = None
    zone: str = "unresolved"
    zone_source: str = "unresolved"


class CallBudget:
    """At most ``limit`` upstream calls per test per source (Mist <= 6)."""

    def __init__(self, limit: int) -> None:
        self.limit = int(limit)
        self.used = 0
        self._lock = threading.Lock()

    def take(self, n: int = 1) -> bool:
        with self._lock:
            if self.used + n > self.limit:
                return False
            self.used += n
            return True


@dataclasses.dataclass
class EvidenceResult:
    kind: str
    source: str
    status: str                       # ok | partial | unavailable | error
    data: dict[str, Any] = dataclasses.field(default_factory=dict)
    raw_refs: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Context:
    test: SpeedtestRef
    window: Window
    identity: Identity
    ring: Ring
    cfg: RunnerConfig
    now_fn: Callable[[], float]
    budgets: dict[str, CallBudget] = dataclasses.field(default_factory=dict)

    def budget(self, source: str, default: int = 6) -> CallBudget:
        return self.budgets.setdefault(source, CallBudget(default))


class Connector(abc.ABC):
    """Base class. ``name`` is the puller name in health (``mist``, ``ec``, ``syslog``, ``baseline``); ``kinds`` the evidence
    kinds it can produce (a kind with no registered connector is posted as ``unavailable``)."""

    name: str = ""
    kinds: tuple[str, ...] = ()
    timeout_s: float = 20.0

    def configured(self) -> bool:
        return True

    @abc.abstractmethod
    def collect(self, ctx: Context) -> list[EvidenceResult]:
        """Pull and normalize. Raise on failure (the pipeline records ``error`` for every kind of this connector)."""


@dataclasses.dataclass
class ClientCandidate:
    """One client the Mist client search found for an IP (identity step; r2 fills it from the Mist client objects)."""

    mac: str
    hostname: str | None = None
    username: str | None = None
    manufacture: str | None = None
    os_family: str | None = None
    wired: bool = False
    site_id: str | None = None
    ap_mac: str | None = None
    ap_name: str | None = None
    ssid: str | None = None
    band: str | None = None
    switch_mac: str | None = None
    switch_port: str | None = None
    vlan: int | None = None
    ref: str | None = None
    ap_macs: tuple[str, ...] = ()      # every AP the client was seen on in the window (roam context; r2 Mist)


@dataclasses.dataclass
class ClientLookup:
    status: str                       # ok | unavailable | error
    candidates: list[ClientCandidate] = dataclasses.field(default_factory=list)


class IdentityProvider(abc.ABC):
    """Mist-like "who had this IP in this window". ``ok`` with 0 or >1 candidates fails the NAT guard closed."""

    @abc.abstractmethod
    def lookup_client(self, ip: str, window: Window, budget: CallBudget) -> ClientLookup: ...


def merge_cross_kind(out: dict[str, EvidenceResult]) -> None:
    """Facts one connector knows that belong in another kind: the client's own EdgeConnect flows dropped by the zone firewall / routing
    (``flows[].drop_reason`` 1 or 2) become ``security.ec_dropped_flows`` (the ``policy_block`` rule reads it). When no syslog security
    evidence exists, an ``ec``-sourced ``security`` document carries just that figure."""
    fl = out.get("flows")
    if fl is None or fl.status not in ("ok", "partial"):
        return
    n = sum(1 for f in fl.data.get("flows", []) if f.get("drop_reason") in (1, 2) or f.get("firewall_dropped"))
    if n <= 0:
        return
    sec = out.get("security")
    if sec is not None and sec.status in ("ok", "partial"):
        sec.data["ec_dropped_flows"] = n
    elif sec is None or sec.status == "unavailable":
        out["security"] = EvidenceResult("security", "ec", "partial", {"events": [], "counts": {"deny": 0, "drop": 0, "block": 0, "session_limit": 0},
                                                                          "ec_dropped_flows": n}, list(fl.raw_refs[:5]))


class PullerStats:
    """Per-connector health: last success and errors in the last hour."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.last_ok: float | None = None
        self._errors: deque[float] = deque(maxlen=1000)
        self._lock = threading.Lock()

    def ok(self, now: float | None = None) -> None:
        with self._lock:
            self.last_ok = now if now is not None else time.time()

    def error(self, now: float | None = None) -> None:
        with self._lock:
            self._errors.append(now if now is not None else time.time())

    def as_dict(self, now: float | None = None) -> dict[str, Any]:
        now = now if now is not None else time.time()
        with self._lock:
            n = sum(1 for t in self._errors if t > now - 3600)
            last = self.last_ok
        return {"source": self.name, "last_ok": None if last is None else _iso(last), "errors_1h": n}


def _iso(ts: float) -> str:
    from .evidence import _fmt
    return _fmt(ts)


# ------------------------------------------------------------------------------------------ syslog

class SyslogConnector(Connector):
    """Security-policy and DNS evidence from the runner's own ring (12 section 5.2)."""

    name = "syslog"
    kinds = ("security", "dns")
    timeout_s = 10.0

    def __init__(self, cfg: RunnerConfig) -> None:
        self.cfg = cfg

    def configured(self) -> bool:
        return bool(self.cfg.syslog.allow) and bool(self.cfg.syslog.listen)

    def collect(self, ctx: Context) -> list[EvidenceResult]:
        ip = ctx.test.client_ip
        lines = ctx.ring.query(ip, ctx.window.from_ts, ctx.window.to_ts, kinds=("security", "dns"), limit=2000)
        attached: list[int] = []
        sec = self._security(lines, ip, attached)
        dns = self._dns(lines, ip, attached)
        ctx.ring.attach(attached, ctx.now_fn())
        return [sec, dns]

    @staticmethod
    def _security(lines: list[dict[str, Any]], ip: str, attached: list[int]) -> EvidenceResult:
        groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        refs: list[str] = []
        total_lines = 0
        for ln in lines:
            if ln["kind"] != "security":
                continue
            f = ln["fields"]
            action = f.get("action", "other")
            if action == "allow":
                continue
            total_lines += 1
            key = (action, f.get("category", "other"), f.get("src_ip"), f.get("dst_ip"), f.get("dst_port"), f.get("proto"),
                   f.get("rule"), f.get("zone_from"), f.get("zone_to"), f.get("host"))
            g = groups.get(key)
            if g is None:
                if len(groups) >= SECURITY_MAX_EVENTS:
                    continue
                g = groups[key] = {"line": ln, "count": 0}
                attached.append(ln["id"])
                if len(refs) < 20:
                    refs.append(f"syslog:{ln['id']}")
            g["count"] += 1
        events: list[dict[str, Any]] = []
        counts = {"deny": 0, "drop": 0, "block": 0, "session_limit": 0}
        for g in groups.values():
            ln, f = g["line"], g["line"]["fields"]
            ev: dict[str, Any] = {"ts": _iso(ln["ts"]), "source": "syslog", "format": FMT_MAP.get(ln["fmt"], "raw"),
                                  "action": f.get("action", "other"), "category": f.get("category", "other"), "count": min(g["count"], 1_000_000),
                                  "raw": ln["raw"][:512]}
            for k, lim in (("src_ip", None), ("dst_ip", None), ("src_port", None), ("dst_port", None), ("proto", 16), ("rule", 128),
                           ("zone_from", 64), ("zone_to", 64), ("reason", 128), ("host", 253)):
                v = f.get(k)
                if v is not None and v != "":
                    ev[k] = v[:lim] if lim and isinstance(v, str) else v
            events.append(ev)
            a, cat = ev["action"], ev["category"]
            if cat == "session_limit" or a == "limit":
                counts["session_limit"] += g["count"]
            elif a in counts:
                counts[a] += g["count"]
        events.sort(key=lambda e: e["ts"])
        truncated = total_lines > sum(g["count"] for g in groups.values())
        return EvidenceResult("security", "syslog", "ok", {"events": events, "counts": counts, "truncated": truncated}, refs)

    @staticmethod
    def _dns(lines: list[dict[str, Any]], ip: str, attached: list[int]) -> EvidenceResult:
        queries: list[dict[str, Any]] = []
        refs: list[str] = []
        resolver: str | None = None
        failures = slow = 0
        slowest: float | None = None
        for ln in lines:
            f = ln["fields"]
            if ln["kind"] != "dns" or len(queries) >= DNS_MAX_QUERIES:
                continue
            q: dict[str, Any] = {"ts": _iso(ln["ts"]), "qname": str(f.get("qname", ""))[:253], "client_ip": ip}
            if f.get("qtype"):
                q["qtype"] = str(f["qtype"])[:8]
            if f.get("rcode"):
                q["rcode"] = str(f["rcode"])[:16]
                if q["rcode"] in DNS_FAIL_RCODES:
                    failures += 1
            rtt = f.get("rtt_ms")
            if isinstance(rtt, (int, float)):
                q["rtt_ms"] = float(rtt)
                slowest = max(slowest or 0.0, float(rtt))
                if rtt >= DNS_SLOW_MS:
                    slow += 1
            queries.append(q)
            attached.append(ln["id"])
            if len(refs) < 20:
                refs.append(f"syslog:{ln['id']}")
            resolver = resolver or (ln["src"] if ln["src"] and _plain_ip(ln["src"]) else None)
        if not queries:
            return EvidenceResult("dns", "syslog", "unavailable")
        data: dict[str, Any] = {"queries": queries, "failures": failures, "slow": slow, "slowest_ms": slowest}
        if resolver:
            data["resolver_ip"] = resolver
        return EvidenceResult("dns", "syslog", "ok", data, refs)


def _plain_ip(text: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True
