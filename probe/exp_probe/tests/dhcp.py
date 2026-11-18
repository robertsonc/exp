"""`dhcp_hb` (beat, rotating port) and `dhcp` (scheduled DORA) -- 02-probe.md 5.2, 5.3.

dhcp_hb  DISCOVER ONLY -- never a REQUEST (SR-18): a heartbeat must not create or alter bindings or
         use up pool addresses. It lives in the port's namespace on an AF_PACKET socket (udhcpc owns
         UDP/68 there), with the port's own MAC and DHCP identity and a probe-unique xid. Offers are
         collected for `tests.dhcp.offer_collect_s` (default 3.0 s: ping-checking servers answer 1-2 s
         late). More than one distinct server answering -- or one that is not in the optional
         `tests.dhcp.allowed_servers` list -- sets ``rogue_suspect`` and degrades the outcome.
dhcp     Full DORA that RE-CONFIRMS the binding the lease holder already has instead of taking a
         second lease (EXM `dhcptest.py` approach): same MAC, same client-id/hostname/vendor class as
         udhcpc, DISCOVER asking for the held address, REQUEST to the holder's server for the address
         it was offered. The server answers with the same binding; this test never configures an
         address, never sends DECLINE/RELEASE, and requires a held lease. If the ACK carries a
         different address than the holder has, the holder is nudged with SIGUSR1 (renew) so both
         converge (as EXM does) and the result is degraded.

Ported from reference/exm/lib/exm/heartbeat.py (`dhcp_hb`, `_dhcp_probe`) and dhcptest.py (`run`).
"""
from __future__ import annotations

import logging
import os
import signal
from dataclasses import dataclass, field
from typing import Any

from exp_common.schema import Measurement

from .. import dhcpwire as W
from ..config import Port
from ..netio import NetnsMissing
from ..scheduler import TestContext, register_test
from .common import candidate_ports, clip, error_record, num, port_info, test_option, thresholds

log = logging.getLogger(__name__)

DEFAULT_COLLECT_S = 3.0
DORA_BACKOFF_S = (2.0, 4.0, 8.0)
MAX_DETAIL_OFFERS = 8
OFFER_SETTLE_S = 0.5


class NoLink(OSError):
    """The port has no carrier: a DHCP exchange cannot even be sent."""


@dataclass
class Offer:
    ms: float                  # since the first DISCOVER of this exchange
    reply: W.DhcpReply
    t: float = 0.0             # endpoint clock at reception


@dataclass
class DiscoverResult:
    offers: list[Offer] = field(default_factory=list)
    resent: bool = False
    xid: int = 0


def discover_run(io: Any, *, hostname: str, vendor: str, client_id: str, collect_s: float,
                 xid: int | None = None, requested_ip: str | None = None) -> DiscoverResult:
    """Send a DISCOVER (one retransmit at half the window if nothing came) and collect OFFERs."""
    import random
    xid = random.getrandbits(32) if xid is None else xid
    mac = io.mac
    frame = W.wrap_frame(mac, W.build_discover(mac, xid, hostname=hostname, vendor=vendor, client_id=client_id,
                                              requested_ip=requested_ip))
    res = DiscoverResult(xid=xid)
    t0 = io.now()
    io.send(frame)
    end = t0 + collect_s
    while True:
        now = io.now()
        if now >= end:
            break
        if not res.resent and not res.offers and now - t0 >= collect_s / 2:
            io.send(frame)                                   # one retransmit covers a single lost packet
            res.resent = True
        wait = end - now
        if not res.resent and not res.offers:
            wait = min(wait, t0 + collect_s / 2 - now)
        fr = io.recv(max(wait, 0.001))
        if fr is None:
            continue
        rep = W.parse_reply(fr, xid, mac)
        if rep is not None and rep.msg_type == W.MSG_OFFER:
            now = io.now()
            res.offers.append(Offer(round((now - t0) * 1000.0, 2), rep, now))
    return res


def distinct_offers(offers: list[Offer]) -> list[Offer]:
    """One offer per (server, address): a server that answers the retransmit too counts once."""
    seen: set[tuple[str, str]] = set()
    out: list[Offer] = []
    for o in offers:
        k = (o.reply.server, o.reply.yiaddr)
        if k not in seen:
            seen.add(k)
            out.append(o)
    return out


def servers_of(offers: list[Offer]) -> list[str]:
    out: list[str] = []
    for o in offers:
        if o.reply.server not in out:
            out.append(o.reply.server)
    return out


def rogue_check(ctx: TestContext, servers: list[str]) -> tuple[bool, str | None]:
    allowed = test_option(ctx, "dhcp", "allowed_servers", None)
    why = None
    rogue = len(servers) > 1
    if rogue:
        why = "multiple DHCP servers answered: " + ", ".join(servers[:4])
    if isinstance(allowed, list) and allowed:
        extra = [s for s in servers if s not in allowed]
        if extra:
            rogue = True
            why = "DHCP server not in the allowed list: " + ", ".join(extra[:4])
    return rogue, why


def _open_packet_io(env: Any, iface: str) -> Any:
    """Inside the namespace: the AF_PACKET endpoint, after checking carrier."""
    if not env.link_running(iface):
        raise NoLink(f"no link on {iface}")
    return env.packet_io(iface)


def _hb_in_ns(env: Any, iface: str, params: dict[str, str], collect_s: float) -> DiscoverResult:
    io = _open_packet_io(env, iface)
    try:
        return discover_run(io, hostname=params["hostname"], vendor=params["vendor_class"],
                            client_id=params["client_id"], collect_s=collect_s)
    finally:
        io.close()


def _offer_detail(o: Offer) -> dict[str, Any]:
    return {"server": o.reply.server, "ip": o.reply.yiaddr, "ms": num(o.ms)}


@register_test("dhcp_hb", roles=("client",))
def dhcp_hb(ctx: TestContext) -> list[Measurement]:
    assert ctx.port is not None
    collect_s = float(test_option(ctx, "dhcp", "offer_collect_s", DEFAULT_COLLECT_S))
    slow_ms = thresholds(ctx, "dhcp", "offer_ms", 1000.0)
    cands = [ctx.port] if ctx.explicit else candidate_ports(ctx, ("client",))
    skipped: list[str] = []
    res: DiscoverResult | None = None
    used: Port = ctx.port
    for p in cands:
        env = ctx.netenv(p)
        try:
            res = env.call(_hb_in_ns, env, p.lease_iface, ctx.cfg.dhcp_params(p), collect_s)
            used = p
            break
        except NetnsMissing:
            skipped.append(f"{p.id} namespace missing")
        except NoLink:
            skipped.append(f"{p.id} no link")
        except PermissionError as exc:
            return [error_record(ctx, "dhcp_hb", f"raw socket denied: {exc.strerror or exc}",
                                 labels={"server": "none"})]
        except OSError as exc:
            skipped.append(f"{p.id} {exc.strerror or exc}")
    if res is None:
        why = "; ".join(skipped)
        return [error_record(ctx, "dhcp_hb", ("cannot send DISCOVER: " if ctx.explicit else "no client could run it: ")
                             + why, port=ctx.port, labels={"server": "none"})]
    labels = {"port": used.id}
    uniq = distinct_offers(res.offers)
    if not uniq:
        return [ctx.measure("dhcp_hb", "fail", labels={**labels, "server": "none"}, metrics={"offers": 0.0},
                            error=f"no DHCPOFFER within {collect_s:g} s")]
    first = res.offers[0]
    servers = servers_of(res.offers)
    rogue, why = rogue_check(ctx, servers)
    detail: dict[str, Any] = {"offered_ip": first.reply.yiaddr, "servers": servers[:8], "rogue_suspect": rogue,
                              "options": {k: v for k, v in first.reply.options.items() if k != "message_type"},
                              "offer_list": [_offer_detail(o) for o in uniq[:MAX_DETAIL_OFFERS]]}
    if res.resent:
        detail["resent"] = True
    outcome, error = "ok", None
    if rogue:
        outcome, error = "degraded", why
    elif first.ms > slow_ms:
        outcome, error = "degraded", f"first DHCPOFFER took {first.ms:g} ms"
    kw: dict[str, Any] = {"error": error} if error else {}
    return [ctx.measure("dhcp_hb", outcome, labels={**labels, "server": first.reply.server},
                        metrics={"offer_ms": num(first.ms), "offers": float(len(uniq))},  # type: ignore[dict-item]
                        detail=detail, **kw)]


# ------------------------------------------------------------------------------------------ DORA

@dataclass
class DoraResult:
    offers: list[Offer] = field(default_factory=list)
    chosen: Offer | None = None
    reply: W.DhcpReply | None = None
    discover_sent: list[float] = field(default_factory=list)
    request_sent: list[float] = field(default_factory=list)
    t_reply: float = 0.0
    xid: int = 0

    @property
    def discovers(self) -> int:
        return len(self.discover_sent)

    @property
    def requests(self) -> int:
        return len(self.request_sent)

    @property
    def discover_offer_ms(self) -> float | None:
        """Time from the DISCOVER that preceded the chosen offer to that offer."""
        if self.chosen is None:
            return None
        before = [t for t in self.discover_sent if t <= self.chosen.t]
        return round((self.chosen.t - (before[-1] if before else self.discover_sent[0])) * 1000.0, 2)

    @property
    def request_ack_ms(self) -> float | None:
        if self.reply is None:
            return None
        before = [t for t in self.request_sent if t <= self.t_reply]
        return round((self.t_reply - (before[-1] if before else self.request_sent[0])) * 1000.0, 2)

    @property
    def total_ms(self) -> float | None:
        return round((self.t_reply - self.discover_sent[0]) * 1000.0, 2) if self.reply and self.discover_sent else None

    @property
    def retries(self) -> int:
        return max(0, self.discovers - 1) + max(0, self.requests - 1)


def dora_run(io: Any, *, hostname: str, vendor: str, client_id: str, held_ip: str | None,
             held_server: str | None, collect_s: float, backoff: tuple[float, ...] = DORA_BACKOFF_S,
             xid: int | None = None) -> DoraResult:
    """DISCOVER (asking for the held address) -> OFFER -> REQUEST (to the holder's server) -> ACK."""
    import random
    xid = random.getrandbits(32) if xid is None else xid
    mac = io.mac
    out = DoraResult(xid=xid)
    ident = dict(hostname=hostname, vendor=vendor, client_id=client_id)
    disc = W.wrap_frame(mac, W.build_discover(mac, xid, requested_ip=held_ip, prl=W.PRL_FULL, **ident))
    t_start = io.now()

    def collect(until: float, want: set[int]) -> bool:
        """Receive until `until`; OFFERs seen on the way are kept; True once a reply in `want` came."""
        while True:
            left = until - io.now()
            if left <= 0:
                return False
            fr = io.recv(left)
            if fr is None:
                return False
            rep = W.parse_reply(fr, xid, mac)
            if rep is None:
                continue
            now = io.now()
            if rep.msg_type == W.MSG_OFFER:
                out.offers.append(Offer(round((now - t_start) * 1000.0, 2), rep, now))
            if rep.msg_type in want:
                if rep.msg_type != W.MSG_OFFER:
                    out.reply, out.t_reply = rep, now
                return True

    for wait in backoff:
        out.discover_sent.append(io.now())
        io.send(disc)
        if collect(out.discover_sent[-1] + wait, {W.MSG_OFFER}):
            break
    if not out.offers:
        return out
    if held_server and not any(o.reply.server == held_server for o in out.offers):
        settle = io.now() + OFFER_SETTLE_S         # a rogue may answer first: give the holder's server a moment
        while io.now() < settle and not any(o.reply.server == held_server for o in out.offers):
            if not collect(settle, {W.MSG_OFFER}):
                break
    # Prefer the offer from the server that holds our lease; otherwise the first one that came.
    out.chosen = next((o for o in out.offers if held_server and o.reply.server == held_server), out.offers[0])
    req = W.wrap_frame(mac, W.build_request(mac, xid, requested_ip=out.chosen.reply.yiaddr,
                                            server_id=out.chosen.reply.server, **ident))
    for wait in backoff:
        out.request_sent.append(io.now())
        io.send(req)
        if collect(out.request_sent[-1] + wait, {W.MSG_ACK, W.MSG_NAK}):
            break
    # keep listening briefly: a second server's late OFFER is how a rogue shows itself
    collect(t_start + collect_s, set())
    return out


def _dora_in_ns(env: Any, iface: str, params: dict[str, str], held_ip: str | None, held_server: str | None,
                collect_s: float) -> DoraResult:
    io = _open_packet_io(env, iface)
    try:
        return dora_run(io, hostname=params["hostname"], vendor=params["vendor_class"],
                        client_id=params["client_id"], held_ip=held_ip, held_server=held_server,
                        collect_s=collect_s)
    finally:
        io.close()


def nudge_lease_holder(ctx: TestContext, port: Port) -> bool:
    """SIGUSR1 = busybox udhcpc "renew now". Only a process whose comm is udhcpc, from our pid file."""
    try:
        with open(ctx.paths.pid_file(port.id), encoding="utf-8") as fh:
            pid = int(fh.read().strip())
        with open(f"{ctx.paths.proc}/{pid}/comm", encoding="utf-8") as fh:
            comm = fh.read().strip()
    except (OSError, ValueError):
        return False
    if pid <= 1 or not comm.startswith("udhcpc"):
        return False
    try:
        os.kill(pid, signal.SIGUSR1)
    except OSError:
        return False
    return True


@register_test("dhcp", roles=("client",))
def dhcp(ctx: TestContext) -> list[Measurement]:
    port = ctx.port
    assert port is not None
    collect_s = float(test_option(ctx, "dhcp", "offer_collect_s", DEFAULT_COLLECT_S))
    slow_ms = thresholds(ctx, "dhcp", "total_ms", 1500.0)
    info = port_info(ctx, port)
    if not info.bound:
        return [error_record(ctx, "dhcp", f"port {port.id} holds no lease to re-confirm", labels={"server": "none"})]
    env = ctx.netenv(port)
    try:
        r: DoraResult = env.call(_dora_in_ns, env, port.lease_iface, ctx.cfg.dhcp_params(port), info.ip,
                                 info.server_id, collect_s)
    except NetnsMissing:
        return [error_record(ctx, "dhcp", f"namespace for port {port.id} is missing", labels={"server": "none"})]
    except NoLink as exc:
        return [error_record(ctx, "dhcp", str(exc), labels={"server": "none"})]
    except PermissionError as exc:
        return [error_record(ctx, "dhcp", f"raw socket denied: {exc.strerror or exc}", labels={"server": "none"})]
    except OSError as exc:
        return [error_record(ctx, "dhcp", f"DHCP exchange failed: {exc.strerror or exc}", labels={"server": "none"})]
    uniq = distinct_offers(r.offers)
    metrics: dict[str, Any] = {"offers": float(len(uniq))}
    if not r.offers:
        return [ctx.measure("dhcp", "fail", labels={"port": port.id, "server": "none"}, metrics=metrics,
                            error=f"no DHCPOFFER after {r.discovers} discovers")]
    metrics["discover_offer_ms"] = r.discover_offer_ms
    assert r.chosen is not None
    server = r.chosen.reply.server
    base = {"port": port.id, "server": server}
    servers = servers_of(r.offers)
    if r.reply is None:
        return [ctx.measure("dhcp", "fail", labels=base, metrics=metrics,
                            detail={"servers": servers[:8], "held_ip": info.ip or ""},
                            error=f"no DHCPACK/NAK after {r.requests} requests")]
    metrics["request_ack_ms"], metrics["total_ms"] = r.request_ack_ms, r.total_ms
    ack = r.reply
    if ack.msg_type == W.MSG_NAK:
        return [ctx.measure("dhcp", "fail", labels={"port": port.id, "server": ack.server}, metrics=metrics,
                            duration_ms=r.total_ms, detail={"servers": servers[:8], "held_ip": info.ip or ""},
                            error="DHCPNAK: " + clip(ack.options.get("message", "")).strip())]
    if ack.options.get("lease_time") is not None:
        metrics["lease_s"] = ack.options["lease_time"]
    flags: list[str] = []
    rogue, why = rogue_check(ctx, servers)
    if rogue:
        flags.append("multiple_dhcp_servers")
    if r.retries:
        flags.append("retries")
    renewed = False
    if info.ip and ack.yiaddr != info.ip:
        flags.append("ack_ip_differs_from_held_lease")
        renewed = nudge_lease_holder(ctx, port)
    if (r.total_ms or 0) > slow_ms:
        flags.append("slow")
    routers = ack.options.get("router") or []
    opts = {k: v for k, v in ack.options.items() if k not in ("message_type", "message")}
    detail: dict[str, Any] = {"ip": ack.yiaddr, "router": routers[0] if routers else None,
                              "dns": list(ack.options.get("dns") or [])[:8], "options": opts,
                              "held_ip": info.ip or "", "servers": servers[:8], "retries": r.retries,
                              "flags": flags}
    if renewed:
        detail["renew_signalled"] = True
    outcome = "degraded" if flags else "ok"
    kw: dict[str, Any] = {}
    if flags:
        kw["error"] = clip(why or ", ".join(flags), 500)
    return [ctx.measure("dhcp", outcome, labels={"port": port.id, "server": ack.server}, metrics=metrics,
                        duration_ms=r.total_ms, detail=detail, **kw)]
