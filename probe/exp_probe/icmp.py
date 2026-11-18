"""ICMP echo and the paced TTL sweep (02-probe.md 5.1, 5.5, 5.6), written against a tiny endpoint
interface so the algorithms run on virtual time in unit tests and on a raw socket in production.

Endpoint contract (`IcmpEndpoint`): ``now()`` (monotonic seconds), ``send(dst, packet, ttl)``,
``recv(timeout)`` -> ``(data, src)`` or None after `timeout`, ``close()``. `data` is what a raw ICMP
socket returns: an IPv4 header followed by the ICMP message.

Everything parsed here arrives from the network: parsing never raises, it returns None.
Ported from reference/exm/lib/exm/heartbeat.py (`_trace_probe`, `_echo`, `_ping`, `_checksum`).
"""
from __future__ import annotations

import random
import re
import select
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

ECHO_REPLY, DEST_UNREACH, ECHO_REQUEST, TIME_EXCEEDED = 0, 3, 8, 11
PAYLOAD = b"exp-probe"
MAX_HOPS = 64


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_echo(ident: int, seq: int, payload: bytes = PAYLOAD) -> bytes:
    hdr = struct.pack("!BBHHH", ECHO_REQUEST, 0, 0, ident & 0xFFFF, seq & 0xFFFF) + payload
    return hdr[:2] + struct.pack("!H", checksum(hdr)) + hdr[4:]


@dataclass(frozen=True)
class IcmpEvent:
    kind: str            # reply | time_exceeded | unreachable
    src: str
    ident: int
    seq: int
    code: int = 0


def parse_icmp(data: bytes, src: str) -> IcmpEvent | None:
    """An echo reply, or a time-exceeded / unreachable quoting one of OUR echo requests; else None."""
    try:
        if len(data) < 20 or data[0] >> 4 != 4:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl + 8 or data[9] != 1:
            return None
        itype, code = data[ihl], data[ihl + 1]
        if itype == ECHO_REPLY:
            ident, seq = struct.unpack("!HH", data[ihl + 4:ihl + 8])
            return IcmpEvent("reply", src, ident, seq, code)
        if itype in (DEST_UNREACH, TIME_EXCEEDED):
            inner = data[ihl + 8:]
            if len(inner) < 28 or inner[0] >> 4 != 4:
                return None
            iihl = (inner[0] & 0x0F) * 4
            if iihl < 20 or len(inner) < iihl + 8 or inner[9] != 1 or inner[iihl] != ECHO_REQUEST:
                return None
            ident, seq = struct.unpack("!HH", inner[iihl + 4:iihl + 8])
            return IcmpEvent("time_exceeded" if itype == TIME_EXCEEDED else "unreachable", src, ident, seq, code)
    except (IndexError, struct.error):
        return None
    return None


class IcmpUnavailable(OSError):
    """No raw ICMP socket (not root / no CAP_NET_RAW)."""


class IcmpEndpoint(Protocol):
    def now(self) -> float: ...
    def send(self, dst: str, packet: bytes, ttl: int | None = None) -> None: ...
    def recv(self, timeout: float) -> tuple[bytes, str] | None: ...
    def close(self) -> None: ...


class RawIcmp:
    """Production endpoint over a raw ICMP socket (already created inside the right namespace)."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def now(self) -> float:
        return time.perf_counter()

    def send(self, dst: str, packet: bytes, ttl: int | None = None) -> None:
        if ttl is not None:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        self.sock.sendto(packet, (dst, 0))

    def recv(self, timeout: float) -> tuple[bytes, str] | None:
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        if not r:
            return None
        data, (src, _) = self.sock.recvfrom(2048)
        return data, src

    def close(self) -> None:
        self.sock.close()


def open_icmp(env: Any) -> IcmpEndpoint:
    """Open an endpoint in `env` (call inside env.call); permission problems become IcmpUnavailable."""
    try:
        return env.icmp()
    except PermissionError as exc:
        raise IcmpUnavailable(f"ICMP socket unavailable: {exc.strerror or exc}") from exc


def pump(ep: IcmpEndpoint, until: float, handler: Callable[[bytes, str, float], bool]) -> None:
    """Receive until time `until` (endpoint clock); `handler` returns True to stop early."""
    while True:
        left = until - ep.now()
        if left <= 0:
            return
        got = ep.recv(left)
        if got is None:
            return
        if handler(got[0], got[1], ep.now()):
            return


# ------------------------------------------------------------------------------------------ ping

@dataclass
class PingResult:
    target: str
    sent: int = 0
    rtts: list[float] = field(default_factory=list)       # ms
    error: str | None = None

    @property
    def received(self) -> int:
        return len(self.rtts)

    @property
    def loss_pct(self) -> float:
        return round(100.0 * (self.sent - self.received) / self.sent, 2) if self.sent else 100.0

    @property
    def rtt_ms(self) -> float | None:
        """Mean round trip of the replies, ms."""
        return round(sum(self.rtts) / len(self.rtts), 2) if self.rtts else None


def ping_many(ep: IcmpEndpoint, targets: list[str], count: int, interval_s: float, timeout_s: float,
              stop_on_reply: bool = False, ident: int | None = None) -> dict[str, PingResult]:
    """Send `count` echoes to every target `interval_s` apart (rounds interleave the targets), then wait
    up to `timeout_s` for stragglers. `stop_on_reply`: a target that answered gets no more echoes
    (the "2 tries, 0.5 s apart" resolver ping). Replies are matched on (ident, seq, source)."""
    ident = random.getrandbits(16) if ident is None else ident
    res = {t: PingResult(t) for t in targets}
    pending: dict[int, tuple[str, float]] = {}
    seq_of = 0
    answered: set[str] = set()

    def on_pkt(data: bytes, src: str, t: float) -> bool:
        ev = parse_icmp(data, src)
        if ev is None or ev.kind != "reply" or ev.ident != ident:
            return False
        hit = pending.pop(ev.seq, None)
        if hit is None or hit[0] != src:
            return False
        res[hit[0]].rtts.append(round((t - hit[1]) * 1000.0, 2))
        answered.add(hit[0])
        return not pending and last_round_done

    last_round_done = False
    t_start = ep.now()
    for n in range(count):
        for tgt in targets:
            if stop_on_reply and tgt in answered:
                continue
            seq_of = (seq_of + 1) & 0xFFFF
            try:
                ep.send(tgt, build_echo(ident, seq_of))
            except OSError as exc:
                res[tgt].error = f"{exc.strerror or exc}"
                continue
            pending[seq_of] = (tgt, ep.now())
            res[tgt].sent += 1
        if n < count - 1:
            pump(ep, t_start + (n + 1) * interval_s, on_pkt)
            if stop_on_reply and all(t in answered or res[t].error for t in targets):
                break
    last_round_done = True
    if pending:
        pump(ep, ep.now() + timeout_s, on_pkt)
    return res


_PING_LOSS = re.compile(r"(\d+) packets transmitted, (\d+)(?: packets)? received.*?([\d.]+)% packet loss")
_PING_RTT = re.compile(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?\s*ms")


def parse_ping_output(text: str) -> PingResult | None:
    """iputils/busybox `ping` summary -> PingResult (used when no raw socket is available)."""
    m = _PING_LOSS.search(text or "")
    if not m:
        return None
    sent, got = int(m.group(1)), int(m.group(2))
    if sent <= 0 or got > sent:
        return None
    r = PingResult("", sent)
    rt = _PING_RTT.search(text)
    if got and rt:
        avg = float(rt.group(2))
        r.rtts = [avg] * got
    return r


# ----------------------------------------------------------------------------------------- trace

@dataclass
class Hop:
    ttl: int
    ip: str | None
    rtt_ms: float | None


@dataclass
class TraceResult:
    target: str
    hops: list[Hop] = field(default_factory=list)        # 1..last, silent hops have ip None
    reached: bool = False
    dest_ttl: int | None = None
    last_ttl: int = 0
    last_ip: str | None = None
    rtt_ms: float | None = None
    unreachable: dict[str, Any] | None = None
    sent_at: dict[int, float] = field(default_factory=dict)   # ttl -> endpoint time (pacing evidence)
    error: str | None = None


def trace_sweep(ep: IcmpEndpoint, target: str, max_hops: int = 30, pace_s: float = 0.020,
                timeout_s: float = 2.0, ident: int | None = None) -> TraceResult:
    """ICMP TTL sweep: one echo per TTL, `pace_s` apart (a simultaneous burst is dropped by large
    providers' edges and falsely reports the target unreachable). Replies are collected WHILE pacing.
    Sending stops at the destination (or at an ICMP unreachable); a silent hop before the destination
    is waited for only briefly. Never sends two probes at once, never runs concurrently with itself."""
    max_hops = max(1, min(int(max_hops), MAX_HOPS))
    ident = random.getrandbits(16) if ident is None else ident
    out = TraceResult(target)
    sent: dict[int, float] = {}
    seen: dict[int, tuple[str, float]] = {}
    state: dict[str, Any] = {"dest": None, "unreach": None}

    def complete() -> bool:
        lim = state["dest"] or (state["unreach"] or {}).get("ttl")
        return bool(lim) and all(t in seen for t in range(1, lim + 1))

    def on_pkt(data: bytes, src: str, t: float) -> bool:
        ev = parse_icmp(data, src)
        if ev is None or ev.ident != ident or ev.seq not in sent:
            return False
        if ev.kind == "reply":
            if src != target:
                return False
            state["dest"] = ev.seq if state["dest"] is None else min(state["dest"], ev.seq)
        elif ev.kind == "unreachable" and state["unreach"] is None:
            state["unreach"] = {"ip": src, "code": ev.code, "ttl": ev.seq}
        if ev.seq not in seen:
            seen[ev.seq] = (src, round((t - sent[ev.seq]) * 1000.0, 2))
        return complete()

    for ttl in range(1, max_hops + 1):
        if state["dest"] is not None and ttl > state["dest"]:
            break
        if state["unreach"] is not None and ttl > state["unreach"]["ttl"]:
            break
        try:
            ep.send(target, build_echo(ident, ttl), ttl)
        except OSError as exc:
            out.error = f"cannot send: {exc.strerror or exc}" if ttl == 1 else out.error
            if ttl == 1:
                return out
            break
        sent[ttl] = ep.now()
        pump(ep, sent[ttl] + pace_s, on_pkt)
    out.sent_at = dict(sent)
    last_sent = max(sent.values()) if sent else ep.now()
    if state["dest"] is not None:
        d_rtt = seen[state["dest"]][1] / 1000.0
        wait_until = ep.now() + min(timeout_s, max(0.3, 3.0 * d_rtt))       # stragglers: briefly
    else:
        wait_until = last_sent + timeout_s
    if not complete():
        pump(ep, wait_until, on_pkt)

    dest, unreach = state["dest"], state["unreach"]
    last = dest or (unreach["ttl"] if unreach else (max(seen) if seen else 0))
    out.hops = [Hop(t, *(seen[t] if t in seen else (None, None))) for t in range(1, last + 1)]
    out.dest_ttl, out.unreachable = dest, unreach
    out.reached = dest is not None
    if out.reached:
        out.last_ttl, out.last_ip, out.rtt_ms = dest, target, seen[dest][1]
    else:
        answering = [t for t in seen if t <= last]
        if answering:
            out.last_ttl = max(answering)
            out.last_ip = seen[out.last_ttl][0]
    return out
