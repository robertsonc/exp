"""Fakes for the measurement tests: a scripted command runner, a virtual-time ICMP endpoint, a
virtual-time DHCP packet endpoint with a tiny server, a NetEnv that needs no namespace and no root,
and helpers that build the wire packets a network would send. Nothing here touches a real network."""
from __future__ import annotations

import json
import socket
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

from exp_common.config import iter_errors

from exp_probe import dhcpwire as W
from exp_probe.icmp import build_echo, checksum
from exp_probe.netio import NetEnv
from exp_probe.runner import CmdResult

RECORDED = Path(__file__).parent / "recorded"


def recorded(name: str) -> str:
    return (RECORDED / name).read_text(encoding="utf-8")


# ------------------------------------------------------------------------------------- the runner

class ScriptRunner:
    """Answers commands by matching argv (after stripping an `ip netns exec <ns>` prefix) against rules.
    A rule is (predicate on the argv list, CmdResult | callable(argv) -> CmdResult)."""

    def __init__(self) -> None:
        self.rules: list[tuple[Callable[[list[str]], bool], Any]] = []
        self.calls: list[list[str]] = []

    def on(self, *prefix: str, out: str = "", rc: int = 0, err: str = "", fn: Callable[[list[str]], CmdResult] | None = None) -> None:
        n = len(prefix)
        self.rules.append((lambda a, p=prefix, n=n: tuple(a[:n]) == p, fn or CmdResult((), rc, out, err)))

    def run(self, argv: Any, timeout: float = 10, **_kw: Any) -> CmdResult:
        a = list(argv)
        self.calls.append(a)
        core = a[4:] if a[:3] == ["ip", "netns", "exec"] else a
        for pred, res in self.rules:
            if pred(core):
                return res(core) if callable(res) else CmdResult(tuple(a), res.rc, res.stdout, res.stderr)
        return CmdResult(tuple(a), 127, "", f"{a[0]}: not scripted")

    def run_ns(self, port_id: str, argv: Any, timeout: float = 10, **kw: Any) -> CmdResult:
        return self.run(["ip", "netns", "exec", f"exp-{port_id}", *argv], timeout, **kw)


def link_rules(r: ScriptRunner, iface: str, *, up: bool = True, changes: int | None = 2, gw: str | None = "10.1.0.1",
               gw_mac: str | None = "00:00:5e:00:01:65") -> None:
    r.on("ip", "-j", "link", "show", "dev", iface, out=recorded("ip_link_up.json" if up else "ip_link_nocarrier.json"))
    if changes is None:
        r.on("cat", rc=1, err="no such file")
    else:
        r.on("cat", out=f"{changes}\n")
    if gw and gw_mac:
        r.on("ip", "-j", "neigh", "show", "to", gw,
             out=json.dumps([{"dst": gw, "lladdr": gw_mac, "state": ["REACHABLE"]}]))
    else:
        r.on("ip", "-j", "neigh", "show", "to", out="[]")


# ------------------------------------------------------------------------------------------ ICMP

def ip_icmp(icmp: bytes, src: str = "10.0.0.9", dst: str = "10.0.0.1", ttl: int = 64) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, ttl, 1, 0, socket.inet_aton(src),
                      socket.inet_aton(dst))
    return hdr + icmp


def echo_reply(ident: int, seq: int, src: str) -> bytes:
    body = struct.pack("!BBHHH", 0, 0, 0, ident, seq) + b"exp-probe"
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return ip_icmp(body, src=src)


def icmp_error(kind: int, code: int, ident: int, seq: int, src: str, target: str = "8.8.8.8") -> bytes:
    inner_icmp = build_echo(ident, seq)
    inner = ip_icmp(inner_icmp, src="10.0.0.9", dst=target)[:28]
    body = struct.pack("!BBHI", kind, code, 0, 0) + inner
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return ip_icmp(body, src=src)


def time_exceeded(ident: int, seq: int, src: str, target: str = "8.8.8.8") -> bytes:
    return icmp_error(11, 0, ident, seq, src, target)


def unreachable(ident: int, seq: int, src: str, code: int = 1, target: str = "8.8.8.8") -> bytes:
    return icmp_error(3, code, ident, seq, src, target)


def echo_request_fields(packet: bytes) -> tuple[int, int]:
    return struct.unpack("!HH", packet[4:8])


class FakeIcmp:
    """Virtual-time ICMP endpoint. `responder(dst, ident, seq, ttl, t)` returns [(delay_s, bytes, src)]."""

    def __init__(self, responder: Callable[[str, int, int, int | None, float], list[tuple[float, bytes, str]]]) -> None:
        self.responder = responder
        self.t = 100.0
        self.queue: list[tuple[float, bytes, str]] = []
        self.sent: list[tuple[float, str, int | None, int, int]] = []     # (t, dst, ttl, ident, seq)
        self.closed = False
        self.fail_send_at: int | None = None

    def now(self) -> float:
        return self.t

    def send(self, dst: str, packet: bytes, ttl: int | None = None) -> None:
        if self.fail_send_at is not None and len(self.sent) + 1 >= self.fail_send_at:
            raise OSError(101, "Network is unreachable")
        ident, seq = echo_request_fields(packet)
        self.sent.append((self.t, dst, ttl, ident, seq))
        for delay, data, src in self.responder(dst, ident, seq, ttl, self.t):
            self.queue.append((self.t + delay, data, src))
        self.queue.sort(key=lambda x: x[0])

    def recv(self, timeout: float) -> tuple[bytes, str] | None:
        if self.queue and self.queue[0][0] <= self.t + timeout:
            at, data, src = self.queue.pop(0)
            self.t = max(self.t, at)
            return data, src
        self.t += timeout
        return None

    def close(self) -> None:
        self.closed = True


def answer_all(rtt_s: float = 0.001) -> Callable[..., list[tuple[float, bytes, str]]]:
    return lambda dst, ident, seq, ttl, t: [(rtt_s, echo_reply(ident, seq, dst), dst)]


def silent(dst: str, ident: int, seq: int, ttl: int | None, t: float) -> list[tuple[float, bytes, str]]:
    return []


def path_responder(hops: list[str | None], target: str, rtts: list[float] | None = None,
                   unreach_at: int | None = None, reach: bool = True) -> Callable[..., list[tuple[float, bytes, str]]]:
    """hops[i] answers TTL i+1 (None = silent); the packet with ttl > len(hops) reaches `target`."""
    def fn(dst: str, ident: int, seq: int, ttl: int | None, t: float) -> list[tuple[float, bytes, str]]:
        ttl = ttl or 64
        rt = (rtts[ttl - 1] if rtts and ttl - 1 < len(rtts) else 0.001 * ttl)
        if ttl <= len(hops):
            hop = hops[ttl - 1]
            if hop is None:
                return []
            if unreach_at == ttl:
                return [(rt, unreachable(ident, seq, hop, 1, dst), hop)]
            return [(rt, time_exceeded(ident, seq, hop, dst), hop)]
        return [(rt, echo_reply(ident, seq, target), target)] if (reach and dst == target) else []
    return fn


# ------------------------------------------------------------------------------------------ DHCP

SERVER_MAC = b"\x02\x00\x5e\x00\x00\x01"


def server_frame(msg_type: int, xid: int, client_mac: bytes, *, server_ip: str, yiaddr: str,
                 router: str | None = "10.1.0.1", dns: list[str] | None = None, lease: int | None = 598,
                 mask: str | None = "255.255.255.0", message: str | None = None,
                 src_mac: bytes = SERVER_MAC, include_server_id: bool = True) -> bytes:
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, bytes(4),
                        socket.inet_aton(yiaddr) if msg_type != W.MSG_NAK else bytes(4), socket.inet_aton(server_ip),
                        bytes(4), client_mac + bytes(10), bytes(64), bytes(128))
    o = W.MAGIC + bytes([53, 1, msg_type])
    if include_server_id:
        o += bytes([54, 4]) + socket.inet_aton(server_ip)
    if lease is not None and msg_type != W.MSG_NAK:
        o += bytes([51, 4]) + struct.pack("!I", lease)
    if mask and msg_type != W.MSG_NAK:
        o += bytes([1, 4]) + socket.inet_aton(mask)
    if router and msg_type != W.MSG_NAK:
        o += bytes([3, 4]) + socket.inet_aton(router)
    if dns and msg_type != W.MSG_NAK:
        o += bytes([6, 4 * len(dns)]) + b"".join(socket.inet_aton(d) for d in dns)
    if message:
        o += bytes([56, len(message)]) + message.encode()
    o += b"\xff"
    payload = bootp + o
    payload += bytes(max(0, 300 - len(payload)))
    udp = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 7, 0, 64, 17, 0, socket.inet_aton(server_ip),
                      b"\xff\xff\xff\xff")
    return b"\xff" * 6 + src_mac + b"\x08\x00" + iph + udp


def frame_summary(frame: bytes) -> tuple[int, int, dict[int, bytes]]:
    """(op, xid, raw options) of a client frame built by dhcpwire.wrap_frame."""
    b = frame[14 + 20 + 8:]
    raw = W._decode_opts(b[240:]) or {}
    return b[0], struct.unpack("!I", b[4:8])[0], raw


class FakePacketIO:
    """Virtual-time DHCP endpoint with scripted servers. `servers`: list of dicts
    {ip, offer_delay, ack_delay (None = never ACK), yiaddr, mac, nak, answer_discover(bool)}."""

    def __init__(self, servers: list[dict[str, Any]], mac: bytes = b"\x02\xaa\xbb\xcc\xdd\x01") -> None:
        self.mac = mac
        self.servers = servers
        self.t = 50.0
        self.queue: list[tuple[float, bytes]] = []
        self.sent: list[tuple[float, bytes]] = []
        self.closed = False
        self.drop_first_discovers = 0

    def now(self) -> float:
        return self.t

    def send(self, frame: bytes) -> None:
        self.sent.append((self.t, frame))
        op, xid, raw = frame_summary(frame)
        mtype = raw[53][0]
        if mtype == W.MSG_DISCOVER and self.drop_first_discovers > 0:
            self.drop_first_discovers -= 1
            return
        for s in self.servers:
            if mtype == W.MSG_DISCOVER and s.get("offer_delay") is not None:
                self.queue.append((self.t + s["offer_delay"], server_frame(
                    W.MSG_OFFER, xid, self.mac, server_ip=s["ip"], yiaddr=s["yiaddr"], src_mac=s.get("mac", SERVER_MAC),
                    dns=s.get("dns", ["10.1.0.2"]), router=s.get("router", "10.1.0.1"))))
            elif mtype == W.MSG_REQUEST and raw.get(54) and socket.inet_ntoa(raw[54]) == s["ip"]:
                if s.get("nak"):
                    self.queue.append((self.t + 0.005, server_frame(W.MSG_NAK, xid, self.mac, server_ip=s["ip"],
                                                                    yiaddr="0.0.0.1", message="wrong network")))
                elif s.get("ack_delay") is not None:
                    self.queue.append((self.t + s["ack_delay"], server_frame(
                        W.MSG_ACK, xid, self.mac, server_ip=s["ip"], yiaddr=s.get("ack_yiaddr", s["yiaddr"]),
                        dns=s.get("dns", ["10.1.0.2"]), router=s.get("router", "10.1.0.1"))))
        self.queue.sort(key=lambda x: x[0])

    def recv(self, timeout: float) -> bytes | None:
        if self.queue and self.queue[0][0] <= self.t + timeout:
            at, data = self.queue.pop(0)
            self.t = max(self.t, at)
            return data
        self.t += timeout
        return None

    def close(self) -> None:
        self.closed = True

    def msg_types_sent(self) -> list[int]:
        return [frame_summary(f)[2][53][0] for _, f in self.sent]


# ------------------------------------------------------------------------------------ the NetEnv

class FakeEnv(NetEnv):
    """A namespace-less environment: code runs in place, endpoints are the injected fakes."""

    def __init__(self, icmp: Any = None, packet_io: Any = None, running: bool = True, exists: bool = True,
                 ns: str | None = "exp-fake") -> None:
        super().__init__(ns, None, label="fake")
        self._icmp, self._pio, self.running, self._exists = icmp, packet_io, running, exists
        self.calls = 0

    def exists(self) -> bool:
        return self._exists

    def call(self, fn: Callable[..., Any], *args: Any, **kw: Any) -> Any:
        self.calls += 1
        return fn(*args, **kw)

    def socket(self, family: int, type_: int, proto: int = 0) -> socket.socket:
        return socket.socket(family, type_, proto)          # real, unpinned (local stub servers)

    def icmp(self) -> Any:
        if self._icmp is None:
            raise PermissionError(1, "Operation not permitted")
        return self._icmp() if callable(self._icmp) and not hasattr(self._icmp, "recv") else self._icmp

    def packet_io(self, iface: str) -> Any:
        if self._pio is None:
            raise PermissionError(1, "Operation not permitted")
        return self._pio

    def link_running(self, iface: str) -> bool:
        return self.running


def net_factory(env: FakeEnv, control: FakeEnv | None = None) -> Callable[..., FakeEnv]:
    def f(cfg: Any, port: Any, ctl: bool = False) -> FakeEnv:
        return control if (ctl and control is not None) else env
    return f


# ---------------------------------------------------------------------------------- validation

def validate_measurements(ms: list[Any]) -> None:
    """Every record: the python validator AND the frozen JSON Schema (require an id, as ingest does)."""
    for m in ms:
        m.validate(require_id=True)
        errs = iter_errors(m.to_dict(), "measurement")
        assert not errs, f"{m.test}: {[str(e) for e in errs]}"
