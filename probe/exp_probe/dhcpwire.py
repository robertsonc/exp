"""DHCP on the wire: message building, frame wrapping, reply parsing, and the AF_PACKET endpoint.

Why raw frames: the client port already holds its lease through udhcpc, which owns UDP port 68
inside the namespace. The measurement tests therefore speak DHCP over an AF_PACKET socket with the
port's own MAC (ported from reference/exm/lib/exm/heartbeat.py `_discover_frame`/`_parse_offer` and
reference/exm/lib/exm/dhcptest.py, without scapy).

SR-18: the heartbeat (`dhcp_hb`) is DISCOVER-only. `build_discover` is the only builder the heartbeat
imports; `build_request` exists solely for the scheduled `dhcp` DORA test (tests/dhcp.py).

Everything parsed here comes from the LAN: `parse_reply` never raises and bounds every loop.
"""
from __future__ import annotations

import ipaddress
import random
import select
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any

MAGIC = b"\x63\x82\x53\x63"
BROADCAST_MAC = b"\xff" * 6
MSG_DISCOVER, MSG_OFFER, MSG_REQUEST, MSG_DECLINE, MSG_ACK, MSG_NAK = 1, 2, 3, 4, 5, 6
MSG_NAMES = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
PRL_HEARTBEAT = [1, 3, 6, 15, 28, 51, 54]
PRL_FULL = [1, 3, 6, 12, 15, 26, 28, 42, 51, 54, 58, 59, 114, 119, 121]
MAX_OPTS = 128

# option code -> (name, kind)
_OPTS: dict[int, tuple[str, str]] = {
    1: ("subnet_mask", "ip"), 3: ("router", "ips"), 6: ("dns", "ips"), 12: ("hostname", "str"),
    15: ("domain", "str"), 26: ("mtu", "u16"), 28: ("broadcast", "ip"), 42: ("ntp", "ips"),
    51: ("lease_time", "u32"), 53: ("message_type", "u8"), 54: ("server_id", "ip"),
    56: ("message", "str"), 58: ("renewal_time", "u32"), 59: ("rebinding_time", "u32"),
    114: ("captive_portal", "str"),
}


def mac_bytes(mac: str) -> bytes:
    b = bytes.fromhex(mac.replace(":", ""))
    if len(b) != 6:
        raise ValueError(f"bad MAC {mac!r}")
    return b


def mac_text(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def client_id_option(mode: str, mac: bytes, hostname: str) -> bytes:
    """Same identity the lease holder uses (lease.udhcpc_argv): "mac" = type 1 + MAC (busybox default),
    "hostname" = type 0 + hostname. A re-confirmation MUST look like the same client."""
    if mode == "hostname":
        return b"\x00" + hostname.encode()[:63]
    return b"\x01" + mac


def _opt(code: int, val: bytes) -> bytes:
    return bytes([code, len(val)]) + val[:255]


def _message(msg_type: int, mac: bytes, xid: int, *, hostname: str, vendor: str, client_id: str,
             prl: list[int], broadcast: bool, requested_ip: str | None, server_id: str | None) -> bytes:
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0,
                        bytes(4), bytes(4), bytes(4), bytes(4), mac + bytes(10), bytes(64), bytes(128))
    opts = MAGIC + _opt(53, bytes([msg_type]))
    opts += _opt(61, client_id_option(client_id, mac, hostname))
    if requested_ip:
        opts += _opt(50, socket.inet_aton(requested_ip))
    if server_id:
        opts += _opt(54, socket.inet_aton(server_id))
    h, v = hostname.encode()[:63], vendor.encode()[:63]
    if h:
        opts += _opt(12, h)
    if v:
        opts += _opt(60, v)
    opts += _opt(55, bytes(prl)) + b"\xff"
    payload = bootp + opts
    return payload + bytes(max(0, 300 - len(payload)))           # BOOTP minimum size


def build_discover(mac: bytes, xid: int, *, hostname: str, vendor: str, client_id: str = "mac",
                   requested_ip: str | None = None, prl: list[int] | None = None) -> bytes:
    """A DHCPDISCOVER payload. The only message type the heartbeat can build."""
    return _message(MSG_DISCOVER, mac, xid, hostname=hostname, vendor=vendor, client_id=client_id,
                    prl=prl or PRL_HEARTBEAT, broadcast=True, requested_ip=requested_ip, server_id=None)


def build_request(mac: bytes, xid: int, *, hostname: str, vendor: str, client_id: str, requested_ip: str,
                  server_id: str, prl: list[int] | None = None) -> bytes:
    """A DHCPREQUEST (SELECTING state: server id + requested address). DORA test only."""
    return _message(MSG_REQUEST, mac, xid, hostname=hostname, vendor=vendor, client_id=client_id,
                    prl=prl or PRL_FULL, broadcast=True, requested_ip=requested_ip, server_id=server_id)


def _ip_checksum(h: bytes) -> int:
    s = sum(struct.unpack("!10H", h))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def wrap_frame(mac: bytes, payload: bytes) -> bytes:
    """Ethernet + IPv4 (0.0.0.0 -> 255.255.255.255) + UDP 68 -> 67 around a DHCP payload."""
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), random.getrandbits(16), 0, 64, 17, 0,
                      bytes(4), b"\xff\xff\xff\xff")
    iph = iph[:10] + struct.pack("!H", _ip_checksum(iph)) + iph[12:]
    return BROADCAST_MAC + mac + b"\x08\x00" + iph + udp


@dataclass
class DhcpReply:
    msg_type: int
    xid: int
    yiaddr: str
    server_id: str | None
    src_ip: str
    src_mac: str
    chaddr: str
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def server(self) -> str:
        return self.server_id or self.src_ip


def _decode_opts(blob: bytes) -> dict[int, bytes] | None:
    out: dict[int, bytes] = {}
    i = n = 0
    while i < len(blob) and blob[i] != 255:
        if blob[i] == 0:
            i += 1
            continue
        if i + 1 >= len(blob):
            return None
        code, ln = blob[i], blob[i + 1]
        if i + 2 + ln > len(blob):
            return None
        out.setdefault(code, blob[i + 2:i + 2 + ln])
        i += 2 + ln
        n += 1
        if n > MAX_OPTS:
            return None
    return out


def _clean_str(b: bytes) -> str:
    return "".join(ch for ch in b.decode("utf-8", "replace") if ch.isprintable())[:200]


def _name_options(raw: dict[int, bytes]) -> dict[str, Any]:
    named: dict[str, Any] = {}
    for code, val in raw.items():
        spec = _OPTS.get(code)
        if spec is None:
            continue
        name, kind = spec
        try:
            if kind == "ip" and len(val) == 4:
                named[name] = socket.inet_ntoa(val)
            elif kind == "ips" and val and len(val) % 4 == 0:
                named[name] = [socket.inet_ntoa(val[i:i + 4]) for i in range(0, min(len(val), 32), 4)]
            elif kind == "u32" and len(val) == 4:
                named[name] = struct.unpack("!I", val)[0]
            elif kind == "u16" and len(val) == 2:
                named[name] = struct.unpack("!H", val)[0]
            elif kind == "u8" and len(val) == 1:
                named[name] = val[0]
            elif kind == "str" and val:
                named[name] = _clean_str(val)
        except (struct.error, OSError, ValueError):
            continue
    return named


def parse_reply(frame: bytes, xid: int | None = None, chaddr: bytes | None = None) -> DhcpReply | None:
    """A BOOTREPLY (server -> client, UDP 67 -> 68) from an Ethernet frame; None for anything else.
    `xid` / `chaddr` (our transaction and MAC) filter out other clients' traffic when given."""
    try:
        if len(frame) < 14 + 20 + 8 + 240 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
            return None
        ihl = (frame[14] & 0x0F) * 4
        if ihl < 20 or frame[14 + 9] != 17:
            return None
        udp = frame[14 + ihl:]
        if len(udp) < 8 + 240:
            return None
        sport, dport = struct.unpack("!HH", udp[:4])
        if sport != 67 or dport != 68:
            return None
        b = udp[8:]
        if b[0] != 2 or b[236:240] != MAGIC:
            return None
        rx_xid = struct.unpack("!I", b[4:8])[0]
        if xid is not None and rx_xid != xid:
            return None
        if b[1] != 1 or b[2] != 6:                       # ethernet only
            return None
        rx_chaddr = b[28:34]
        if chaddr is not None and rx_chaddr != chaddr:
            return None
        raw = _decode_opts(b[240:])
        if raw is None or 53 not in raw or len(raw[53]) != 1:
            return None
        named = _name_options(raw)
        src_ip = socket.inet_ntoa(frame[14 + 12:14 + 16])
        return DhcpReply(raw[53][0], rx_xid, socket.inet_ntoa(b[16:20]), named.get("server_id"), src_ip,
                         mac_text(frame[6:12]), mac_text(rx_chaddr), named)
    except (IndexError, struct.error, OSError, ValueError):
        return None


def valid_ipv4(v: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Address(v))
    except (ValueError, TypeError):
        return None


class PacketIO:
    """AF_PACKET endpoint: ``mac``, ``now()``, ``send(frame)``, ``recv(timeout) -> frame | None``."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.mac: bytes = sock.getsockname()[4][:6]

    def now(self) -> float:
        return time.perf_counter()

    def send(self, frame: bytes) -> None:
        self.sock.send(frame)

    def recv(self, timeout: float) -> bytes | None:
        r, _, _ = select.select([self.sock], [], [], max(0.0, timeout))
        return self.sock.recv(4096) if r else None

    def close(self) -> None:
        self.sock.close()
