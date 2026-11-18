"""Wire protocol between probe `path` tests and the reflector (netvitals lineage).

Design notes: the fixed header and the "reflector echoes the header with its own clock readings"
idea come from reference/netvitals/netquality.py (HEADER struct, probe/echo types), reduced to what
02-probe.md section 7 requires. Forward and return loss are computed from sequence gaps, so no
clock synchronisation is needed; t1/t2/t3 are each in their *own* clock domain (the sender's
t1 is only ever compared with the sender's own receive time; t3-t2 is the reflector's residence time).

UDP datagram = HEADER (56 bytes, network byte order) + ``pad_len`` padding bytes:

    offset size field
    0      4    magic        b"EXP1"
    4      1    version      1
    5      1    type         0x01 probe, 0x02 reflect
    6      16   session      session id announced over TCP 8862 control (HELLO)
    22     4    seq          probe sequence number (echoed back unchanged)
    26     4    reply_seq    reflector's own reply counter (0 in a probe)
    30     8    t1_ns        probe send time, sender clock (echoed back)
    38     8    t2_ns        reflector receive time, reflector clock (0 in a probe)
    46     8    t3_ns        reflector send time, reflector clock (0 in a probe)
    54     2    pad_len      number of padding bytes that follow

Total datagram length MUST equal 56 + pad_len and be <= MAX_DATAGRAM (1,400). Anything else
(wrong magic/version/type/length, trailing bytes, oversize) is rejected with ProtocolError.
The reply has the same length as the request, so the reflector is never an amplifier; padding in
a reply is zeroed (request padding content is never reflected).

TCP variant: the TCP 8862 stream (PQI goodput stream and control channel) is framed as
``uint16 length (network order) + packet`` where the packet is one datagram-format message;
``FrameReader`` reassembles frames incrementally and rejects length 0, length > MAX_DATAGRAM.
The control handshake is one line ``HELLO <session-hex32> <probe_id> <ingest-token>\\n`` (<= 256
bytes), parsed by ``parse_hello``; verifying the token is the reflector's job.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, replace

MAGIC = b"EXP1"
VERSION = 1
TYPE_PROBE = 0x01
TYPE_REFLECT = 0x02
HEADER = struct.Struct("!4sBB16sIIQQQH")
HEADER_LEN = HEADER.size           # 56
MAX_DATAGRAM = 1400
MAX_PAD = MAX_DATAGRAM - HEADER_LEN
SESSION_LEN = 16
MAX_HELLO = 256
_U32 = 0xFFFFFFFF
_U64 = (1 << 64) - 1


class ProtocolError(ValueError):
    """Malformed or out-of-bounds protocol input."""


@dataclass(frozen=True)
class Packet:
    type: int
    session: bytes
    seq: int
    t1_ns: int
    pad_len: int = 0
    reply_seq: int = 0
    t2_ns: int = 0
    t3_ns: int = 0


def _u(name: str, v: int, mx: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= mx:
        raise ProtocolError(f"{name} out of range")
    return v


def pack(p: Packet) -> bytes:
    """Serialize; raises ProtocolError for any out-of-range field."""
    if p.type not in (TYPE_PROBE, TYPE_REFLECT):
        raise ProtocolError("unknown packet type")
    if not isinstance(p.session, (bytes, bytearray)) or len(p.session) != SESSION_LEN:
        raise ProtocolError(f"session must be {SESSION_LEN} bytes")
    pad = _u("pad_len", p.pad_len, MAX_PAD)
    return HEADER.pack(MAGIC, VERSION, p.type, bytes(p.session), _u("seq", p.seq, _U32),
                       _u("reply_seq", p.reply_seq, _U32), _u("t1_ns", p.t1_ns, _U64),
                       _u("t2_ns", p.t2_ns, _U64), _u("t3_ns", p.t3_ns, _U64), pad) + bytes(pad)


def unpack(data: bytes) -> Packet:
    """Parse one datagram strictly; raises ProtocolError (never anything else) on bad input."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ProtocolError("packet must be bytes")
    n = len(data)
    if n > MAX_DATAGRAM:
        raise ProtocolError("datagram too large")
    if n < HEADER_LEN:
        raise ProtocolError("datagram shorter than header")
    magic, ver, typ, session, seq, rseq, t1, t2, t3, pad = HEADER.unpack_from(data)
    if magic != MAGIC:
        raise ProtocolError("bad magic")
    if ver != VERSION:
        raise ProtocolError(f"unsupported version {ver}")
    if typ not in (TYPE_PROBE, TYPE_REFLECT):
        raise ProtocolError("unknown packet type")
    if n != HEADER_LEN + pad:
        raise ProtocolError("length does not match header pad_len")
    return Packet(typ, bytes(session), seq, t1, pad, rseq, t2, t3)


def probe_packet(session: bytes, seq: int, t1_ns: int, size: int = HEADER_LEN) -> bytes:
    """Build a probe datagram of total `size` bytes (HEADER_LEN..MAX_DATAGRAM)."""
    if isinstance(size, bool) or not isinstance(size, int) or not HEADER_LEN <= size <= MAX_DATAGRAM:
        raise ProtocolError(f"size must be {HEADER_LEN}..{MAX_DATAGRAM}")
    return pack(Packet(TYPE_PROBE, session, seq, t1_ns, pad_len=size - HEADER_LEN))


def reflect(packet: bytes, rx_ns: int, tx_ns: int, reply_seq: int = 0) -> bytes:
    """Pure reflector step: validate a probe and build the reply (same length as the request,
    type 0x02, t1/seq echoed, t2=rx_ns, t3=tx_ns, reflector's own `reply_seq`, zeroed padding).
    Raises ProtocolError for anything that is not a well-formed probe (reflect packets are not
    reflected again)."""
    p = unpack(packet)
    if p.type != TYPE_PROBE:
        raise ProtocolError("only probe packets are reflected")
    return pack(replace(p, type=TYPE_REFLECT, reply_seq=reply_seq, t2_ns=rx_ns, t3_ns=tx_ns))


# ------------------------------------------------------------------------------------ TCP framing

_LEN = struct.Struct("!H")


def frame(packet: bytes) -> bytes:
    """Length-prefix one packet for the TCP variant."""
    if not 0 < len(packet) <= MAX_DATAGRAM:
        raise ProtocolError("frame payload size out of range")
    return _LEN.pack(len(packet)) + bytes(packet)


class FrameReader:
    """Incremental decoder of ``uint16 length + payload`` frames. ``feed`` returns complete
    payloads; a zero or oversize length raises ProtocolError (caller must drop the connection)."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buf += data
        out: list[bytes] = []
        while True:
            if len(self._buf) < _LEN.size:
                break
            (n,) = _LEN.unpack_from(self._buf)
            if n == 0 or n > MAX_DATAGRAM:
                raise ProtocolError(f"invalid frame length {n}")
            if len(self._buf) < _LEN.size + n:
                break
            out.append(bytes(self._buf[_LEN.size:_LEN.size + n]))
            del self._buf[:_LEN.size + n]
        return out

    @property
    def pending(self) -> int:
        return len(self._buf)


# ------------------------------------------------------------------------------------ control line

_HELLO_RE = re.compile(rb"HELLO ([0-9a-f]{32}) ([a-z0-9][a-z0-9-]{0,63}) (exp[aeidn]_[A-Za-z0-9_-]{43})\n\Z")


def format_hello(session: bytes, probe_id: str, token: str) -> bytes:
    if len(session) != SESSION_LEN:
        raise ProtocolError(f"session must be {SESSION_LEN} bytes")
    line = f"HELLO {bytes(session).hex()} {probe_id} {token}\n".encode("ascii", "strict")
    if _HELLO_RE.match(line) is None or len(line) > MAX_HELLO:
        raise ProtocolError("invalid HELLO fields")
    return line


def parse_hello(line: bytes) -> tuple[bytes, str, str]:
    """Parse a HELLO control line -> (session, probe_id, token). Strict; ProtocolError otherwise."""
    if not isinstance(line, (bytes, bytearray)) or len(line) > MAX_HELLO:
        raise ProtocolError("HELLO line too long")
    m = _HELLO_RE.match(bytes(line))
    if m is None:
        raise ProtocolError("malformed HELLO line")
    return bytes.fromhex(m.group(1).decode()), m.group(2).decode(), m.group(3).decode()


def one_way_loss(sent: int, received_by_reflector: int | None, returned: int) -> tuple[float, float]:
    """(forward_loss, return_loss) fractions from counts: forward = packets the reflector never saw,
    return = packets it saw (replied to) that never came back. Clock-free."""
    if sent <= 0:
        return 0.0, 0.0
    seen = sent if received_by_reflector is None else min(max(received_by_reflector, 0), sent)
    fwd = (sent - seen) / sent
    ret = (seen - min(returned, seen)) / seen if seen else 0.0
    return fwd, ret
