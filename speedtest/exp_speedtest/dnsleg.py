"""The DNS-leg authoritative server (12 section 4.2, SR-22): UDP + TCP on ``serve.listen_ip`` for ``dns_leg.zone`` ONLY.

* A  ``<nonce>.<zone>`` (16 hex chars) -> ``serve.listen_ip`` (TTL 60, so the page's repeated "warm" lookup is a cache hit)
* A/NS/SOA at the apex, A ``ns.<zone>`` (glue) -> ``serve.listen_ip``; every other type NODATA, every other name under
  the zone NXDOMAIN (authoritative, with the SOA)
* anything outside the zone (including ``CHAOS`` class and ``version.bind``) -> REFUSED, never recursion (``RA`` is always
  0), ``AXFR``/``IXFR`` -> REFUSED on UDP and TCP, non-QUERY opcodes -> NOTIMP, malformed or response packets are dropped
* per-source token bucket (over the limit: silently dropped, so the box cannot be used as a reflector), bounded packet and
  TCP-frame sizes, bounded concurrent TCP connections, 5 s TCP idle timeout, at most 16 queries per TCP connection

Parsing and building use the vendored dnspython (packaging/vendor.lock), never a hand parser. The server records the
FIRST arrival (time + resolver address) per registered nonce: that is how the result learns the resolver IP and whether the
delegation works at all. Unregistered nonces are answered but not recorded.
"""
from __future__ import annotations

import dataclasses
import logging
import re
import socket
import struct
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .limits import TokenBucket

log = logging.getLogger(__name__)

MAX_UDP_QUERY = 1232
MAX_TCP_FRAME = 4096
MAX_TCP_CONNS = 32
MAX_TCP_QUERIES = 16
TCP_IDLE_S = 5.0
NONCE_RE = re.compile(r"[0-9a-f]{16}\Z")
NONCE_TTL_S = 600.0
NONCE_MAX = 8192
ANSWER_TTL = 60
APEX_TTL = 300
NEG_TTL = 30
SOURCE_RATE = 200.0        # queries per second per source address (a shared campus resolver is one source)
SOURCE_BURST = 400.0
_NONCE_LABEL = re.compile(rb"[0-9a-f]{16}\Z")


@dataclasses.dataclass
class Arrival:
    resolver_ip: str
    at: float
    count: int = 1


class NonceBook:
    """nonce -> session, and the first arrival per nonce. Bounded; entries expire after 10 minutes."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self._sessions: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._arrivals: dict[str, Arrival] = {}
        self._lock = threading.Lock()

    def register(self, nonce: str, session_id: str) -> None:
        with self._lock:
            self._sessions[nonce] = (session_id, self.clock())
            while len(self._sessions) > NONCE_MAX:
                old, _ = self._sessions.popitem(last=False)
                self._arrivals.pop(old, None)

    def arrived(self, nonce: str, resolver_ip: str) -> None:
        with self._lock:
            if nonce not in self._sessions:
                return
            cur = self._arrivals.get(nonce)
            if cur is None:
                self._arrivals[nonce] = Arrival(resolver_ip, self.clock())
            else:
                cur.count += 1

    def for_session(self, nonces: list[str]) -> list[tuple[str, Arrival]]:
        with self._lock:
            return sorted(((n, self._arrivals[n]) for n in nonces if n in self._arrivals), key=lambda t: t[1].at)

    def prune(self) -> None:
        cutoff = self.clock() - NONCE_TTL_S
        with self._lock:
            for n in [n for n, (_, t) in self._sessions.items() if t < cutoff]:
                del self._sessions[n]
                self._arrivals.pop(n, None)


class DnsLegServer:
    def __init__(self, zone: str, listen_ip: str, port: int = 53, *, book: NonceBook | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.zone_text = zone.lower().rstrip(".")
        self.zone = dns.name.from_text(self.zone_text + ".")
        self.ns_name = dns.name.from_text("ns", origin=self.zone)
        self.listen_ip = listen_ip
        self.port = port
        self.book = book or NonceBook(clock)
        self.clock = clock
        self._rate = TokenBucket(SOURCE_RATE, SOURCE_BURST, max_keys=4096)
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._tcp_slots = threading.BoundedSemaphore(MAX_TCP_CONNS)
        self.udp_port = 0
        self.tcp_port = 0
        self.stats = {"queries": 0, "refused": 0, "dropped_rate": 0, "answered": 0, "malformed": 0}

    # --------------------------------------------------------------------------------------- protocol core
    def _soa(self) -> dns.rrset.RRset:
        return dns.rrset.from_text(self.zone, APEX_TTL, "IN", "SOA",
                                   f"{self.ns_name} hostmaster.{self.zone} 1 3600 600 86400 {NEG_TTL}")

    def process(self, data: bytes, src_ip: str, tcp: bool = False) -> bytes | None:
        """One query packet -> one response packet (or None to drop). Pure apart from the arrival book and the
        per-source rate limit; this is what the tests drive."""
        if len(data) < 12 or len(data) > (MAX_TCP_FRAME if tcp else MAX_UDP_QUERY):
            self.stats["malformed"] += 1
            return None
        if self._rate.take(src_ip, self.clock()) > 0:
            self.stats["dropped_rate"] += 1
            return None
        flags_hi = data[2]
        if flags_hi & 0x80:                                # QR set: a response, never answered (no reflection loops)
            return None
        opcode = (flags_hi >> 3) & 0xF
        if opcode != 0:                                    # NOTIFY/UPDATE/...: refuse by header alone (their bodies differ)
            self.stats["queries"] += 1
            return data[:2] + bytes([0x80 | (opcode << 3) | (flags_hi & 0x01), dns.rcode.NOTIMP]) + b"\x00" * 8
        try:
            q = dns.message.from_wire(data)
        except (dns.exception.DNSException, ValueError, IndexError, struct.error, EOFError):
            self.stats["malformed"] += 1
            return None
        self.stats["queries"] += 1
        resp = dns.message.make_response(q, recursion_available=False, our_payload=MAX_UDP_QUERY)
        resp.flags &= ~dns.flags.RA
        if len(q.question) != 1:
            resp.set_rcode(dns.rcode.FORMERR)
        else:
            self._answer(q, resp, src_ip)
        try:
            wire = resp.to_wire(max_size=MAX_TCP_FRAME if tcp else (q.payload if q.edns >= 0 and q.payload >= 512 else 512))
        except dns.exception.TooBig:
            resp.answer, resp.authority, resp.additional = [], [], []
            resp.flags |= dns.flags.TC
            wire = resp.to_wire()
        return wire

    def _answer(self, q: dns.message.Message, resp: dns.message.Message, src_ip: str) -> None:
        question = q.question[0]
        qname, rdtype, rdclass = question.name, question.rdtype, question.rdclass
        if rdclass != dns.rdataclass.IN or rdtype in (dns.rdatatype.AXFR, dns.rdatatype.IXFR) \
                or not qname.is_subdomain(self.zone):
            resp.set_rcode(dns.rcode.REFUSED)
            self.stats["refused"] += 1
            return
        resp.flags |= dns.flags.AA
        self.stats["answered"] += 1
        rel = qname.relativize(self.zone)
        labels = rel.labels
        if rel == dns.name.empty:                                           # the apex
            if rdtype == dns.rdatatype.SOA:
                resp.answer.append(self._soa())
            elif rdtype == dns.rdatatype.NS:
                resp.answer.append(dns.rrset.from_text(self.zone, APEX_TTL, "IN", "NS", str(self.ns_name)))
                resp.additional.append(dns.rrset.from_text(self.ns_name, APEX_TTL, "IN", "A", self.listen_ip))
            elif rdtype == dns.rdatatype.A:
                resp.answer.append(dns.rrset.from_text(qname, ANSWER_TTL, "IN", "A", self.listen_ip))
            else:
                resp.authority.append(self._soa())
            return
        if len(labels) == 1 and labels[0].lower() == b"ns":
            if rdtype == dns.rdatatype.A:
                resp.answer.append(dns.rrset.from_text(qname, APEX_TTL, "IN", "A", self.listen_ip))
            else:
                resp.authority.append(self._soa())
            return
        if len(labels) == 1 and _NONCE_LABEL.match(labels[0].lower()):
            self.book.arrived(labels[0].decode("ascii").lower(), src_ip)    # the delegation works: a query arrived
            if rdtype in (dns.rdatatype.A, dns.rdatatype.ANY):
                resp.answer.append(dns.rrset.from_text(qname, ANSWER_TTL, "IN", "A", self.listen_ip))
            else:
                resp.authority.append(self._soa())                           # NODATA (AAAA, TXT, ...)
            return
        resp.set_rcode(dns.rcode.NXDOMAIN)
        resp.authority.append(self._soa())

    # ----------------------------------------------------------------------------------------- sockets
    def start(self) -> None:
        """Bind UDP and TCP. Raises OSError when either bind fails (the daemon degrades the DNS leg, never crashes)."""
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.bind((self.listen_ip, self.port))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                tcp.bind((self.listen_ip, self.port or udp.getsockname()[1]))
            except OSError:
                tcp.close()
                raise
        except OSError:
            udp.close()
            raise
        tcp.listen(32)
        udp.settimeout(0.5)
        tcp.settimeout(0.5)
        self._udp, self._tcp = udp, tcp
        self.udp_port, self.tcp_port = udp.getsockname()[1], tcp.getsockname()[1]
        for target, name in ((self._udp_loop, "dns-udp"), (self._tcp_loop, "dns-tcp")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self._threads.append(t)
        log.info("dns-leg authority for %s on %s:%d (udp+tcp)", self.zone_text, self.listen_ip, self.udp_port)

    def stop(self) -> None:
        self._stop.set()
        for s in (self._udp, self._tcp):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        for t in self._threads:
            t.join(timeout=2)

    def _udp_loop(self) -> None:
        sock = self._udp
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(MAX_UDP_QUERY + 1)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                out = self.process(data, addr[0])
                if out is not None:
                    sock.sendto(out, addr)
            except OSError:
                continue
            except Exception:           # a query must never kill the listener
                log.exception("dns-leg: unexpected error handling a query")

    def _tcp_loop(self) -> None:
        sock = self._tcp
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            if not self._tcp_slots.acquire(blocking=False):
                conn.close()
                continue
            threading.Thread(target=self._tcp_conn, args=(conn, addr[0]), name="dns-tcp-conn", daemon=True).start()

    def _tcp_conn(self, conn: socket.socket, src: str) -> None:
        try:
            conn.settimeout(TCP_IDLE_S)
            for _ in range(MAX_TCP_QUERIES):
                hdr = _recv_exact(conn, 2)
                if hdr is None:
                    return
                (n,) = struct.unpack(">H", hdr)
                if n < 12 or n > MAX_TCP_FRAME:
                    return
                body = _recv_exact(conn, n)
                if body is None:
                    return
                out = self.process(body, src, tcp=True)
                if out is None:
                    return
                conn.sendall(struct.pack(">H", len(out)) + out)
        except OSError:
            return
        except Exception:
            log.exception("dns-leg: unexpected error on a tcp connection")
        finally:
            try:
                conn.close()
            finally:
                self._tcp_slots.release()


def _recv_exact(conn: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf
