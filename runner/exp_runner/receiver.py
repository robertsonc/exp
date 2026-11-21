"""Syslog receiver (SR-24): UDP, TCP (octet-counting and LF framing) and TLS, no privileged ports.

Defences, all counted (``stats()``): source allowlist (empty = receive nothing), per-source and global token-bucket
rate limits, a line-length bound (oversize lines are dropped, never buffered), a bounded write queue, bounded
connection count and per-connection idle/handshake timeouts. Nothing in a line is ever executed or followed.
"""
from __future__ import annotations

import ipaddress
import logging
import queue
import socket
import ssl
import threading
import time
from collections.abc import Callable
from pathlib import Path

from .config import SyslogCfg
from .ring import Ring
from .syslog_parse import ParsedLine, parse_line

log = logging.getLogger(__name__)

MAX_OCTET_COUNT = 1 << 20          # an octet count above this closes the connection (hostile)
MAX_CONNECTIONS = 64
CONN_IDLE_S = 120.0
HANDSHAKE_S = 10.0
QUEUE_MAX = 20000
BATCH = 500
MAX_SOURCES = 4096                 # per-source buckets kept (the allowlist bounds real sources anyway)


class TokenBucket:
    def __init__(self, rate: float, burst: float, now: float) -> None:
        self.rate, self.burst = float(rate), float(burst)
        self.tokens, self.t = float(burst), now

    def take(self, now: float) -> bool:
        self.tokens = min(self.burst, self.tokens + max(0.0, now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class FramingError(Exception):
    pass


class FrameReader:
    """Incremental RFC 6587 framing: per message, ``LEN SP MSG`` (octet counting) if the stream starts with 1-7 digits and
    a space, else LF-terminated. Oversize messages are skipped without buffering them."""

    def __init__(self, max_line: int, on_message: Callable[[bytes], None], on_oversize: Callable[[], None]) -> None:
        self.max_line = max_line
        self.on_message, self.on_oversize = on_message, on_oversize
        self.buf = bytearray()
        self.skip = 0
        self.skip_to_lf = False

    def feed(self, data: bytes) -> None:
        self.buf += data
        buf = self.buf
        while True:
            if self.skip:
                n = min(self.skip, len(buf))
                del buf[:n]
                self.skip -= n
                if self.skip:
                    return
                continue
            if self.skip_to_lf:
                nl = buf.find(b"\n")
                if nl < 0:
                    buf.clear()
                    return
                del buf[:nl + 1]
                self.skip_to_lf = False
                continue
            if not buf:
                return
            if 48 <= buf[0] <= 57:
                sp = buf.find(b" ", 0, 9)
                if sp < 0 and len(buf) < 9 and bytes(buf).isdigit():
                    return                       # could still be an octet count: wait for the space
                if sp > 0 and bytes(buf[:sp]).isdigit():
                    n = int(bytes(buf[:sp]))
                    if n < 1 or n > MAX_OCTET_COUNT:
                        raise FramingError("octet count out of range")
                    if n > self.max_line:
                        self.on_oversize()
                        del buf[:sp + 1]
                        self.skip = n
                        continue
                    if len(buf) < sp + 1 + n:
                        return
                    msg = bytes(buf[sp + 1:sp + 1 + n])
                    del buf[:sp + 1 + n]
                    self.on_message(msg)
                    continue
            nl = buf.find(b"\n")
            if nl < 0:
                if len(buf) > self.max_line:
                    self.on_oversize()
                    buf.clear()
                    self.skip_to_lf = True
                return
            line = bytes(buf[:nl]).rstrip(b"\r")
            del buf[:nl + 1]
            if len(line) > self.max_line:
                self.on_oversize()
            elif line.strip():
                self.on_message(line)


class SyslogReceiver:
    def __init__(self, cfg: SyslogCfg, ring: Ring, *, tls_files: tuple[Path, Path] | None = None,
                 now_fn: Callable[[], float] = time.time, global_rate_lines_per_s: float | None = None) -> None:
        self.cfg = cfg
        self.ring = ring
        self.tls_files = tls_files
        self.now = now_fn
        default_global = min(100000, max(1000, cfg.rate_limit_lines_per_s * 20))
        self.global_rate = float(global_rate_lines_per_s) if global_rate_lines_per_s else float(default_global)
        self._lock = threading.Lock()
        self._buckets: dict[str, TokenBucket] = {}
        self._global = TokenBucket(self.global_rate, self.global_rate, now_fn())
        self._allow_cache: dict[str, bool] = {}
        self._q: queue.Queue[tuple[ParsedLine, str, float] | None] = queue.Queue(QUEUE_MAX)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._socks: list[socket.socket] = []
        self._conns = 0
        self._counters = {"received": 0, "stored": 0, "dropped_rate": 0, "dropped_oversize": 0, "dropped_queue": 0,
                          "refused": 0, "tls_failures": 0, "connections_total": 0}
        self._sec: dict[int, list[int]] = {}       # epoch second -> [received, dropped]
        self.ports: dict[str, int] = {}
        self._ctx: ssl.SSLContext | None = None
        self._idle = threading.Condition()
        self._inflight = 0

    # --------------------------------------------------------------------------------- lifecycle
    def start(self) -> SyslogReceiver:
        writer = threading.Thread(target=self._writer, name="syslog-writer", daemon=True)
        writer.start()
        self._threads.append(writer)
        for proto, port in self.cfg.listen:
            if proto == "tls":
                if self.tls_files is None:
                    log.error("syslog tls:%d requested but no certificate is available; listener not started", port)
                    continue
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(str(self.tls_files[0]), str(self.tls_files[1]))
                self._ctx = ctx
            kind = socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM
            s = socket.socket(socket.AF_INET, kind)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.cfg.bind, port))
            s.settimeout(0.25)
            if kind == socket.SOCK_STREAM:
                s.listen(32)
            self._socks.append(s)
            self.ports[proto] = s.getsockname()[1]
            target = self._udp_loop if proto == "udp" else self._tcp_loop
            t = threading.Thread(target=target, args=(s, proto == "tls"), name=f"syslog-{proto}", daemon=True)
            t.start()
            self._threads.append(t)
            log.info("syslog %s listening on %s:%d", proto, self.cfg.bind, self.ports[proto])
        return self

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._q.put(None)
        for t in self._threads:
            t.join(timeout=3)

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait until every accepted line is in the ring (tests, shutdown)."""
        end = time.monotonic() + timeout
        with self._idle:
            while (self._inflight or not self._q.empty()) and time.monotonic() < end:
                self._idle.wait(0.05)
        return not self._inflight and self._q.empty()

    # ------------------------------------------------------------------------------------- policy
    def allowed(self, ip: str) -> bool:
        hit = self._allow_cache.get(ip)
        if hit is not None:
            return hit
        try:
            addr = ipaddress.ip_address(ip)
            ok = any(addr in net for net in self.cfg.allow if addr.version == net.version)
        except ValueError:
            ok = False
        if len(self._allow_cache) > 8192:
            self._allow_cache.clear()
        self._allow_cache[ip] = ok
        return ok

    def _count(self, key: str, n: int = 1, *, dropped: bool = False, received: bool = False) -> None:
        sec = int(self.now())
        with self._lock:
            self._counters[key] += n
            if dropped or received:
                b = self._sec.setdefault(sec, [0, 0])
                if received:
                    b[0] += n
                if dropped:
                    b[1] += n
                if len(self._sec) > 130:
                    for k in [k for k in self._sec if k < sec - 120]:
                        del self._sec[k]

    def refuse(self) -> None:
        self._count("refused")

    def handle(self, src_ip: str, data: bytes) -> None:
        """One syslog message from an (already allowlist-checked) source."""
        now = self.now()
        with self._lock:
            b = self._buckets.get(src_ip)
            if b is None:
                if len(self._buckets) >= MAX_SOURCES:
                    self._buckets.clear()
                b = self._buckets[src_ip] = TokenBucket(self.cfg.rate_limit_lines_per_s, self.cfg.rate_limit_lines_per_s, now)
            ok = b.take(now) and self._global.take(now)
        if not ok:
            self._count("dropped_rate", dropped=True)
            return
        if len(data) > self.cfg.max_line_bytes:
            self._count("dropped_oversize", dropped=True)
            return
        parsed = parse_line(data.decode("utf-8", "replace"), now)
        with self._idle:
            self._inflight += 1
        try:
            self._q.put_nowait((parsed, src_ip, now))
            self._count("received", received=True)
        except queue.Full:
            self._count("dropped_queue", dropped=True)
            with self._idle:
                self._inflight -= 1
                self._idle.notify_all()

    def _oversize(self) -> None:
        self._count("dropped_oversize", dropped=True)

    # ------------------------------------------------------------------------------------ threads
    def _writer(self) -> None:
        while not self._stop.is_set():
            item = self._q.get()
            if item is None:
                return
            batch = [item]
            while len(batch) < BATCH:
                try:
                    nxt = self._q.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    self._stop.set()
                    break
                batch.append(nxt)
            try:
                n = self.ring.insert_many(batch)
                self._count("stored", n)
            except Exception:  # noqa: BLE001 - a bad batch must not stop the receiver
                log.exception("syslog ring write failed (%d lines dropped)", len(batch))
                self._count("dropped_queue", len(batch), dropped=True)
            with self._idle:
                self._inflight -= len(batch)
                self._idle.notify_all()

    def _udp_loop(self, s: socket.socket, _tls: bool) -> None:
        cap = self.cfg.max_line_bytes + 1
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(cap)
            except TimeoutError:
                continue
            except OSError:
                return
            ip = addr[0]
            if not self.allowed(ip):
                self.refuse()
                continue
            if len(data) > self.cfg.max_line_bytes:
                self._oversize()
                continue
            data = data.rstrip(b"\r\n")
            if data.strip():
                self.handle(ip, data)

    def _tcp_loop(self, s: socket.socket, tls: bool) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = s.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            ip = addr[0]
            if not self.allowed(ip):
                self.refuse()
                conn.close()
                continue
            with self._lock:
                full = self._conns >= MAX_CONNECTIONS
                if not full:
                    self._conns += 1
            if full:
                self.refuse()
                conn.close()
                continue
            self._count("connections_total")
            threading.Thread(target=self._serve, args=(conn, ip, tls), name="syslog-conn", daemon=True).start()

    def _serve(self, conn: socket.socket, ip: str, tls: bool) -> None:
        try:
            conn.settimeout(HANDSHAKE_S)
            if tls:
                if self._ctx is None:
                    return
                try:
                    conn = self._ctx.wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    self._count("tls_failures")
                    return
            conn.settimeout(5.0)
            fr = FrameReader(self.cfg.max_line_bytes, lambda m: self.handle(ip, m), self._oversize)
            last = time.monotonic()
            while not self._stop.is_set():
                try:
                    data = conn.recv(65536)
                except TimeoutError:
                    if time.monotonic() - last > CONN_IDLE_S:
                        return
                    continue
                except (OSError, ssl.SSLError):
                    return
                if not data:
                    return
                last = time.monotonic()
                try:
                    fr.feed(data)
                except FramingError:
                    log.warning("syslog: closing connection from %s (bad framing)", ip)
                    return
        finally:
            with self._lock:
                self._conns -= 1
            try:
                conn.close()
            except OSError:
                pass

    # ------------------------------------------------------------------------------------- stats
    def stats(self) -> dict[str, float]:
        now = int(self.now())
        with self._lock:
            c = dict(self._counters)
            recent = [v for k, v in self._sec.items() if now - 60 < k <= now]
        rec = sum(v[0] for v in recent)
        drp = sum(v[1] for v in recent)
        out: dict[str, float] = {k: float(v) for k, v in c.items()}
        out["lines_per_s"] = round(rec / 60.0, 3)
        out["dropped_per_min"] = float(drp)
        return out
