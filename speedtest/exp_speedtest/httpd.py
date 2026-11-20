"""A small, strict HTTP/1.1 server for the speedtest box (SR-21: bounded everything).

Why not ``http.server``: the box is an unauthenticated service on an event LAN, so the parser has to be strict and every
limit explicit, and the data path (``/st/down``) has to hand bytes to the kernel (``sendfile``) without Python in the loop.

Limits: request line 8 KiB (414), whole head 16 KiB and 64 headers (431), head must arrive within 10 s (408, slowloris),
15 s idle between keep-alive requests, no ``Transfer-Encoding`` request bodies (501) and ``Content-Length`` must be plain
digits, bodies are read by the handler with an explicit limit, at most 512 connections (48 per client address), 1000
requests per connection. Origin-form targets only; the path is percent-decoded once and control characters refused.
No request header is ever logged. The peer address is the TCP peer: ``X-Forwarded-For`` is never consulted (D15: the box
must see the real client address).
"""
from __future__ import annotations

import logging
import re
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable
from email.utils import formatdate
from typing import Any

from .errors import ApiError

log = logging.getLogger(__name__)

MAX_REQUEST_LINE = 8192
MAX_HEAD = 16384
MAX_HEADERS = 64
HEAD_TIMEOUT_S = 10.0
IDLE_TIMEOUT_S = 15.0
SEND_TIMEOUT_S = 30.0
MAX_REQUESTS_PER_CONN = 1000
MAX_QUERY = 2048
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z")
_METHOD = re.compile(r"[A-Z]{1,10}\Z")
_DIGITS = re.compile(r"[0-9]{1,10}\Z")
_BAD_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


class Conn:
    """A client connection with a receive buffer (so pipelined bytes are never lost and the head has a hard deadline)."""

    def __init__(self, sock: socket.socket, peer: str) -> None:
        self.sock = sock
        self.peer = peer
        self.buf = bytearray()
        self.scratch = bytearray(1 << 20)          # one reusable read buffer for uploads (per connection thread)

    def recv_head(self, first_timeout: float) -> bytes | None:
        """The request head (without the terminating blank line), or None on a clean idle close / timeout."""
        deadline: float | None = None
        while True:
            i = self.buf.find(b"\r\n\r\n")
            if i >= 0:
                head = bytes(self.buf[:i])
                del self.buf[:i + 4]
                return head
            if len(self.buf) > MAX_HEAD:
                raise ApiError(431, "header_too_large", "request header too large", close=True)
            if self.buf and b"\r\n" not in self.buf and len(self.buf) > MAX_REQUEST_LINE:
                raise ApiError(414, "uri_too_long", "request line too long", close=True)
            if self.buf and deadline is None:
                deadline = time.monotonic() + HEAD_TIMEOUT_S
            timeout = first_timeout if deadline is None else deadline - time.monotonic()
            if timeout <= 0:
                raise ApiError(408, "request_timeout", "request timeout", close=True)
            self.sock.settimeout(timeout)
            try:
                chunk = self.sock.recv(8192)
            except TimeoutError:
                if not self.buf:
                    return None
                raise ApiError(408, "request_timeout", "request timeout", close=True) from None
            except (OSError, ssl.SSLError):
                return None
            if not chunk:
                return None
            self.buf += chunk
            if deadline is None:
                deadline = time.monotonic() + HEAD_TIMEOUT_S

    def read_into(self, mv: memoryview, timeout: float) -> int:
        """Read up to ``len(mv)`` body bytes (buffered bytes first). 0 means the peer closed."""
        if self.buf:
            n = min(len(mv), len(self.buf))
            mv[:n] = self.buf[:n]
            del self.buf[:n]
            return n
        self.sock.settimeout(timeout)
        return self.sock.recv_into(mv)


class Request:
    __slots__ = ("method", "target", "path", "query", "version", "headers", "peer", "conn", "content_length",
                 "body_read", "continue_sent", "keep_alive", "server")

    def __init__(self, method: str, target: str, path: str, query: dict[str, str], version: str,
                 headers: dict[str, str], conn: Conn, content_length: int, server: HttpServer) -> None:
        self.method, self.target, self.path, self.query, self.version = method, target, path, query, version
        self.headers, self.conn, self.peer, self.server = headers, conn, conn.peer, server
        self.content_length = content_length
        self.body_read = 0
        self.continue_sent = False
        conn_h = headers.get("connection", "").lower()
        self.keep_alive = ("keep-alive" in conn_h) if version == "HTTP/1.0" else ("close" not in conn_h)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def _maybe_continue(self) -> None:
        if not self.continue_sent and self.headers.get("expect", "").lower() == "100-continue":
            self.continue_sent = True
            self.conn.sock.settimeout(SEND_TIMEOUT_S)
            self.conn.sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    def read_body(self, limit: int, timeout: float = 15.0) -> bytes:
        """The whole body, at most ``limit`` bytes (413 before reading anything when the declared length exceeds it)."""
        if self.content_length > limit:
            raise ApiError(413, "payload_too_large", "request body too large", close=True)
        self._maybe_continue()
        out = bytearray()
        deadline = time.monotonic() + timeout
        mv = memoryview(self.conn.scratch)
        while len(out) < self.content_length:
            left = deadline - time.monotonic()
            if left <= 0:
                raise ApiError(408, "request_timeout", "request timeout", close=True)
            try:
                n = self.conn.read_into(mv[:min(len(mv), self.content_length - len(out))], left)
            except TimeoutError:
                raise ApiError(408, "request_timeout", "request timeout", close=True) from None
            if n == 0:
                raise ApiError(400, "invalid_request", "truncated body", close=True)
            out += mv[:n]
        self.body_read = len(out)
        return bytes(out)

    def discard_body(self, deadline_s: float, on_bytes: Callable[[int], None] | None = None) -> int:
        """Read and drop the body, counting bytes; returns bytes consumed (may be fewer than declared on abort)."""
        self._maybe_continue()
        mv = memoryview(self.conn.scratch)
        deadline = time.monotonic() + deadline_s
        total = 0
        while total < self.content_length:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            try:
                n = self.conn.read_into(mv[:min(len(mv), self.content_length - total)], min(left, 15.0))
            except (TimeoutError, OSError):
                break
            if n == 0:
                break
            total += n
            if on_bytes is not None:
                on_bytes(n)
        self.body_read = total
        return total


class Response:
    __slots__ = ("status", "headers", "body", "stream", "length", "close")

    def __init__(self, status: int, headers: list[tuple[str, str]] | None = None, body: bytes = b"",
                 stream: Callable[[socket.socket], None] | None = None, length: int | None = None, close: bool = False) -> None:
        self.status, self.headers, self.body, self.stream, self.close = status, headers or [], body, stream, close
        self.length = len(body) if length is None else length


_REASONS = {100: "Continue", 200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 301: "Moved Permanently",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
            408: "Request Timeout", 409: "Conflict", 411: "Length Required", 413: "Payload Too Large",
            414: "URI Too Long", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
            500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable", 505: "HTTP Version Not Supported"}

_date_cache: tuple[int, str] = (0, "")


def http_date() -> str:
    global _date_cache
    now = int(time.time())
    if _date_cache[0] != now:
        _date_cache = (now, formatdate(now, usegmt=True))
    return _date_cache[1]


def parse_head(head: bytes, conn: Conn, server: HttpServer) -> Request:
    lines = head.split(b"\r\n")
    if len(lines[0]) > MAX_REQUEST_LINE:
        raise ApiError(414, "uri_too_long", "request line too long", close=True)
    parts = lines[0].split(b" ")
    if len(parts) != 3:
        raise ApiError(400, "invalid_request", "malformed request line", close=True)
    try:
        method, raw_target, version = (p.decode("ascii") for p in parts)
    except UnicodeDecodeError:
        raise ApiError(400, "invalid_request", "malformed request line", close=True) from None
    if not _METHOD.match(method):
        raise ApiError(400, "invalid_request", "malformed method", close=True)
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise ApiError(505, "http_version", "http version not supported", close=True)
    if not raw_target.startswith("/") or raw_target.startswith("//"):
        raise ApiError(400, "invalid_request", "only origin-form request targets are accepted", close=True)
    if len(lines) - 1 > MAX_HEADERS:
        raise ApiError(431, "header_too_large", "too many headers", close=True)
    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if not ln or ln[:1] in (b" ", b"\t"):
            raise ApiError(400, "invalid_request", "malformed header", close=True)
        name, sep, val = ln.partition(b":")
        if not sep or not _TOKEN.match(name):
            raise ApiError(400, "invalid_request", "malformed header", close=True)
        text = val.strip(b" \t").decode("latin-1")
        if _BAD_VALUE.search(text):
            raise ApiError(400, "invalid_request", "malformed header value", close=True)
        key = name.decode("ascii").lower()
        if key in headers and key in ("content-length", "host", "transfer-encoding", "x-exp-leg-token", "x-exp-view-proof"):
            raise ApiError(400, "invalid_request", "duplicate header", close=True)
        headers[key] = text
    if "transfer-encoding" in headers:
        raise ApiError(501, "not_implemented", "transfer encodings are not supported", close=True)
    cl = 0
    if "content-length" in headers:
        if not _DIGITS.match(headers["content-length"]):
            raise ApiError(400, "invalid_request", "invalid content-length", close=True)
        cl = int(headers["content-length"])
    path_raw, _, qs = raw_target.partition("?")
    if len(qs) > MAX_QUERY:
        raise ApiError(414, "uri_too_long", "query too long", close=True)
    try:
        path = urllib.parse.unquote(path_raw, errors="strict")
        pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True, max_num_fields=16, errors="strict")
    except (ValueError, UnicodeDecodeError):
        raise ApiError(400, "invalid_request", "malformed target", close=True) from None
    if re.search(r"[\x00-\x1f\x7f\\]", path):
        raise ApiError(400, "invalid_request", "malformed path", close=True)
    query: dict[str, str] = {}
    for k, v in pairs:
        query.setdefault(k, v)
    return Request(method, raw_target, path, query, version, headers, conn, cl, server)


class HttpServer:
    """Threaded accept loop around ``app.handle(request) -> Response``. ``app.on_response(request, response)`` is optional."""

    def __init__(self, host: str, port: int, app: Any, *, ssl_context: ssl.SSLContext | None = None,
                 max_connections: int = 512, max_per_ip: int = 48, name: str = "http") -> None:
        self.host, self._want_port, self.app, self.ssl_context, self.name = host, port, app, ssl_context, name
        self.max_connections, self.max_per_ip = max_connections, max_per_ip
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._count = 0
        self._per_ip: dict[str, int] = {}
        self.port = 0
        self.connections_total = 0
        self.connections_refused = 0

    @property
    def connections(self) -> int:
        return self._count

    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, self._want_port))
        except OSError:
            s.close()
            raise
        s.listen(256)
        s.settimeout(0.5)
        self._listener = s
        self.port = s.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, name=f"{self.name}-accept", daemon=True)
        self._thread.start()
        log.info("%s listening on %s:%d%s", self.name, self.host, self.port, " (tls)" if self.ssl_context else "")

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def _accept_loop(self) -> None:
        lst = self._listener
        if lst is None:
            return
        while not self._stop.is_set():
            try:
                sock, addr = lst.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            ip = addr[0]
            with self._lock:
                if self._count >= self.max_connections or self._per_ip.get(ip, 0) >= self.max_per_ip:
                    self.connections_refused += 1
                    sock.close()
                    continue
                self._count += 1
                self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
                self.connections_total += 1
            threading.Thread(target=self._serve, args=(sock, ip), name=f"{self.name}-conn", daemon=True).start()

    # ----------------------------------------------------------------------------------------- one connection
    def _serve(self, sock: socket.socket, ip: str) -> None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.ssl_context is not None:
                sock.settimeout(HEAD_TIMEOUT_S)
                sock = self.ssl_context.wrap_socket(sock, server_side=True)
            conn = Conn(sock, ip)
            first = HEAD_TIMEOUT_S
            for _ in range(MAX_REQUESTS_PER_CONN):
                close = self._one(conn, first)
                first = IDLE_TIMEOUT_S
                if close:
                    break
        except (OSError, ssl.SSLError):
            pass
        except Exception:
            log.exception("%s: unexpected error on a connection", self.name)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            with self._lock:
                self._count -= 1
                n = self._per_ip.get(ip, 1) - 1
                if n <= 0:
                    self._per_ip.pop(ip, None)
                else:
                    self._per_ip[ip] = n

    def _one(self, conn: Conn, first_timeout: float) -> bool:
        """Serve one request; True when the connection must close."""
        req: Request | None = None
        try:
            head = conn.recv_head(first_timeout)
            if head is None:
                return True
            req = parse_head(head, conn, self)
            resp = self.app.handle(req)
        except ApiError as exc:
            resp = error_response(exc)
            if exc.close:
                resp.close = True
        except (OSError, ssl.SSLError):
            return True
        except Exception:
            log.exception("%s: handler crashed", self.name)
            resp = error_response(ApiError(500, "internal_error", "internal error", close=True))
            resp.close = True
        close = resp.close or req is None or not req.keep_alive
        if req is not None and req.content_length and req.body_read < req.content_length:
            close = True                                    # an unread body would desync the next request
        try:
            self._write(conn, req, resp, close)
        except (OSError, ssl.SSLError):
            return True
        hook = getattr(self.app, "on_response", None)
        if hook is not None and req is not None:
            try:
                hook(req, resp)
            except Exception:
                log.exception("%s: on_response hook failed", self.name)
        return close

    def _write(self, conn: Conn, req: Request | None, resp: Response, close: bool) -> None:
        reason = _REASONS.get(resp.status, "Status")
        hdrs = [("Date", http_date()), ("Server", "exp-speedtest")]
        has_len = False
        for k, v in resp.headers:
            hdrs.append((k, v))
            has_len |= k.lower() == "content-length"
        if not has_len and resp.length >= 0 and resp.status not in (204, 304):    # length -1 = unknown (SSE): close-delimited
            hdrs.append(("Content-Length", str(resp.length)))
        hdrs.append(("Connection", "close" if close else "keep-alive"))
        head = f"HTTP/1.1 {resp.status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "\r\n"
        sock = conn.sock
        sock.settimeout(SEND_TIMEOUT_S)
        head_only = req is not None and req.method == "HEAD"
        if resp.stream is not None and not head_only:
            sock.sendall(head.encode("latin-1"))
            resp.stream(sock)
        elif resp.body and not head_only:
            sock.sendall(head.encode("latin-1") + resp.body)
        else:
            sock.sendall(head.encode("latin-1"))


def error_response(exc: ApiError) -> Response:
    import json
    body = json.dumps(exc.body(), separators=(",", ":")).encode("utf-8")
    hdrs = [("Content-Type", "application/json"), ("Cache-Control", "no-store"), *API_SECURITY_HEADERS, *exc.headers.items()]
    return Response(exc.status, hdrs, body, close=exc.close)


API_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
]
