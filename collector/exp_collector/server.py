"""HTTPS server (03-collector.md section 2).

``ThreadingHTTPServer`` + ``ssl.SSLContext`` (TLS >= 1.2). Hard limits: <= 512 concurrent
connections (excess -> 503), 10 s to deliver the request line and headers in total (slowloris),
request line <= 8 KiB, header block <= 32 KiB / 64 headers, body limits per route. The route table
is FIXED: anything not registered is 404, a registered path with the wrong method is 405.
``GET /healthz`` is the only unauthenticated route and says only ``ok`` or ``fail``.
Errors use the contract envelope; no stack traces or secrets ever reach a client.
"""
from __future__ import annotations

import http.client
import io
import json
import logging
import re
import socket
import ssl
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import auth
from .ingest import IngestError, gunzip_bounded

if TYPE_CHECKING:  # pragma: no cover
    from .app import CollectorApp

log = logging.getLogger(__name__)

MAX_CONNECTIONS = 512
HEADER_TIMEOUT_S = 10.0
MAX_REQUEST_LINE = 8 * 1024
MAX_HEADER_LINE = 8 * 1024
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADERS = 64
BODY_READ_TIMEOUT_S = 15.0
BODY_TOTAL_TIMEOUT_S = 60.0
DRAIN_LIMIT = 64 * 1024            # unread body we will swallow to keep a connection after an error
DRAIN_LIMIT_413 = 8 * 1024 * 1024  # an oversize upload is drained so the client can read the 413
DRAIN_DEADLINE_S = 15.0
MAX_REJECT_THREADS = 32

AUTH_NONE = "none"
AUTH_INGEST = auth.SCOPE_INGEST
AUTH_DASHBOARD = auth.SCOPE_DASHBOARD
# The ONE /api route an executor (probe or runner) calls with its ingest token: the drill kill switch.
EXECUTOR_ROUTE = "/api/v1/drills/control"

_PARAM = re.compile(r"\{([a-z_]+)\}")
_SEGMENT = r"[A-Za-z0-9_.-]{1,128}"


class HttpError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None,
                 details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.headers = headers or {}
        self.details = details or {}


@dataclass
class Route:
    method: str
    pattern: re.Pattern[str]
    template: str
    handler: Callable[[Handler], None]
    auth: str
    max_body: int


class Router:
    """The fixed route table. Routes are registered at start-up by the application; nothing
    user-controlled ever adds or changes one."""

    def __init__(self) -> None:
        self._routes: list[Route] = []

    def add(self, method: str, template: str, handler: Callable[[Handler], None], *, auth: str,
            max_body: int = 0) -> None:
        if auth not in (AUTH_NONE, AUTH_INGEST, AUTH_DASHBOARD):
            raise ValueError(f"bad auth scope {auth!r}")
        if template.startswith("/ingest/") and auth != AUTH_INGEST:
            raise ValueError("/ingest/* routes must use ingest-token auth")
        if template.startswith("/api/") and auth != AUTH_DASHBOARD and not (
                template == EXECUTOR_ROUTE and auth == AUTH_INGEST):
            raise ValueError("/api/* routes must use dashboard-token auth")
        rx = "^" + _PARAM.sub(lambda m: f"(?P<{m.group(1)}>{_SEGMENT})", re.escape(template).replace("\\{", "{")
                              .replace("\\}", "}")) + "$"
        self._routes.append(Route(method, re.compile(rx), template, handler, auth, max_body))

    def match(self, method: str, path: str) -> tuple[Route | None, dict[str, str], bool]:
        """(route, params, path_known). `path_known` distinguishes 404 from 405."""
        known = False
        for r in self._routes:
            m = r.pattern.match(path)
            if m is None:
                continue
            known = True
            if r.method == method or (method == "HEAD" and r.method == "GET"):
                return r, m.groupdict(), True
        return None, {}, known

    def allowed(self, path: str) -> list[str]:
        return sorted({r.method for r in self._routes if r.pattern.match(path)})

    def templates(self) -> list[tuple[str, str]]:
        return [(r.method, r.template) for r in self._routes]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: ExpHTTPServer

    # --- plumbing ------------------------------------------------------------------------------
    def version_string(self) -> str:
        return "exp-collector"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        log.debug("%s %s", self.address_string(), format % args)

    @property
    def app(self) -> CollectorApp:
        return self.server.app

    @property
    def client_ip(self) -> str:
        return str(self.client_address[0])

    def _abort_conn(self) -> None:
        """Header deadline hit: tear the connection down so blocked reads return."""
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    @property
    def user(self) -> str:
        """The dashboard user from ``X-Exp-User`` (audit only, never used for authorization): printable
        ASCII-ish text <= 128 chars with control characters removed; "-" when absent."""
        raw = self.headers.get("X-Exp-User") or ""
        return "".join(ch for ch in raw if ch >= " " and ch != "\x7f")[:128].strip() or "-"

    # --- request loop --------------------------------------------------------------------------
    def handle_one_request(self) -> None:
        self.close_connection = True
        self.command = "GET"
        self.requestline = ""
        self.request_version = "HTTP/1.1"
        self.identity: str | None = None
        self.params: dict[str, str] = {}
        self.query: dict[str, list[str]] = {}
        self._body_remaining = 0
        self._responded = False
        timer = threading.Timer(self.server.header_timeout, self._abort_conn)
        timer.daemon = True
        timer.start()
        try:
            ok = self._read_head()
        except (OSError, ssl.SSLError, ValueError):
            return
        finally:
            timer.cancel()
        if not ok:
            return
        try:
            self.connection.settimeout(BODY_READ_TIMEOUT_S)
            self._dispatch()
        except HttpError as err:
            self._send_error(err)
        except (OSError, ssl.SSLError):
            self.close_connection = True
        except Exception:  # noqa: BLE001 - never leak internals
            log.exception("unhandled error serving %s %s", self.command, self.path.split("?")[0])
            if not self._responded:
                self._send_error(HttpError(500, "internal_error", "internal error"))
            self.close_connection = True
        finally:
            try:
                self.connection.settimeout(self.server.header_timeout)
            except OSError:
                self.close_connection = True

    def _read_head(self) -> bool:
        line = self.rfile.readline(MAX_REQUEST_LINE + 1)
        if not line:
            return False
        if len(line) > MAX_REQUEST_LINE:
            self._send_error(HttpError(414, "uri_too_long", "request line too long"), close=True)
            return False
        self.raw_requestline = line
        self.requestline = line.decode("iso-8859-1").rstrip("\r\n")
        parts = self.requestline.split(" ")
        if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0") or not parts[0].isalpha():
            self._send_error(HttpError(400, "bad_request", "malformed request line"), close=True)
            return False
        self.command, self.path, self.request_version = parts
        raw = bytearray()
        count = 0
        while True:
            h = self.rfile.readline(MAX_HEADER_LINE + 1)
            if len(h) > MAX_HEADER_LINE:
                self._send_error(HttpError(431, "headers_too_large", "header line too long"), close=True)
                return False
            if h in (b"\r\n", b"\n"):
                break
            if not h:
                return False
            count += 1
            raw += h
            if count > MAX_HEADERS or len(raw) > MAX_HEADER_BYTES:
                self._send_error(HttpError(431, "headers_too_large", "too many or too large headers"), close=True)
                return False
        try:
            self.headers = http.client.parse_headers(io.BytesIO(bytes(raw) + b"\r\n"))
        except http.client.HTTPException:
            self._send_error(HttpError(400, "bad_request", "malformed headers"), close=True)
            return False
        conn_hdr = (self.headers.get("Connection") or "").lower()
        self.close_connection = (self.request_version == "HTTP/1.0" or "close" in conn_hdr)
        return True

    # --- dispatch ------------------------------------------------------------------------------
    def _dispatch(self) -> None:
        if not self.path.startswith("/"):
            raise HttpError(400, "bad_request", "bad request target")
        path, _, qs = self.path.partition("?")
        try:
            self.query = urllib.parse.parse_qs(qs, keep_blank_values=True, max_num_fields=64,
                                               errors="strict")
        except ValueError:
            raise HttpError(400, "bad_request", "bad query string") from None
        self.path_only = path
        route, params, known = self.server.router.match(self.command, path)
        if route is None:
            if known:
                raise HttpError(405, "method_not_allowed", "method not allowed",
                                {"Allow": ", ".join(self.server.router.allowed(path))})
            raise HttpError(404, "not_found", "no such path")
        self.params = params
        cl = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding"):
            raise HttpError(400, "bad_request", "chunked transfer encoding is not supported")
        if cl is not None:
            if not cl.isdigit() or len(cl) > 12:
                raise HttpError(400, "bad_request", "bad Content-Length")
            self._body_remaining = int(cl)
        if route.auth != AUTH_NONE:
            ident = auth.authenticate(self.app.creds, route.auth, self.headers.get("Authorization"))
            if ident is None:
                self.app.note_auth_failure(self.client_ip, route.auth)
                raise HttpError(401, "invalid_token", "missing or invalid token", {"WWW-Authenticate": "Bearer"})
            self.identity = ident
        route.handler(self)

    # --- body ----------------------------------------------------------------------------------
    def read_body(self, limit: int) -> bytes:
        """The whole request body (Content-Length required for non-empty bodies), at most `limit`."""
        n = self._body_remaining
        if self.headers.get("Content-Length") is None:
            raise HttpError(400, "length_required", "Content-Length is required")
        if n > limit:
            raise HttpError(413, "payload_too_large", f"body exceeds {limit} bytes")
        if (self.headers.get("Expect") or "").lower() == "100-continue":
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            self.wfile.flush()
        deadline = time.monotonic() + BODY_TOTAL_TIMEOUT_S
        chunks: list[bytes] = []
        left = n
        while left > 0:
            if time.monotonic() > deadline:
                self.close_connection = True
                raise HttpError(408, "request_timeout", "body took too long")
            try:
                chunk = self.rfile.read(min(65536, left))
            except TimeoutError:
                self.close_connection = True
                raise HttpError(408, "request_timeout", "timed out reading the body") from None
            if not chunk:
                self.close_connection = True
                raise OSError("client closed the connection mid-body")
            chunks.append(chunk)
            left -= len(chunk)
        self._body_remaining = 0
        return b"".join(chunks)

    def _discard_body(self, limit: int = DRAIN_LIMIT) -> None:
        """Before answering an error: drain a bounded unread body (so the client can read our
        answer), else close the connection."""
        n = self._body_remaining
        if n <= 0:
            return
        if n > limit:
            self.close_connection = True
            return
        try:
            self.connection.settimeout(2.0)
            deadline = time.monotonic() + DRAIN_DEADLINE_S
            left = n
            while left > 0:
                if time.monotonic() > deadline:
                    self.close_connection = True
                    return
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    self.close_connection = True
                    return
                left -= len(chunk)
            self._body_remaining = 0
        except (OSError, ssl.SSLError):
            self.close_connection = True

    # --- responses -----------------------------------------------------------------------------
    def _send(self, status: int, body: bytes, ctype: str, headers: dict[str, str] | None = None) -> None:
        self._responded = True
        if self._body_remaining > 0:
            self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()

    def send_json(self, status: int, obj: Any, headers: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8"),
                   "application/json", headers)

    # --- streaming (SSE) -----------------------------------------------------------------------
    def begin_stream(self, ctype: str = "text/event-stream") -> None:
        """Start an open-ended response (no Content-Length; the connection closes at the end)."""
        self._responded = True
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()

    def write_stream(self, data: bytes) -> None:
        """One chunk of an open response; raises OSError when the client is gone or too slow."""
        self.wfile.write(data)
        self.wfile.flush()

    def send_text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _send_error(self, err: HttpError, close: bool = False) -> None:
        if close:
            self.close_connection = True
        else:
            self._discard_body(DRAIN_LIMIT_413 if err.status == 413 else DRAIN_LIMIT)
        if status_closes(err.status):
            self.close_connection = True
        body = {"error": {"code": err.code, "message": err.message, "details": err.details}}
        try:
            self.send_json(err.status, body, err.headers)
        except (OSError, ssl.SSLError):
            self.close_connection = True


def status_closes(status: int) -> bool:
    return status in (400, 408, 413, 414, 431, 500)


class ExpHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256

    def __init__(self, address: tuple[str, int], app: CollectorApp, router: Router,
                 ssl_context: ssl.SSLContext, *, max_connections: int = MAX_CONNECTIONS,
                 header_timeout: float = HEADER_TIMEOUT_S) -> None:
        self.app = app
        self.router = router
        self.ssl_context = ssl_context
        self.max_connections = max_connections
        self.header_timeout = header_timeout
        self._slots = threading.BoundedSemaphore(max_connections)
        self._reject_slots = threading.BoundedSemaphore(MAX_REJECT_THREADS)
        self._active = 0
        self._active_lock = threading.Lock()
        self.rejected_connections = 0
        super().__init__(address, Handler)

    @property
    def active_connections(self) -> int:
        return self._active

    # The listening socket stays plain; TLS is negotiated in the per-connection thread so a slow
    # handshake can never block accept().
    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self._reject_overloaded(request)
            return
        with self._active_lock:
            self._active += 1
        t = threading.Thread(target=self.process_request_thread, args=(request, client_address),
                             name="http-conn", daemon=True)
        t.start()

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            request.settimeout(self.header_timeout)
            try:
                request = self.ssl_context.wrap_socket(request, server_side=True)
            except (OSError, ssl.SSLError):
                return
            self.finish_request(request, client_address)
        except Exception:  # noqa: BLE001
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            with self._active_lock:
                self._active -= 1
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        log.debug("connection error from %s", client_address[0], exc_info=True)

    def _reject_overloaded(self, raw: socket.socket) -> None:
        self.rejected_connections += 1
        if not self._reject_slots.acquire(blocking=False):
            self.shutdown_request(raw)
            return
        threading.Thread(target=self._send_503, args=(raw,), name="http-reject", daemon=True).start()

    def _send_503(self, raw: socket.socket) -> None:
        conn: Any = raw
        try:
            raw.settimeout(2.0)
            conn = self.ssl_context.wrap_socket(raw, server_side=True)
            body = b'{"error":{"code":"unavailable","message":"too many connections","details":{}}}'
            head = ("HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nRetry-After: 1\r\nConnection: close\r\n\r\n")
            conn.sendall(head.encode("ascii") + body)
            try:  # let the client finish sending so closing does not turn into a reset
                conn.settimeout(0.3)
                conn.recv(4096)
            except OSError:
                pass
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.shutdown_request(conn)
            self._reject_slots.release()


def build_ssl_context(cert: Path, key: Path) -> ssl.SSLContext:
    """TLS >= 1.2 server context from the locally generated key/cert. Refuses a key that is
    readable by 'other'."""
    import os
    import stat
    try:
        st = os.stat(key)
    except OSError as exc:
        raise ssl.SSLError(f"TLS key {key} is not readable ({exc.strerror})") from exc
    if st.st_mode & stat.S_IRWXO:
        raise ssl.SSLError(f"TLS key {key} is accessible to 'other' (mode {st.st_mode & 0o777:04o}); "
                           "refusing to use it")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.load_cert_chain(str(cert), str(key))
    return ctx


# --------------------------------------------------------------------------------- route handlers

def handle_healthz(req: Handler) -> None:
    ok = req.app.healthy()
    req.send_text(200 if ok else 503, "ok" if ok else "fail")


def handle_ingest(req: Handler) -> None:
    app = req.app
    ctype = (req.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if ctype != "application/x-ndjson":
        raise HttpError(415, "unsupported_media_type", "Content-Type must be application/x-ndjson")
    enc = (req.headers.get("Content-Encoding") or "identity").strip().lower()
    if enc not in ("gzip", "identity"):
        raise HttpError(415, "unsupported_media_type", "Content-Encoding must be gzip or identity")
    try:
        app.ingestor.check_backpressure()
    except IngestError as e:
        raise HttpError(e.status, e.code, e.message, e.headers) from None
    wire = req.read_body(app.config.max_body_bytes)
    try:
        body = gunzip_bounded(wire) if enc == "gzip" else wire
        if req.identity is None:  # unreachable: the route requires ingest auth
            raise HttpError(401, "invalid_token", "missing or invalid token")
        result = app.ingestor.process(req.identity, body, len(wire))
    except IngestError as e:
        raise HttpError(e.status, e.code, e.message, e.headers) from None
    req.send_json(200, result)
