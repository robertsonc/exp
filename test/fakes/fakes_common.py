"""Shared plumbing for the exp fakes (dev/test tooling; stdlib only).

Provides: sys.path setup for exp_common, deterministic fake tokens, a threaded HTTP(S) server wrapper
with start()/stop() returning the bound port, and request/response helpers (error envelope, bounded body
reads, bearer parsing, loopback check). Nothing here talks to a real network: every fake binds
127.0.0.1 unless told otherwise.
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import logging
import socketserver
import ssl
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
_SHARED_PY = str(REPO_ROOT / "shared" / "python")
if _SHARED_PY not in sys.path:
    sys.path.insert(0, _SHARED_PY)

from exp_common import ids as exp_ids  # noqa: E402
from exp_common import tlspin  # noqa: E402
from exp_common.schema import utcnow  # noqa: E402

log = logging.getLogger("exp.fakes")

FIXTURES_DIR = REPO_ROOT / "test" / "fixtures"
VERSION = "0.1.0"

__all__ = [
    "FIXTURES_DIR",
    "REPO_ROOT",
    "VERSION",
    "BaseHandler",
    "FakeServer",
    "bearer_token",
    "cursor_decode",
    "cursor_encode",
    "det_id",
    "error_body",
    "fixture_token",
    "iso_from_epoch",
    "load_fixture",
    "token_hash",
    "utcnow",
]


# ------------------------------------------------------------------------------------------ tokens

def fixture_token(kind: str, name: str) -> str:
    """Deterministic, obviously-fake token: prefix + base64url(sha256("fixture:<name>")) (43 chars)."""
    prefix = kind if kind.endswith("_") else kind + "_"
    body = base64.urlsafe_b64encode(hashlib.sha256(f"fixture:{name}".encode()).digest()).rstrip(b"=").decode()
    token = prefix + body
    if not exp_ids.is_token(token):  # pragma: no cover - guards a wrong `kind`
        raise ValueError(f"bad token kind {kind!r}")
    return token


def token_hash(token: str) -> str:
    return exp_ids.token_hash(token)


def bearer_token(header: str | None) -> str | None:
    """The token from ``Authorization: Bearer <token>``; None if absent or malformed."""
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    tok = parts[1].strip()
    return tok if tok and " " not in tok else None


def match_token(token: str | None, hashes: dict[str, str]) -> str | None:
    """Identity whose stored sha256 matches `token`, comparing every entry in constant time."""
    if not token:
        return None
    digest = exp_ids.token_hash(token)
    found: str | None = None
    for ident, stored in hashes.items():
        if exp_ids.tokens_equal(digest, stored) and found is None:
            found = ident
    return found


# ------------------------------------------------------------------------------------------ helpers

def error_body(code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details or {}}}


def det_id(prefix: str, seed: str) -> str:
    """Deterministic prefixed id whose body is a valid ULID, derived from `seed`."""
    n = int.from_bytes(hashlib.sha256(seed.encode()).digest()[:16], "big")   # 128 bits: first char <= 7
    chars = []
    for _ in range(26):
        chars.append(exp_ids.CROCKFORD[n & 31])
        n >>= 5
    return prefix + "".join(reversed(chars))


def cursor_encode(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def cursor_decode(cursor: str | None) -> int:
    """Offset from an opaque cursor; ValueError if malformed."""
    if not cursor:
        return 0
    try:
        off = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))["o"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("invalid cursor") from exc
    if not isinstance(off, int) or isinstance(off, bool) or off < 0:
        raise ValueError("invalid cursor")
    return off


def iso_from_epoch(seconds: float) -> str:
    import datetime
    dt = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def load_fixture(rel: str) -> Any:
    with open(FIXTURES_DIR / rel, encoding="utf-8") as fh:
        return json.load(fh)


def is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr in ("::1", "::ffff:127.0.0.1")


# ---------------------------------------------------------------------------------------- the server

class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64
    block_on_close = False

    def handle_error(self, request: Any, client_address: Any) -> None:  # noqa: D401
        # client resets / broken pipes are routine for a fake that refuses oversize bodies
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, ssl.SSLError, TimeoutError)):
            log.debug("client %s: %s", client_address, exc)
            return
        log.exception("unhandled error serving %s", client_address)


class FakeServer:
    """A started/stoppable HTTP(S) server around a handler class and an application object.

    ``start()`` returns the bound port. The handler reaches the application via ``self.server.app``.
    """

    def __init__(self, handler: type[http.server.BaseHTTPRequestHandler], app: Any, *,
                 host: str = "127.0.0.1", port: int = 0, tls: tuple[Path, Path] | None = None,
                 name: str = "fake") -> None:
        self._handler = handler
        self.app = app
        self.host = host
        self._want_port = port
        self._tls = tls
        self.name = name
        self.httpd: _Server | None = None
        self.thread: threading.Thread | None = None
        self.port = 0
        self.fingerprint: str | None = None
        self.stopping = threading.Event()
        if tls is not None:
            self.fingerprint = tlspin.fingerprint_of_pem_file(tls[0])

    @property
    def scheme(self) -> str:
        return "https" if self._tls else "http"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def start(self) -> int:
        if self.httpd is not None:
            return self.port
        httpd = _Server((self.host, self._want_port), self._handler)
        httpd.app = self.app  # type: ignore[attr-defined]
        httpd.fake = self  # type: ignore[attr-defined]
        if self._tls is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(str(self._tls[0]), str(self._tls[1]))
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self.httpd = httpd
        self.port = httpd.server_address[1]
        self.stopping.clear()
        self.thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.1},
                                       name=f"{self.name}-http", daemon=True)
        self.thread.start()
        log.info("%s listening on %s", self.name, self.base_url)
        return self.port

    def stop(self) -> None:
        self.stopping.set()
        httpd, self.httpd = self.httpd, None
        if httpd is None:
            return
        httpd.shutdown()
        httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
            self.thread = None


class BaseHandler(http.server.BaseHTTPRequestHandler):
    """HTTP/1.1 handler with JSON helpers. Subclasses implement ``dispatch(method, path, query)``."""

    protocol_version = "HTTP/1.1"
    server_version = "exp-fake/0.1"
    sys_version = ""
    timeout = 30  # per-socket read timeout: a stalled client cannot pin a thread forever

    # -- plumbing --------------------------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        log.debug("%s - %s", self.address_string(), fmt % args)

    @property
    def app(self) -> Any:
        return self.server.app  # type: ignore[attr-defined]

    @property
    def fake(self) -> FakeServer:
        return self.server.fake  # type: ignore[attr-defined]

    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._route("PUT")

    def do_PATCH(self) -> None:  # noqa: N802
        self._route("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._route("DELETE")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._route("OPTIONS")

    def do_HEAD(self) -> None:  # noqa: N802
        self._route("HEAD")

    def _route(self, method: str) -> None:
        import urllib.parse
        self._body_consumed = False
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        try:
            self.dispatch(method, parts.path, query)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:  # noqa: BLE001 - last-resort: a fake must answer, not hang the client
            log.exception("fake handler crashed on %s %s", method, parts.path)
            self.close_connection = True
            try:
                self.send_json(500, error_body("internal_error", "fake crashed"))
            except OSError:
                pass
        finally:
            # an unread request body on a keep-alive connection would desync the next request
            if not self._body_consumed and int(self.headers.get("Content-Length") or 0) > 0:
                self.close_connection = True

    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        raise NotImplementedError

    # -- request helpers -------------------------------------------------------------------------
    def header(self, name: str) -> str | None:
        return self.headers.get(name)

    def client_is_loopback(self) -> bool:
        return is_loopback(self.client_address[0])

    def content_length(self) -> int | None:
        raw = self.headers.get("Content-Length")
        if raw is None:
            return None
        try:
            n = int(raw)
        except ValueError:
            return -1
        return n if n >= 0 else -1

    def read_body(self, limit: int) -> bytes | None:
        """Read the request body (Content-Length framed) if <= limit; else drain and return None.

        Returns b"" for no body. Chunked requests are not supported (411 is the caller's call)."""
        n = self.content_length()
        if n is None:
            self._body_consumed = True
            return b""
        if n < 0:
            return None
        if n > limit:
            self.drain(n)
            return None
        data = self._read_exact(n)
        self._body_consumed = True
        return data

    def _read_exact(self, n: int) -> bytes:
        chunks: list[bytes] = []
        left = n
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
        return b"".join(chunks)

    def drain(self, n: int, cap: int = 64 * 1024 * 1024) -> None:
        """Discard up to `cap` request-body bytes so the client sees our response, not a reset."""
        left = min(n, cap)
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            left -= len(chunk)
        self._body_consumed = True
        self.close_connection = True

    def read_json(self, limit: int = 1024 * 1024) -> tuple[Any, bool]:
        """(parsed, ok). On failure the 4xx response has already been sent and ok is False."""
        body = self.read_body(limit)
        if body is None:
            self.send_json(413, error_body("payload_too_large", "request body too large"))
            return None, False
        if not body:
            self.send_json(400, error_body("invalid_request", "a JSON body is required"))
            return None, False
        try:
            from exp_common import config as exp_config
            return exp_config.parse_json(body, "request body"), True
        except ValueError as exc:
            self.send_json(400, error_body("invalid_request", f"invalid JSON: {exc}"[:512]))
            return None, False

    # -- response helpers ------------------------------------------------------------------------
    def send_bytes(self, status: int, body: bytes, content_type: str,
                   headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, obj: Any, headers: dict[str, str] | None = None) -> None:
        self.send_bytes(status, json.dumps(obj, separators=(",", ":")).encode("utf-8"),
                        "application/json", headers)

    def send_empty(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        if status != 304:
            self.send_header("Content-Length", "0")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def send_err(self, status: int, code: str, message: str, details: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None) -> None:
        self.send_json(status, error_body(code, message, details), headers)

    def send_text(self, status: int, text: str, content_type: str = "text/plain",
                  headers: dict[str, str] | None = None) -> None:
        self.send_bytes(status, text.encode("utf-8"), content_type + "; charset=utf-8", headers)


def run_forever(server: FakeServer, banner: Callable[[], str] | None = None) -> None:
    """Block until Ctrl-C / SIGTERM (CLI entry points)."""
    import signal
    port = server.start()
    if banner:
        print(banner(), flush=True)
    else:
        print(f"{server.name} listening on {server.base_url} (port {port})", flush=True)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        while not stop.wait(0.5):
            pass
    finally:
        server.stop()


def prepare_tls(state_dir: Path, cn: str = "localhost") -> tuple[Path, Path, str]:
    """Self-signed cert/key under <state_dir>/tls (reused if present); returns (cert, key, fingerprint)."""
    tdir = Path(state_dir) / "tls"
    cert, key = tdir / "cert.pem", tdir / "key.pem"
    if not (cert.is_file() and key.is_file()):
        cert, key = tlspin.generate_self_signed_cert(tdir, cn=cn)
    return cert, key, tlspin.fingerprint_of_pem_file(cert)
