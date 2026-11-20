"""HTTPS server, HTTP->HTTPS redirector, routing, CSRF, security headers, static files."""
from __future__ import annotations

import hmac
import html
import http.server
import json
import logging
import posixpath
import queue
import re
import select
import socket
import socketserver
import ssl
import threading
import time
import urllib.parse
from collections import deque
from pathlib import Path
from typing import Any

from . import __version__
from .auth import AuthError, AuthService, CredentialStore, Throttled, clean_text
from .config import Settings
from .federate import ApiProblem, Federation, valid_id
from .health import HealthSocket
from .health import build as build_health
from .sessions import COOKIE_NAME, Session, SessionStore
from .speedtests import SpeedtestApi
from .sse import Hub, Subscription, format_event

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_CONNECTIONS = 256
MAX_SSE_CLIENTS = 200
ACK_NOTE_MAX = 512                      # shared/openapi/collector.yaml AckRequest.note maxLength
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")   # ... and its pattern ^[^\x00-\x1f\x7f]*$
MAX_BODY = 16 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_REQUEST_TARGET = 4096
SOCKET_TIMEOUT_S = 15.0
SSE_KEEPALIVE_S = 15.0
SESSION_RECHECK_S = 5.0

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
PERMISSIONS_POLICY = ("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), "
                      "microphone=(), payment=(), usb=(), interest-cohort=()")
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8", ".webmanifest": "application/manifest+json",
    ".woff2": "font/woff2", ".map": "application/json",
}
SPA_ROUTES = re.compile(r"^/(probe/[a-z0-9][a-z0-9-]{0,63}|incidents|drills|login"
                        r"|speedtests(/(breakdowns|support|test/st_[0-9A-HJKMNP-TV-Z]{26}))?)?/?$")
_BAD_TARGET = re.compile(r"[\x00-\x20\x7f-\xff\\]")
_HOST_OK = re.compile(r"^[A-Za-z0-9.\-]{1,253}(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:.]{2,45}\](:[0-9]{1,5})?$")
_ERR_TEXT = {"1": "Username or password is wrong.", "429": "Too many attempts. Try again later."}


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, addr: tuple[str, int], handler: type, app: DashboardApp,
                 ctx: ssl.SSLContext | None) -> None:
        self.address_family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
        self.app, self.ctx = app, ctx
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(addr, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            if self.ctx is not None:
                try:
                    request.settimeout(10)
                    request = self.ctx.wrap_socket(request, server_side=True)
                except (ssl.SSLError, OSError) as exc:
                    log.debug("TLS handshake failed from %s: %s", client_address[0], type(exc).__name__)
                    try:
                        request.close()
                    except OSError:
                        pass
                    return
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        log.debug("connection error from %s", client_address[0], exc_info=True)


def security_headers(hsts: bool) -> list[tuple[str, str]]:
    h = [("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"),
         ("Referrer-Policy", "no-referrer"), ("Permissions-Policy", PERMISSIONS_POLICY),
         ("Cross-Origin-Opener-Policy", "same-origin"), ("Cross-Origin-Resource-Policy", "same-origin"),
         ("X-Frame-Options", "DENY")]
    if hsts:
        h.append(("Strict-Transport-Security", "max-age=31536000"))
    return h


def err_body(code: str, message: str, details: dict | None = None) -> bytes:
    return json.dumps({"error": {"code": code, "message": message, "details": details or {}}},
                      separators=(",", ":")).encode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = SOCKET_TIMEOUT_S
    server_version = "exp-dashboard"
    sys_version = ""
    _extra_headers: list[tuple[str, str]] = []   # replaced per request in _handle
    _body_read = False

    # -- plumbing ---------------------------------------------------------------------------
    @property
    def app(self) -> DashboardApp:
        return self.server.app  # type: ignore[attr-defined]

    def version_string(self) -> str:
        return "exp-dashboard"

    def log_message(self, fmt: str, *args: Any) -> None:   # access log: never the query string
        pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self.close_connection = True
        try:
            self._send(code, err_body("bad_request" if code < 500 else "internal_error",
                                      (message or "request refused")[:100]), "application/json")
        except OSError:
            pass

    def parse_request(self) -> bool:
        ok = super().parse_request()
        if ok:
            if sum(len(k) + len(v) + 4 for k, v in self.headers.items()) > MAX_HEADER_BYTES:
                self.send_error(431, "headers too large")
                return False
            if len(self.path) > MAX_REQUEST_TARGET or _BAD_TARGET.search(self.path):
                self.send_error(400, "bad request target")
                return False
            if self.headers.get("Transfer-Encoding") is not None:
                self.send_error(501, "chunked requests are not supported")
                return False
        return ok

    def _send(self, status: int, body: bytes, ctype: str, headers: list[tuple[str, str]] | None = None,
              cache: str = "no-store") -> None:
        self.send_response(status)
        for k, v in security_headers(self.app.hsts):
            self.send_header(k, v)
        self.send_header("Cache-Control", cache)
        if status not in (204, 304):
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or []):
            self.send_header(k, v)
        for k, v in self._extra_headers:
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD" and status not in (204, 304):
            self.wfile.write(body)

    def _json(self, status: int, obj: Any, headers: list[tuple[str, str]] | None = None) -> None:
        self._send(status, json.dumps(obj, separators=(",", ":")).encode(), "application/json", headers)

    def _problem(self, p: ApiProblem, headers: list[tuple[str, str]] | None = None) -> None:
        self._send(p.status, err_body(p.code, p.message, p.details), "application/json", headers)

    def _read_body(self, limit: int = MAX_BODY) -> bytes:
        raw = self.headers.get("Content-Length")
        self._body_read = True
        if raw is None:
            return b""
        if not raw.isdigit() or len(raw) > 9:
            self.close_connection = True
            raise ApiProblem(400, "invalid_request", "bad Content-Length")
        n = int(raw)
        if n > limit:
            self.close_connection = True
            raise ApiProblem(413, "payload_too_large", "request body too large")
        return self.rfile.read(n) if n else b""

    def _body_params(self, body: bytes) -> dict[str, Any]:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if not body:
            return {}
        if ctype == "application/json":
            try:
                doc = json.loads(body.decode("utf-8"))
            except (ValueError, RecursionError):
                raise ApiProblem(400, "invalid_request", "invalid JSON body") from None
            if not isinstance(doc, dict):
                raise ApiProblem(400, "invalid_request", "JSON object expected")
            return doc
        if ctype == "application/x-www-form-urlencoded":
            try:
                pairs = urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True,
                                               strict_parsing=False, max_num_fields=20)
            except (ValueError, UnicodeDecodeError):
                raise ApiProblem(400, "invalid_request", "invalid form body") from None
            return dict(pairs)
        raise ApiProblem(415, "unsupported_media_type", "use application/json or form encoding")

    @property
    def _is_form(self) -> bool:
        ctype = (self.headers.get("Content-Type") or "").lower()
        return ctype.startswith("application/x-www-form-urlencoded")

    # -- sessions ---------------------------------------------------------------------------
    def _cookie_id(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw or len(raw) > 4096:
            return None
        for part in raw.split(";"):
            name, _, val = part.strip().partition("=")
            if name == COOKIE_NAME and re.fullmatch(r"[A-Za-z0-9_-]{20,100}", val):
                return val
        return None

    def _session(self) -> Session | None:
        if self._sess_loaded:
            return self._sess
        self._sess_loaded = True
        sid = self._cookie_id()
        s = self.app.sessions.get(sid) if sid else None
        if s is not None and not self.app.creds.session_valid(s, self.app.clock()):
            self.app.sessions.delete_hash(s.id_hash)
            s = None
        if s is not None and s.kind == "noc":
            s2 = self.app.auth.renew_if_noc(s)
            if s2.expires != s.expires and sid:
                self._extra_headers.append(("Set-Cookie", self._cookie(sid, s2.expires - self.app.clock())))
            s = s2
        self._sess = s
        return s

    def _require(self, min_role: str = "viewer") -> Session:
        s = self._session()
        if s is None:
            raise ApiProblem(401, "unauthorized", "sign in required")
        if min_role == "operator" and s.role == "viewer":
            raise ApiProblem(403, "insufficient_role", "operator role required")
        if min_role == "admin" and s.role != "admin":
            raise ApiProblem(403, "insufficient_role", "admin role required")
        return s

    def _cookie(self, sid: str, max_age: float) -> str:
        return (f"{COOKIE_NAME}={sid}; Max-Age={max(0, int(max_age))}; Secure; HttpOnly; "
                "SameSite=Lax; Path=/")

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return False
        host = self.headers.get("Host", "")
        allowed = {self.app.settings.origin}
        if _HOST_OK.match(host):
            allowed.add("https://" + host)
        return origin in allowed

    def _check_csrf(self, s: Session) -> None:
        """State-changing requests: session cookie (SameSite) AND matching Origin AND CSRF header."""
        if not self._origin_ok():
            raise ApiProblem(403, "csrf_origin", "request origin not allowed")
        tok = self.headers.get("X-Exp-CSRF") or ""
        if not hmac.compare_digest(tok.encode("utf-8", "replace"), s.csrf.encode()):
            raise ApiProblem(403, "csrf_token", "missing or invalid CSRF token")

    def _check_origin_if_present(self) -> None:
        if self.headers.get("Origin") is not None and not self._origin_ok():
            raise ApiProblem(403, "csrf_origin", "request origin not allowed")

    def _client_ip(self) -> str:
        return self.client_address[0]

    # -- dispatch ---------------------------------------------------------------------------
    def _handle(self) -> None:
        self._extra_headers = []
        self._body_read = False
        self._sess: Session | None = None
        self._sess_loaded = False
        self.app.note_request()
        u = urllib.parse.urlsplit(self.path)
        path, query = u.path, urllib.parse.parse_qs(u.query, max_num_fields=30)
        try:
            self._route(self.command, path, query)
        except ApiProblem as p:
            if not self._body_read and self.headers.get("Content-Length", "0") != "0":
                self.close_connection = True       # unread body: never reuse the connection
            hdrs = [("Retry-After", str(p.details["retry_after"]))] if "retry_after" in p.details else None
            self._problem(p, hdrs)
        except (BrokenPipeError, ConnectionResetError, TimeoutError, ssl.SSLError):
            self.close_connection = True
        except Exception:   # noqa: BLE001 - last resort: generic 500, details only in the log
            log.exception("unhandled error serving %s %s", self.command, path)
            self.close_connection = True
            try:
                self._send(500, err_body("internal_error", "internal error"), "application/json")
            except OSError:
                pass

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle

    def _allow(self, method: str, *allowed: str) -> None:
        if method not in allowed:
            self.close_connection = True
            raise ApiProblem(405, "method_not_allowed", "method not allowed")

    def _route(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        if path == "/healthz":
            self._allow(method, "GET", "HEAD")
            return self._send(200, b"ok", "text/plain; charset=utf-8")
        if path.startswith("/api/v1/") or path == "/api/v1":
            return self._api(method, path[len("/api/v1"):].strip("/").split("/") if path != "/api/v1" else [],
                             query)
        if path.startswith("/api/"):
            raise ApiProblem(404, "not_found", "no such endpoint")
        if path.startswith("/auth/"):
            return self._auth_route(method, path)
        self._allow(method, "GET", "HEAD")
        return self._static(path)

    # -- auth routes ------------------------------------------------------------------------
    def _auth_route(self, method: str, path: str) -> None:
        if path == "/auth/login":
            self._allow(method, "GET", "HEAD", "POST")
            return self._login_page() if method != "POST" else self._login_post()
        if path == "/auth/sso":
            self._allow(method, "POST")
            return self._sso_post()
        if path == "/auth/noc":
            self._allow(method, "POST")
            return self._noc_post()
        if path == "/auth/logout":
            self._allow(method, "POST")
            return self._logout()
        if path == "/auth/session":
            self._allow(method, "GET")
            return self._session_info()
        raise ApiProblem(404, "not_found", "no such endpoint")

    def _login_page(self) -> None:
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        msg = _ERR_TEXT.get((q.get("e") or [""])[0], "")
        try:
            page = (STATIC_DIR / "login.html").read_text(encoding="utf-8")
        except OSError:
            raise ApiProblem(404, "not_found", "login page missing") from None
        page = page.replace("@@ERROR@@", html.escape(msg))
        page = page.replace("@@TITLE@@", html.escape(self.app.settings.title))
        self._send(200, page.encode(), CONTENT_TYPES[".html"])

    def _issue(self, sid: str, s: Session, to_page: bool) -> None:
        cookie = ("Set-Cookie", self._cookie(sid, s.expires - self.app.clock()))
        if to_page:
            self._send(303, b"", "text/plain", [cookie, ("Location", "/")])
        else:
            self._json(200, {"user": s.username, "role": s.role, "csrf": s.csrf, "kind": s.kind,
                             "expires": s.expires}, [cookie])

    def _fail_page(self, status: int, retry_after: int | None = None) -> None:
        extra = [("Retry-After", str(retry_after))] if retry_after else None
        if self._is_form:
            if status == 429:
                return self._send(303, b"", "text/plain", [("Location", "/auth/login?e=429")] + (extra or []))
            return self._send(303, b"", "text/plain", [("Location", "/auth/login?e=1")])
        code = "rate_limited" if status == 429 else "unauthorized"
        msg = "too many attempts" if status == 429 else "username or password is wrong"
        self._send(status, err_body(code, msg), "application/json", extra)

    def _login_post(self) -> None:
        params = self._body_params(self._read_body())
        self._check_origin_if_present()
        ip = self._client_ip()
        try:
            sid, s = self.app.auth.login(params.get("username"), params.get("password"), ip)
        except Throttled as t:
            log.warning("login throttled for %s", ip)
            return self._fail_page(429, t.retry_after)
        except AuthError as e:
            log.info("login refused (%s) from %s", e.code, ip)
            return self._fail_page(401)
        log.info("login ok: %s (%s)", clean_text(s.username, 64), s.role)
        self._issue(sid, s, self._is_form)

    def _sso_post(self) -> None:
        # The token is taken ONLY from the POST body; the query string is never looked at.
        params = self._body_params(self._read_body())
        try:
            sid, s = self.app.auth.sso(params.get("token"))
        except AuthError as e:
            log.info("sso refused (%s) from %s", e.code, self._client_ip())
            if self._is_form:
                return self._send(401, b"<!doctype html><meta charset=utf-8><title>Sign-in failed</title>"
                                  b"<p>Sign-in failed. <a href=\"/auth/login\">Use a local account</a></p>",
                                  CONTENT_TYPES[".html"])
            return self._send(401, err_body("unauthorized", "sign-in failed"), "application/json")
        log.info("sso login ok: %s (%s)", clean_text(s.username, 64), s.role)
        self._issue(sid, s, self._is_form)

    def _noc_post(self) -> None:
        params = self._body_params(self._read_body())
        self._check_origin_if_present()
        ip = self._client_ip()
        try:
            sid, s = self.app.auth.noc(params.get("token"), ip)
        except Throttled as t:
            return self._send(429, err_body("rate_limited", "too many attempts"), "application/json",
                              [("Retry-After", str(t.retry_after))])
        except AuthError as e:
            log.info("noc exchange refused (%s) from %s", e.code, ip)   # never the token
            return self._send(401, err_body("unauthorized", "invalid or expired link"), "application/json")
        log.info("noc session started: %s", clean_text(s.subject, 64))
        self._issue(sid, s, False)

    def _logout(self) -> None:
        self._read_body()
        s = self._session()
        clear = ("Set-Cookie", self._cookie("deleted", 0))
        if s is None:
            return self._send(204, b"", "text/plain", [clear])
        self._check_csrf(s)
        sid = self._cookie_id()
        if sid:
            self.app.sessions.delete(sid)
        self.app.hub.drop_session(s.id_hash)
        self._send(204, b"", "text/plain", [clear])

    def _session_info(self) -> None:
        s = self._require()
        st = self.app.settings
        self._json(200, {"user": s.username, "role": s.role, "kind": s.kind, "csrf": s.csrf,
                         "expires": s.expires, "dashboard_id": st.dashboard_id, "title": st.title,
                         "voice": st.voice, "timezone": st.timezone, "version": __version__,
                         "sso": bool(st.sso_issuer and self.app.creds.creds.sso_secret),
                         "local_users": st.local_users,
                         "collectors": [{"collector_id": c.collector_id, "site": c.site}
                                        for c in st.collectors]})

    # -- API --------------------------------------------------------------------------------
    def _api(self, method: str, segs: list[str], query: dict[str, list[str]]) -> None:
        s = self._require()
        if not segs or any(not valid_id(x) for x in segs):
            raise ApiProblem(404, "not_found", "no such endpoint")
        fed = self.app.fed
        user = s.username
        if method not in ("GET", "HEAD"):
            body = self._read_body(4096)
            self._check_csrf(s)
            if segs[0] == "incidents" and len(segs) == 3 and segs[2] == "ack":
                self._allow(method, "POST")
                self._require("operator")
                doc = self._body_params(body) if body else {}
                note = doc.get("note")
                if note is not None and (not isinstance(note, str) or len(note) > ACK_NOTE_MAX
                                         or _CTRL_RE.search(note)):
                    raise ApiProblem(400, "invalid_request",
                                     f"note must be a string of at most {ACK_NOTE_MAX} characters "
                                     "without control characters")
                payload = json.dumps({"note": note} if note else {}).encode()
                return self._relay(*fed.post_try_all(f"incidents/{segs[1]}/ack", user, payload))
            if segs[0] == "drills" and len(segs) == 3 and segs[2] == "abort" and segs[1] != "control":
                self._allow(method, "POST")
                self._require("operator")
                return self._relay(*fed.post_try_all(f"drills/{segs[1]}/abort", user, None))
            if segs == ["speedtests", "purge"]:
                self._allow(method, "POST")
                self._require("admin")        # SR-25: a data-subject purge is an admin (SSO) action
                return self._relay(*self.app.speedtests.purge(self._body_params(body), user))
            raise ApiProblem(404, "not_found", "no such endpoint")
        self._allow(method, "GET", "HEAD")
        if segs[0] == "speedtests":
            return self._speedtests(s, segs, query)
        if len(segs) == 1 and segs[0] == "stream":
            return self._stream(s, query)
        if len(segs) == 1 and segs[0] == "collectors":
            st = self.app.fed.state
            return self._json(200, {"collectors": [
                {"collector_id": c.collector_id, "site": c.site,
                 "ok": st[c.collector_id].ok is not False,
                 **({"error": st[c.collector_id].error} if st[c.collector_id].ok is False else {})}
                for c in self.app.settings.collectors]})
        if len(segs) == 1:
            return self._relay(*fed.get(segs[0], query, user))
        if len(segs) == 2 and segs[0] == "drills" and segs[1] != "control":
            return self._relay(*fed.get_try_all(f"drills/{segs[1]}", user))
        raise ApiProblem(404, "not_found", "no such endpoint")

    def _speedtests(self, s: Session, segs: list[str], query: dict[str, list[str]]) -> None:
        st, admin = self.app.speedtests, s.role == "admin"
        if len(segs) == 1:
            return self._relay(*st.list(query, s.username, admin))
        if len(segs) == 2 and segs[1] == "aggregate":
            return self._relay(*st.aggregate(query, s.username))
        if len(segs) == 2 and segs[1] not in ("purge", "stream"):
            return self._relay(*st.detail(segs[1], query, s.username, admin))
        raise ApiProblem(404, "not_found", "no such endpoint")

    def _relay(self, status: int, body: bytes, extra: dict[str, str]) -> None:
        self._send(status, body, "application/json", list(extra.items()))

    def _stream(self, s: Session, query: dict[str, list[str]]) -> None:
        probes_raw = (query.get("probes") or [""])[0]
        site = (query.get("site") or [""])[0]
        if bool(probes_raw) == bool(site):
            raise ApiProblem(400, "invalid_request", "provide exactly one of probes or site")
        probes: set[str] | None = None
        if probes_raw:
            parts = probes_raw.split(",")
            if len(parts) > 200 or not all(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", p) for p in parts):
                raise ApiProblem(400, "invalid_request", "probes must be a comma-separated list of slugs")
            probes = set(parts)
        elif not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", site):
            raise ApiProblem(400, "invalid_request", "bad site")
        last = self.headers.get("Last-Event-ID")
        if last is not None and len(last) > 64:
            raise ApiProblem(400, "invalid_request", "Last-Event-ID too long")
        hub = self.app.hub
        if hub.client_count >= MAX_SSE_CLIENTS:
            raise ApiProblem(503, "unavailable", "too many live connections", {"retry_after": 5})
        sub = Subscription(probes, None if probes else site, s.id_hash)
        replay = hub.subscribe(sub, last)
        sid = self._cookie_id()
        try:
            self.close_connection = True
            self.send_response(200)
            for k, v in security_headers(self.app.hsts):
                self.send_header(k, v)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            out = self.wfile
            out.write(b"retry: 3000\n\n")
            for cid, up in hub.upstream_up.items():
                info = json.dumps({"collector_id": cid, "ok": up})
                out.write(f"event: collector\ndata: {info}\n\n".encode())
            for e in replay:
                out.write(format_event(e))
            out.flush()
            self.connection.settimeout(10)
            last_write = last_check = time.monotonic()
            while not self.app.stopping.is_set() and not sub.dropped:
                try:
                    e = sub.q.get(timeout=1.0)
                    if e.kind == "collector":
                        out.write(f"event: collector\ndata: {e.data}\n\n".encode())
                    else:
                        out.write(format_event(e))
                    out.flush()
                    last_write = time.monotonic()
                except queue.Empty:
                    if self._peer_gone():
                        break
                now = time.monotonic()
                if now - last_write >= SSE_KEEPALIVE_S:
                    out.write(b": keepalive\n\n")
                    out.flush()
                    last_write = now
                if now - last_check >= SESSION_RECHECK_S:
                    last_check = now
                    cur = self.app.sessions.get(sid) if sid else None
                    if cur is None or not self.app.creds.session_valid(cur, self.app.clock()):
                        break
                    if cur.kind == "noc":
                        self.app.auth.renew_if_noc(cur)
        except (OSError, ssl.SSLError):
            pass
        finally:
            hub.unsubscribe(sub)

    def _peer_gone(self) -> bool:
        """True when the browser closed the connection (EOF/reset), without blocking."""
        conn = self.connection
        try:
            readable, _, _ = select.select([conn], [], [], 0)
            if not readable:
                return False
            return conn.recv(1024) == b""
        except ssl.SSLWantReadError:
            return False
        except (OSError, ValueError):
            return True

    # -- static -----------------------------------------------------------------------------
    def _static(self, path: str) -> None:
        rel = self._safe_static_path(path)
        if rel is None:
            raise ApiProblem(404, "not_found", "not found")
        target = STATIC_DIR / rel
        if path == "/noc" and (STATIC_DIR / "noc.html").is_file():
            target = STATIC_DIR / "noc.html"
        elif SPA_ROUTES.match(path) and (STATIC_DIR / "index.html").is_file():
            target = STATIC_DIR / "index.html"
        try:
            real = target.resolve(strict=True)
            real.relative_to(STATIC_DIR.resolve())
        except (OSError, ValueError, RuntimeError):
            raise ApiProblem(404, "not_found", "not found") from None
        ctype = CONTENT_TYPES.get(real.suffix.lower())
        parts = real.relative_to(STATIC_DIR.resolve()).parts
        if not real.is_file() or ctype is None or any(p.startswith(".") for p in parts):
            raise ApiProblem(404, "not_found", "not found")
        try:
            data = real.read_bytes()
        except OSError:
            raise ApiProblem(404, "not_found", "not found") from None
        self._send(200, data, ctype, cache="no-cache")

    @staticmethod
    def _safe_static_path(path: str) -> str | None:
        """Decoded relative path, or None when it is not a plain file name under the static root."""
        if "\x00" in path or "\\" in path:
            return None
        decoded = urllib.parse.unquote(path)
        if "\x00" in decoded or "\\" in decoded or "%" in decoded:
            return None                      # double-encoded input is refused, not decoded twice
        norm = posixpath.normpath(decoded)
        if decoded.endswith("/") and decoded != "/":
            return None                      # directories are never listed
        if decoded in ("/", ""):
            return "index.html"
        parts = [p for p in norm.split("/") if p]
        if ".." in decoded.split("/") or any(p in (".", "..") or p.startswith(".") for p in parts):
            return None
        return "/".join(parts) if parts else None


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Port 80: ONLY redirects to the configured https origin."""
    protocol_version = "HTTP/1.1"
    timeout = 10.0
    server_version = "exp-dashboard"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def _redirect(self) -> None:
        app: DashboardApp = self.server.app  # type: ignore[attr-defined]
        target = self.path if self.path.startswith("/") and not _BAD_TARGET.search(self.path) \
            and len(self.path) <= MAX_REQUEST_TARGET else "/"
        self.close_connection = True
        self.send_response(301 if self.command in ("GET", "HEAD") else 308)
        self.send_header("Location", app.settings.origin + target)
        for k, v in security_headers(False):
            self.send_header(k, v)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _redirect


class DashboardApp:
    def __init__(self, settings: Settings, *, clock=time.time, watch_interval: float = 5.0) -> None:
        self.settings, self.clock, self.watch_interval = settings, clock, watch_interval
        self.stopping = threading.Event()
        self.started_mono = time.monotonic()
        self.hsts = settings.tls_mode == "provided"
        self._req_times: deque[float] = deque()
        self._req_lock = threading.Lock()
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        self.sessions = SessionStore(settings.sessions_db, clock)
        self.creds = CredentialStore(settings, on_change=self._creds_changed)
        self.auth = AuthService(settings, self.creds, self.sessions, clock)
        self.fed = Federation(settings, lambda: self.creds.creds.collector_tokens, clock)
        self.speedtests = SpeedtestApi(self.fed)
        self.hub = Hub(list(settings.collectors), lambda: self.creds.creds.collector_tokens,
                       self.fed.site_of, clock)
        self.ctx = self._tls_context()
        self._tls_stamp = self._stamp()
        self._servers: list[_Server] = []
        self._threads: list[threading.Thread] = []
        self.health_socket = HealthSocket(self, settings.run_dir)
        self.https_port = 0
        self.http_port = 0
        self.sessions.sweep(lambda s: self.creds.session_valid(s, clock()))   # reconcile at start-up

    # -- tls --------------------------------------------------------------------------------
    def _tls_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(str(self.settings.tls_cert), str(self.settings.tls_key))
        except (OSError, ssl.SSLError) as exc:
            raise RuntimeError(f"cannot load the TLS certificate/key ({self.settings.tls_cert}): "
                               f"{getattr(exc, 'strerror', None) or type(exc).__name__}") from None
        return ctx

    def _stamp(self) -> tuple:
        out = []
        for p in (self.settings.tls_cert, self.settings.tls_key):
            try:
                st = p.stat()
                out.append((st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def _creds_changed(self, _c: Any) -> None:
        if hasattr(self, "auth"):
            self.sessions.sweep(lambda s: self.creds.session_valid(s, self.clock()))

    # -- metrics ----------------------------------------------------------------------------
    def note_request(self) -> None:
        now = time.monotonic()
        with self._req_lock:
            self._req_times.append(now)
            while self._req_times and self._req_times[0] < now - 60:
                self._req_times.popleft()

    def requests_last_minute(self) -> int:
        now = time.monotonic()
        with self._req_lock:
            while self._req_times and self._req_times[0] < now - 60:
                self._req_times.popleft()
            return len(self._req_times)

    # -- lifecycle --------------------------------------------------------------------------
    def start(self) -> None:
        st = self.settings
        https = _Server(st.https, Handler, self, self.ctx)
        self._servers.append(https)
        self.https_port = https.server_address[1]
        if st.http_redirect:
            red = _Server(st.http_redirect, RedirectHandler, self, None)
            self._servers.append(red)
            self.http_port = red.server_address[1]
        for srv in self._servers:
            t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.2},
                                 name="http", daemon=True)
            t.start()
            self._threads.append(t)
        self.hub.start()
        self.fed.start()
        self.health_socket.start()
        w = threading.Thread(target=self._watch, name="watch", daemon=True)
        w.start()
        self._threads.append(w)
        log.info("exp-dashboard %s listening on https %s:%d%s", __version__, st.https[0], self.https_port,
                 f", http redirect :{self.http_port}" if self.http_port else "")

    def _watch(self) -> None:
        last_purge = 0.0
        while not self.stopping.wait(self.watch_interval):
            try:
                self.creds.reload()
                stamp = self._stamp()
                if stamp != self._tls_stamp:
                    self._tls_stamp = stamp
                    try:
                        self.ctx.load_cert_chain(str(self.settings.tls_cert), str(self.settings.tls_key))
                        log.info("TLS certificate reloaded")
                    except (OSError, ssl.SSLError):
                        log.error("TLS certificate changed but could not be loaded; keeping the old one")
                if time.monotonic() - last_purge > 60:
                    last_purge = time.monotonic()
                    self.sessions.purge_expired()
            except Exception:   # noqa: BLE001 - the watcher must survive anything
                log.exception("watcher iteration failed")

    def wait(self) -> None:
        self.stopping.wait()

    def stop(self) -> None:
        self.stopping.set()
        self.hub.stop()
        self.fed.stop()
        self.health_socket.stop()
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()
        self._servers.clear()
        self.sessions.close()

    def health(self) -> dict[str, Any]:
        return build_health(self)
