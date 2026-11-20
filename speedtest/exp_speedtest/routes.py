"""The public HTTP surface of the box (shared/openapi/speedtest.yaml): the page, the session API and the on-network leg.

Everything here is unauthenticated by design (SR-21) apart from the two session credentials: the leg token for
``/st/ping|down|up`` and the view proof for the session routes. Handlers are thin: they parse and bound the request and call
:class:`exp_speedtest.core.Core`, which owns every rule.
"""
from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import time
from collections.abc import Callable
from typing import Any

from exp_common import config as exp_config

from .core import Core
from .errors import ApiError, bad_request, not_found, too_many
from .httpd import API_SECURITY_HEADERS, Request, Response
from .static import Payload, StaticSite

log = logging.getLogger(__name__)

SEG_BYTES = 8 * 1024 * 1024
TRANSFER_DEADLINE_S = 90.0
SSE_MAX_EVENTS = 60
_DIGITS = re.compile(r"[0-9]{1,12}\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_PATH_RE = re.compile(r"/st/api/v1/sessions/(st_[0-9A-HJKMNP-TV-Z]{26})(/path|/internet-slot|/result|/comment)?\Z")
_RESULT_RE = re.compile(r"/st/r/(st_[0-9A-HJKMNP-TV-Z]{26})\Z")
_ASSET_RE = re.compile(r"/st/assets/([^/]{1,64})\Z")
_PX_HDRS = [("Timing-Allow-Origin", "*"), ("Access-Control-Allow-Origin", "*"), ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff")]


def json_response(status: int, doc: Any, extra: list[tuple[str, str]] | None = None) -> Response:
    body = json.dumps(doc, separators=(",", ":")).encode("utf-8")
    return Response(status, [("Content-Type", "application/json"), ("Cache-Control", "no-store"), *API_SECURITY_HEADERS,
                             *(extra or [])], body)


def parse_json_body(req: Request, limit: int) -> Any:
    if "content-length" not in req.headers:
        raise ApiError(411, "length_required", "content-length required", close=True)
    raw = req.read_body(limit)
    try:
        return exp_config.parse_json(raw, "request body")
    except ValueError:
        raise bad_request("body must be a JSON document") from None


class PublicApp:
    def __init__(self, core: Core, site: StaticSite, payload: Payload) -> None:
        self.core, self.site, self.payload = core, site, payload
        self._offset = 0

    # ------------------------------------------------------------------------------------------ dispatch
    def handle(self, req: Request) -> Response:
        try:
            return self._dispatch(req)
        except ApiError as exc:
            if exc.status in (401, 403, 413, 429):
                self.core.note_rejected()
            raise

    def _dispatch(self, req: Request) -> Response:
        path, m = req.path, req.method
        # the local-leg endpoints are limited by their token, not by the general per-address budget
        if path == "/st/ping":
            return self._need(m, "GET", lambda: self._ping(req))
        if path == "/st/down":
            return self._need(m, "GET", lambda: self._down(req))
        if path == "/st/up":
            return self._need(m, "POST", lambda: self._up(req))
        wait = self.core.api_limiter.take(req.peer, self.core.clock())
        if wait > 0:
            raise too_many("requests_per_ip", wait)
        if path == "/":
            return self._need(m, "GET", lambda: self._page(req), head=True)
        if path == "/st/px":
            if m == "OPTIONS":
                return Response(204, [*_PX_HDRS, ("Access-Control-Allow-Methods", "GET, OPTIONS"),
                                      ("Access-Control-Max-Age", "600")])
            return self._need(m, "GET", lambda: Response(204, list(_PX_HDRS)), head=True)
        if path == "/st/api/v1/config":
            return self._need(m, "GET", self._config)
        if path == "/st/api/v1/where":
            return self._need(m, "GET", lambda: self._where(req))
        if path == "/st/api/v1/sessions":
            return self._need(m, "POST", lambda: self._create(req))
        mm = _PATH_RE.match(path)
        if mm:
            sid, sub = mm.group(1), mm.group(2)
            table: dict[str | None, tuple[str, Callable[[], Response]]] = {
                None: ("GET", lambda: self._view(req, sid)), "/path": ("GET", lambda: self._path(req, sid)),
                "/internet-slot": ("POST", lambda: self._slot(req, sid)), "/result": ("POST", lambda: self._result(req, sid)),
                "/comment": ("POST", lambda: self._comment(req, sid))}
            method, fn = table[sub]
            return self._need(m, method, fn)
        mm = _RESULT_RE.match(path)
        if mm:
            return self._need(m, "GET", lambda: self._page(req), head=True)
        mm = _ASSET_RE.match(path)
        if mm:
            return self._need(m, "GET", lambda: self._asset(mm.group(1)), head=True)
        raise not_found()

    @staticmethod
    def _need(method: str, want: str, fn: Callable[[], Response], head: bool = False) -> Response:
        if method == want or (head and method == "HEAD"):
            return fn()
        raise ApiError(405, "method_not_allowed", "method not allowed", headers={"Allow": want + (", HEAD" if head else "")})

    # --------------------------------------------------------------------------------------------- page
    def _page(self, req: Request) -> Response:
        body, csp = self.site.page()
        if not body:
            raise not_found()
        return Response(200, [("Content-Type", "text/html; charset=utf-8"), ("Content-Security-Policy", csp),
                              ("Cache-Control", "no-cache"), ("X-Content-Type-Options", "nosniff"),
                              ("Referrer-Policy", "no-referrer"), ("Cross-Origin-Opener-Policy", "same-origin")], body)

    def _asset(self, name: str) -> Response:
        hit = self.site.asset(name)
        if hit is None:
            raise not_found()
        data, ctype = hit
        if ctype.startswith("text/javascript"):      # the engine worker: its own CSP governs what the worker may fetch
            return Response(200, [("Content-Type", ctype), ("Cache-Control", "public, max-age=300"), ("X-Content-Type-Options", "nosniff"),
                                  ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", self.site.worker_csp()),
                                  ("Cross-Origin-Resource-Policy", "same-origin")], data)
        return Response(200, [("Content-Type", ctype), ("Cache-Control", "public, max-age=300"),
                              ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
                              ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox"),
                              ("Cross-Origin-Resource-Policy", "same-origin")], data)

    # ---------------------------------------------------------------------------------------------- api
    def _config(self) -> Response:
        return json_response(200, self.core.public_config(), [("Cache-Control", "no-cache")])

    def _where(self, req: Request) -> Response:
        hint = req.query.get("z")
        if hint is not None and not _SLUG.match(hint):
            raise bad_request("malformed zone hint", field="z")
        return json_response(200, self.core.where(req.peer, hint))

    def _create(self, req: Request) -> Response:
        body = parse_json_body(req, 4096)
        return json_response(201, self.core.create_session(req.peer, body, req.header("user-agent")))

    def _path(self, req: Request, sid: str) -> Response:
        proof = req.header("x-exp-view-proof")
        doc = self.core.session_path(sid, proof)
        if "text/event-stream" not in (req.header("accept") or ""):
            return json_response(200, doc)

        def stream(sock: socket.socket) -> None:
            sock.sendall(b"retry: 2000\n\n")
            for i in range(SSE_MAX_EVENTS):
                if i:
                    time.sleep(0.5)
                    try:
                        d = self.core.session_path(sid, proof)
                    except ApiError:
                        return
                else:
                    d = doc
                sock.sendall(b"event: path\ndata: " + json.dumps(d, separators=(",", ":")).encode() + b"\n\n")

        return Response(200, [("Content-Type", "text/event-stream"), ("Cache-Control", "no-store"), ("X-Accel-Buffering", "no"),
                              *API_SECURITY_HEADERS], stream=stream, length=-1, close=True)

    def _slot(self, req: Request, sid: str) -> Response:
        body = parse_json_body(req, 1024)
        return json_response(200, self.core.internet_slot(sid, req.header("x-exp-view-proof"), body))

    def _result(self, req: Request, sid: str) -> Response:
        # authorize BEFORE reading a 64 KiB body from an unknown caller
        self.core._auth_view(sid, req.header("x-exp-view-proof"))
        body = parse_json_body(req, 64 * 1024)
        return json_response(202, self.core.submit_result(sid, req.header("x-exp-view-proof"), req.peer, body))

    def _view(self, req: Request, sid: str) -> Response:
        return json_response(200, self.core.get_view(sid, req.header("x-exp-view-proof")))

    def _comment(self, req: Request, sid: str) -> Response:
        self.core._auth_view(sid, req.header("x-exp-view-proof"))
        body = parse_json_body(req, 4096)
        self.core.post_comment(sid, req.header("x-exp-view-proof"), body)
        return Response(204, [("Cache-Control", "no-store"), *API_SECURITY_HEADERS])

    # ------------------------------------------------------------------------------------------ local leg
    def _leg_headers(self) -> list[tuple[str, str]]:
        return [("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer")]

    def _ping(self, req: Request) -> Response:
        s = self.core.authorize_leg(req.header("x-exp-leg-token"), req.peer)
        n = req.query.get("n")
        if n is not None and (not _DIGITS.match(n) or int(n) > 1_000_000):
            raise bad_request("n must be an integer 0..1000000")
        self.core.ping(s)
        hdrs = self._leg_headers()
        if n is not None:
            hdrs.append(("X-Exp-Seq", str(int(n))))
        return Response(204, hdrs)

    def _down(self, req: Request) -> Response:
        s = self.core.authorize_leg(req.header("x-exp-leg-token"), req.peer)
        raw = req.query.get("bytes")
        if raw is None or not _DIGITS.match(raw) or not 1 <= int(raw) <= 100_000_000:
            raise bad_request("bytes must be an integer 1..100000000", field="bytes")
        n = int(raw)
        self.core.reserve(s, n)
        payload, core = self.payload, self.core
        self._offset = (self._offset + 1_048_576 * 7 + 4096) % payload.size
        start = self._offset

        def abort() -> None:                       # the head could not be sent: give the reservation back
            core.settle(s, n, 0, down=True)

        def stream(sock: socket.socket) -> None:
            sent = 0
            f = payload.open()
            try:
                deadline = time.monotonic() + TRANSFER_DEADLINE_S
                off = start
                while sent < n:
                    if time.monotonic() > deadline:
                        raise TimeoutError("transfer deadline")
                    seg = min(n - sent, payload.size - off, SEG_BYTES)
                    if isinstance(sock, ssl.SSLSocket):                    # no sendfile over TLS: pread + send
                        sock.sendall(_pread(f, seg, off))
                        moved = seg
                    else:
                        moved = sock.sendfile(f, off, seg)
                        if not moved:
                            break
                    sent += moved
                    core.meter.add(moved)
                    off = (off + moved) % payload.size
            finally:
                f.close()
                core.settle(s, n, sent, down=True)

        return Response(200, [("Content-Type", "application/octet-stream"), *self._leg_headers()], stream=stream, length=n,
                        cleanup=abort)

    def _up(self, req: Request) -> Response:
        s = self.core.authorize_leg(req.header("x-exp-leg-token"), req.peer)
        if "content-length" not in req.headers:
            raise ApiError(411, "length_required", "content-length required", close=True)
        n = req.content_length
        if n > 100_000_000:
            raise ApiError(413, "payload_too_large", "upload too large", close=True)
        self.core.reserve(s, n)
        received = 0
        try:
            received = req.discard_body(TRANSFER_DEADLINE_S, on_bytes=self.core.meter.add)
        finally:
            self.core.settle(s, n, received, down=False)
        return Response(204, [("X-Exp-Received", str(received)), *self._leg_headers()])


def _pread(f: Any, n: int, off: int) -> bytes:
    import os
    return os.pread(f.fileno(), n, off)
