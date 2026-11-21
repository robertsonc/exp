"""The runner -> speedtest localhost channel (``/local/v1``, 01-contracts.md section 14.6).

Loopback only: a connection whose peer is not 127.0.0.1 gets 403 BEFORE the token is looked at. The ``expl_`` bearer is
compared (constant time) with the sha256 held in the ``runner_channel_token_sha256`` credential. The speedtest never calls
the runner and never sees a MAC or username: the runner pushes IP -> zone answers (the Mist "where" cache) and the EdgeConnect
WAN utilization for the internet-leg auto-pause.
"""
from __future__ import annotations

import hashlib
import hmac
import logging

from .core import Core
from .errors import ApiError, not_found, too_many
from .httpd import Request, Response
from .routes import json_response, parse_json_body

log = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"


class ChannelApp:
    def __init__(self, core: Core) -> None:
        self.core = core

    def handle(self, req: Request) -> Response:
        if req.peer != LOOPBACK:
            self.core.note_rejected()
            raise ApiError(403, "forbidden", "forbidden", close=True)
        self._auth(req)
        wait = self.core.api_limiter.take("channel", self.core.clock(), cost=0.25)     # a generous shared budget
        if wait > 0:
            raise too_many("channel", wait)
        path, m = req.path, req.method
        if path == "/local/v1/where/wanted":
            self._method(m, "GET")
            return json_response(200, self.core.channel_where_wanted())
        if path == "/local/v1/where":
            self._method(m, "PUT")
            self.core.channel_put_where(parse_json_body(req, 256 * 1024))
            return json_response(200, {"ok": True})
        if path == "/local/v1/pause":
            self._method(m, "PUT")
            self.core.channel_put_pause(parse_json_body(req, 1024))
            return json_response(200, {"ok": True})
        raise not_found()

    @staticmethod
    def _method(got: str, want: str) -> None:
        if got != want:
            raise ApiError(405, "method_not_allowed", "method not allowed", headers={"Allow": want})

    def _auth(self, req: Request) -> None:
        want = self.core.channel_sha256
        h = req.header("authorization") or ""
        tok = h[7:] if h[:7].lower() == "bearer " else ""
        if want is None or not tok.startswith("expl_") or len(tok) != 48:
            raise ApiError(401, "invalid_token", "invalid token")
        if not hmac.compare_digest(hashlib.sha256(tok.encode("utf-8")).hexdigest(), want):
            self.core.note_rejected()
            raise ApiError(401, "invalid_token", "invalid token")
