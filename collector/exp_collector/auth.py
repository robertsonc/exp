"""Bearer-token authentication (03-collector.md section 2).

``Authorization: Bearer <token>`` -> sha256 -> constant-time lookup. Scoping is structural:
ingest tokens (``expi_``) are looked up ONLY in ``ingest_tokens.json`` and used only on
``/ingest/*``; dashboard tokens (``expd_``) only in ``dashboard_tokens.json`` and only on
``/api/*``. A token of the other kind never matches (wrong table AND wrong prefix) -> 401.
Token values are never logged or returned.
"""
from __future__ import annotations

import re

from exp_common import ids as exp_ids

from .config import CredStore

_BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{1,128})\Z")

SCOPE_INGEST = "ingest"
SCOPE_DASHBOARD = "dashboard"
SCOPE_SPEEDTEST = "speedtest"     # M6: exps_ (speedtest -> collector), only /api/v1/speedtests ingest/status/comment
SCOPE_RUNNER = "runner"           # M6: expr_ (runner -> collector), only the speedtest feed/evidence/baseline routes
_PREFIX = {SCOPE_INGEST: "expi", SCOPE_DASHBOARD: "expd", SCOPE_SPEEDTEST: "exps", SCOPE_RUNNER: "expr"}


def bearer_token(header: str | None) -> str | None:
    """The token in ``Bearer <token>`` (single space, URL-safe charset, <= 128 chars) or None."""
    if not header or len(header) > 160:
        return None
    m = _BEARER.match(header.strip())
    return m.group(1) if m else None


def authenticate(creds: CredStore, scope: str, header: str | None) -> str | None:
    """Identity for a valid token of `scope`, else None."""
    token = bearer_token(header)
    if token is None:
        return None
    if scope not in _PREFIX:
        raise ValueError(f"unknown auth scope {scope!r}")
    if not exp_ids.is_token(token, _PREFIX[scope]):
        return None
    table = {SCOPE_INGEST: creds.ingest, SCOPE_DASHBOARD: creds.dashboard,
             SCOPE_SPEEDTEST: creds.speedtest, SCOPE_RUNNER: creds.runner}[scope]
    return table.lookup(token)
