"""HTTP handlers of the ``speedtests`` operations of ``shared/openapi/collector.yaml``.

Three callers, three token families, structurally separate (the route's auth scope decides which credential table is
consulted, so a token of another family is simply unknown -> 401):

* ``exps_`` (the speedtest box): ``POST speedtests``, ``GET speedtests/{id}/status``, ``POST speedtests/{id}/comment``;
* ``expr_`` (the runner): ``GET speedtests/feed``, ``POST speedtests/{id}/evidence``, ``.../evidence/complete``,
  ``GET speedtests/baseline``;
* ``expd_`` (the dashboard): query, detail, aggregate, stream, purge. ``identifiers=true`` (raw IP / MAC / username /
  hostname) is sent by the dashboard only for admin-role sessions (SR-25); the collector requires ``X-Exp-User`` for it
  and audits every use.
"""
from __future__ import annotations

import logging
import re
import time
from typing import TYPE_CHECKING, Any

from exp_common import config as exp_config
from exp_common import speedtest as st_helpers

from .. import sse
from ..api import (
    bool_param,
    decode_cursor,
    encode_cursor,
    int_param,
    one_param,
    slug_param,
    ts_param,
    ts_required,
)
from ..server import AUTH_DASHBOARD, AUTH_RUNNER, AUTH_SPEEDTEST, Handler, HttpError, Router
from .repo import KINDS
from .service import SpeedtestService, iso

if TYPE_CHECKING:  # pragma: no cover
    from ..app import CollectorApp

log = logging.getLogger(__name__)

BASE = "/api/v1/speedtests"
MAX_RESULT_BODY = 256 * 1024
MAX_EVIDENCE_BODY = 1024 * 1024
MAX_SMALL_BODY = 4096
MAX_FEED = 100
_ZONE = re.compile(r"(unresolved|[a-z0-9][a-z0-9-]{0,63})\Z")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_CAUSE = re.compile(r"[a-z_]{1,64}\Z")
_COMMENT = re.compile(r"[^\x00-\x08\x0b-\x1f\x7f]*\Z")
GROUPS = ("zone", "ap", "ssid", "band", "os_family", "hour", "cause")
METRICS = ("down_p50", "up_p50", "loaded_p50", "score_p50", "count")
SOURCES = {"device_key", "mac", "ip", "test"}


def svc(req: Handler) -> SpeedtestService:
    s: SpeedtestService = req.app.speedtests
    return s


def _json_body(req: Handler, limit: int) -> Any:
    raw = req.read_body(limit)
    try:
        return exp_config.parse_json(raw, "request body")
    except (exp_config.ConfigError, ValueError, RecursionError):
        raise HttpError(400, "invalid_request", "body must be valid JSON") from None


def _text_param(req: Handler, name: str, maxlen: int) -> str | None:
    v = one_param(req, name)
    if v is None or v == "":
        return None
    if len(v) > maxlen or _CTRL.search(v):
        raise HttpError(400, "invalid_request", f"{name} must be text of at most {maxlen} characters")
    return v


def _speedtest_identity(req: Handler) -> str:
    s = svc(req)
    s.require_enabled()
    ident = req.identity or ""
    if not s.allowed_speedtest(ident):
        raise HttpError(401, "invalid_token", "missing or invalid token", {"WWW-Authenticate": "Bearer"})
    return ident


def _runner_site(req: Handler) -> str:
    s = svc(req)
    s.require_enabled()
    if not s.allowed_runner(req.identity or ""):
        raise HttpError(401, "invalid_token", "missing or invalid token", {"WWW-Authenticate": "Bearer"})
    return str(req.app.config.site)


def _test_id(req: Handler) -> str:
    tid = req.params["id"]
    if not st_helpers.is_speedtest_id(tid):
        raise HttpError(404, "not_found", "no such test")
    return tid


def _identifiers(req: Handler, what: str) -> bool:
    """``identifiers=true``: only with a user to audit (SR-25)."""
    if not bool_param(req, "identifiers"):
        return False
    user = req.user
    if user == "-":
        raise HttpError(403, "forbidden", "X-Exp-User is required to read raw identifiers")
    svc(req).audit_identifiers_view(user, what)
    return True


# ------------------------------------------------------------------------------- speedtest box (exps_)
def handle_ingest(req: Handler) -> None:
    ident = _speedtest_identity(req)
    doc = _json_body(req, MAX_RESULT_BODY)
    status, body = svc(req).ingest(ident, doc)
    req.send_json(status, body)


def handle_status(req: Handler) -> None:
    ident = _speedtest_identity(req)
    req.send_json(200, svc(req).status(ident, _test_id(req)))


def handle_comment(req: Handler) -> None:
    ident = _speedtest_identity(req)
    tid = _test_id(req)
    doc = _json_body(req, MAX_SMALL_BODY)
    c = doc.get("comment") if isinstance(doc, dict) else None
    if (not isinstance(doc, dict) or set(doc) != {"comment"} or not isinstance(c, str) or not 1 <= len(c) <= 500
            or not _COMMENT.match(c)):
        raise HttpError(400, "invalid_request", "comment must be 1-500 characters without control characters")
    svc(req).comment(ident, tid, c)
    req._send(204, b"", "application/json")


# ------------------------------------------------------------------------------------- runner (expr_)
def handle_feed(req: Handler) -> None:
    site = _runner_site(req)
    limit = min(MAX_FEED, int_param(req, "limit", 1, 1000, 100))
    wait_s = int_param(req, "wait_s", 0, 25, 0)
    cur = decode_cursor(one_param(req, "after"))
    after = 0
    if cur is not None:
        q = cur.get("q")
        if isinstance(q, bool) or not isinstance(q, int) or q < 0:
            raise HttpError(400, "invalid_request", "invalid cursor")
        after = q
    items, last = svc(req).feed(site, after, limit, wait_s)
    nxt = encode_cursor({"q": last}) if (items or after) else None
    req.send_json(200, {"items": items, "next_cursor": nxt})


def handle_evidence(req: Handler) -> None:
    site = _runner_site(req)
    tid = _test_id(req)
    doc = _json_body(req, MAX_EVIDENCE_BODY)
    req.send_json(200, svc(req).put_evidence(site, tid, doc))


def handle_complete(req: Handler) -> None:
    site = _runner_site(req)
    tid = _test_id(req)
    doc = _json_body(req, MAX_SMALL_BODY)
    kinds = doc.get("kinds") if isinstance(doc, dict) else None
    ok = (isinstance(doc, dict) and set(doc) == {"kinds", "status"} and doc.get("status") in ("ok", "partial", "failed")
          and isinstance(kinds, list) and len(kinds) <= 8 and all(isinstance(k, str) for k in kinds)
          and len(set(kinds)) == len(kinds) and all(k in KINDS for k in kinds))
    if not ok:
        raise HttpError(400, "invalid_request", "body must be {kinds: [...], status: ok|partial|failed}")
    req.send_json(200, svc(req).complete(site, tid, doc))


def handle_baseline(req: Handler) -> None:
    site = _runner_site(req)
    want = slug_param(req, "site", required=True)
    zone = one_param(req, "zone")
    if zone and not _ZONE.match(zone):
        raise HttpError(400, "invalid_request", "zone must be a zone id")
    ap = _text_param(req, "ap", 128)
    at = ts_required(req, "at")
    if want != site:
        raise HttpError(404, "not_found", "no baseline for that site")
    req.send_json(200, svc(req).baseline_for_runner(site, zone or None, ap, at))


# -------------------------------------------------------------------------------------- dashboard (expd_)
def handle_list(req: Handler) -> None:
    s = svc(req)
    s.require_enabled()
    site = slug_param(req, "site")
    zone = one_param(req, "zone")
    if zone and not _ZONE.match(zone):
        raise HttpError(400, "invalid_request", "zone must be a zone id")
    ap, ssid, q = _text_param(req, "ap", 128), _text_param(req, "ssid", 64), _text_param(req, "q", 128)
    cause = one_param(req, "cause")
    if cause and not _CAUSE.match(cause):
        raise HttpError(400, "invalid_request", "cause must be a cause id")
    frm, to = ts_param(req, "from"), ts_param(req, "to")
    if frm is not None and to is not None and to < frm:
        raise HttpError(400, "invalid_request", "to must not be before from")
    lo = int_param(req, "min_score", 0, 100, -1) if one_param(req, "min_score") not in (None, "") else None
    hi = int_param(req, "max_score", 0, 100, -1) if one_param(req, "max_score") not in (None, "") else None
    limit = int_param(req, "limit", 1, 1000, 100)
    cur = decode_cursor(one_param(req, "cursor"))
    before: tuple[int, str] | None = None
    if cur is not None:
        st, i = cur.get("s"), cur.get("i")
        if isinstance(st, bool) or not isinstance(st, int) or not isinstance(i, str) or not 0 < len(i) <= 64:
            raise HttpError(400, "invalid_request", "invalid cursor")
        before = (st, i)
    ident = _identifiers(req, "list")
    rows = s.repo.list(site=site, zone=zone or None, ap=ap, ssid=ssid, cause=cause or None, from_ms=frm, to_ms=to,
                       min_score=lo, max_score=hi, q=q, identifiers=ident, limit=limit + 1, before=before)
    more = len(rows) > limit
    rows = rows[:limit]
    nxt = encode_cursor({"s": rows[-1]["started_ms"], "i": rows[-1]["id"]}) if more and rows else None
    req.send_json(200, {"items": [s.public_row(r, ident) for r in rows], "next_cursor": nxt})


def handle_detail(req: Handler) -> None:
    s = svc(req)
    s.require_enabled()
    tid = _test_id(req)
    ident = _identifiers(req, tid)
    req.send_json(200, s.detail(tid, ident))


def handle_aggregate(req: Handler) -> None:
    s = svc(req)
    s.require_enabled()
    group_by, metric = one_param(req, "group_by"), one_param(req, "metric")
    if group_by not in GROUPS or metric not in METRICS:
        raise HttpError(400, "invalid_request", "group_by and metric are required and must be listed values")
    leg = one_param(req, "leg") or "local"
    if leg not in ("local", "internet"):
        raise HttpError(400, "invalid_request", "leg must be local or internet")
    site = slug_param(req, "site")
    now = s.now_ms()
    to = ts_param(req, "to")
    frm = ts_param(req, "from")
    to = now if to is None else to
    frm = to - 86400_000 if frm is None else frm
    if to <= frm:
        raise HttpError(400, "invalid_request", "to must be after from")
    if to - frm > 366 * 86400_000:
        raise HttpError(400, "range_too_large", "the range is limited to 366 days")
    from ..api import HEAVY_SLOTS, _Heavy
    with _Heavy(HEAVY_SLOTS):
        rows = s.repo.aggregate(group_by, metric, leg, site, frm, to)
    items = [{"key": k[:128], "value": round(v, 3), "count": n} for k, v, n in rows[:1000]]
    req.send_json(200, {"group_by": group_by, "metric": metric, "leg": leg, "from": iso(frm), "to": iso(to),
                        "items": items})


def handle_purge(req: Handler) -> None:
    s = svc(req)
    s.require_enabled()
    user = req.user
    if user == "-":
        raise HttpError(403, "forbidden", "X-Exp-User is required: a purge is audited")
    doc = _json_body(req, MAX_SMALL_BODY)
    if (not isinstance(doc, dict) or not set(doc) <= {"by", "value", "dry_run"} or doc.get("by") not in SOURCES
            or not isinstance(doc.get("value"), str) or not 0 < len(doc["value"]) <= 128
            or not isinstance(doc.get("dry_run", False), bool)):
        raise HttpError(400, "invalid_request", "body must be {by, value, dry_run?}")
    req.send_json(200, s.purge(doc["by"], doc["value"].strip(), bool(doc.get("dry_run", False)), user))


def handle_stream(req: Handler) -> None:
    s = svc(req)
    s.require_enabled()
    site = slug_param(req, "site")
    last_id = req.headers.get("Last-Event-ID")
    if last_id is not None and (len(last_id) > 128 or not last_id.isascii()):
        raise HttpError(400, "invalid_request", "bad Last-Event-ID")
    try:
        client = s.hub.subscribe(site, last_id)
    except sse.TooManyClients:
        raise HttpError(429, "rate_limited", "too many live connections", {"Retry-After": "3"}) from None
    log.info("speedtest stream opened by=%s site=%s resume=%s", req.user, site or "-", bool(last_id))
    try:
        req.begin_stream()
        req.write_stream(sse.preamble())
        last_write = time.monotonic()
        while True:
            wait = max(0.05, min(1.0, s.hub.keepalive_s - (time.monotonic() - last_write)))
            item = s.hub.next_event(client, wait)
            if item == "closed":
                break
            if item is not None and not isinstance(item, str):
                req.write_stream(item.wire())
                last_write = time.monotonic()
            elif time.monotonic() - last_write >= s.hub.keepalive_s:
                req.write_stream(sse.KEEPALIVE)
                last_write = time.monotonic()
            if not req.app.started or req.client_gone():
                break
    finally:
        s.hub.unsubscribe(client)
        req.close_connection = True


def register(r: Router, app: CollectorApp) -> None:
    """The fixed route table of the speedtest operations. Static paths come before ``{id}`` so they are never
    taken for a test id."""
    r.add("POST", BASE, handle_ingest, auth=AUTH_SPEEDTEST, max_body=MAX_RESULT_BODY)
    r.add("GET", BASE, handle_list, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/aggregate", handle_aggregate, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/stream", handle_stream, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/feed", handle_feed, auth=AUTH_RUNNER)
    r.add("GET", f"{BASE}/baseline", handle_baseline, auth=AUTH_RUNNER)
    r.add("POST", f"{BASE}/purge", handle_purge, auth=AUTH_DASHBOARD, max_body=MAX_SMALL_BODY)
    r.add("GET", f"{BASE}/{{id}}", handle_detail, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/{{id}}/status", handle_status, auth=AUTH_SPEEDTEST)
    r.add("POST", f"{BASE}/{{id}}/comment", handle_comment, auth=AUTH_SPEEDTEST, max_body=MAX_SMALL_BODY)
    r.add("POST", f"{BASE}/{{id}}/evidence/complete", handle_complete, auth=AUTH_RUNNER, max_body=MAX_SMALL_BODY)
    r.add("POST", f"{BASE}/{{id}}/evidence", handle_evidence, auth=AUTH_RUNNER, max_body=MAX_EVIDENCE_BODY)
