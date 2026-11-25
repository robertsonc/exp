"""Dashboard query API (01-contracts.md section 5, shared/openapi/collector.yaml).

Every route here is behind a dashboard token (``expd_``) except ``GET /healthz`` and the drill kill-switch
poll, which takes the executor's ingest token. ``X-Exp-User`` is passed through for audit only: it is never
used for authorization (the dashboard session enforces roles) and is logged sanitised.

Routes are registered once at start-up from ``build_router``; the table is fixed.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import http.client
import json
import logging
import re
import shutil
import threading
import time
from typing import TYPE_CHECKING, Any

from exp_common import ids
from exp_common import schema as exp_schema

from . import __version__, drills, queryguard, sse, summary
from .incidents import incident_doc
from .server import (
    AUTH_DASHBOARD,
    AUTH_INGEST,
    AUTH_NONE,
    EXECUTOR_ROUTE,
    Handler,
    HttpError,
    Router,
    handle_healthz,
    handle_ingest,
)

if TYPE_CHECKING:  # pragma: no cover
    from .app import CollectorApp

log = logging.getLogger(__name__)
audit = logging.getLogger("exp-collector.audit")

INGEST_PATH = "/ingest/v1/measurements"
BASE = "/api/v1"
MAX_BEATS_RANGE_MS = 6 * 3600 * 1000
MAX_ACK_BODY = 2048
VM_TIMEOUT_S = 10.0
VM_MAX_RESPONSE = 32 * 1024 * 1024
MAX_SERIES = 500
VOICES = ("plain", "sysadmin")
OUTCOMES = ("ok", "degraded", "fail", "error")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_TEXT = re.compile(r"[^\x00-\x1f\x7f]*\Z")
HEAVY_SLOTS = threading.BoundedSemaphore(6)       # concurrent SQLite-heavy reads (time travel, beats, summary)
VM_SLOTS = threading.BoundedSemaphore(8)          # concurrent VictoriaMetrics proxy calls


def _iso(epoch_ms: float) -> str:
    return (datetime.datetime.fromtimestamp(epoch_ms / 1000.0, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


# ------------------------------------------------------------------------------------ parameters
def one_param(req: Handler, name: str) -> str | None:
    vals = req.query.get(name)
    if not vals:
        return None
    if len(vals) > 1:
        raise HttpError(400, "invalid_request", f"{name} given more than once")
    return vals[0]


def int_param(req: Handler, name: str, lo: int, hi: int, default: int | None) -> int:
    raw = one_param(req, name)
    if raw is None or raw == "":
        if default is None:
            raise HttpError(400, "invalid_request", f"{name} is required")
        return default
    if not raw.isdigit() or len(raw) > 9:
        raise HttpError(400, "invalid_request", f"{name} must be an integer")
    v = int(raw)
    if not lo <= v <= hi:
        raise HttpError(400, "invalid_request", f"{name} must be between {lo} and {hi}")
    return v


def slug_param(req: Handler, name: str, required: bool = False) -> str | None:
    v = one_param(req, name)
    if v is None or v == "":
        if required:
            raise HttpError(400, "invalid_request", f"{name} is required")
        return None
    if not ids.is_slug(v):
        raise HttpError(400, "invalid_request", f"{name} must be a slug")
    return v


def ts_param(req: Handler, name: str, required: bool = False) -> int | None:
    """An exp ``ts`` (UTC ISO-8601 with Z) -> epoch ms."""
    v = one_param(req, name)
    if v is None or v == "":
        if required:
            raise HttpError(400, "invalid_request", f"{name} is required")
        return None
    if not queryguard._TS.match(v):
        raise HttpError(400, "invalid_request", f"{name} must be a UTC ISO-8601 timestamp ending in Z")
    try:
        return exp_schema.iso_to_ms(v)
    except ValueError:
        raise HttpError(400, "invalid_request", f"{name} is not a valid timestamp") from None


def ts_required(req: Handler, name: str) -> int:
    v = ts_param(req, name, required=True)
    if v is None:  # pragma: no cover - ts_param raises when required
        raise HttpError(400, "invalid_request", f"{name} is required")
    return v


def voice_param(req: Handler) -> str | None:
    v = one_param(req, "voice")
    if v is None or v == "":
        return None
    if v not in VOICES:
        raise HttpError(400, "invalid_request", "voice must be plain or sysadmin")
    return v


def bool_param(req: Handler, name: str) -> bool:
    v = one_param(req, name)
    if v is None or v == "":
        return False
    if v in ("true", "1"):
        return True
    if v in ("false", "0"):
        return False
    raise HttpError(400, "invalid_request", f"{name} must be true or false")


def known_probe(req: Handler, name: str = "probe") -> str:
    probe = slug_param(req, name, required=True) or ""
    if probe not in req.app.config.probes:
        raise HttpError(404, "unknown_probe", "unknown probe")
    return probe


def encode_cursor(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def decode_cursor(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    if len(raw) > 1024:
        raise HttpError(400, "invalid_request", "invalid cursor")
    try:
        obj = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise HttpError(400, "invalid_request", "invalid cursor") from None
    if not isinstance(obj, dict):
        raise HttpError(400, "invalid_request", "invalid cursor")
    return obj


def offset_cursor(raw: str | None) -> int:
    obj = decode_cursor(raw)
    if obj is None:
        return 0
    o = obj.get("o")
    if isinstance(o, bool) or not isinstance(o, int) or o < 0:
        raise HttpError(400, "invalid_request", "invalid cursor")
    return o


class _Heavy:
    """Bounds concurrent expensive reads: busy -> 429 with Retry-After (the contract's rate_limited)."""

    def __init__(self, sem: threading.BoundedSemaphore) -> None:
        self.sem = sem

    def __enter__(self) -> None:
        if not self.sem.acquire(timeout=2.0):
            raise HttpError(429, "rate_limited", "too many expensive queries in flight", {"Retry-After": "1"})

    def __exit__(self, *exc: object) -> None:
        self.sem.release()


# --------------------------------------------------------------------------------------- router
def build_router(app: CollectorApp) -> Router:
    r = Router()
    r.add("GET", "/healthz", handle_healthz, auth=AUTH_NONE)
    r.add("POST", INGEST_PATH, handle_ingest, auth=AUTH_INGEST, max_body=app.config.max_body_bytes)
    r.add("GET", f"{BASE}/health", handle_health, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/probes", handle_probes, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/state", handle_state, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/states", handle_states, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/beats", handle_beats, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/records", handle_records, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/incidents", handle_incidents, auth=AUTH_DASHBOARD)
    r.add("POST", f"{BASE}/incidents/{{id}}/ack", handle_ack, auth=AUTH_DASHBOARD, max_body=MAX_ACK_BODY)
    r.add("GET", f"{BASE}/summary", handle_summary, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/sites/{{site}}/lines", handle_site_lines, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/sites/{{site}}/lines/timeline", handle_site_lines_timeline, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/query_range", handle_query_range, auth=AUTH_DASHBOARD)
    r.add("GET", f"{BASE}/stream", handle_stream, auth=AUTH_DASHBOARD)
    r.add("GET", EXECUTOR_ROUTE, handle_drill_control, auth=AUTH_INGEST)       # registered before {run_id}
    r.add("GET", f"{BASE}/drills/{{run_id}}", handle_drill_report, auth=AUTH_DASHBOARD)
    r.add("POST", f"{BASE}/drills/{{run_id}}/abort", handle_drill_abort, auth=AUTH_DASHBOARD)
    from .speedtest import api as speedtest_api  # M6: the `speedtests` operations (late: it imports this module)
    speedtest_api.register(r, app)
    return r


# ---------------------------------------------------------------------------------- health, probes
def health_doc(app: CollectorApp) -> dict[str, object]:
    from .health import evaluate
    m = app.monitor.metrics
    status, _ = evaluate(m, app.monitor.problems(m))
    try:
        free_mb = int(shutil.disk_usage(app.paths.state_dir).free // (1024 * 1024))
    except OSError:
        free_mb = 0
    w = app.ingestor.stats.window(60)
    return {"status": status, "version": __version__,
            "vm": {"up": bool(app.vm.up), "lag_s": round(app.vm.lag_s(), 3)},
            "ingest": {"rps": round(w["accepted"] / 60.0, 3), "rejects_1m": int(w["rejected"])},
            "probes": {"total": len(app.config.probes), "reporting": app.ingestor.reporting_probes()},
            "disk_free_mb": free_mb}


def handle_health(req: Handler) -> None:
    req.send_json(200, health_doc(req.app))


def handle_probes(req: Handler) -> None:
    app = req.app
    site = slug_param(req, "site")
    limit = int_param(req, "limit", 1, 1000, 100)
    offset = offset_cursor(one_param(req, "cursor"))
    entries = sorted((e for e in app.config.probes.values() if site is None or e.site == site),
                     key=lambda e: e.probe_id)
    page = entries[offset:offset + limit]
    now = time.time()
    items = []
    for e in page:
        newest = app.ingestor.newest_ts_ms.get(e.probe_id)
        if newest is None:
            newest = app.store.newest_ts_ms(e.probe_id)
        items.append({
            "probe": e.probe_id, "site": e.site, "label": e.label,
            "last_seen": _iso(newest) if newest is not None else None,
            "newest_s": round(max(0.0, now - newest / 1000.0), 1) if newest is not None else None,
            "version": app.ingestor.last_agent_ver.get(e.probe_id),
            "state": app.rules.severity(e.probe_id),
            "cadence_s": app.rules.cadence_s(e.probe_id),
        })
    nxt = encode_cursor({"o": offset + limit}) if offset + limit < len(entries) else None
    req.send_json(200, {"items": items, "next_cursor": nxt})


# ------------------------------------------------------------------------------- state and states
def handle_state(req: Handler) -> None:
    app = req.app
    probe = known_probe(req)
    at = ts_param(req, "at")
    voice = voice_param(req)
    if at is None:
        doc = app.rules.state(probe, None, voice)
    else:
        with _Heavy(HEAVY_SLOTS):
            doc = app.rules.state(probe, at, voice)
    if doc is None:
        raise HttpError(404, "unknown_probe", "unknown probe")
    req.send_json(200, doc)


def handle_states(req: Handler) -> None:
    app = req.app
    site = slug_param(req, "site")
    at = ts_param(req, "at")
    voice = voice_param(req)
    limit = int_param(req, "limit", 1, 1000, 100)
    offset = offset_cursor(one_param(req, "cursor"))
    probes = sorted(p for p, e in app.config.probes.items() if site is None or e.site == site)
    page = probes[offset:offset + limit]
    items = []
    from .engine import state_lite
    if at is None:
        for p in page:
            doc = app.rules.state(p, None, voice)
            if doc is not None:
                items.append(state_lite(doc))
    else:
        with _Heavy(HEAVY_SLOTS):
            for p in page:
                doc = app.rules.state(p, at, voice)
                if doc is not None:
                    items.append(state_lite(doc))
    nxt = encode_cursor({"o": offset + limit}) if offset + limit < len(probes) else None
    req.send_json(200, {"items": items, "next_cursor": nxt})


# ------------------------------------------------------------------------------- site lines board
MAX_LINES_RANGE_MS = 60 * 60 * 1000      # the board shows 15 min; an hour leaves room to scroll back


def _site_path(req: Handler) -> str:
    site = str(req.params.get("site", ""))
    if not ids.is_slug(site):
        raise HttpError(400, "invalid_request", "site must be a slug")
    return site


def handle_site_lines(req: Handler) -> None:
    site = _site_path(req)
    at = ts_param(req, "at")
    if at is None:
        doc = req.app.rules.site_lines(site, None)
    else:
        with _Heavy(HEAVY_SLOTS):
            doc = req.app.rules.site_lines(site, at)
    if doc is None:
        raise HttpError(404, "unknown_site", "no probe of this collector is in that site")
    req.send_json(200, doc)


def handle_site_lines_timeline(req: Handler) -> None:
    site = _site_path(req)
    now = int(time.time() * 1000)
    to = ts_param(req, "to") or now
    frm = ts_param(req, "from") or (to - 15 * 60 * 1000)
    if frm >= to or to - frm > MAX_LINES_RANGE_MS:
        raise HttpError(400, "invalid_request", "from must be before to, at most 60 minutes apart")
    step = int_param(req, "step_s", 2, 60, 10) * 1000
    with _Heavy(HEAVY_SLOTS):
        doc = req.app.rules.site_lines_timeline(site, frm, to, step)
    if doc is None:
        raise HttpError(404, "unknown_site", "no probe of this collector is in that site")
    req.send_json(200, doc)


# ------------------------------------------------------------------------------------------ beats
def handle_beats(req: Handler) -> None:
    app = req.app
    probe = known_probe(req)
    frm = ts_required(req, "from")
    to = ts_required(req, "to")
    if to < frm:
        raise HttpError(400, "invalid_request", "to must not be before from")
    if to - frm > MAX_BEATS_RANGE_MS:
        raise HttpError(400, "range_too_large", "to - from must be at most 6 hours")
    with _Heavy(HEAVY_SLOTS):
        doc = app.rules.beats(probe, frm, to)
    if doc is None:
        raise HttpError(404, "unknown_probe", "unknown probe")
    req.send_json(200, doc)


# ---------------------------------------------------------------------------------------- records
def handle_records(req: Handler) -> None:
    app = req.app
    probe = known_probe(req)
    test = one_param(req, "test")
    if test is not None and not _IDENT.match(test):
        raise HttpError(400, "invalid_request", "test must be an identifier")
    outcome = one_param(req, "outcome")
    if outcome is not None and outcome not in OUTCOMES:
        raise HttpError(400, "invalid_request", "outcome must be ok, degraded, fail or error")
    frm = ts_required(req, "from")
    to = ts_required(req, "to")
    if to < frm:
        raise HttpError(400, "invalid_request", "to must not be before from")
    limit = int_param(req, "limit", 1, 1000, 100)
    cur = decode_cursor(one_param(req, "cursor"))
    after: tuple[int, str] | None = None
    if cur is not None:
        t, i = cur.get("t"), cur.get("i")
        if isinstance(t, bool) or not isinstance(t, int) or not isinstance(i, str) or not 0 < len(i) <= 64:
            raise HttpError(400, "invalid_request", "invalid cursor")
        after = (t, i)
    rows = app.store.read_records(probe, frm, to, test=test or None, outcome=outcome or None, limit=limit + 1,
                                  after=after)
    more = len(rows) > limit
    rows = rows[:limit]
    items: list[Any] = []
    for _ts, _rid, body in rows:
        try:
            items.append(json.loads(body))
        except ValueError:
            log.error("unreadable stored record %s/%s skipped", probe, _rid)
    nxt = encode_cursor({"t": rows[-1][0], "i": rows[-1][1]}) if more and rows else None
    req.send_json(200, {"items": items, "next_cursor": nxt})


# -------------------------------------------------------------------------------------- incidents
def handle_incidents(req: Handler) -> None:
    app = req.app
    probe = slug_param(req, "probe")
    site = slug_param(req, "site")
    frm = ts_param(req, "from")
    to = ts_param(req, "to")
    if frm is not None and to is not None and to < frm:
        raise HttpError(400, "invalid_request", "to must not be before from")
    open_only = bool_param(req, "open")
    limit = int_param(req, "limit", 1, 1000, 100)
    cur = decode_cursor(one_param(req, "cursor"))
    before: tuple[int, str] | None = None
    if cur is not None:
        s, i = cur.get("s"), cur.get("i")
        if isinstance(s, bool) or not isinstance(s, int) or not isinstance(i, str) or not 0 < len(i) <= 64:
            raise HttpError(400, "invalid_request", "invalid cursor")
        before = (s, i)
    rows = app.store.list_incidents(probe=probe, site=site, from_ms=frm, to_ms=to, open_only=open_only,
                                    limit=limit + 1, before=before)
    more = len(rows) > limit
    rows = rows[:limit]
    board = app.rules.icfg.board_url
    nxt = encode_cursor({"s": rows[-1]["start_ms"], "i": rows[-1]["id"]}) if more and rows else None
    req.send_json(200, {"items": [incident_doc(x, board) for x in rows], "next_cursor": nxt})


def handle_ack(req: Handler) -> None:
    app = req.app
    inc_id = req.params["id"]
    if not re.fullmatch(r"inc_[0-9A-HJKMNP-TV-Z]{26}", inc_id):
        raise HttpError(400, "invalid_request", "malformed incident id")
    user = req.user
    if user == "-":
        raise HttpError(403, "forbidden", "X-Exp-User is required to acknowledge an incident")
    note = ""
    if req.headers.get("Content-Length") not in (None, "0"):
        raw = req.read_body(MAX_ACK_BODY)
        try:
            body = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        except (ValueError, UnicodeDecodeError):
            raise HttpError(400, "invalid_request", "body must be JSON") from None
        if not isinstance(body, dict):
            raise HttpError(400, "invalid_request", "body must be an object")
        n = body.get("note", "")
        if not isinstance(n, str) or len(n) > 512 or not _TEXT.match(n):
            raise HttpError(400, "invalid_request", "note must be text of at most 512 characters")
        note = n
    now_ms = int(app.clock() * 1000)
    if not app.store.ack_incident(inc_id, user, now_ms):
        raise HttpError(404, "not_found", "no such incident")
    # the audit trail: who, what, when (the note is operator text: logged as data, never interpreted)
    audit.info("incident acknowledged id=%s by=%s dashboard=%s note=%s", inc_id, user, req.identity or "-",
               json.dumps(note))
    row = app.store.get_incident(inc_id)
    if row is not None:
        app.hub.publish("incident", incident_doc(row, app.rules.icfg.board_url))
    req._send(204, b"", "application/json")


# --------------------------------------------------------------------------------------- summary
def handle_summary(req: Handler) -> None:
    app = req.app
    probe = known_probe(req)
    minutes = int_param(req, "minutes", 1, summary.MAX_MINUTES, None)
    with _Heavy(HEAVY_SLOTS):
        tables = summary.build(app.store, probe, minutes, int(app.clock() * 1000))
    req.send_json(200, tables)


# ----------------------------------------------------------------------------------- query_range
def _vm_get(app: CollectorApp, path: str) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection(app.vm.host, app.vm.port, timeout=VM_TIMEOUT_S)
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        resp = conn.getresponse()
        data = resp.read(VM_MAX_RESPONSE + 1)
        return resp.status, data
    finally:
        conn.close()


def handle_query_range(req: Handler) -> None:
    import urllib.parse
    app = req.app
    query = one_param(req, "query")
    if query is None or query == "":
        raise HttpError(400, "invalid_request", "query is required")
    if len(query.encode("utf-8", "replace")) > queryguard.MAX_QUERY_BYTES:
        raise HttpError(400, "invalid_query", f"query is longer than {queryguard.MAX_QUERY_BYTES} bytes")
    raw_start, raw_end, raw_step = one_param(req, "start"), one_param(req, "end"), one_param(req, "step")
    if not raw_start or not raw_end or not raw_step:
        raise HttpError(400, "invalid_request", "query, start, end and step are required")
    try:
        start, end = queryguard.parse_time_s(raw_start), queryguard.parse_time_s(raw_end)
    except ValueError:
        raise HttpError(400, "invalid_request", "start and end must be UTC ISO-8601 timestamps") from None
    try:
        step = queryguard.parse_step_s(raw_step)
    except ValueError:
        raise HttpError(400, "invalid_request", "step must look like 10s, 1m or 1h") from None
    if end <= start:
        raise HttpError(400, "invalid_request", "end must be after start")
    if end - start > queryguard.MAX_RANGE_S:
        raise HttpError(400, "range_too_large", "range is limited to 30 days")
    if step < queryguard.MIN_STEP_S:
        raise HttpError(400, "step_too_small", f"step must be at least {queryguard.MIN_STEP_S} s")
    if (end - start) / step > queryguard.MAX_POINTS:
        raise HttpError(400, "step_too_small",
                        f"step too small for this range (at most {queryguard.MAX_POINTS} points)")
    try:
        queryguard.check_query(query)
    except queryguard.QueryRefused as exc:
        raise HttpError(400, "invalid_query", str(exc)) from None
    qs = urllib.parse.urlencode({"query": query, "start": f"{start:.3f}", "end": f"{end:.3f}",
                                 "step": f"{step}s", "timeout": f"{int(VM_TIMEOUT_S)}s"})
    with _Heavy(VM_SLOTS):
        try:
            status, data = _vm_get(app, f"/api/v1/query_range?{qs}")
        except (OSError, http.client.HTTPException):
            raise HttpError(503, "vm_unavailable", "VictoriaMetrics is not answering",
                            {"Retry-After": "5"}) from None
    if len(data) > VM_MAX_RESPONSE:
        raise HttpError(422, "result_too_large", "the result is too large; narrow the query or widen the step")
    if status != 200:
        text = data[:300].decode("utf-8", "replace")
        if status == 422 or ("series" in text and ("exceed" in text or "limit" in text)):
            raise HttpError(422, "too_many_series", f"the query matches more than {MAX_SERIES} series")
        if status in (400, 408):
            raise HttpError(400, "invalid_query", "VictoriaMetrics rejected the query")
        raise HttpError(503, "vm_unavailable", "VictoriaMetrics failed", {"Retry-After": "5"})
    try:
        doc = json.loads(data.decode("utf-8"))
        result = doc["data"]["result"]
        ok = doc.get("status") == "success" and isinstance(result, list)
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        ok = False
    if not ok:
        raise HttpError(503, "vm_unavailable", "VictoriaMetrics sent an unreadable answer", {"Retry-After": "5"})
    if len(result) > MAX_SERIES:
        raise HttpError(422, "too_many_series", f"the query matches more than {MAX_SERIES} series")
    req.send_json(200, doc)


# --------------------------------------------------------------------------------------- stream
def handle_stream(req: Handler) -> None:
    import time as _time
    app = req.app
    probes_raw, site = one_param(req, "probes"), slug_param(req, "site")
    if (probes_raw in (None, "")) == (site is None):
        raise HttpError(400, "invalid_request", "give exactly one of probes or site")
    probes: list[str] | None = None
    if probes_raw:
        probes = probes_raw.split(",")
        if len(probes) > 64 or any(not ids.is_slug(p) for p in probes):
            raise HttpError(400, "invalid_request", "probes must be a comma-separated list of probe ids")
        unknown = [p for p in probes if p not in app.config.probes]
        if unknown:
            raise HttpError(400, "invalid_request", "unknown probe in probes")
    elif site is not None and not any(e.site == site for e in app.config.probes.values()):
        raise HttpError(400, "invalid_request", "unknown site")
    last_id = req.headers.get("Last-Event-ID")
    if last_id is not None and (len(last_id) > 128 or not last_id.isascii()):
        raise HttpError(400, "invalid_request", "bad Last-Event-ID")
    try:
        client = app.hub.subscribe(probes, site, last_id)
    except sse.TooManyClients:
        raise HttpError(429, "rate_limited", "too many live connections", {"Retry-After": "3"}) from None
    audit.info("stream opened by=%s probes=%s site=%s resume=%s", req.user, ",".join(probes or []) or "-",
               site or "-", bool(last_id))
    try:
        req.begin_stream()
        req.write_stream(sse.preamble())
        last_write = _time.monotonic()
        while True:
            wait = max(0.05, min(1.0, app.hub.keepalive_s - (_time.monotonic() - last_write)))
            item = app.hub.next_event(client, wait)
            if item == "closed":
                break
            if isinstance(item, sse.Event):
                req.write_stream(item.wire())
                last_write = _time.monotonic()
            elif _time.monotonic() - last_write >= app.hub.keepalive_s:
                req.write_stream(sse.KEEPALIVE)
                last_write = _time.monotonic()
            if not app.started or req.client_gone():
                break
    finally:
        app.hub.unsubscribe(client)
        req.close_connection = True


# ----------------------------------------------------------------------------------------- drills
def handle_drill_control(req: Handler) -> None:
    req.send_json(200, {"abort": list(req.app.drills.abort_list())[:64]})


def handle_drill_report(req: Handler) -> None:
    run_id = req.params["run_id"]
    doc = req.app.drills.report(run_id) if drills.valid_run_id(run_id) else None
    if doc is None:
        raise HttpError(404, "drill_not_found", "no such drill run")
    req.send_json(200, doc)


def handle_drill_abort(req: Handler) -> None:
    run_id = req.params["run_id"]
    user = req.user
    if not drills.valid_run_id(run_id) or not req.app.drills.abort(run_id, user):
        raise HttpError(404, "drill_not_found", "no such drill run")
    audit.info("drill abort requested run=%s by=%s dashboard=%s", run_id, user, req.identity or "-")
    req.send_json(202, {"run_id": run_id, "abort": True})

