"""Dashboard query API (01-contracts.md section 5). Step 1 implements ``GET health`` and ``GET probes``;
the rest (state, beats, records, incidents, summary, query_range, stream, drills) is registered by
later steps through ``register_routes`` using the same Router."""
from __future__ import annotations

import base64
import datetime
import json
import shutil
import time
from typing import TYPE_CHECKING

from . import __version__
from .server import (
    AUTH_DASHBOARD,
    AUTH_INGEST,
    AUTH_NONE,
    Handler,
    HttpError,
    Router,
    handle_healthz,
    handle_ingest,
)

if TYPE_CHECKING:  # pragma: no cover
    from .app import CollectorApp

INGEST_PATH = "/ingest/v1/measurements"


def _iso(epoch_ms: float) -> str:
    return (datetime.datetime.fromtimestamp(epoch_ms / 1000.0, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def one_param(req: Handler, name: str) -> str | None:
    vals = req.query.get(name)
    if not vals:
        return None
    if len(vals) > 1:
        raise HttpError(400, "invalid_request", f"{name} given more than once")
    return vals[0]


def int_param(req: Handler, name: str, lo: int, hi: int, default: int) -> int:
    raw = one_param(req, name)
    if raw is None or raw == "":
        return default
    if not raw.isdigit() or len(raw) > 9:
        raise HttpError(400, "invalid_request", f"{name} must be an integer")
    v = int(raw)
    if not lo <= v <= hi:
        raise HttpError(400, "invalid_request", f"{name} must be between {lo} and {hi}")
    return v


def build_router(app: CollectorApp) -> Router:
    r = Router()
    r.add("GET", "/healthz", handle_healthz, auth=AUTH_NONE)
    r.add("POST", INGEST_PATH, handle_ingest, auth=AUTH_INGEST, max_body=app.config.max_body_bytes)
    r.add("GET", "/api/v1/health", handle_health, auth=AUTH_DASHBOARD)
    r.add("GET", "/api/v1/probes", handle_probes, auth=AUTH_DASHBOARD)
    return r


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
    site = one_param(req, "site")
    if site is not None:
        from exp_common import ids
        if not ids.is_slug(site):
            raise HttpError(400, "invalid_request", "site must be a slug")
    limit = int_param(req, "limit", 1, 1000, 100)
    cursor = one_param(req, "cursor")
    offset = 0
    if cursor:
        try:
            offset = int(json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))["o"])
            if offset < 0:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise HttpError(400, "invalid_request", "invalid cursor") from None
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
        })
    nxt = None
    if offset + limit < len(entries):
        nxt = base64.urlsafe_b64encode(json.dumps({"o": offset + limit}).encode()).decode().rstrip("=")
    req.send_json(200, {"items": items, "next_cursor": nxt})
