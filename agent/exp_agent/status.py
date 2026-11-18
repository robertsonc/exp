"""Status report builder: exactly exp.status/1 (01-contracts.md section 8)."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .context import Context
from .facts import collect_facts, interface_facts
from .health import HealthResult, run_health
from .metrics import HostMetrics
from .state import iso_now

log = logging.getLogger(__name__)

MAX_REPORT_BYTES = 240 * 1024
_STATE_MAP = {
    "active": "running",
    "reloading": "running",
    "inactive": "stopped",
    "failed": "failed",
    "activating": "starting",
    "deactivating": "stopping",
}


def _component_entry(
    ctx: Context, hm: HostMetrics, c: str, rec: dict[str, Any], h: HealthResult
) -> dict[str, Any]:
    units = list(rec.get("units", [])) + list(rec.get("instances", []))
    main = next((u for u in rec.get("units", []) if u.endswith(".service")), units[0] if units else None)
    active = ctx.sysctl.show(main, ["ActiveState"]).get("ActiveState", "") if main else ""
    state = _STATE_MAP.get(active, "unknown")
    proc = hm.process([u for u in units])
    health = h.status if h.status in ("ok", "degraded", "fail") else "unknown"
    if state in ("stopped", "failed") and health == "ok":
        health = "fail"
    since = None
    if proc.get("uptime_s") is not None:
        since = iso_now(ctx.clock() - float(proc["uptime_s"]))
    entry: dict[str, Any] = {
        "type": c,
        "id": rec.get("id", c),
        "version": rec["version"],
        "state": state,
        "health": health,
        "detail": h.detail[:1000],
        "since": since,
        "process": proc,
        "metrics": h.metrics,
        "facts": h.facts,
    }
    return entry


def build_status(ctx: Context, hm: HostMetrics, interval_s: int = 60) -> dict[str, Any]:
    st = ctx.state
    facts = collect_facts(ctx)
    _ifaces, _default, roles = interface_facts(ctx)
    metrics = hm.collect(interval_s, roles)
    recs = dict(st.data["components"])
    comps: list[dict[str, Any]] = []
    if recs:
        with ThreadPoolExecutor(max_workers=min(4, len(recs))) as pool:
            futures = {c: pool.submit(run_health, ctx, c, r["version"]) for c, r in recs.items()}
            results = {c: f.result() for c, f in futures.items()}
        for c in sorted(recs):
            comps.append(_component_entry(ctx, hm, c, recs[c], results[c]))
    for ig in st.data.get("ignored", []):
        comps.append(
            {
                "type": ig["type"],
                "id": ig["id"] or "unknown",
                "state": "unsupported",
                "health": "unknown",
                "detail": ig["reason"][:1000],
            }
        )
    events = st.pending_events()
    doc: dict[str, Any] = {
        "schema": "exp.status/1",
        "agent": {
            "version": ctx.agent_version,
            "desired_version": st.data.get("desired_version"),
            "applied_version": st.data.get("applied_version"),
            "uptime_s": round(max(0.0, ctx.monotonic() - ctx.started), 1),
            "last_poll": st.data.get("last_poll"),
        },
        "facts": facts,
        "metrics": metrics,
        "components": comps[:16],
        "reconcile": st.data.get("last_reconcile"),
        "events": events[-100:],
    }
    if (
        len(json.dumps(doc)) > MAX_REPORT_BYTES
    ):  # drop bulky per-component metrics before the manager rejects it
        for entry in doc["components"]:
            entry.pop("metrics", None)
    return doc
