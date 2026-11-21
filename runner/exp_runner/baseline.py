"""The probe baseline connector and the SSE placeholder (12 section 5.2).

``baseline`` (source ``exp``): the nearest probe's state at test time, read from the collector's own records
(``GET speedtests/baseline?site&zone&ap&at`` with the runner's ``expr_`` token). The collector decides "nearest" (same AP, then zone,
then site); the runner only passes where the client was (resolved zone and AP name) and when the test ended. The answer is the
``kind=baseline`` data shape; it is re-bounded here (closed key sets, string lengths) so a misbehaving collector cannot break the
evidence document.

``SseConnector``: HPE Aruba SSE (Axis) has **no local vendor documentation**, so no API connector exists (CR-m6-runner-connectors,
decision 2 of the M6 brief): it reports ``unavailable`` with the reason and never guesses a field. SSE decisions can still arrive as
syslog lines, which the syslog connector normalizes (``source`` stays ``syslog``).
"""
from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Any

from . import upstream as up
from .collector_client import CollectorClient, CollectorError
from .connectors import Connector, Context, EvidenceResult
from .evidence import _fmt

log = logging.getLogger(__name__)

SSE_REASON = "HPE Aruba SSE (Axis) has no local vendor API documentation: no connector (decision recorded in CR-m6-runner-connectors); " \
             "SSE logs are accepted via syslog"
SEVERITIES = ("ok", "warn", "fail", "unknown")
DISTANCES = ("same_ap", "same_zone", "same_site")
LINE_KEYS = ("network", "dhcp", "dns", "internet", "apps", "wifi", "path")
MAX_LINES = 8
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def _ts(v: Any) -> str | None:
    return v if isinstance(v, str) and len(v) <= 40 and v.endswith("Z") else None


def normalize_baseline(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Closed-key copy of a collector baseline answer, or None when it has no usable verdict."""
    sev = doc.get("severity")
    probe = up.s(doc.get("probe"), 64)
    if sev not in SEVERITIES or not probe or not _SLUG.match(probe):
        return None
    out: dict[str, Any] = {"probe": probe, "severity": sev}
    site = up.s(doc.get("site"), 64)
    if site and _SLUG.match(site):
        out["site"] = site
    if doc.get("distance") in DISTANCES:
        out["distance"] = doc["distance"]
    up.put(out, "at", _ts(doc.get("at")))
    lines = []
    for ln in (doc.get("lines") if isinstance(doc.get("lines"), list) else [])[:MAX_LINES]:
        if isinstance(ln, dict) and ln.get("key") in LINE_KEYS and ln.get("state") in SEVERITIES:
            item: dict[str, Any] = {"key": ln["key"], "state": ln["state"]}
            up.put(item, "detail", up.s(ln.get("detail"), 200))
            lines.append(item)
    if lines:
        out["lines"] = lines
    th = doc.get("throughput")
    if isinstance(th, dict):
        t: dict[str, Any] = {}
        for k in ("down_mbps", "up_mbps", "latency_idle_ms", "latency_loaded_ms"):
            if k in th:
                t[k] = up.f(th.get(k))
        up.put(t, "ts", _ts(th.get("ts")))
        if t:
            out["throughput"] = t
    wf = doc.get("wifi")
    if isinstance(wf, dict):
        w: dict[str, Any] = {}
        up.put(w, "ssid", up.s(wf.get("ssid")))
        up.put(w, "band", up.s(wf.get("band"), 16))
        for k in ("rssi_dbm", "snr_db"):
            if k in wf:
                w[k] = up.f(wf.get(k))
        if w:
            out["wifi"] = w
    return out


class BaselineConnector(Connector):
    name = "baseline"
    kinds = ("baseline",)
    timeout_s = 25.0

    def __init__(self, client_fn: Callable[[], CollectorClient | None] | None = None) -> None:
        self._client_fn: Callable[[], CollectorClient | None] = client_fn or (lambda: None)

    def use_client(self, client_fn: Callable[[], CollectorClient | None]) -> None:
        """The runner app hands over the correlator's own (pinned, token-bound) collector client; ``None`` = no token yet."""
        self._client_fn = client_fn

    def collect(self, ctx: Context) -> list[EvidenceResult]:
        client = self._client_fn()
        if client is None:
            return [EvidenceResult("baseline", "exp", "unavailable")]
        ident = ctx.identity
        try:
            doc = client.baseline(ctx.test.site, ident.zone if ident.zone != "unresolved" else None, ident.ap_name, _fmt(ctx.test.ended))
        except CollectorError as exc:
            log.warning("baseline read failed: %s", exc)
            return [EvidenceResult("baseline", "exp", "error")]
        if doc is None:
            return [EvidenceResult("baseline", "exp", "unavailable")]
        data = normalize_baseline(doc)
        if data is None:
            return [EvidenceResult("baseline", "exp", "unavailable")]
        return [EvidenceResult("baseline", "exp", "ok", data, [f"probe:{data['probe']}"])]


class SseConnector(Connector):
    """Reports ``unavailable`` (with the reason) for the kinds an SSE API would have produced; produces no evidence of its own."""

    name = "sse"
    kinds = ()
    reason = SSE_REASON

    def configured(self) -> bool:
        return False

    def collect(self, ctx: Context) -> list[EvidenceResult]:       # pragma: no cover - never scheduled
        return []

    def status(self) -> dict[str, str]:
        return {"status": "unavailable", "reason": self.reason}
