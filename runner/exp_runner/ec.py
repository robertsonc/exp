"""HPE EdgeConnect Orchestrator connector: ``flows`` and ``wan`` evidence, and the WAN-utilization feed for the speedtest auto-pause
(12 section 5.2).

**Endpoint paths, query parameters and response fields come only from HPE's official SDK pyedgeconnect 0.16.0a1 (MIT, a dev-time
reference, never imported)**, under the REST root ``/gms/rest`` (``Orchestrator.url_prefix``):

=========================================================  =================================================================
call                                                       pyedgeconnect function (module)
=========================================================  =================================================================
GET /flow?nePk&ip1&ipEitherFlag&uptime&filter              ``get_appliance_flows`` (``_flow.py``; 63-element positional rows)
GET /appliance?nePk                                        ``get_appliances`` (``_appliance.py``: ``state``, ``hostName``)
GET /interfaceState?nePk&cached                            ``get_appliance_interface_state`` (``_interface_state.py``)
GET /stats/timeseries/interface?nePk&startTime&endTime...  ``get_timeseries_stats_interface_single_appliance`` (``_timeseries_stats.py``)
GET /health/{latency,loss,jitter,mos}PeriodSummary         ``get_health_latency|loss|jitter|mos`` (``_health.py``)
POST /alarm/appliance?view&from&to  {"nePks": [...]}       ``get_alarms_from_appliances`` (``_alarm.py``)
=========================================================  =================================================================

Auth is the API key header ``X-Auth-Token`` (``Orchestrator.__init__``); the key is only ever sent there and never logged.

What pyedgeconnect does **not** document, and how this connector copes (stated plainly, never presented as vendor fact):

* **Time-series column names** ("COLUMN_DEF ... and DATA"): the interface, time, rx and tx byte columns are found at runtime from
  ``COLUMN_DEF`` by name (``interface``/``ifname``; ``time``/``timestamp``; ``rx``+``byte``; ``tx``+``byte``). If they cannot be
  identified the raw series is still reported and ``util_pct`` is absent (status ``partial``). The values are read as bytes per
  ``minute`` bucket (an assumption: bps = bytes * 8 / 60). The response may be the documented ``list`` or the
  ``{"COLUMN_DEF", "DATA": {nePk: rows}}`` object; both are accepted.
* **Flow time window**: the documented custom time filters apply to active / terminated flows separately, so flows are requested with
  ``uptime=anytime|term<N>`` (documented values) and narrowed to the correlation window client-side by flow start/end.
  ``ipEitherFlag=False`` = both directions (documented as "directionality" for ``True``).
* **Health summaries** are typed ``dict`` but described per tunnel: a dict (worst tunnel) or a list is accepted; values are reported
  as returned, never converted.
* The "WAN path / boost" attributes of a flow are the documented row fields (tunnel ids, overlay, traffic class, DSCP); no field not
  in the docstring is used.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import threading
import time
from collections.abc import Callable
from typing import Any

from . import upstream as up
from .connectors import CallBudget, Connector, Context, EvidenceResult, Window
from .upstream import Scope, Ttl, UpstreamClient, UpstreamError

log = logging.getLogger(__name__)

PREFIX = "/gms/rest"
CALLS_PER_TEST = 32
COLLECT_DEADLINE_S = 40.0
CONNECTOR_TIMEOUT_S = 50.0
CACHE_TTL_S = 30.0
MAX_FLOWS = 50
MAX_APPLIANCES = 8
MAX_TS_ROWS = 120
MAX_TS_COLS = 32
MAX_ALARMS = 50
MAX_TUNNELS = 16
BUCKET_S = 60.0
POLL_DEADLINE_S = 20.0
SEVERITIES = ("warning", "minor", "major", "critical")
FLOW_MIN_ROW = 61
HEALTH_KINDS = (("latency", "latency"), ("loss", "loss"), ("jitter", "jitter"), ("mos", "mos"))


FATAL_KINDS = frozenset({"auth", "rate_limited", "transport", "timeout", "deadline"})


def _guard(sc: Scope, fn: Callable[[], Any]) -> Any:
    """Run one upstream read; after a failure that makes every further call pointless (credential refused, rate limited, host down,
    deadline) the rest of the chain is skipped with the same error instead of repeating it."""
    if sc.failed:
        raise UpstreamError(sc.failed, f"ec: skipped after {sc.failed}")
    try:
        return fn()
    except UpstreamError as exc:
        if exc.kind in FATAL_KINDS:
            sc.failed = exc.kind
        raise


def _ip(v: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        return None


def _at(row: list[Any], idx: int) -> Any:
    return row[idx] if idx < len(row) else None


def parse_flow(row: Any) -> dict[str, Any] | None:
    """One positional flow row (pyedgeconnect ``get_appliance_flows`` docstring indexes) -> the ``flows[]`` item."""
    if not isinstance(row, list) or len(row) < FLOW_MIN_ROW:
        return None
    ip1, ip2 = _ip(_at(row, 9)), _ip(_at(row, 16))
    if ip1 is None or ip2 is None:
        return None
    f: dict[str, Any] = {"ip1": ip1, "ip2": ip2}
    up.put(f, "application", up.s(_at(row, 3)))
    up.put(f, "port1", up.i(_at(row, 10)))
    up.put(f, "port2", up.i(_at(row, 17)))
    up.put(f, "protocol", up.s(_at(row, 26), 16))
    b_in_tx, b_in_rx, b_out_rx, b_out_tx = (up.i(_at(row, n)) or 0 for n in (20, 21, 22, 23))
    f.update({"bytes_in_tx": b_in_tx, "bytes_in_rx": b_in_rx, "bytes_out_rx": b_out_rx, "bytes_out_tx": b_out_tx,
              "bytes_total": b_in_tx + b_in_rx + b_out_rx + b_out_tx})
    for out, idx in (("uptime_ms", 25), ("lan_vlan", 30), ("traffic_class", 31), ("start_s", 38), ("end_s", 39), ("slow_duration", 43),
                     ("from_zone", 46), ("to_zone", 47), ("firewall_dropped", 48), ("drop_reason", 59)):
        up.put(f, out, up.i(_at(row, idx)))
    for out, idx, n in (("outbound_tunnel", 27, 64), ("inbound_tunnel", 28, 64), ("overlay", 60, 64), ("lan_dscp", 32, 32),
                        ("wan_dscp", 33, 32), ("app_type", 58, 64), ("nat_type", 57, 32), ("domain", 45, 253)):
        up.put(f, out, up.s(_at(row, idx), n))
    if f["bytes_total"] < 0:
        return None
    return f


def _cell(v: Any) -> Any:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, str)) or (isinstance(v, float) and math.isfinite(v)):
        return v
    return None


def _clean_row(r: list[Any]) -> list[Any]:
    return [_cell(v) for v in r[:MAX_TS_COLS]]


def _flow_in_window(f: dict[str, Any], w: Window) -> bool:
    start, end = f.get("start_s"), f.get("end_s")
    if isinstance(start, int) and start > w.to_ts:
        return False
    return not (isinstance(end, int) and end > 0 and end < w.from_ts)


def _ts_unpack(doc: Any, ne: str) -> tuple[list[str], list[list[Any]]]:
    """``COLUMN_DEF`` + the rows of appliance ``ne`` from either documented response shape."""
    if isinstance(doc, list):
        doc = doc[0] if doc and isinstance(doc[0], dict) else {}
    if not isinstance(doc, dict):
        return [], []
    cols = [str(c)[:64] for c in (doc.get("COLUMN_DEF") or []) if isinstance(c, (str, int))][:MAX_TS_COLS * 4]
    data = doc.get("DATA")
    rows = data.get(ne) if isinstance(data, dict) else data
    rows = [r for r in (rows or []) if isinstance(r, list)]
    return cols, rows


def _col(cols: list[str], *needles: str, all_of: tuple[str, ...] = ()) -> int | None:
    low = [c.lower() for c in cols]
    for i, c in enumerate(low):
        if any(c == n for n in needles) or (all_of and all(n in c for n in all_of)):
            return i
    for i, c in enumerate(low):
        if any(n in c for n in needles if len(n) > 3):
            return i
    return None


def ts_utilization(cols: list[str], rows: list[list[Any]], wan_ifs: set[str] | None, max_kbps: int | None, w_from: float,
                   w_to: float) -> tuple[dict[str, dict[str, Any]], bool]:
    """Per interface ``{rx_bps, tx_bps, util_pct}`` (peak over the window) derived from a time series; the bool says whether the
    columns could be identified at all."""
    c_if = _col(cols, "interface", "ifname", "interface_name", "name")
    c_t = _col(cols, "time", "timestamp", "ts", "starttime")
    c_rx = _col(cols, all_of=("rx", "byte"))
    c_tx = _col(cols, all_of=("tx", "byte"))
    if c_rx is None or c_tx is None:
        return {}, False
    peaks: dict[str, tuple[float, float]] = {}
    for r in rows:
        t = up.f(_at(r, c_t)) if c_t is not None else None
        if t is not None:
            if t > 1e11:
                t /= 1000.0
            if not (w_from - BUCKET_S <= t <= w_to):
                continue
        name = up.s(_at(r, c_if), 32) if c_if is not None else None
        name = name or "*"
        rx, tx = up.f(_at(r, c_rx)), up.f(_at(r, c_tx))
        if rx is None or tx is None:
            continue
        old = peaks.get(name, (0.0, 0.0))
        peaks[name] = (max(old[0], rx * 8 / BUCKET_S), max(old[1], tx * 8 / BUCKET_S))
    out: dict[str, dict[str, Any]] = {}
    for name, (rx, tx) in peaks.items():
        if wan_ifs is not None and name != "*" and name not in wan_ifs:
            continue
        d: dict[str, Any] = {"rx_bps": int(rx), "tx_bps": int(tx)}
        if max_kbps and max_kbps > 0:
            d["util_pct"] = round(max(rx, tx) / (max_kbps * 1000.0) * 100.0, 2)
        out[name] = d
    return out, True


class EcService:
    def __init__(self, cfg: dict[str, Any], creds: dict[str, str], *, clock: Callable[[], float] = time.time,
                 client: UpstreamClient | None = None, ca_file: str | None = None) -> None:
        self.clock = clock
        self.appliances = [a for a in (cfg.get("appliances") or []) if isinstance(a, dict) and isinstance(a.get("ne_pk"), str)][:MAX_APPLIANCES]
        self.max_flows = max(1, min(MAX_FLOWS, int(cfg.get("max_flows", MAX_FLOWS))))
        self.wan_util_enabled = bool((cfg.get("wan_util") or {}).get("enabled", False))
        self.wan_util_interval = int((cfg.get("wan_util") or {}).get("interval_s", 30))
        base = creds["url"].rstrip("/")
        if not base.endswith(PREFIX):
            base += PREFIX
        self.client = client or UpstreamClient("ec", base, {"X-Auth-Token": creds["api_key"]}, ca_file=ca_file)
        self._cache = Ttl(CACHE_TTL_S, clock)

    def scope(self, budget: CallBudget, seconds: float) -> Scope:
        return Scope(budget, self.client._clock() + seconds)

    def _wan_ifs(self, ne: str) -> set[str] | None:
        for a in self.appliances:
            if a["ne_pk"] == ne and a.get("wan_interfaces"):
                return {str(x) for x in a["wan_interfaces"]}
        return None

    def _get(self, sc: Scope, path: str, params: dict[str, Any]) -> Any:
        return _guard(sc, lambda: self.client.get(path, params, budget=sc.budget, deadline=sc.deadline))

    def _cached(self, key: tuple[Any, ...], fn: Callable[[], Any]) -> Any:
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        val = fn()
        self._cache.put(key, val)
        return val

    # -------------------------------------------------------------------------------------------- reads
    def flows(self, ne: str, ip: str, window: Window, now: float, sc: Scope) -> dict[str, Any]:
        age = now - window.to_ts
        uptime = "anytime|term1hr" if age < 3500 else ("anytime|term24hr" if age < 86000 else "anytime")
        doc = self._get(sc, "/flow", {"nePk": ne, "ip1": ip, "ipEitherFlag": "false", "filter": "all", "uptime": uptime})
        if not isinstance(doc, dict):
            raise UpstreamError("bad_response", "ec: unexpected flow response")
        return doc

    def appliance(self, ne: str, sc: Scope) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            doc = self._get(sc, "/appliance", {"nePk": ne})
            return doc if isinstance(doc, dict) else {}
        return self._cached(("appliance", ne), go)

    def interface_state(self, ne: str, sc: Scope) -> dict[str, Any]:
        def go() -> dict[str, Any]:
            doc = self._get(sc, "/interfaceState", {"nePk": ne, "cached": "true"})
            return doc if isinstance(doc, dict) else {}
        return self._cached(("ifstate", ne), go)

    def timeseries(self, ne: str, start: int, end: int, sc: Scope) -> Any:
        key = ("ts", ne, start // 30, end // 30)
        params = {"nePk": ne, "startTime": start, "endTime": end, "granularity": "minute", "trafficType": "all_traffic"}
        return self._cached(key, lambda: self._get(sc, "/stats/timeseries/interface", params))

    def health(self, ne: str, kind: str, hour: int, sc: Scope) -> Any:
        return self._cached(("health", ne, kind, hour), lambda: self._get(
            sc, f"/health/{kind}PeriodSummary", {"applianceId": ne, "time": hour, "overlayId": -1}))

    def alarms(self, ne: str, w: Window, sc: Scope) -> list[dict[str, Any]]:
        def go() -> list[dict[str, Any]]:
            doc = _guard(sc, lambda: self.client.request(
                "POST", "/alarm/appliance", {"view": "all", "from": int(w.from_ts * 1000), "to": int(w.to_ts * 1000) + 1000, "maxAlarms": MAX_ALARMS,
                                             "orderBySeverity": "true"}, {"nePks": [ne]}, budget=sc.budget, deadline=sc.deadline, idempotent=True))
            return [a for a in doc if isinstance(a, dict)] if isinstance(doc, list) else []
        return self._cached(("alarms", ne, int(w.from_ts // 30), int(w.to_ts // 30)), go)


class EcConnector(Connector):
    name = "ec"
    kinds = ("flows", "wan")
    timeout_s = CONNECTOR_TIMEOUT_S

    def __init__(self, svc: EcService) -> None:
        self.svc = svc

    def configured(self) -> bool:
        return bool(self.svc.appliances)

    def collect(self, ctx: Context) -> list[EvidenceResult]:
        sc = self.svc.scope(ctx.budget("ec", CALLS_PER_TEST), COLLECT_DEADLINE_S)
        return [self._flows(ctx, sc), self._wan(ctx, sc)]

    # ---------------------------------------------------------------------------------------------- flows
    def _flows(self, ctx: Context, sc: Scope) -> EvidenceResult:
        svc = self.svc
        ip, w = ctx.test.client_ip, ctx.window
        counts = dict.fromkeys(("total_flows", "matched_flows", "returned_flows", "flows_firewall_dropped", "flows_route_dropped"), 0)
        merged: list[tuple[str, dict[str, Any]]] = []
        errors: list[str] = []
        ok_n = 0
        for a in svc.appliances:
            ne = a["ne_pk"]
            try:
                doc = svc.flows(ne, ip, w, ctx.now_fn(), sc)
            except UpstreamError as exc:
                errors.append(exc.kind)
                log.warning("ec flows %s: %s", ne, exc.kind)
                continue
            ok_n += 1
            for k in ("total_flows", "matched_flows", "returned_flows"):
                counts[k] += up.i(doc.get(k)) or 0
            for side in ("active", "inactive"):
                blk = doc.get(side) if isinstance(doc.get(side), dict) else {}
                counts["flows_firewall_dropped"] += up.i(blk.get("flows_firewall_dropped")) or 0
                counts["flows_route_dropped"] += up.i(blk.get("flows_route_dropped")) or 0
            for row in (doc.get("flows") if isinstance(doc.get("flows"), list) else [])[:5000]:
                fl = parse_flow(row)
                if fl is not None and ip in (fl["ip1"], fl["ip2"]) and _flow_in_window(fl, w):
                    merged.append((ne, fl))
        if ok_n == 0:
            return EvidenceResult("flows", "ec", "error")
        merged.sort(key=lambda t: t[1]["bytes_total"], reverse=True)
        top = merged[:svc.max_flows]
        by_ne: dict[str, int] = {}
        for ne, fl in top:
            by_ne[ne] = by_ne.get(ne, 0) + fl["bytes_total"]
        appliance = max(by_ne, key=lambda k: by_ne[k]) if by_ne else svc.appliances[0]["ne_pk"]
        counts["returned_flows"] = len(top)
        counts["matched_flows"] = max(counts["matched_flows"], len(merged))
        data = {"appliance": up.s(appliance, 128), "counts": counts, "flows": [fl for _ne, fl in top]}
        status = "ok" if not errors else "partial"
        return EvidenceResult("flows", "ec", status, data, [f"ec:{ne}:flows" for ne in by_ne][:20])

    # ------------------------------------------------------------------------------------------------ wan
    def _wan(self, ctx: Context, sc: Scope) -> EvidenceResult:
        svc = self.svc
        w = ctx.window
        hour = int(ctx.test.ended) // 3600 * 3600
        apps: list[dict[str, Any]] = []
        errors: list[str] = []
        best: float | None = None
        for a in svc.appliances:
            ne = a["ne_pk"]
            entry, errs, util = self._one_appliance(ne, a, w, hour, sc)
            errors += errs
            if util is not None:
                best = util if best is None else max(best, util)
            if entry is not None:
                apps.append(entry)
        if not apps:
            return EvidenceResult("wan", "ec", "error" if errors else "unavailable")
        data: dict[str, Any] = {"appliances": apps}
        if best is not None:
            data["wan_util_pct"] = round(best, 2)
        return EvidenceResult("wan", "ec", "ok" if not errors and best is not None else "partial", data,
                              [f"ec:{x['ne_pk']}:wan" for x in apps][:20])

    def _one_appliance(self, ne: str, a: dict[str, Any], w: Window, hour: int, sc: Scope) -> tuple[dict[str, Any] | None, list[str], float | None]:
        svc = self.svc
        errors: list[str] = []
        entry: dict[str, Any] = {"ne_pk": up.s(ne, 128) or ne}
        up.put(entry, "hostname", up.s(a.get("hostname"), 128))

        def guarded(fn: Callable[[], Any]) -> Any:
            try:
                return fn()
            except UpstreamError as exc:
                errors.append(exc.kind)
                log.warning("ec %s: %s", ne, exc.kind)
                return None
        app = guarded(lambda: svc.appliance(ne, sc))
        if isinstance(app, dict) and app:
            up.put(entry, "hostname", up.s(app.get("hostName"), 128))
            up.put(entry, "state", up.i(app.get("state")))
        ifs = guarded(lambda: svc.interface_state(ne, sc))
        ts = guarded(lambda: svc.timeseries(ne, int(w.from_ts), int(w.to_ts) + 1, sc))
        scal = (ifs or {}).get("scalars") if isinstance(ifs, dict) else None
        max_kbps = up.i((scal or {}).get("maxWanBandwidth")) if isinstance(scal, dict) else None
        cols, rows = _ts_unpack(ts, ne) if ts is not None else ([], [])
        wan_names = svc._wan_ifs(ne)
        interfaces = self._interfaces(ifs, max_kbps)
        if wan_names is None:
            wan_names = {i["ifname"] for i in interfaces if i.get("wan_if")} or None
        util_map, ident = ts_utilization(cols, rows, wan_names, max_kbps, w.from_ts, w.to_ts) if ts is not None else ({}, True)
        if ts is not None and not ident:
            errors.append("timeseries_columns")
        best: float | None = None
        for it in interfaces:
            u = util_map.get(it["ifname"]) or (util_map.get("*") if len(wan_names or ()) <= 1 and it.get("wan_if") else None)
            if u and (wan_names is None or it["ifname"] in wan_names):
                for k in ("rx_bps", "tx_bps"):
                    it[k] = u[k]
                if "util_pct" in u:
                    it["util_pct"] = u["util_pct"]
                    best = u["util_pct"] if best is None else max(best, u["util_pct"])
        if interfaces:
            entry["interfaces"] = interfaces[:16]
        health: dict[str, list[dict[str, Any]]] = {}
        for key, kind in HEALTH_KINDS:
            doc = guarded(lambda kind=kind: svc.health(ne, kind, hour, sc))
            items = self._health_items(doc, key)
            if items:
                health[key] = items
        if health:
            entry["health"] = health
        alarms = guarded(lambda: svc.alarms(ne, w, sc))
        if alarms:
            entry["alarms"] = self._alarms(alarms)
        if cols and rows:
            entry["timeseries"] = {"columns": cols[:MAX_TS_COLS], "rows": [_clean_row(r) for r in rows[-MAX_TS_ROWS:]]}
        if errors and not any(k in entry for k in ("state", "interfaces", "health", "alarms", "timeseries")):
            return None, errors, None
        return entry, errors, best

    @staticmethod
    def _interfaces(doc: Any, max_kbps: int | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for r in ((doc or {}).get("ifInfo") if isinstance(doc, dict) else None) or []:
            name = up.s(r.get("ifname"), 32) if isinstance(r, dict) else None
            if not name:
                continue
            it: dict[str, Any] = {"ifname": name}
            for k_out, k in (("wan_if", "wan-if"), ("lan_if", "lan-if"), ("admin", "admin"), ("oper", "oper")):
                up.put(it, k_out, up.b(r.get(k)))
            up.put(it, "if_speed", up.s(r.get("ifSpeed"), 32))
            up.put(it, "duplex", up.s(r.get("duplex"), 32))
            up.put(it, "label", up.s(r.get("label"), 32))
            up.put(it, "public_ip", _ip(r.get("publicIp")) if r.get("publicIp") else None)
            up.put(it, "max_wan_bandwidth_kbps", max_kbps)
            out.append(it)
        return out[:16]

    @staticmethod
    def _health_items(doc: Any, kind: str) -> list[dict[str, Any]]:
        rows = doc if isinstance(doc, list) else ([doc] if isinstance(doc, dict) and doc else [])
        out = []
        for r in rows[:MAX_TUNNELS]:
            if not isinstance(r, dict):
                continue
            it: dict[str, Any] = {}
            up.put(it, "tunnel_id", up.s(r.get("tunnelId"), 128))
            up.put(it, "health_status", up.s(r.get("healthStatus"), 32))
            for k_out, k in (("critical_mins", "criticalMins"), ("major_mins", "majorMins"), ("normal_mins", "normalMins")):
                up.put(it, k_out, up.i(r.get(k)))
            up.put(it, "max", up.f(r.get("maxLossPercentage") if kind == "loss" else r.get("max")))
            if it:
                out.append(it)
        return out

    @staticmethod
    def _alarms(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for r in rows[:MAX_ALARMS]:
            sev = str(r.get("severity", "")).lower()
            name = up.s(r.get("name"), 128)
            if sev not in SEVERITIES or not name:
                continue
            al: dict[str, Any] = {"severity": sev, "alarm_name": name}
            up.put(al, "sequence_id", up.i(r.get("sequenceId")))
            up.put(al, "type", up.s(r.get("type"), 64))
            up.put(al, "description", up.s(r.get("description"), 512))
            up.put(al, "time_occurred_ms", up.i(r.get("timeOccurredInMills")))
            up.put(al, "occurrence_count", up.i(r.get("occurrenceCount")))
            up.put(al, "service_affect", up.b(r.get("serviceAffect")))
            up.put(al, "closed", up.b(r.get("closed")))
            up.put(al, "cleared_ms", up.i(r.get("clearedTimeInMills")))
            up.put(al, "host_name", up.s(r.get("hostName"), 128))
            out.append(al)
        return out


class WanUtilMonitor:
    """The auto-pause signal: the held peak WAN utilization (percent of ``maxWanBandwidth``) over the last two minute buckets across the
    configured appliances. The speedtest owns the threshold (``internet_leg.auto_pause_wan_util_pct``) and its own staleness/fail-open
    rule; holding the previous bucket here is the hysteresis on the way down (a spike keeps the leg paused for ~2 minutes) and any
    failure returns None (nothing published = fail open)."""

    def __init__(self, svc: EcService, *, clock: Callable[[], float] = time.time) -> None:
        self.svc, self.clock = svc, clock
        self._lock = threading.Lock()
        self.last: float | None = None

    def value(self) -> float | None:
        svc = self.svc
        now = self.clock()
        sc = svc.scope(CallBudget(4 * max(1, len(svc.appliances))), POLL_DEADLINE_S)
        best: float | None = None
        for a in svc.appliances:
            ne = a["ne_pk"]
            try:
                ifs = svc.interface_state(ne, sc)
                ts = svc.timeseries(ne, int(now - 3 * BUCKET_S), int(now) + 1, sc)
            except UpstreamError as exc:
                log.warning("ec wan utilization %s: %s", ne, exc.kind)
                continue
            scal = ifs.get("scalars") if isinstance(ifs, dict) else None
            max_kbps = up.i((scal or {}).get("maxWanBandwidth")) if isinstance(scal, dict) else None
            cols, rows = _ts_unpack(ts, ne)
            wan = svc._wan_ifs(ne) or {i["ifname"] for i in EcConnector._interfaces(ifs, max_kbps) if i.get("wan_if")} or None
            c_t = _col(cols, "time", "timestamp", "ts", "starttime")
            if c_t is not None:      # the two latest buckets (the current one is still filling)
                times = sorted({up.f(_at(r, c_t)) or 0.0 for r in rows})[-2:]
                rows = [r for r in rows if (up.f(_at(r, c_t)) or 0.0) in times]
            util, ident = ts_utilization(cols, rows, wan, max_kbps, 0.0, float("inf"))
            if not ident:
                continue
            for u in util.values():
                if "util_pct" in u:
                    best = u["util_pct"] if best is None else max(best, u["util_pct"])
        with self._lock:
            self.last = best
        return best
