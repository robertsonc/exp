"""Federation: the dashboard's /api/v1/* mirrors the collector query API across collectors[].

* probe-scoped calls (state, beats, records, summary) go to the collector that owns the probe
  (probe -> collector map, refreshed every 30 s from ``probes``);
* list calls (probes, states, incidents, health) fan out in parallel (3 s each) and merge, adding
  ``"collectors":[{collector_id, site, ok, error?}]`` so the UI can show partial results;
* upstream calls carry the per-collector ``expd_`` token and ``X-Exp-User`` over pinned TLS.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import logging
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

from exp_common import tlspin

from .auth import user_header
from .config import CollectorCfg, Settings

log = logging.getLogger(__name__)

UPSTREAM_TIMEOUT_S = 3.0
ACTION_TIMEOUT_S = 10.0          # purge: secure_delete on a big database is slower than a read
MAP_REFRESH_S = 30.0
MAX_UPSTREAM_BYTES = 8 * 1024 * 1024
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_TIME = re.compile(r"^[0-9T:.+\-Zz]{10,40}$")
_CURSOR = re.compile(r"^[A-Za-z0-9_=.\-]{1,512}$")
_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ApiProblem(Exception):
    """Maps to the standard error envelope."""

    def __init__(self, status: int, code: str, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details or {}


def _slug(v: str) -> str:
    if not SLUG.match(v):
        raise ValueError
    return v


def _time(v: str) -> str:
    if not _TIME.match(v):
        raise ValueError
    return v


def _int(lo: int, hi: int):
    def f(v: str) -> str:
        if not re.fullmatch(r"[0-9]{1,6}", v) or not lo <= int(v) <= hi:
            raise ValueError
        return v
    return f


def _enum(*vals: str):
    def f(v: str) -> str:
        if v not in vals:
            raise ValueError
        return v
    return f


def _cursor(v: str) -> str:
    if not _CURSOR.match(v):
        raise ValueError
    return v


def _text(limit: int):
    def f(v: str) -> str:
        if len(v) > limit or re.search(r"[\x00-\x1f\x7f]", v):
            raise ValueError
        return v
    return f


# endpoint -> {param: validator}; required params listed separately. Unknown params are dropped.
PARAMS: dict[str, dict[str, Any]] = {
    "probes": {"site": _slug},
    "states": {"site": _slug, "at": _time, "voice": _enum("plain", "sysadmin")},
    "incidents": {"probe": _slug, "site": _slug, "from": _time, "to": _time,
                  "open": _enum("true", "false")},
    "state": {"probe": _slug, "at": _time, "voice": _enum("plain", "sysadmin")},
    "beats": {"probe": _slug, "from": _time, "to": _time},
    "records": {"probe": _slug, "test": _text(64), "outcome": _text(32), "from": _time, "to": _time,
                "limit": _int(1, 1000), "cursor": _cursor},
    "summary": {"probe": _slug, "minutes": _int(1, 1440)},
    "query_range": {"query": _text(2048), "start": _time, "end": _time, "step": _text(16),
                    "collector": _slug},
    "health": {},
}
REQUIRED = {"state": ("probe",), "beats": ("probe", "from", "to"), "records": ("probe", "from", "to"),
            "summary": ("probe", "minutes"), "query_range": ("query", "start", "end", "step")}
SCOPED = ("state", "beats", "records", "summary")
FANOUT = ("probes", "states", "incidents", "health")


def clean_params(endpoint: str, raw: dict[str, list[str]]) -> dict[str, str]:
    allowed = PARAMS[endpoint]
    out: dict[str, str] = {}
    for k, vals in raw.items():
        fn = allowed.get(k)
        if fn is None or not vals:
            continue
        try:
            out[k] = fn(vals[0])
        except ValueError:
            raise ApiProblem(400, "invalid_request", f"bad value for '{k}'") from None
    for k in REQUIRED.get(endpoint, ()):
        if k not in out:
            raise ApiProblem(400, "invalid_request", f"missing '{k}'")
    return out


@dataclass
class UpstreamResult:
    collector_id: str
    ok: bool
    status: int = 0
    body: bytes = b""
    error: str | None = None
    headers: dict[str, str] | None = None

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


@dataclass
class CollectorState:
    ok: bool | None = None          # None = not polled yet
    error: str | None = None
    last_ok: float | None = None


class Federation:
    def __init__(self, settings: Settings, get_tokens, clock=time.time) -> None:
        self.settings = settings
        self._get_tokens = get_tokens          # () -> {collector_id: expd_ token}
        self._clock = clock
        self.collectors: dict[str, CollectorCfg] = {c.collector_id: c for c in settings.collectors}
        self.state: dict[str, CollectorState] = {cid: CollectorState() for cid in self.collectors}
        self.probe_map: dict[str, tuple[str, str]] = {}      # probe -> (collector_id, site)
        self._map_at = 0.0
        self._lock = threading.Lock()
        self._pool = cf.ThreadPoolExecutor(max_workers=max(4, min(64, len(self.collectors) * 4)),
                                           thread_name_prefix="fed")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.on_collector_state = None          # callback(collector_id, ok)

    # -- lifecycle --------------------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="fed-map", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._pool.shutdown(wait=False, cancel_futures=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.refresh_map()
            except Exception:   # noqa: BLE001 - the refresher must never die
                log.exception("probe map refresh failed")
            self._stop.wait(MAP_REFRESH_S)

    # -- upstream ---------------------------------------------------------------------------
    def _call(self, c: CollectorCfg, method: str, path: str, params: dict[str, str] | None,
              user: str, body: bytes | None = None, timeout: float = UPSTREAM_TIMEOUT_S) -> UpstreamResult:
        token = self._get_tokens().get(c.collector_id)
        if not token:
            return UpstreamResult(c.collector_id, False, error="no_credential")
        url = f"{c.url}/api/v1/{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Authorization": f"Bearer {token}", "X-Exp-User": user_header(user),
                   "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            r = tlspin.request(method, url, c.pin, body=body, headers=headers, connect_timeout=timeout,
                               read_timeout=timeout, total_timeout=timeout,
                               max_response_bytes=MAX_UPSTREAM_BYTES)
        except tlspin.PinMismatch:
            log.error("collector %s: TLS pin mismatch (nothing was sent)", c.collector_id)
            return UpstreamResult(c.collector_id, False, error="tls_pin_mismatch")
        except tlspin.PinnedTimeout:
            return UpstreamResult(c.collector_id, False, error="timeout")
        except (tlspin.TlsPinError, OSError, ValueError) as exc:
            log.warning("collector %s unreachable: %s", c.collector_id, type(exc).__name__)
            return UpstreamResult(c.collector_id, False, error="unreachable")
        except Exception as exc:   # noqa: BLE001 - http.client errors etc.: report, never crash a worker
            log.warning("collector %s call failed: %s", c.collector_id, type(exc).__name__)
            return UpstreamResult(c.collector_id, False, error="unreachable")
        if r.status in (401, 403):
            return UpstreamResult(c.collector_id, False, r.status, error="unauthorized")
        if r.status >= 500:
            return UpstreamResult(c.collector_id, False, r.status, error="upstream_error")
        return UpstreamResult(c.collector_id, True, r.status, r.body, headers=r.headers)

    def _note(self, res: UpstreamResult) -> None:
        st = self.state[res.collector_id]
        changed = st.ok is not res.ok
        st.ok, st.error = res.ok, res.error
        if res.ok:
            st.last_ok = self._clock()
        if changed and self.on_collector_state:
            self.on_collector_state(res.collector_id, res.ok)

    def fan_out(self, path: str, params: dict[str, str], user: str,
                only: list[str] | None = None) -> list[UpstreamResult]:
        cols = [c for c in self.collectors.values() if only is None or c.collector_id in only]
        futs = {self._pool.submit(self._call, c, "GET", path, params, user): c for c in cols}
        done, pending = cf.wait(futs, timeout=UPSTREAM_TIMEOUT_S + 1.0)
        results = []
        for f, c in futs.items():
            if f in done:
                try:
                    r = f.result()
                except Exception:   # noqa: BLE001
                    r = UpstreamResult(c.collector_id, False, error="unreachable")
            else:
                f.cancel()
                r = UpstreamResult(c.collector_id, False, error="timeout")
            self._note(r)
            results.append(r)
        return results

    def fan_out_each(self, path: str, user: str, params_for) -> list[UpstreamResult]:
        """Like fan_out with per-collector params; ``params_for(cid)`` returning None skips that collector."""
        cols = []
        for c in self.collectors.values():
            p = params_for(c.collector_id)
            if p is not None:
                cols.append((c, p))
        futs = {self._pool.submit(self._call, c, "GET", path, p, user): c for c, p in cols}
        done, _pending = cf.wait(futs, timeout=UPSTREAM_TIMEOUT_S + 1.0)
        results = []
        for f, c in futs.items():
            if f in done:
                try:
                    r = f.result()
                except Exception:   # noqa: BLE001
                    r = UpstreamResult(c.collector_id, False, error="unreachable")
            else:
                f.cancel()
                r = UpstreamResult(c.collector_id, False, error="timeout")
            self._note(r)
            results.append(r)
        return results

    def post_all(self, path: str, user: str, body: bytes | None) -> list[UpstreamResult]:
        """POST to EVERY collector in parallel (an action that applies wherever the data is, e.g. a purge)."""
        futs = {self._pool.submit(self._call, c, "POST", path, None, user, body, ACTION_TIMEOUT_S): c
                for c in self.collectors.values()}
        done, _pending = cf.wait(futs, timeout=ACTION_TIMEOUT_S + 1.0)
        results = []
        for f, c in futs.items():
            if f in done:
                try:
                    r = f.result()
                except Exception:   # noqa: BLE001
                    r = UpstreamResult(c.collector_id, False, error="unreachable")
            else:
                r = UpstreamResult(c.collector_id, False, error="timeout")
            self._note(r)
            results.append(r)
        return results

    def status_list(self, results: list[UpstreamResult]) -> list[dict[str, Any]]:
        out = []
        for r in results:
            e: dict[str, Any] = {"collector_id": r.collector_id,
                                 "site": self.collectors[r.collector_id].site, "ok": r.ok}
            if not r.ok:
                e["error"] = r.error or "unreachable"
            out.append(e)
        return out

    # -- probe map --------------------------------------------------------------------------
    def refresh_map(self) -> None:
        results = self.fan_out("probes", {}, "dashboard")
        new: dict[str, tuple[str, str]] = {}
        for r in results:
            if not r.ok or r.status != 200:
                continue
            try:
                items = r.json().get("items", [])
            except (ValueError, AttributeError, UnicodeDecodeError):
                continue
            for it in items if isinstance(items, list) else []:
                if isinstance(it, dict) and isinstance(it.get("probe"), str) and SLUG.match(it["probe"]):
                    site = it.get("site") if isinstance(it.get("site"), str) else \
                        self.collectors[r.collector_id].site
                    new.setdefault(it["probe"], (r.collector_id, site))
        with self._lock:
            # keep entries of collectors that did not answer, so scoped calls keep trying them
            down = {r.collector_id for r in results if not r.ok}
            for p, v in self.probe_map.items():
                if v[0] in down:
                    new.setdefault(p, v)
            self.probe_map = new
            self._map_at = self._clock()

    def owner_of(self, probe: str) -> tuple[str, str] | None:
        with self._lock:
            hit = self.probe_map.get(probe)
            age = self._clock() - self._map_at
        if hit is None and age > 5.0:        # unknown probe: one on-demand refresh, rate limited
            self.refresh_map()
            with self._lock:
                hit = self.probe_map.get(probe)
        return hit

    def site_of(self, probe: str, collector_id: str) -> str:
        with self._lock:
            hit = self.probe_map.get(probe)
        return hit[1] if hit else self.collectors[collector_id].site

    # -- API --------------------------------------------------------------------------------
    def get(self, endpoint: str, raw_query: dict[str, list[str]],
            user: str) -> tuple[int, bytes, dict[str, str]]:
        """Handle GET /api/v1/<endpoint>. Returns (status, body, extra headers)."""
        if endpoint in FANOUT:
            params = clean_params(endpoint, raw_query)
            return self._fanout_get(endpoint, params, user)
        if endpoint in SCOPED or endpoint == "query_range":
            params = clean_params(endpoint, raw_query)
            if endpoint == "query_range":
                cid = params.pop("collector", None)
                if cid is None:
                    if len(self.collectors) != 1:
                        raise ApiProblem(400, "invalid_request", "specify collector=<id>")
                    cid = next(iter(self.collectors))
            else:
                owner = self.owner_of(params["probe"])
                if owner is None:
                    raise ApiProblem(404, "probe_not_found", "unknown probe")
                cid = owner[0]
            return self._single(cid, endpoint, params, user)
        raise ApiProblem(404, "not_found", "no such endpoint")

    def _single(self, cid: str, path: str, params: dict[str, str], user: str,
                method: str = "GET", body: bytes | None = None) -> tuple[int, bytes, dict[str, str]]:
        if cid not in self.collectors:
            raise ApiProblem(404, "collector_not_found", "unknown collector")
        res = self._call(self.collectors[cid], method, path, params, user, body)
        self._note(res)
        return self._passthrough(res)

    def _passthrough(self, res: UpstreamResult) -> tuple[int, bytes, dict[str, str]]:
        if not res.ok:
            raise ApiProblem(502, "collector_unreachable", "collector unreachable",
                             {"collector_id": res.collector_id, "reason": res.error or "unreachable"})
        h = {"X-Exp-Collector": res.collector_id}
        if res.status == 204 or not res.body:
            return res.status, b"", h
        try:
            json.loads(res.body)
        except (ValueError, UnicodeDecodeError):
            raise ApiProblem(502, "bad_upstream", "collector returned an invalid response",
                             {"collector_id": res.collector_id}) from None
        return res.status, res.body, h

    def _fanout_get(self, endpoint: str, params: dict[str, str],
                    user: str) -> tuple[int, bytes, dict[str, str]]:
        only = None
        if endpoint == "incidents" and "probe" in params:
            owner = self.owner_of(params["probe"])
            only = [owner[0]] if owner else None
        if "site" in params and endpoint in ("probes", "states", "incidents"):
            pass   # collectors filter by site themselves; the others return empty lists
        results = self.fan_out(endpoint, params, user, only)
        items: list[dict[str, Any]] = []
        statuses = self.status_list(results)
        for r, st in zip(results, statuses, strict=True):
            if r.ok and r.status != 200:
                st["ok"], st["error"] = False, "upstream_error"
                continue
            if not r.ok:
                continue
            try:
                doc = r.json()
            except (ValueError, UnicodeDecodeError):
                st["ok"], st["error"] = False, "bad_response"
                continue
            if endpoint == "health":
                items.append({"collector_id": r.collector_id,
                              "site": self.collectors[r.collector_id].site, "health": doc})
                continue
            for it in doc.get("items", []) if isinstance(doc, dict) else []:
                if isinstance(it, dict):
                    it["collector_id"] = r.collector_id
                    items.append(it)
        if endpoint == "incidents":
            items.sort(key=lambda i: str(i.get("start", "")), reverse=True)
        elif endpoint in ("probes", "states"):
            items.sort(key=lambda i: (str(i.get("site", "")), str(i.get("probe", ""))))
        out = {"items": items, "next_cursor": None, "collectors": statuses}
        return 200, json.dumps(out, separators=(",", ":")).encode(), {}

    def post_try_all(self, path: str, user: str, body: bytes | None,
                     hint: str | None = None) -> tuple[int, bytes, dict[str, str]]:
        """POST an action whose owner is unknown (incident ack, drill abort): try collectors in turn,
        stop at the first answer that is not 404. 404s have no side effects."""
        order = list(self.collectors.values())
        if hint:
            order.sort(key=lambda c: c.collector_id != hint)
        last_err: UpstreamResult | None = None
        for c in order:
            res = self._call(c, "POST", path, None, user, body)
            self._note(res)
            if not res.ok:
                last_err = res
                continue
            if res.status == 404:
                continue
            return self._passthrough(res)
        if last_err is not None:
            raise ApiProblem(502, "collector_unreachable", "collector unreachable",
                             {"collector_id": last_err.collector_id,
                              "reason": last_err.error or "unreachable"})
        raise ApiProblem(404, "not_found", "no such item")

    def get_try_all(self, path: str, user: str) -> tuple[int, bytes, dict[str, str]]:
        results = self.fan_out(path, {}, user)
        for r in results:
            if r.ok and r.status == 200:
                return self._passthrough(r)
        if any(not r.ok for r in results):
            bad = next(r for r in results if not r.ok)
            raise ApiProblem(502, "collector_unreachable", "a collector is unreachable",
                             {"collector_id": bad.collector_id, "reason": bad.error or "unreachable"})
        raise ApiProblem(404, "not_found", "no such item")

    # -- health -----------------------------------------------------------------------------
    def reachability(self) -> tuple[int, int]:
        total = len(self.collectors)
        return total, sum(1 for s in self.state.values() if s.ok)


def valid_id(v: str) -> bool:
    return bool(_ID.match(v))
