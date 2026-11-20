# ruff: noqa: E501  (protocol tables in the module docstring)
"""Collector-side fake for the M6 speedtest box and the runner (dev/test tooling; stdlib + jsonschema when available).

A separate module next to ``fake_collector.py`` (same conventions: ``start()`` returns a running server with ``.port``,
``.app``, ``.stop()``; injectable clock; deterministic fixture tokens; ``/_fake/`` control, loopback only). It implements the
``speedtests`` operations of ``shared/openapi/collector.yaml`` that WP-9 / WP-10 build against, with the c0 token checks:

=======================================  =============  ================================================================================
route (under ``/api/v1``)                token          operationId
=======================================  =============  ================================================================================
``POST /speedtests``                     ``exps_``      ingestSpeedtest (schema ``exp.speedtest/1``; identity binding ``observed.server_id`` = token
                                                         identity and ``site`` = its site, else 403 ``identity_mismatch``; idempotent on ``id``)
``GET  /speedtests/{id}/status``         ``exps_``      getSpeedtestStatus (404 unless the test came from this token's speedtest)
``POST /speedtests/{id}/comment``        ``exps_``      postSpeedtestComment (<= 500 chars, no control characters; 204)
``GET  /speedtests/feed``                ``expr_``      speedtestFeed (oldest first, not-final tests of the runner's site; ``after``, ``limit``, long-poll ``wait_s``)
``POST /speedtests/{id}/evidence``       ``expr_``      postSpeedtestEvidence (``exp.evidence/1``; ``test_id`` = path id else 400 ``id_mismatch``; <= 256 KiB per test
                                                         across kinds, 413 ``evidence_too_large``; re-post replaces; 409 ``evidence_final``)
``POST /speedtests/{id}/evidence/complete``  ``expr_``  completeSpeedtestEvidence (final diagnosis; privacy scrub when enabled; 409 ``already_final``)
``GET  /speedtests/baseline``            ``expr_``      speedtestBaseline (the ``kind=baseline`` data shape)
``GET  /speedtests``, ``/{id}``          ``expd_``      listSpeedtests, getSpeedtest (``identifiers=true`` only on request)
``GET  /speedtests/stream``              ``expd_``      streamSpeedtests (SSE ``speedtest`` / ``evidence`` / ``diagnosis``, ``retry: 3000``, ``: keepalive``,
                                                         ``Last-Event-ID`` replay <= 300 s)
``POST /speedtests/purge``               ``expd_``      purgeSpeedtests (needs ``X-Exp-User`` else 403; by test / ip / device_key / mac)
=======================================  =============  ================================================================================

A token of the wrong family is simply unknown on a route (401), e.g. an ``expr_`` token on ``POST /speedtests``. Every request body is
validated against the shipped JSON Schemas (``jsonschema`` from the test venv; without it only structural checks run).

**Stand-in diagnosis.** The real rule engine is WP-11. This fake derives a deterministic diagnosis from the evidence with a handful of
obvious rules (``wifi_signal`` rssi <= -75, ``wifi_congestion`` AP util >= 80, ``wifi_roaming`` >= 3 roam events, ``wired_port`` errors / half
duplex, ``wan_saturation`` util >= 85, ``policy_block`` firewall drops, ``qos_shaping`` slowed traffic class >= 7, ``dns``) so runner and
speedtest tests can assert an end-to-end flow; it is not the contract for WP-11's rules.

Control (``/_fake/``, loopback): ``GET stats``, ``POST force|baseline|test|window``. In-process the same are methods on ``fake.app``.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import json
import logging
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fakes_common as fc  # noqa: E402,I001  (must come first: it puts shared/python on sys.path)
from exp_common import speedtest as st_helpers  # noqa: E402,I001
from exp_common.schema import iso_to_ms  # noqa: E402,I001

log = logging.getLogger("exp.fakes.st_collector")

SCHEMAS = fc.REPO_ROOT / "shared" / "schemas"
KINDS = ("wifi", "wired", "flows", "wan", "security", "baseline", "dns", "identity")
MAX_RESULT_BYTES = 256 * 1024
MAX_EVIDENCE_BODY = 1024 * 1024
MAX_EVIDENCE_TOTAL = 256 * 1024
MAX_FEED = 100
MAX_WAIT_S = 25
REPLAY_WINDOW_S = 300
RAW_IDENTITY_KEYS = ("ip", "mac", "hostname", "username")
_ID = re.compile(r"st_[0-9A-HJKMNP-TV-Z]{26}\Z")
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z\Z")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.headers = status, code, message, headers


class Schemas:
    """JSON Schema validation with the repo's ``$id``-by-filename registry (lazy; None-validator without jsonschema)."""

    def __init__(self) -> None:
        self.ok = True
        try:
            from jsonschema import Draft202012Validator
            from referencing import Registry, Resource
        except ImportError:   # pragma: no cover - the test venv has them
            self.ok = False
            return
        reg = Registry()
        self._docs: dict[str, Any] = {}
        for f in sorted(SCHEMAS.glob("*.schema.json")):
            doc = json.loads(f.read_text("utf-8"))
            self._docs[f.name] = doc
            reg = reg.with_resource(f.name, Resource.from_contents(doc))
        self._validators = {n: Draft202012Validator(self._docs[n], registry=reg) for n in ("speedtest.schema.json", "evidence.schema.json")}

    def errors(self, name: str, doc: Any) -> list[str]:
        if not self.ok:
            return [] if isinstance(doc, dict) and doc.get("schema") else ["missing schema field"]
        errs = sorted(self._validators[name].iter_errors(doc), key=lambda e: [str(p) for p in e.path])
        return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message[:160]}" for e in errs[:5]]


SCHEMA_SET = Schemas()


@dataclasses.dataclass
class Event:
    seq: int
    ts: float
    kind: str
    site: str
    data: dict[str, Any]


@dataclasses.dataclass
class Test:
    seq: int
    doc: dict[str, Any]
    speedtest_id: str
    site: str
    received: float
    state: str = "submitted"
    evidence: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    sizes: dict[str, int] = dataclasses.field(default_factory=dict)
    final_at: str | None = None
    diagnosis: dict[str, Any] | None = None
    comment: str | None = None
    complete_status: str | None = None
    scrubbed: bool = False


def default_tokens() -> dict[str, dict[str, dict[str, str]]]:
    """Deterministic fake credentials: ``{family: {identity: {"token", "sha256", "site"}}}`` (runtime-derived)."""
    def mk(prefix: str, ident: str, site: str | None = None) -> dict[str, str]:
        tok = fc.fixture_token(prefix, ident)
        return {"token": tok, "sha256": fc.token_hash(tok), "site": site or ""}
    return {"speedtest": {"spd-core": mk("exps", "spd-core", "hall-b")}, "runner": {"runner-core": mk("expr", "runner-core", "hall-b")},
            "dashboard": {"dash-main": mk("expd", "dash-main")}}


def quick_diagnosis(doc: dict[str, Any], now_iso: str) -> dict[str, Any]:
    score = (doc.get("score") or {}).get("total")
    if score is None or score >= 70:
        cause, user, noc = "none", "Your connection looks healthy.", "No fault indicated by the legs alone."
    else:
        cause, user, noc = "network_wide", "Your connection is slower than expected; we are checking why.", f"Score {score}; waiting for evidence."
    return {"stage": "quick", "updated": now_iso, "cause": [{"id": cause, "confidence": 0.4, "cites": [{"kind": "legs"}]}],
            "user_text": user, "noc_text": noc}


def final_diagnosis(evidence: dict[str, dict[str, Any]], now_iso: str) -> dict[str, Any]:
    causes: list[tuple[float, str, str]] = []
    d = {k: (v.get("data") or {}) for k, v in evidence.items()}
    ident = d.get("identity", {})
    wifi = d.get("wifi", {})
    rssi = (wifi.get("client") or {}).get("rssi")
    if isinstance(rssi, (int, float)) and rssi <= -75:
        causes.append((0.8, "wifi_signal", "wifi"))
    util = ((wifi.get("ap") or {}).get("radio") or {}).get("util_all")
    util = util if isinstance(util, (int, float)) else (wifi.get("ap") or {}).get("util_all")
    if isinstance(util, (int, float)) and util >= 80:
        causes.append((0.75, "wifi_congestion", "wifi"))
    if (wifi.get("roam_count") or 0) >= 3:
        causes.append((0.6, "wifi_roaming", "wifi"))
    port = (d.get("wired", {}).get("port") or {})
    if port and ((port.get("rx_errors") or 0) > 1000 or port.get("full_duplex") is False):
        causes.append((0.8, "wired_port", "wired"))
    wan = d.get("wan", {})
    if isinstance(wan.get("wan_util_pct"), (int, float)) and wan["wan_util_pct"] >= 85:
        causes.append((0.8, "wan_saturation", "wan"))
    sec = d.get("security", {})
    if (sec.get("ec_dropped_flows") or 0) > 0 or (sec.get("counts") or {}).get("deny", 0) > 0:
        causes.append((0.85, "policy_block", "security"))
    for f in (d.get("flows", {}).get("flows") or []):
        if (f.get("traffic_class") or 0) >= 7 and (f.get("slow_duration") or 0) > 0:
            causes.append((0.7, "qos_shaping", "flows"))
            break
    if (d.get("dns", {}).get("slow") or 0) > 3:
        causes.append((0.5, "dns", "dns"))
    if ident.get("nat_suspected"):
        causes = [(0.3, "none", "identity")]
    if not causes:
        causes = [(0.6, "none", "identity" if ident else "wifi")]
    causes.sort(key=lambda c: -c[0])
    top = causes[0][1]
    user = {"none": "No problem found on the network.", "wifi_signal": "Your Wi-Fi signal looks weak where you are.",
            "wifi_congestion": "The Wi-Fi in this area is busy right now.", "wifi_roaming": "Your device keeps switching between access points.",
            "wired_port": "The wired link looks unhealthy.", "wan_saturation": "The venue's internet link is very busy right now.",
            "policy_block": "Some traffic is blocked by network policy.", "qos_shaping": "This kind of traffic is being rate-limited.",
            "dns": "Name lookups are slow."}.get(top, "We found something to look at.")
    return {"stage": "final", "updated": now_iso,
            "cause": [{"id": c[1], "confidence": c[0], "cites": [{"kind": c[2]}]} for c in causes[:8]],
            "user_text": user, "noc_text": f"Top cause {top} from evidence kinds {sorted(evidence)}."}


class StApp:
    def __init__(self, *, tokens: dict[str, dict[str, dict[str, str]]] | None = None, now_fn: Any = time.time, scrub_after_diagnosis: bool = False,
                 window_before_s: int = 300, window_after_s: int = 120, device_key_secret: str | None = None) -> None:
        self.tokens = tokens or default_tokens()
        self.now = now_fn
        self.scrub = scrub_after_diagnosis
        self.window_before_s, self.window_after_s = window_before_s, window_after_s
        self.device_key_secret = device_key_secret
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.tests: dict[str, Test] = {}
        self.events: list[Event] = []
        self.seq = 0
        self.event_seq = 0
        self.force: dict[str, Any] | None = None
        self.baseline: dict[str, Any] | None = copy.deepcopy(fc.load_fixture("evidence/baseline.ok.json")["data"])
        self.keepalive_s = 15.0
        self.requests = 0
        self.audit: list[dict[str, Any]] = []

    # ---- helpers ---------------------------------------------------------------------------------------------
    def iso(self) -> str:
        return fc.iso_from_epoch(self.now())

    def hashes(self, family: str) -> dict[str, str]:
        return {i: v["sha256"] for i, v in self.tokens[family].items()}

    def set_force(self, status: int | None, count: int | None = None, retry_after: int = 1) -> None:
        with self.lock:
            self.force = None if status is None else {"status": int(status), "left": count, "retry_after": retry_after}

    def take_force(self) -> dict[str, Any] | None:
        with self.lock:
            f = self.force
            if not f:
                return None
            if f["left"] is not None:
                f["left"] -= 1
                if f["left"] <= 0:
                    self.force = None
            return f

    def emit(self, kind: str, site: str, data: dict[str, Any]) -> None:
        with self.cond:
            self.event_seq += 1
            self.events.append(Event(self.event_seq, self.now(), kind, site, data))
            del self.events[:-2000]
            self.cond.notify_all()

    def set_baseline(self, data: dict[str, Any] | None) -> None:
        self.baseline = copy.deepcopy(data)

    # ---- result handling ---------------------------------------------------------------------------------------
    def store(self, doc: dict[str, Any], speedtest_id: str, site: str) -> tuple[Test, bool]:
        with self.cond:
            existing = self.tests.get(doc["id"])
            if existing is not None:
                return existing, False
            self.seq += 1
            t = Test(self.seq, copy.deepcopy(doc), speedtest_id, site, self.now())
            t.diagnosis = quick_diagnosis(doc, self.iso())
            self.tests[doc["id"]] = t
            self.cond.notify_all()
        self.emit("speedtest", site, self.row(t))
        self.emit("diagnosis", site, {"id": doc["id"], "stage": "quick", "cause": t.diagnosis["cause"][0]["id"]})
        return t, True

    def evidence_state(self, t: Test) -> dict[str, Any]:
        state = "final" if t.state == "final" else ("correlating" if t.evidence else "pending")
        if t.state == "final" and not t.evidence:
            state = "unavailable"
        return {"state": state, "kinds_done": [k for k in KINDS if k in t.evidence], "final_at": t.final_at}

    def zone_of(self, t: Test) -> tuple[str, str]:
        ident = (t.evidence.get("identity") or {}).get("data") or {}
        if ident.get("zone"):
            return ident["zone"], ident.get("zone_source", "unresolved")
        return t.doc["zone"], t.doc["zone_source"]

    def row(self, t: Test) -> dict[str, Any]:
        d = t.doc
        legs = d.get("legs", {})
        zone, zsrc = self.zone_of(t)
        ident = (t.evidence.get("identity") or {}).get("data") or {}
        wifi = ((t.evidence.get("wifi") or {}).get("data") or {}).get("client") or {}
        ua = (d.get("client") or {}).get("ua") or {}
        return {"id": d["id"], "site": d["site"], "zone": zone, "zone_source": zsrc, "started": d["started"], "ended": d["ended"],
                "score": (d.get("score") or {}).get("total"), "local_down_mbps": (legs.get("local") or {}).get("down_mbps"),
                "local_up_mbps": (legs.get("local") or {}).get("up_mbps"), "internet_down_mbps": (legs.get("internet") or {}).get("down_mbps"),
                "internet_up_mbps": (legs.get("internet") or {}).get("up_mbps"), "loaded_ms": (legs.get("local") or {}).get("loaded_down_ms"),
                "flags": list(d.get("flags", [])), "cause": (t.diagnosis or {}).get("cause", [{}])[0].get("id"),
                "ap_name": ident.get("ap_name"), "ssid": ident.get("ssid") or wifi.get("ssid"), "band": ident.get("band") or wifi.get("band"),
                "os_family": ua.get("os_family") or ident.get("os_family"), "device_key": ident.get("device_key"),
                "evidence_state": self.evidence_state(t)["state"], "has_comment": t.comment is not None}

    def feed_item(self, t: Test) -> dict[str, Any]:
        d = t.doc
        started_ms, ended_ms = iso_to_ms(d["started"]), iso_to_ms(d["ended"])
        zone, zsrc = self.zone_of(t)
        item = {"id": d["id"], "site": d["site"], "started": d["started"], "ended": d["ended"], "client_ip": d["client"]["ip"],
                "zone_hint": d["zone"] if d["zone_source"] == "qr" else None, "zone": zone, "zone_source": zsrc,
                "window": {"from": fc.iso_from_epoch(started_ms / 1000 - self.window_before_s), "to": fc.iso_from_epoch(ended_ms / 1000 + self.window_after_s)}}
        if (d.get("observed") or {}).get("server_id"):
            item["observed_server"] = d["observed"]["server_id"]
        return item

    def status_doc(self, t: Test) -> dict[str, Any]:
        zone, zsrc = self.zone_of(t)
        diag = None
        if t.diagnosis:
            diag = {"stage": t.diagnosis["stage"], "updated": t.diagnosis["updated"],
                    "cause": [{"id": c["id"], "confidence": c["confidence"]} for c in t.diagnosis["cause"]], "user_text": t.diagnosis["user_text"]}
        checks = []
        for kind in KINDS:
            ev = t.evidence.get(kind)
            if ev is None:
                checks.append({"kind": kind, "state": "unavailable" if t.state == "final" else "checking"})
            else:
                s = {"ok": "ok", "partial": "attention"}.get(ev["status"], "unavailable")
                checks.append({"kind": kind, "state": s})
        wifi = ((t.evidence.get("wifi") or {}).get("data") or {})
        client = wifi.get("client") or {}
        ap = wifi.get("ap") or {}
        details = None
        if client.get("band") or ap.get("name"):
            details = {k: v for k, v in (("ap_name", ap.get("name") or ap.get("ap_name")), ("band", client.get("band")), ("channel", client.get("channel")))
                       if v is not None}
        return {"id": t.doc["id"], "state": "final" if t.state == "final" else ("correlating" if t.evidence else "submitted"), "zone": zone,
                "zone_name": None if zone == "unresolved" else zone, "zone_source": zsrc, "diagnosis": diag, "evidence": self.evidence_state(t),
                "checks": checks, "network_details": details, "comment": t.comment}

    def detail(self, t: Test, identifiers: bool) -> dict[str, Any]:
        doc = copy.deepcopy(t.doc)
        ev = [copy.deepcopy(e) for k, e in sorted(t.evidence.items())]
        if not identifiers:
            (doc.get("client") or {}).pop("ip", None)
            for e in ev:
                if e["kind"] == "identity":
                    for k in RAW_IDENTITY_KEYS:
                        e["data"].pop(k, None)
        ident = (t.evidence.get("identity") or {}).get("data") or {}
        return {"test": doc, "diagnosis": t.diagnosis, "evidence": ev, "evidence_state": self.evidence_state(t), "device_key": ident.get("device_key")}

    # ---- evidence ---------------------------------------------------------------------------------------------
    def put_evidence(self, t: Test, doc: dict[str, Any]) -> dict[str, Any]:
        kind = doc["kind"]
        with self.lock:
            if t.state == "final":
                raise ApiError(409, "evidence_final", "evidence is final")
            size = len(json.dumps(doc, separators=(",", ":")).encode())
            total = sum(v for k, v in t.sizes.items() if k != kind) + size
            if total > MAX_EVIDENCE_TOTAL:
                raise ApiError(413, "evidence_too_large", "evidence for this test exceeds 256 KiB")
            t.evidence[kind] = copy.deepcopy(doc)
            t.sizes[kind] = size
            t.state = "correlating"
        self.emit("evidence", t.site, {"id": doc["test_id"], "kind": kind})
        return {"test_id": doc["test_id"], "kind": kind, "stored_bytes": size, "total_bytes": total}

    def complete(self, t: Test, body: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            if t.state == "final":
                raise ApiError(409, "already_final", "already final")
            t.state = "final"
            t.final_at = self.iso()
            t.complete_status = body["status"]
            t.diagnosis = final_diagnosis(t.evidence, self.iso())
            if self.scrub:
                self.scrub_test(t)
        self.emit("diagnosis", t.site, {"id": t.doc["id"], "stage": "final", "cause": t.diagnosis["cause"][0]["id"]})
        with self.cond:
            self.cond.notify_all()
        return {"id": t.doc["id"], "diagnosis": t.diagnosis}

    def scrub_test(self, t: Test) -> None:
        """Privacy scrub (A6.6): drop raw ip / mac / hostname / username, keep device_key and the zone data."""
        (t.doc.get("client") or {}).pop("ip", None)
        for ev in t.evidence.values():
            if ev["kind"] == "identity":
                for k in RAW_IDENTITY_KEYS:
                    ev["data"].pop(k, None)
                ev["data"]["scrubbed"] = True
            if ev["kind"] == "wifi":
                (ev["data"].get("client") or {}).pop("mac", None)
            if ev["kind"] == "wired":
                (ev["data"].get("client") or {}).pop("mac", None)
        t.scrubbed = True

    def purge(self, by: str, value: str, dry_run: bool, user: str) -> dict[str, Any]:
        matched: list[str] = []
        dk_matched = True
        wanted_key = None
        if by == "mac":
            if self.device_key_secret:
                wanted_key = st_helpers.device_key(self.device_key_secret, value)
            else:
                dk_matched = False
        with self.lock:
            for tid, t in self.tests.items():
                ident = (t.evidence.get("identity") or {}).get("data") or {}
                hit = (by == "test" and tid == value) or (by == "ip" and (t.doc.get("client") or {}).get("ip") == value) \
                    or (by == "device_key" and ident.get("device_key") == value) \
                    or (by == "mac" and ((wanted_key and ident.get("device_key") == wanted_key)
                                         or (ident.get("mac") and st_helpers.normalize_mac(ident["mac"]) == st_helpers.normalize_mac(value))))
                if hit:
                    matched.append(tid)
            ev_n = sum(len(self.tests[i].evidence) for i in matched)
            if not dry_run:
                for i in matched:
                    del self.tests[i]
            self.audit.append({"action": "purge", "by": by, "dry_run": dry_run, "user": user, "matched": len(matched)})
        return {"dry_run": dry_run, "matched_tests": len(matched), "deleted": {"tests": 0 if dry_run else len(matched), "evidence": 0 if dry_run else ev_n,
                                                                                 "diagnoses": 0 if dry_run else len(matched)},
                "device_key_matched": dk_matched, "audited_by": user}


class _Q:
    def __init__(self, query: dict[str, list[str]]) -> None:
        self.q = query

    def one(self, name: str) -> str | None:
        v = self.q.get(name)
        return v[-1] if v else None

    def integer(self, name: str, lo: int, hi: int, default: int) -> int:
        v = self.one(name)
        if v is None:
            return default
        if not re.fullmatch(r"[0-9]{1,9}", v) or not lo <= int(v) <= hi:
            raise ApiError(400, "invalid_request", f"{name} must be an integer {lo}..{hi}")
        return int(v)

    def ts(self, name: str, required: bool = False) -> str | None:
        v = self.one(name)
        if v is None:
            if required:
                raise ApiError(400, "invalid_request", f"{name} is required")
            return None
        if not _TS.match(v):
            raise ApiError(400, "invalid_request", f"{name} must be an RFC 3339 UTC timestamp")
        return v

    def slug(self, name: str, required: bool = False) -> str | None:
        v = self.one(name)
        if v is None:
            if required:
                raise ApiError(400, "invalid_request", f"{name} is required")
            return None
        if not _SLUG.match(v):
            raise ApiError(400, "invalid_request", f"{name} must be a slug")
        return v


class Handler(fc.BaseHandler):
    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        app: StApp = self.app
        with app.lock:
            app.requests += 1
        try:
            if path == "/healthz":
                self.send_text(200, "ok")
            elif path.startswith("/_fake/"):
                self._control(method, path)
            elif path.startswith("/api/v1/speedtests"):
                self._st(method, path[len("/api/v1/speedtests"):], _Q(query))
            else:
                raise ApiError(404, "not_found", "no such path")
        except ApiError as e:
            self.send_err(e.status, e.code, e.message, headers=e.headers)

    # ---- auth ------------------------------------------------------------------------------------------------
    def _auth(self, family: str, prefix: str) -> tuple[str, str]:
        """(identity, site). Wrong family or malformed -> 401."""
        tok = fc.bearer_token(self.header("Authorization"))
        ident = fc.match_token(tok, self.app.hashes(family)) if tok and tok.startswith(prefix) else None
        if ident is None:
            raise ApiError(401, "invalid_token", "missing or invalid token", {"WWW-Authenticate": "Bearer"})
        return ident, self.app.tokens[family][ident].get("site", "")

    def _forced(self) -> None:
        f = self.app.take_force()
        if f is None:
            return
        n = self.content_length() or 0
        if n > 0:
            self.drain(n)
        code = "rate_limited" if f["status"] == 429 else "unavailable"
        raise ApiError(f["status"], code, code.replace("_", " "), {"Retry-After": str(f["retry_after"])})

    @staticmethod
    def _need(method: str, want: str) -> None:
        if method != want:
            raise ApiError(405, "method_not_allowed", f"{want} only", {"Allow": want})

    def _test(self, tid: str) -> Test:
        if not _ID.match(tid):
            raise ApiError(404, "not_found", "no such test")
        t = self.app.tests.get(tid)
        if t is None:
            raise ApiError(404, "not_found", "no such test")
        return t

    # ---- routing ----------------------------------------------------------------------------------------------
    def _st(self, method: str, rest: str, q: _Q) -> None:
        app: StApp = self.app
        if rest == "":
            if method == "POST":
                return self._ingest()
            self._need(method, "GET")
            return self._list(q)
        if rest == "/feed":
            self._need(method, "GET")
            return self._feed(q)
        if rest == "/baseline":
            self._need(method, "GET")
            return self._baseline(q)
        if rest == "/stream":
            self._need(method, "GET")
            return self._stream(q)
        if rest == "/purge":
            self._need(method, "POST")
            return self._purge()
        m = re.fullmatch(r"/([^/]+)(/status|/comment|/evidence/complete|/evidence)?", rest)
        if not m:
            raise ApiError(404, "not_found", "no such path")
        tid, sub = m.group(1), m.group(2)
        if sub is None:
            self._need(method, "GET")
            self._auth("dashboard", "expd_")
            self._forced()
            t = self._test(tid)
            ident = q.one("identifiers") == "true"
            if ident:
                app.audit.append({"action": "view_identifiers", "id": tid, "user": self.header("X-Exp-User")})
            return self.send_json(200, app.detail(t, ident))
        if sub == "/status":
            self._need(method, "GET")
            sid, _site = self._auth("speedtest", "exps_")
            self._forced()
            t = self._test(tid)
            if t.speedtest_id != sid:
                raise ApiError(404, "not_found", "no such test")
            return self.send_json(200, app.status_doc(t))
        if sub == "/comment":
            self._need(method, "POST")
            return self._comment(tid)
        self._need(method, "POST")
        return self._evidence(tid) if sub == "/evidence" else self._complete(tid)

    # ---- handlers ---------------------------------------------------------------------------------------------
    def _ingest(self) -> None:
        app: StApp = self.app
        sid, site = self._auth("speedtest", "exps_")
        self._forced()
        body = self.read_body(MAX_RESULT_BYTES)
        if body is None:
            raise ApiError(413, "payload_too_large", "result too large")
        try:
            doc = json.loads(body)
        except ValueError as exc:
            raise ApiError(400, "invalid_request", f"invalid JSON: {exc}"[:200]) from exc
        errs = SCHEMA_SET.errors("speedtest.schema.json", doc)
        if errs:
            raise ApiError(400, "invalid_request", "; ".join(errs)[:500])
        if not (doc.get("client") or {}).get("ip"):
            raise ApiError(400, "invalid_request", "client.ip is required at ingest")
        if doc["observed"]["server_id"] != sid or doc["site"] != site:
            raise ApiError(403, "identity_mismatch", "observed.server_id / site do not match the token")
        t, created = app.store(doc, sid, site)
        self.send_json(201 if created else 200, {"id": doc["id"], "status": "stored" if created else "duplicate", "diagnosis": t.diagnosis})

    def _comment(self, tid: str) -> None:
        sid, _ = self._auth("speedtest", "exps_")
        self._forced()
        doc, ok = self.read_json(8192)
        if not ok:
            return
        c = doc.get("comment") if isinstance(doc, dict) else None
        if set(doc) != {"comment"} or not isinstance(c, str) or not 1 <= len(c) <= 500 or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", c):
            raise ApiError(400, "invalid_request", "comment must be 1-500 characters without control characters")
        t = self._test(tid)
        if t.speedtest_id != sid:
            raise ApiError(404, "not_found", "no such test")
        t.comment = c
        self.send_empty(204)

    def _feed(self, q: _Q) -> None:
        app: StApp = self.app
        _rid, site = self._auth("runner", "expr_")
        self._forced()
        after = q.integer("after", 0, 10**12, 0)
        limit = q.integer("limit", 1, MAX_FEED, 50)
        wait_s = q.integer("wait_s", 0, MAX_WAIT_S, 0)
        deadline = time.monotonic() + wait_s

        def pending() -> list[Test]:
            return sorted((t for t in app.tests.values() if t.site == site and t.state != "final" and t.seq > after), key=lambda t: t.seq)[:limit]
        with app.cond:
            batch = pending()
            while not batch and time.monotonic() < deadline and not self.fake.stopping.is_set():
                app.cond.wait(min(0.2, max(0.01, deadline - time.monotonic())))
                batch = pending()
        items = [app.feed_item(t) for t in batch]
        self.send_json(200, {"items": items, "next_cursor": str(batch[-1].seq) if batch else (str(after) if after else None)})

    def _evidence(self, tid: str) -> None:
        app: StApp = self.app
        _rid, site = self._auth("runner", "expr_")
        self._forced()
        body = self.read_body(MAX_EVIDENCE_BODY)
        if body is None:
            raise ApiError(413, "payload_too_large", "evidence document too large")
        try:
            doc = json.loads(body)
        except ValueError as exc:
            raise ApiError(400, "invalid_request", f"invalid JSON: {exc}"[:200]) from exc
        errs = SCHEMA_SET.errors("evidence.schema.json", doc)
        if errs:
            raise ApiError(400, "invalid_request", "; ".join(errs)[:500])
        if doc["test_id"] != tid:
            raise ApiError(400, "id_mismatch", "test_id does not equal the path id")
        t = self._test(tid)
        if t.site != site:
            raise ApiError(403, "identity_mismatch", "test belongs to another site")
        self.send_json(200, app.put_evidence(t, doc))

    def _complete(self, tid: str) -> None:
        app: StApp = self.app
        _rid, site = self._auth("runner", "expr_")
        self._forced()
        doc, ok = self.read_json(8192)
        if not ok:
            return
        if not (isinstance(doc, dict) and set(doc) == {"kinds", "status"} and doc["status"] in ("ok", "partial", "failed")
                and isinstance(doc["kinds"], list) and len(doc["kinds"]) <= 8 and len(set(doc["kinds"])) == len(doc["kinds"])
                and all(k in KINDS for k in doc["kinds"])):
            raise ApiError(400, "invalid_request", "body must be {kinds: [...], status: ok|partial|failed}")
        t = self._test(tid)
        if t.site != site:
            raise ApiError(403, "identity_mismatch", "test belongs to another site")
        self.send_json(200, app.complete(t, doc))

    def _baseline(self, q: _Q) -> None:
        app: StApp = self.app
        _rid, site = self._auth("runner", "expr_")
        self._forced()
        q.slug("site", required=True)
        q.ts("at", required=True)
        q.slug("zone")
        ap = q.one("ap")
        if ap is not None and len(ap) > 128:
            raise ApiError(400, "invalid_request", "ap too long")
        if q.one("site") != site:
            raise ApiError(404, "not_found", "no baseline for that site")
        if app.baseline is None:
            raise ApiError(404, "not_found", "no probe near that location")
        data = copy.deepcopy(app.baseline)
        data["site"], data["at"] = site, q.one("at")
        self.send_json(200, data)

    def _list(self, q: _Q) -> None:
        app: StApp = self.app
        self._auth("dashboard", "expd_")
        self._forced()
        limit = q.integer("limit", 1, 200, 50)
        site, zone = q.slug("site"), q.one("zone")
        frm, to = q.ts("from"), q.ts("to")
        with app.lock:
            rows = [app.row(t) for t in sorted(app.tests.values(), key=lambda t: -t.seq)
                    if (not site or t.site == site) and (not frm or t.doc["started"] >= frm) and (not to or t.doc["started"] < to)]
        if zone:
            rows = [r for r in rows if r["zone"] == zone]
        off = fc.cursor_decode(q.one("cursor")) if q.one("cursor") else 0
        page = rows[off: off + limit]
        self.send_json(200, {"items": page, "next_cursor": fc.cursor_encode(off + limit) if off + limit < len(rows) else None})

    def _purge(self) -> None:
        app: StApp = self.app
        self._auth("dashboard", "expd_")
        self._forced()
        user = self.header("X-Exp-User")
        if not user:
            raise ApiError(403, "forbidden", "X-Exp-User is required")
        doc, ok = self.read_json(4096)
        if not ok:
            return
        if not (isinstance(doc, dict) and doc.get("by") in ("device_key", "mac", "ip", "test") and isinstance(doc.get("value"), str)
                and 0 < len(doc["value"]) <= 128 and set(doc) <= {"by", "value", "dry_run"}):
            raise ApiError(400, "invalid_request", "body must be {by, value, dry_run?}")
        self.send_json(200, app.purge(doc["by"], doc["value"], bool(doc.get("dry_run", False)), user[:128]))

    def _stream(self, q: _Q) -> None:
        app, fake = self.app, self.fake
        self._auth("dashboard", "expd_")
        site = q.slug("site")
        last = self.header("Last-Event-ID")
        if last is not None and len(last) > 128:
            raise ApiError(400, "invalid_request", "Last-Event-ID too long")
        self.send_response(200)
        for k, v in (("Content-Type", "text/event-stream"), ("Cache-Control", "no-store"), ("X-Accel-Buffering", "no"), ("Connection", "close")):
            self.send_header(k, v)
        self.end_headers()
        self.close_connection = True
        out = self.wfile
        out.write(b"retry: 3000\n\n")
        out.flush()
        with app.lock:
            head = app.events[-1].seq if app.events else 0
            replay = last is not None and last.isdigit()
            cursor = min(int(last), head) if replay else head
        last_write = time.monotonic()
        first = True
        while not fake.stopping.is_set():
            with app.cond:
                batch = [e for e in app.events if e.seq > cursor]
                if not batch:
                    app.cond.wait(max(0.02, min(0.2, app.keepalive_s - (time.monotonic() - last_write))))
                    batch = [e for e in app.events if e.seq > cursor]
            if batch and first and replay:
                horizon = app.now() - REPLAY_WINDOW_S
                batch = [e for e in batch if e.ts >= horizon]
            for e in batch:
                cursor = max(cursor, e.seq)
                if site is None or e.site == site:
                    out.write(f"event: {e.kind}\nid: {e.seq}\ndata: {json.dumps(e.data, separators=(',', ':'))}\n\n".encode())
                    last_write = time.monotonic()
            if batch:
                first = False
            if time.monotonic() - last_write >= app.keepalive_s:
                out.write(b": keepalive\n\n")
                last_write = time.monotonic()
            out.flush()

    def _control(self, method: str, path: str) -> None:
        if not self.client_is_loopback():
            raise ApiError(403, "forbidden", "loopback only")
        app: StApp = self.app
        sub = path[len("/_fake/"):]
        if method == "GET" and sub == "stats":
            with app.lock:
                self.send_json(200, {"tests": len(app.tests), "events": len(app.events), "requests": app.requests, "audit": list(app.audit)})
            return
        if method != "POST":
            raise ApiError(404, "not_found", "no such control")
        doc, ok = self.read_json(MAX_RESULT_BYTES)
        if not ok:
            return
        if sub == "force":
            app.set_force(doc.get("status"), doc.get("count"), int(doc.get("retry_after", 1)))
        elif sub == "baseline":
            app.set_baseline(doc.get("data"))
        elif sub == "window":
            app.window_before_s, app.window_after_s = int(doc["before_s"]), int(doc["after_s"])
        else:
            raise ApiError(404, "not_found", "no such control")
        self.send_json(200, {"ok": True})


class FakeStCollector(fc.FakeServer):
    def stop(self) -> None:
        super().stop()
        with self.app.cond:
            self.app.cond.notify_all()


def start(*, host: str = "127.0.0.1", port: int = 0, tls: tuple[Path, Path] | None = None, **app_kwargs: Any) -> FakeStCollector:
    app = StApp(**app_kwargs)
    srv = FakeStCollector(Handler, app, host=host, port=port, tls=tls, name="fake_st_collector")
    srv.start()
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listen", default="127.0.0.1:8490")
    ap.add_argument("--scrub", action="store_true", help="privacy.scrub_after_diagnosis")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, stream=sys.stderr)
    host, _, port = args.listen.rpartition(":")
    app = StApp(scrub_after_diagnosis=args.scrub)
    srv = FakeStCollector(Handler, app, host=host or "127.0.0.1", port=int(port), name="fake_st_collector")

    def banner() -> str:
        lines = [f"fake_st_collector on {srv.base_url}"]
        for fam, ids in app.tokens.items():
            for ident, v in ids.items():
                lines.append(f"  {fam} {ident} (site={v['site'] or '-'}) token {v['token']}")
        return "\n".join(lines)
    fc.run_forever(srv, banner)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
