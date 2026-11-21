#!/usr/bin/env python3
"""mock_admin: the manager admin API (shared/openapi/admin.yaml) served from deterministic in-memory state,
for developing the manager UI (WP-5) without a Cloudflare Worker.

Run:    python test/fakes/mock_admin/server.py --listen 127.0.0.1:8787            (UI proxies /api/admin/v1)
Import: ``from mock_admin.server import start; fake = start(); fake.port; fake.stop()``

Access simulation: every /api/admin/v1/* request needs a ``Cf-Access-Jwt-Assertion`` header (any value; the
mock does NOT verify it) unless --no-auth; the caller is owner@example.com with role owner. Dev-only aids:
``X-Mock-Role: viewer|operator|admin|owner`` and ``X-Mock-Email: <email>`` override the identity (to test role
gating and two-person approval), ``X-Mock-Force: 429|500|503`` makes that request fail.

The add-host wizard is simulated: a pending host becomes enrolled with facts ``--enrol-delay-s`` (default 10)
seconds after its enrol token was issued. CORS is allowed for http://localhost:5173 only.
"""
from __future__ import annotations

import argparse
import base64
import email.parser
import email.policy
import hashlib
import hmac
import html
import json
import logging
import re
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "shared" / "python"))
import seed  # noqa: E402
from exp_common import config as exp_config  # noqa: E402
from exp_common import ids as exp_ids  # noqa: E402

import fakes_common as fc  # noqa: E402

log = logging.getLogger("exp.fakes.mock_admin")

BASE = "/api/admin/v1"
CORS_ORIGIN = "http://localhost:5173"
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2, "owner": 3}
HEALTH_RANK = {"unknown": 0, "ok": 1, "degraded": 2, "fail": 3}
MAX_JSON = 1024 * 1024
MAX_UPLOAD = 64 * 1024 * 1024
FLEET_CACHE = "private, max-age=15"
SNAP_S = 15
SSO_SECRET = b"mock-admin-sso-secret-not-a-real-key"
DRILL_TARGET_ALLOWLIST = {"10.1.0.1", "8.8.8.8", "1.1.1.1", "1.NE"}
SCHEMA_DEFS: dict[str, Any] = json.loads((HERE / "admin_schemas.json").read_text("utf-8"))
CONFIG_SCHEMA = {"probe": "probe.config.schema.json", "collector": "collector.config.schema.json",
                 "dashboard": "dashboard.config.schema.json", "runner": "runner.config.schema.json"}
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z\Z")
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\Z")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.details, self.headers = status, code, message, details, headers


class Resp:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None,
                 raw: tuple[bytes, str] | None = None, fleet: bool = False) -> None:
        self.status, self.body, self.headers, self.raw, self.fleet = status, body, headers or {}, raw, fleet


def check_body(doc: Any, name: str) -> None:
    errs = exp_config.iter_errors(doc, {"$defs": SCHEMA_DEFS, "$ref": f"#/$defs/{name}"})
    if errs:
        raise ApiError(400, "invalid_request", "request body failed validation",
                       {"errors": [{"path": e.path, "message": e.message} for e in errs[:20]]})


class Query:
    def __init__(self, q: dict[str, list[str]]) -> None:
        self.q = q

    def one(self, name: str) -> str | None:
        v = self.q.get(name)
        if not v:
            return None
        if len(v) > 1:
            raise ApiError(400, "invalid_request", f"'{name}' given more than once")
        return v[0]

    def enum(self, name: str, allowed: tuple[str, ...], default: str | None = None) -> str | None:
        v = self.one(name)
        if v is None:
            return default
        if v not in allowed:
            raise ApiError(400, "invalid_request", f"'{name}' must be one of {', '.join(allowed)}")
        return v

    def slug(self, name: str) -> str | None:
        v = self.one(name)
        if v is not None and not _SLUG.match(v):
            raise ApiError(400, "invalid_request", f"'{name}' must be a slug")
        return v

    def ts(self, name: str) -> float | None:
        v = self.one(name)
        if v is None:
            return None
        if not _TS.match(v):
            raise ApiError(400, "invalid_request", f"'{name}' must be a UTC timestamp ending in Z")
        return exp_ts(v)

    def integer(self, name: str, lo: int, hi: int, default: int) -> int:
        v = self.one(name)
        if v is None:
            return default
        if not re.fullmatch(r"[0-9]{1,9}", v) or not lo <= int(v) <= hi:
            raise ApiError(400, "invalid_request", f"'{name}' must be an integer in {lo}..{hi}")
        return int(v)

    def text(self, name: str, maxlen: int) -> str | None:
        v = self.one(name)
        if v is not None and (len(v) > maxlen or re.search(r"[\x00-\x1f\x7f]", v)):
            raise ApiError(400, "invalid_request", f"'{name}' invalid")
        return v


def exp_ts(v: str) -> float:
    from exp_common.schema import iso_to_ms
    return iso_to_ms(v) / 1000.0


def paginate(q: Query, items: list[Any]) -> dict[str, Any]:
    limit = q.integer("limit", 1, 1000, 100)
    try:
        off = fc.cursor_decode(q.one("cursor"))
    except ValueError as exc:
        raise ApiError(400, "invalid_request", "invalid cursor") from exc
    page = items[off:off + limit]
    return {"items": page, "next_cursor": fc.cursor_encode(off + limit) if off + limit < len(items) else None}


class Req:
    def __init__(self, handler: Handler, method: str, params: dict[str, str], query: Query, email_: str,
                 role: str) -> None:
        self.h, self.method, self.params, self.q, self.email, self.role = handler, method, params, query, email_, role
        self._body: bytes | None = None

    def raw(self, limit: int = MAX_JSON) -> bytes:
        if self._body is None:
            data = self.h.read_body(limit)
            if data is None:
                raise ApiError(413, "payload_too_large", "request body too large")
            self._body = data
        return self._body

    def json(self, schema: str | None = None, optional: bool = False) -> Any:
        body = self.raw()
        if not body.strip():
            if optional:
                return {}
            raise ApiError(400, "invalid_request", "a JSON body is required")
        try:
            doc = exp_config.parse_json(body, "request body")
        except ValueError as exc:
            raise ApiError(400, "invalid_request", str(exc)[:300]) from exc
        if schema:
            check_body(doc, schema)
        return doc


# ------------------------------------------------------------------------------------- the app

class MockAdmin:
    def __init__(self, *, now_fn: Callable[[], float] = time.time, enrol_delay_s: float | None = 10.0,
                 decommission_delay_s: float = 20.0, canary_delay_s: float = 30.0, auth: bool = True) -> None:
        self.now = now_fn
        self.require_auth = auth
        self.enrol_delay_s = enrol_delay_s
        self.decommission_delay_s = decommission_delay_s
        self.canary_delay_s = canary_delay_s
        self.lock = threading.RLock()
        self.w = seed.build_world(self.now())
        self.version = 0     # bumped on every mutation: part of the fleet ETag
        self.requests = 0

    # ---- helpers
    def snap(self) -> float:
        return float(int(self.now() // SNAP_S) * SNAP_S)

    def mutated(self) -> None:
        self.version += 1

    def audit(self, actor: str, action: str, resource: str, details: dict[str, Any] | None = None) -> None:
        self.w["audit"].append({"evt_id": exp_ids.new_id("evt_"), "ts": seed.iso(self.now()), "actor": actor,
                                "action": action, "resource": resource, "details": details or {}, "ip": "127.0.0.1"})

    def host(self, hid: str) -> dict[str, Any]:
        h = self.w["hosts"].get(hid)
        if h is None:
            raise ApiError(404, "not_found", "no such host")
        return h

    def comp(self, cid: str) -> dict[str, Any]:
        c = self.w["components"].get(cid)
        if c is None:
            raise ApiError(404, "not_found", "no such component")
        return c

    def site(self, slug: str) -> dict[str, Any]:
        s = self.w["sites"].get(slug)
        if s is None:
            raise ApiError(404, "not_found", "no such site")
        return s

    def host_comps(self, hid: str) -> list[dict[str, Any]]:
        return [c for c in self.w["components"].values() if c["host_id"] == hid]

    def host_health(self, h: dict[str, Any]) -> str:
        if h["state"] not in ("enrolled", "stale"):
            return "unknown"
        hs = [c["health"] for c in self.host_comps(h["host_id"])]
        return max(hs, key=lambda x: HEALTH_RANK[x]) if hs else "unknown"

    def bump(self, h: dict[str, Any]) -> int:
        if h["state"] == "pending" or h["desired_version"] is None:
            return 0
        h["desired_version"] += 1
        h["updated_at"] = seed.iso(self.now())
        return int(h["desired_version"])

    def open_issues(self, snoozed: bool = False) -> list[dict[str, Any]]:
        out = []
        for i in self.w["issues"]:
            if i["resolved_at"] is None and (snoozed or not i["snoozed_until"]):
                out.append(i)
        return out

    # ---- the clock-driven simulation
    def tick(self) -> None:
        now = self.now()
        w = self.w
        for h in list(w["hosts"].values()):
            at = h.get("_enrol_at")
            if h["state"] == "pending" and at is not None and now >= at:
                self._enrol_host(h)
            dat = h.get("_decom_at")
            if h["state"] == "decommissioning" and dat is not None and now >= dat:
                h["state"] = "removed"
                h["updated_at"] = seed.iso(now)
                for c in self.host_comps(h["host_id"]):
                    c["health"] = "unknown"
                self.audit("system", "host.removed", f"host:{h['name']}")
                self.mutated()
        for s in w["sites"].values():
            at = s.get("_canary_at")
            if s["canary_state"] in ("pending", "healthy_waiting") and at is not None:
                if now >= at:
                    s["release_version"], s["canary_state"] = s["_canary_target"], "promoted"
                    s["updated_at"] = seed.iso(now)
                    self.mutated()
                elif now >= at - self.canary_delay_s / 2 and s["canary_state"] == "pending":
                    s["canary_state"] = "healthy_waiting"
                    self.mutated()

    def _enrol_host(self, h: dict[str, Any]) -> None:
        now = self.now()
        site = self.w["sites"][h["site"]]
        n = sum(1 for x in self.w["hosts"].values() if x["site"] == h["site"] and x["state"] != "pending")
        ip = f"{site.get('_subnet', '10.40.98')}.{80 + n % 150}"
        role = "collector" if "collector" in h["shapes"] else (h["shapes"][0] if h["shapes"] else "probe")
        h.update(state="enrolled", mgmt_ip=ip, facts=seed.new_facts_for(h["name"], ip, h["shapes"]),
                 last_seen=seed.iso(now), agent_version=site["release_version"] or "0.1.1", desired_version=1,
                 applied_version=1, updated_at=seed.iso(now), _last_seen=now, _role=role,
                 _profile=seed.host_profile(role), _enrol_at=None)
        for c in self.host_comps(h["host_id"]):
            c["health"], c["version"] = "ok", h["agent_version"]
        self.w["reports"][h["host_id"]] = seed.make_report(h, self.host_comps(h["host_id"]), now)
        self.audit("system", "host.enrol", f"host:{h['name']}", {"mgmt_ip": ip})
        self.mutated()

    def schedule_enrol(self, h: dict[str, Any]) -> None:
        if self.enrol_delay_s is not None:
            h["_enrol_at"] = self.now() + self.enrol_delay_s

    def new_enrol(self, h: dict[str, Any]) -> dict[str, Any]:
        tok = exp_ids.new_token("expe")
        exp = self.now() + 3600
        h["_enrol_token_hash"] = exp_ids.token_hash(tok)
        self.schedule_enrol(h)
        return {"token": tok, "command": f"curl -fsSL https://{seed.MANAGER_HOST}/install.sh | sudo bash -s -- {tok}",
                "expires_at": seed.iso(exp)}

    # ---- fleet computations (all values at the 15 s snapshot)
    def at_of(self, h: dict[str, Any], snap: float) -> float | None:
        if h["state"] not in ("enrolled", "stale", "offline") or h.get("_last_seen") is None:
            return None
        return min(snap, h["_last_seen"])

    def host_value(self, h: dict[str, Any], key: str, snap: float) -> float | None:
        at = self.at_of(h, snap)
        return None if at is None else seed.metric_value(h["host_id"], key, h["_profile"], at)

    def comp_value(self, c: dict[str, Any], key: str, snap: float) -> float | None:
        h = self.w["hosts"][c["host_id"]]
        at = self.at_of(h, snap)
        return None if at is None else seed.metric_value(c["component_id"], key, c["_profile"], at)

    def fleet_row(self, h: dict[str, Any], snap: float) -> dict[str, Any]:
        comps = self.host_comps(h["host_id"])
        at = self.at_of(h, snap)
        ex: dict[str, Any] = {}
        spark_cpu = spark_net = []
        if at is not None:
            end = int(at // 300) * 300
            ts_list = [end - (59 - i) * 300 for i in range(60)]
            spark_cpu = [seed.metric_value(h["host_id"], "cpu_pct", h["_profile"], t) for t in ts_list]
            spark_net = [round(seed.metric_value(h["host_id"], "net_rx_pps", h["_profile"], t)
                               + seed.metric_value(h["host_id"], "net_tx_pps", h["_profile"], t), 1) for t in ts_list]
            ex = {"cpu_pct": self.host_value(h, "cpu_pct", snap), "mem_pct": self.host_value(h, "mem_pct", snap),
                  "disk_pct_max": self.host_value(h, "disk_pct", snap),
                  "uptime_s": int(1234567 + (at - self.w["now"])),
                  "net": {k: self.host_value(h, f"net_{k}", snap) for k in ("rx_pps", "tx_pps", "rx_bps", "tx_bps")}}
        work: dict[str, Any] = {"measurements_per_min": None, "ingest_records_per_s": None,
                                "sessions_active": None, "drills_active": None, "tests_per_hour": None}
        for c in comps:
            if c["type"] == "probe" and self.comp_value(c, "measurements_per_min", snap) is not None:
                work["measurements_per_min"] = round((work["measurements_per_min"] or 0)
                                                     + self.comp_value(c, "measurements_per_min", snap), 1)
            elif c["type"] == "collector":
                work["ingest_records_per_s"] = self.comp_value(c, "ingest_records_per_s", snap)
            elif c["type"] == "dashboard" and at is not None:
                work["sessions_active"] = int(self.comp_value(c, "sessions_active", snap) or 0)
            elif c["type"] == "runner" and at is not None:
                work["drills_active"] = 0
            elif c["type"] == "speedtest" and at is not None:
                work["tests_per_hour"] = int(self.comp_value(c, "tests_per_hour", snap) or 0)
        n_issues = sum(1 for i in self.open_issues() if i["host_id"] == h["host_id"])
        return {"host_id": h["host_id"], "name": h["name"], "mgmt_ip": h["mgmt_ip"], "site": h["site"],
                "shapes": list(h["shapes"]), "state": h["state"], "stale": h["state"] in ("stale", "offline"),
                "health": self.host_health(h), "open_issues": n_issues,
                "cpu_pct": ex.get("cpu_pct"), "mem_pct": ex.get("mem_pct"), "disk_pct_max": ex.get("disk_pct_max"),
                "uptime_s": ex.get("uptime_s"), "net": ex.get("net"), "work": work,
                "cpu_spark": spark_cpu, "net_spark": spark_net, "agent_version": h["agent_version"],
                "desired_version": h["desired_version"], "applied_version": h["applied_version"],
                "last_seen": h["last_seen"]}

    def live_hosts(self) -> list[dict[str, Any]]:
        return [h for h in self.w["hosts"].values() if h["state"] != "removed"]

    def health_counts(self, comps: list[dict[str, Any]]) -> dict[str, int]:
        out = {"ok": 0, "degraded": 0, "fail": 0, "unknown": 0}
        for c in comps:
            out[c["health"]] += 1
        return out

    def state_counts(self, hosts: list[dict[str, Any]]) -> dict[str, int]:
        out = {"pending": 0, "enrolled": 0, "stale": 0, "offline": 0, "decommissioning": 0}
        for h in hosts:
            if h["state"] in out:
                out[h["state"]] += 1
        return out

    def drift_hosts(self) -> int:
        n = 0
        for h in self.live_hosts():
            rel = self.w["sites"][h["site"]]["release_version"]
            if h["state"] in ("enrolled", "stale") and h["agent_version"] and rel and h["agent_version"] != rel:
                n += 1
        return n


# ----------------------------------------------------------------------------------------- handlers

class Handler(fc.BaseHandler):
    app: MockAdmin  # type: ignore[assignment]

    # CORS only for the Vite dev origin; everything else gets no CORS headers at all.
    def _cors(self) -> dict[str, str]:
        if self.header("Origin") == CORS_ORIGIN:
            return {"Access-Control-Allow-Origin": CORS_ORIGIN, "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Expose-Headers": "ETag, Cache-Control, Retry-After", "Vary": "Origin"}
        return {"Vary": "Origin"}

    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        cors = self._cors()
        try:
            if path == "/healthz":
                return self.send_text(200, "ok")
            if not (path == BASE or path.startswith(BASE + "/")):
                raise ApiError(404, "not_found", "not an admin API path")
            if method == "OPTIONS":
                if self.header("Origin") != CORS_ORIGIN:
                    raise ApiError(403, "forbidden", "origin not allowed")
                return self.send_empty(204, {**cors, "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                                             "Access-Control-Allow-Headers": "Content-Type, If-None-Match, Cf-Access-Jwt-Assertion, "
                                                                             "X-Mock-Role, X-Mock-Email, X-Mock-Force",
                                             "Access-Control-Max-Age": "600"})
            resp = self._handle(method, path[len(BASE):], query)
            self._send(resp, cors)
        except ApiError as e:
            self.send_err(e.status, e.code, e.message, e.details, {**cors, **(e.headers or {})})

    def _handle(self, method: str, rest: str, query: dict[str, list[str]]) -> Resp:
        app = self.app
        with app.lock:
            app.requests += 1
        if app.require_auth and not (self.header("Cf-Access-Jwt-Assertion") or "").strip():
            self.drain(self.content_length() or 0) if (self.content_length() or 0) > 0 else None
            raise ApiError(401, "unauthenticated", "missing Cf-Access-Jwt-Assertion header")
        role = (self.header("X-Mock-Role") or "owner").lower()
        if role not in ROLE_RANK:
            raise ApiError(400, "invalid_request", "X-Mock-Role must be viewer|operator|admin|owner")
        email_ = (self.header("X-Mock-Email") or seed.OWNER_EMAIL)[:254]
        force = self.header("X-Mock-Force")
        if force in ("429", "500", "503"):
            code = {"429": "rate_limited", "500": "internal_error", "503": "unavailable"}[force]
            raise ApiError(int(force), code, f"forced by X-Mock-Force {force}",
                           headers={"Retry-After": "1"} if force != "500" else None)
        matched_path = False
        for rmethod, rx, min_role, fn in ROUTES:
            m = rx.fullmatch(rest)
            if not m:
                continue
            matched_path = True
            if rmethod != method:
                continue
            if ROLE_RANK[role] < ROLE_RANK[min_role]:
                raise ApiError(403, "insufficient_role", f"requires role {min_role}")
            req = Req(self, method, m.groupdict(), Query(query), email_, role)
            with app.lock:
                app.tick()
                return fn(app, req)
        if matched_path:
            raise ApiError(405, "method_not_allowed", "method not allowed")
        raise ApiError(404, "not_found", "no such endpoint")

    def _send(self, resp: Resp, cors: dict[str, str]) -> None:
        headers = dict(cors)
        headers.update(resp.headers)
        if resp.raw is not None:
            body, ctype = resp.raw
            return self.send_bytes(resp.status, body, ctype, headers)
        if resp.body is None:
            return self.send_empty(resp.status, headers)
        data = json.dumps(resp.body, separators=(",", ":")).encode("utf-8")
        if resp.fleet:
            etag = '"' + hashlib.sha256(data).hexdigest()[:20] + '"'
            headers.update({"ETag": etag, "Cache-Control": FLEET_CACHE})
            inm = self.header("If-None-Match")
            if inm and (inm.strip() == "*" or etag in [c.strip().removeprefix("W/") for c in inm.split(",")]):
                return self.send_empty(304, headers)
        self.send_bytes(resp.status, data, "application/json", headers)


# ------------------------------------------------------------------ route implementations (a: app)

def ok(body: Any, status: int = 200, headers: dict[str, str] | None = None) -> Resp:
    return Resp(status, body, headers)


NO_STORE = {"Cache-Control": "no-store"}


def r_me(a: MockAdmin, r: Req) -> Resp:
    return ok({"email": r.email, "role": r.role})


# --- sites
def site_out(a: MockAdmin, s: dict[str, Any]) -> dict[str, Any]:
    return seed.public(s)


def r_sites_list(a: MockAdmin, r: Req) -> Resp:
    return ok(paginate(r.q, [site_out(a, s) for s in sorted(a.w["sites"].values(), key=lambda s: s["site"])]))


def r_sites_create(a: MockAdmin, r: Req) -> Resp:
    d = r.json("SiteCreate")
    if d["site"] in a.w["sites"]:
        raise ApiError(409, "site_exists", "a site with that slug already exists")
    now = seed.iso(a.now())
    s = {"site": d["site"], "name": d["name"], "timezone": d["timezone"], "edge_label": d.get("edge_label", "EC"),
         "release_version": None, "canary_host_id": None, "canary_state": None, "retention": d.get("retention"),
         "created_at": now, "updated_at": now, "_subnet": "10.40.98"}
    a.w["sites"][d["site"]] = s
    a.w["alerts"][d["site"]] = {"config": {"enabled": True, "board_url": None, "timezone": d["timezone"], "voice": "sysadmin",
                                           "hold_down_s": 20, "hold_back_s": 60, "reopen_s": 300, "calm_s": 600}, "webhooks": []}
    a.audit(r.email, "site.create", f"site:{d['site']}", {"name": d["name"]})
    a.mutated()
    return ok(site_out(a, s), 201)


def r_site_get(a: MockAdmin, r: Req) -> Resp:
    return ok(site_out(a, a.site(r.params["site"])))


def r_site_patch(a: MockAdmin, r: Req) -> Resp:
    s = a.site(r.params["site"])
    d = r.json("SitePatch")
    s.update(d)
    s["updated_at"] = seed.iso(a.now())
    a.audit(r.email, "site.update", f"site:{s['site']}", {"fields": sorted(d)})
    a.mutated()
    return ok(site_out(a, s))


def r_site_delete(a: MockAdmin, r: Req) -> Resp:
    s = a.site(r.params["site"])
    if any(h["site"] == s["site"] and h["state"] != "removed" for h in a.w["hosts"].values()):
        raise ApiError(409, "site_not_empty", "hosts still belong to this site")
    del a.w["sites"][s["site"]]
    a.w["alerts"].pop(s["site"], None)
    a.audit(r.email, "site.delete", f"site:{s['site']}")
    a.mutated()
    return Resp(204)


# --- hosts
def host_out(a: MockAdmin, h: dict[str, Any]) -> dict[str, Any]:
    return seed.public(h)


def r_hosts_list(a: MockAdmin, r: Req) -> Resp:
    site, state = r.q.slug("site"), r.q.enum("state", tuple(seed_states()))
    items = [host_out(a, h) for h in sorted(a.w["hosts"].values(), key=lambda h: h["name"])
             if (not site or h["site"] == site) and (not state or h["state"] == state)]
    return ok(paginate(r.q, items))


def seed_states() -> list[str]:
    return ["pending", "enrolled", "stale", "offline", "decommissioning", "removed"]


def r_hosts_create(a: MockAdmin, r: Req) -> Resp:
    d = r.json("HostCreate")
    site = a.site(d["site"])
    now = seed.iso(a.now())
    hid = exp_ids.new_id("h_")
    h = {"host_id": hid, "name": d["name"], "site": site["site"], "shapes": d.get("shapes", []), "state": "pending",
         "mgmt_ip": None, "facts": None, "last_seen": None, "agent_version": None, "desired_version": None,
         "applied_version": None, "created_at": now, "updated_at": now, "_last_seen": None, "_enrol_at": None}
    a.w["hosts"][hid] = h
    enrol = a.new_enrol(h)
    a.audit(r.email, "host.create", f"host:{h['name']}", {"site": site["site"]})
    a.mutated()
    return ok({"host": host_out(a, h), "enrol": enrol}, 201, NO_STORE)


def r_host_get(a: MockAdmin, r: Req) -> Resp:
    return ok(host_out(a, a.host(r.params["id"])))


def r_host_patch(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    d = r.json("HostPatch")
    if "site" in d:
        a.site(d["site"])
    h.update(d)
    h["updated_at"] = seed.iso(a.now())
    a.audit(r.email, "host.update", f"host:{h['name']}", {"fields": sorted(d)})
    a.mutated()
    return ok(host_out(a, h))


def r_host_delete(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    if h["state"] not in ("pending", "removed"):
        raise ApiError(409, "host_not_removable", "host is enrolled; decommission it first")
    for c in a.host_comps(h["host_id"]):
        del a.w["components"][c["component_id"]]
    del a.w["hosts"][h["host_id"]]
    a.audit(r.email, "host.delete", f"host:{h['name']}")
    a.mutated()
    return Resp(204)


def r_host_enrol_token(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    if h["state"] != "pending":
        raise ApiError(409, "host_already_enrolled", "token reissue is for pending hosts; use rotate-agent")
    enrol = a.new_enrol(h)
    a.audit(r.email, "host.enrol_token", f"host:{h['name']}")
    a.mutated()
    return ok(enrol, 201, NO_STORE)


def r_host_decommission(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    if h["state"] not in ("enrolled", "stale", "offline"):
        raise ApiError(409, "host_not_enrolled", "only an enrolled host can be decommissioned")
    h["state"] = "decommissioning"
    h["_decom_at"] = a.now() + a.decommission_delay_s
    a.bump(h)
    a.audit(r.email, "host.decommission", f"host:{h['name']}")
    a.mutated()
    return ok(host_out(a, h), 202)


def r_host_rotate_agent(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    if h["state"] != "enrolled":
        raise ApiError(409, "host_not_enrolled", "host is not enrolled")
    dv = a.bump(h)
    a.audit(r.email, "host.rotate_agent", f"host:{h['name']}")
    a.mutated()
    return ok({"host_id": h["host_id"], "action_id": "act_" + exp_ids.new_ulid(), "desired_version": dv}, 202)


def r_host_status(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    rep = a.w["reports"].get(h["host_id"])
    if rep is None:
        raise ApiError(404, "no_status", "the host has not sent a status report yet")
    return ok({"host_id": h["host_id"], "state": h["state"], "received_at": h["last_seen"] or seed.iso(a.now()),
               "desired_version": h["desired_version"], "applied_version": h["applied_version"], "report": rep})


# --- components
def comp_out(a: MockAdmin, c: dict[str, Any]) -> dict[str, Any]:
    return seed.public(c)


def validate_component_config(a: MockAdmin, ctype: str, config: dict[str, Any], h: dict[str, Any],
                              own_cid: str | None) -> dict[str, Any] | None:
    """422 invalid_config on schema failure. Returns the rendered config (None if config is partial)."""
    rendered = None
    if ctype in CONFIG_SCHEMA and "schema" in config:
        try:
            exp_config.validate(config, CONFIG_SCHEMA[ctype])
        except exp_config.ConfigError as exc:
            raise ApiError(422, "invalid_config", "config failed schema validation",
                           {"errors": [{"path": i.path, "message": i.message} for i in exc.errors[:20]]}) from exc
        rendered = json.loads(json.dumps(config))
    if ctype == "probe" and isinstance(config.get("ports"), list) and config["ports"]:
        check_ports(a, h, config["ports"], own_cid)
    return rendered


def is_mgmt(iface: dict[str, Any]) -> bool:
    return iface.get("in_use_by") == "mgmt" or bool(iface.get("default_route"))


def check_ports(a: MockAdmin, h: dict[str, Any], ports: list[dict[str, Any]], own_cid: str | None) -> None:
    facts = h.get("facts")
    if not facts:
        raise ApiError(422, "unknown_interface", "the host has not reported its interfaces yet")
    ifaces = {i["name"]: i for i in facts["interfaces"]}
    seen_ids: set[str] = set()
    seen_if: set[str] = set()
    other = {}
    for c in a.host_comps(h["host_id"]):
        if c["type"] == "probe" and c["component_id"] != own_cid:
            for p in c["config"].get("ports", []):
                other[p.get("iface")] = c["id"]
    for p in ports:
        iface = p.get("iface")
        if iface not in ifaces:
            raise ApiError(422, "unknown_interface", f"interface '{iface}' does not exist on this host",
                           {"iface": iface})
        if is_mgmt(ifaces[iface]):
            raise ApiError(422, "mgmt_interface_refused", f"interface '{iface}' is the management interface",
                           {"iface": iface})
        if p.get("id") in seen_ids or iface in seen_if:
            raise ApiError(422, "invalid_ports", "duplicate port id or interface", {"port": p.get("id")})
        if iface in other:
            raise ApiError(422, "invalid_ports", f"interface '{iface}' is used by probe {other[iface]}", {"iface": iface})
        seen_ids.add(p.get("id"))
        seen_if.add(iface)


def refresh_port_usage(a: MockAdmin, h: dict[str, Any]) -> None:
    if not h.get("facts"):
        return
    used = {}
    for c in a.host_comps(h["host_id"]):
        if c["type"] == "probe":
            for p in c["config"].get("ports", []):
                used[p.get("iface")] = p.get("id")
    for iface in h["facts"]["interfaces"]:
        if not is_mgmt(iface):
            iface["in_use_by"] = f"probe:{used[iface['name']]}" if iface["name"] in used else "none"


def r_host_components(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    return ok(paginate(r.q, [comp_out(a, c) for c in a.host_comps(h["host_id"])]))


def r_comp_create(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    d = r.json("ComponentCreate")
    if h["state"] in ("decommissioning", "removed"):
        raise ApiError(409, "conflict", "host is being removed")
    if any(c["type"] == d["type"] and c["id"] == d["id"] for c in a.w["components"].values()):
        raise ApiError(409, "component_slug_exists", "that id is already used by a component of this type")
    rendered = validate_component_config(a, d["type"], d["config"], h, None)
    now = seed.iso(a.now())
    cid = exp_ids.new_id("cmp_")
    c = {"component_id": cid, "host_id": h["host_id"], "type": d["type"], "id": d["id"], "config": d["config"],
         "rendered_config": rendered, "enabled": True, "health": "unknown", "version": None, "facts": {},
         "created_at": now, "updated_at": now, "_profile": seed.component_profile(d["type"]), "_rotated_at": None,
         "_detail": ""}
    a.w["components"][cid] = c
    if d["type"] not in h["shapes"] and d["type"] in ("probe", "collector", "dashboard", "runner", "speedtest") and len(h["shapes"]) < 5:
        h["shapes"].append(d["type"])
    refresh_port_usage(a, h)
    a.bump(h)
    a.audit(r.email, "component.create", f"component:{d['id']}", {"type": d["type"], "host": h["name"]})
    a.mutated()
    return ok(comp_out(a, c), 201)


def r_comp_patch(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    d = r.json("ComponentPatch")
    if "config" in d:
        c["rendered_config"] = validate_component_config(a, c["type"], d["config"], h, c["component_id"])
        c["config"] = d["config"]
    if "enabled" in d:
        c["enabled"] = d["enabled"]
    c["updated_at"] = seed.iso(a.now())
    refresh_port_usage(a, h)
    a.bump(h)
    a.audit(r.email, "component.update", f"component:{c['id']}", {"fields": sorted(d)})
    a.mutated()
    return ok(comp_out(a, c))


def r_comp_delete(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    del a.w["components"][c["component_id"]]
    refresh_port_usage(a, h)
    a.bump(h)
    a.audit(r.email, "component.delete", f"component:{c['id']}")
    a.mutated()
    return Resp(204)


def r_comp_restart(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    dv = a.bump(h)
    a.audit(r.email, "component.restart", f"component:{c['id']}")
    a.mutated()
    return ok({"host_id": h["host_id"], "action_id": "act_" + exp_ids.new_ulid(), "desired_version": dv}, 202)


def r_comp_ports(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    d = r.json("PortsPut")
    if c["type"] != "probe":
        raise ApiError(422, "invalid_ports", "only probe components have ports")
    check_ports(a, h, d["ports"], c["component_id"])
    c["config"]["ports"] = d["ports"]
    if c["rendered_config"] is not None:
        c["rendered_config"]["ports"] = json.loads(json.dumps(d["ports"]))
    c["updated_at"] = seed.iso(a.now())
    refresh_port_usage(a, h)
    dv = a.bump(h)
    a.audit(r.email, "component.ports", f"component:{c['id']}", {"ports": [p["id"] for p in d["ports"]]})
    a.mutated()
    return ok({"component_id": c["component_id"], "ports": d["ports"], "desired_version": dv if dv else None})


def r_comp_rotate(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    now = a.now()
    if c["_rotated_at"] is not None and now - c["_rotated_at"] < 600:
        raise ApiError(409, "rotation_in_progress", "the previous rotation grace period has not elapsed")
    c["_rotated_at"] = now
    kinds = {"probe": ["ingest_token"], "collector": ["ingest_tokens", "dashboard_tokens"],
             "dashboard": ["dashboard_token"]}.get(c["type"], ["token"])
    dv = a.bump(h)
    a.audit(r.email, "component.rotate", f"component:{c['id']}", {"kinds": kinds})
    a.mutated()
    return ok({"component_id": c["component_id"], "kinds": kinds, "previous_valid_until": seed.iso(now + 600),
               "desired_version": dv})


# --- releases
def release_out(a: MockAdmin, rel: dict[str, Any]) -> dict[str, Any]:
    out = seed.public(rel)
    out["sites"] = sorted(s["site"] for s in a.w["sites"].values() if s["release_version"] == rel["version"])
    return out


def r_releases_list(a: MockAdmin, r: Req) -> Resp:
    rels = sorted(a.w["releases"], key=lambda x: [int(p) for p in re.split(r"[.-]", x["version"])[:3]], reverse=True)
    return ok(paginate(r.q, [release_out(a, x) for x in rels]))


def _make_release(a: MockAdmin, version: str, source: str) -> dict[str, Any]:
    rel = seed._release(version, a.now() - 60, [])
    rel["source"] = source
    rel["verified_at"] = seed.iso(a.now())
    a.w["releases"].append(rel)
    return rel


def r_release_import(a: MockAdmin, r: Req) -> Resp:
    d = r.json("ReleaseImport")
    if any(x["version"] == d["version"] for x in a.w["releases"]):
        raise ApiError(409, "release_exists", "that release is already imported")
    if d["source"] == "github" and d["version"] not in a.w["github_catalog"]:
        raise ApiError(404, "release_not_found", "no such release in RELEASES_REPO")
    if d["source"] == "upload":
        raise ApiError(422, "manifest_invalid", "source 'upload' is for POST /releases/upload")
    rel = _make_release(a, d["version"], "github")
    a.audit(r.email, "release.import", f"release:{d['version']}", {"source": "github"})
    a.mutated()
    return ok(release_out(a, rel), 201)


def parse_multipart(ctype: str, body: bytes) -> dict[str, list[tuple[str | None, bytes]]]:
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + ctype.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body)
    if not msg.is_multipart():
        raise ValueError("not multipart")
    out: dict[str, list[tuple[str | None, bytes]]] = {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        out.setdefault(str(name), []).append((part.get_filename(), part.get_payload(decode=True) or b""))
    return out


def r_release_upload(a: MockAdmin, r: Req) -> Resp:
    ctype = r.h.header("Content-Type") or ""
    if not ctype.lower().startswith("multipart/form-data"):
        r.h.drain(min(r.h.content_length() or 0, MAX_UPLOAD))
        raise ApiError(415, "unsupported_media_type", "Content-Type must be multipart/form-data")
    n = r.h.content_length() or 0
    if n > MAX_UPLOAD:
        r.h.drain(n)
        raise ApiError(413, "payload_too_large", f"upload exceeds {MAX_UPLOAD} bytes")
    body = r.raw(MAX_UPLOAD)
    try:
        parts = parse_multipart(ctype, body)
    except ValueError as exc:
        raise ApiError(400, "invalid_request", f"bad multipart body: {exc}") from exc
    missing = [k for k in ("manifest", "signature", "artifacts") if k not in parts]
    if missing:
        raise ApiError(400, "invalid_request", "missing form fields", {"missing": missing})
    man_bytes = parts["manifest"][0][1]
    try:
        manifest = exp_config.parse_json(man_bytes, "manifest")
        exp_config.validate(manifest, "manifest.schema.json")
    except exp_config.ConfigError as exc:
        raise ApiError(422, "manifest_invalid", str(exc.summary)[:300]) from exc
    sig = parts["signature"][0][1].decode("ascii", "replace").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/]{86}==", sig):   # the mock has no release key: it checks the format only
        raise ApiError(422, "signature_invalid", "signature must be base64 of 64 raw bytes")
    files = {fn: data for fn, data in parts["artifacts"] if fn}
    for art in manifest["artifacts"]:
        data = files.get(art["name"])
        if data is None or hashlib.sha256(data).hexdigest() != art["sha256"] or len(data) != art["size"]:
            raise ApiError(422, "artifact_hash_mismatch", f"artifact {art['name']} missing or does not match the manifest")
    if any(x["version"] == manifest["version"] for x in a.w["releases"]):
        raise ApiError(409, "release_exists", "that release is already imported")
    rel = _make_release(a, manifest["version"], "upload")
    rel["artifacts"] = [{"artifact_id": fc.det_id("art_", x["name"]), **{k: x[k] for k in ("name", "component", "arch", "sha256", "size")}}
                        for x in manifest["artifacts"]]
    rel["min_agent_version"] = manifest["min_agent_version"]
    a.audit(r.email, "release.upload", f"release:{manifest['version']}")
    a.mutated()
    return ok(release_out(a, rel), 201)


def r_site_release(a: MockAdmin, r: Req) -> Resp:
    s = a.site(r.params["site"])
    d = r.json("SiteRelease")
    rel = next((x for x in a.w["releases"] if x["version"] == d["version"]), None)
    if rel is None:
        raise ApiError(422, "release_not_imported", "import the release first")
    if s["canary_state"] in ("pending", "healthy_waiting"):
        raise ApiError(409, "rollout_in_progress", "a canary rollout is already in progress")
    if s["canary_state"] == "failed":
        raise ApiError(409, "canary_failed", "the previous canary failed; clear it first")
    min_v = [int(x) for x in rel["min_agent_version"].split("-")[0].split(".")]
    for h in a.live_hosts():
        if h["site"] == s["site"] and h["agent_version"]:
            if [int(x) for x in h["agent_version"].split("-")[0].split(".")] < min_v:
                raise ApiError(422, "min_agent_version", f"host {h['name']} agent is older than {rel['min_agent_version']}")
    canary = d.get("canary_host_id")
    if canary:
        ch = a.host(canary)
        if ch["site"] != s["site"]:
            raise ApiError(422, "release_not_imported", "canary host is not in this site")
        s.update(canary_host_id=canary, canary_state="pending", _canary_target=d["version"],
                 _canary_at=a.now() + a.canary_delay_s)
    else:
        s.update(release_version=d["version"], canary_host_id=None, canary_state=None)
    s["updated_at"] = seed.iso(a.now())
    for h in a.live_hosts():
        if h["site"] == s["site"]:
            a.bump(h)
    a.audit(r.email, "site.release", f"site:{s['site']}", {"version": d["version"], "canary": bool(canary)})
    a.mutated()
    return ok(site_out(a, s))


# --- dashboards
def dashboard(a: MockAdmin, dash_id: str) -> dict[str, Any]:
    for c in a.w["components"].values():
        if c["type"] == "dashboard" and c["id"] == dash_id:
            return c
    raise ApiError(404, "not_found", "no such dashboard")


def r_dash_users(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    return ok(paginate(r.q, list(a.w["dash_users"].get(d["id"], []))))


def r_dash_user_create(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    body = r.json("DashboardUserCreate")
    users = a.w["dash_users"].setdefault(d["id"], [])
    if any(u["username"] == body["username"] for u in users):
        raise ApiError(409, "user_exists", "a user with that name already exists")
    u = {"usr_id": exp_ids.new_id("usr_"), "username": body["username"], "role": body["role"],
         "created_at": seed.iso(a.now())}
    users.append(u)
    a.audit(r.email, "dashboard_user.create", f"dashboard:{d['id']}", {"username": body["username"], "role": body["role"]})
    a.mutated()
    return ok(u, 201)


def r_dash_user_delete(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    users = a.w["dash_users"].get(d["id"], [])
    u = next((x for x in users if x["usr_id"] == r.params["usr"]), None)
    if u is None:
        raise ApiError(404, "not_found", "no such user")
    users.remove(u)
    a.audit(r.email, "dashboard_user.delete", f"dashboard:{d['id']}", {"username": u["username"]})
    a.mutated()
    return Resp(204)


_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----")
_PEM_KEY = re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]+?\s*-----END (?:RSA |EC )?PRIVATE KEY-----")


def _tls_view(t: dict[str, Any] | None) -> dict[str, Any]:
    if not t:
        return {"mode": "self_signed", "set": False, "updated_at": None, "cert": None}
    return {"mode": "provided", "set": True, "updated_at": t["updated_at"], "cert": t["cert"]}


def r_dash_tls_get(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    return ok(_tls_view(a.w.setdefault("dash_tls", {}).get(d["id"])))


def r_dash_tls_put(a: MockAdmin, r: Req) -> Resp:
    """Mock of PUT dashboards/{id}/tls: structure checks only (the real Worker parses X.509 and proves key possession).
    The key is never stored. Test directives inside cert_pem (PEM parsers ignore text outside the blocks):
    `# mock-not-after: <iso>` sets the expiry (in the past: 422 expired); `# mock-mismatch` simulates a key mismatch."""
    d = dashboard(a, r.params["dashboard_id"])
    body = r.json("DashboardTlsPut")
    store = a.w.setdefault("dash_tls", {})
    if body["mode"] == "self_signed":
        store.pop(d["id"], None)
        a.audit(r.email, "dashboard.tls", f"dashboard:{d['id']}", {"mode": "self_signed", "secret_set": False})
        a.mutated()
        return ok(_tls_view(None))
    m = _PEM_CERT.search(body["cert_pem"])
    if m is None:
        raise ApiError(422, "invalid_config", "cert_pem holds no PEM CERTIFICATE")
    if _PEM_KEY.search(body["key_pem"]) is None:
        raise ApiError(422, "invalid_config", "exactly one PEM private key (PRIVATE KEY, RSA PRIVATE KEY or EC PRIVATE KEY) is required")
    if "# mock-mismatch" in body["cert_pem"]:
        raise ApiError(422, "invalid_config", "the private key does not match the certificate")
    now = a.now()
    na = re.search(r"# mock-not-after:\s*(\S+)", body["cert_pem"])
    not_after = na.group(1) if na else seed.iso(now + 365 * 86400)
    if not_after <= seed.iso(now):
        raise ApiError(422, "invalid_config", f"the certificate expired on {not_after}")
    try:
        der = base64.b64decode("".join(m.group(1).split()), validate=True)
    except ValueError:
        raise ApiError(422, "invalid_config", "malformed CERTIFICATE PEM") from None
    fp = hashlib.sha256(der).hexdigest().upper()
    cn = (d["config"].get("title") or d["id"]).replace(" ", "-")
    cert = {"subject": "O=Mock Events, CN=" + cn, "issuer": "O=Mock Events CA, CN=Mock Issuing CA",
            "not_before": seed.iso(now - 86400), "not_after": not_after, "sha256": ":".join(fp[i:i + 2] for i in range(0, 64, 2)),
            "san": ["dash.example.test"]}
    store[d["id"]] = {"updated_at": seed.iso(now), "cert": cert}
    a.audit(r.email, "dashboard.tls", f"dashboard:{d['id']}",
            {"mode": "provided", "sha256": cert["sha256"], "not_after": not_after, "secret_set": True})
    a.mutated()
    return ok(_tls_view(store[d["id"]]))


def r_noc_list(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    return ok(paginate(r.q, list(a.w["noc_tokens"].get(d["id"], []))))


def r_noc_create(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    body = r.json("NocTokenCreate")
    now = a.now()
    tok = exp_ids.new_token("expn")
    n = {"noc_id": exp_ids.new_id("noc_"), "label": body["label"], "role": "viewer",
         "expires_at": seed.iso(now + body["expires_in_h"] * 3600) if "expires_in_h" in body else None,
         "revoked_at": None, "created_at": seed.iso(now)}
    a.w["noc_tokens"].setdefault(d["id"], []).append(n)
    url = (d["config"].get("url") or "").rstrip("/")
    a.audit(r.email, "noc_token.create", f"dashboard:{d['id']}", {"noc_id": n["noc_id"], "label": body["label"]})
    a.mutated()
    return ok({"noc": n, "token": tok, "url": f"{url}/noc#t={tok}" if url.startswith("https://") else None}, 201, NO_STORE)


def r_noc_revoke(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    n = next((x for x in a.w["noc_tokens"].get(d["id"], []) if x["noc_id"] == r.params["noc"]), None)
    if n is None:
        raise ApiError(404, "not_found", "no such NOC token")
    if n["revoked_at"] is None:
        n["revoked_at"] = seed.iso(a.now())
    a.audit(r.email, "noc_token.revoke", f"dashboard:{d['id']}", {"noc_id": n["noc_id"]})
    a.mutated()
    return Resp(204)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def r_dash_sso(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    h = a.w["hosts"][d["host_id"]]
    if h["state"] != "enrolled" or not d["enabled"]:
        raise ApiError(409, "dashboard_not_ready", "the dashboard is not running yet")
    now = int(a.now())
    claims = {"iss": "exp-manager:default", "aud": d["id"], "sub": r.email, "name": r.email.split("@")[0],
              "role": "admin" if r.role == "owner" else r.role, "iat": now, "exp": now + 120, "jti": exp_ids.new_ulid()}
    head = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    pay = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64(hmac.new(SSO_SECRET, f"{head}.{pay}".encode(), hashlib.sha256).digest())
    action = (d["config"].get("url") or "https://dashboard.invalid").rstrip("/") + "/auth/sso"
    page = ("<!doctype html><html><head><meta charset=\"utf-8\"><title>Signing in</title></head>"
            "<body onload=\"document.forms[0].submit()\">"
            f"<form method=\"post\" action=\"{html.escape(action, quote=True)}\">"
            f"<input type=\"hidden\" name=\"token\" value=\"{head}.{pay}.{sig}\">"
            "<noscript><button type=\"submit\">Continue</button></noscript></form></body></html>")
    a.audit(r.email, "dashboard.sso", f"dashboard:{d['id']}")
    return Resp(200, raw=(page.encode(), "text/html; charset=utf-8"), headers=NO_STORE)


def _launch_nonce(a: MockAdmin, r: Req, did: str, exp: int) -> str:
    return f"{exp}." + _b64(hashlib.sha256(f"{SSO_SECRET!r}|{r.email}|{did}|{exp}".encode()).digest())


def r_dash_sso_launch(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    n = _launch_nonce(a, r, d["id"], int(a.now()) + 30)
    return Resp(200, body={"url": f"/api/admin/v1/dashboards/{d['id']}/sso/page?n={n}", "expires_in_s": 30}, headers=NO_STORE)


def r_dash_sso_page(a: MockAdmin, r: Req) -> Resp:
    d = dashboard(a, r.params["dashboard_id"])
    n = r.q.text("n", 100) or ""
    exp = int(n.split(".")[0]) if re.fullmatch(r"\d{10}\.[A-Za-z0-9_-]{43}", n) else 0
    if not exp or exp < int(a.now()) or n != _launch_nonce(a, r, d["id"], exp):
        raise ApiError(403, "invalid_launch_nonce", "the dashboard launch link is invalid or expired")
    return r_dash_sso(a, r)


# --- alerts / integrations / webhooks
def alerts_out(a: MockAdmin, site: str) -> dict[str, Any]:
    al = a.w["alerts"][site]
    return {"config": al["config"], "webhooks": [
        {"id": w["id"], "format": w["format"], "url": {"set": True, "updated_at": w["_updated"]}} for w in al["webhooks"]]}


def r_alerts_get(a: MockAdmin, r: Req) -> Resp:
    return ok(alerts_out(a, a.site(r.params["site"])["site"]))


def r_alerts_put(a: MockAdmin, r: Req) -> Resp:
    s = a.site(r.params["site"])["site"]
    d = r.json("AlertsPut")
    old = {w["id"]: w for w in a.w["alerts"][s]["webhooks"]}
    new = []
    now = seed.iso(a.now())
    for w in d["webhooks"]:
        wid = w.get("id") or "wh_" + exp_ids.new_ulid()[-8:].lower()
        if "url" in w:
            new.append({"id": wid, "format": w["format"], "_url": w["url"], "_updated": now})
        elif wid in old:
            new.append({"id": wid, "format": w["format"], "_url": old[wid]["_url"], "_updated": old[wid]["_updated"]})
        else:
            raise ApiError(400, "invalid_request", "a new webhook needs a url", {"errors": [{"path": "/webhooks", "message": "url required"}]})
    a.w["alerts"][s] = {"config": d["config"], "webhooks": new}
    a.audit(r.email, "alerts.update", f"site:{s}", {"webhooks": len(new)})
    a.mutated()
    return ok(alerts_out(a, s))


def r_alerts_test(a: MockAdmin, r: Req) -> Resp:
    s = a.site(r.params["site"])["site"]
    res = [{"webhook_id": w["id"], "ok": True, "http_status": 200, "error": None} for w in a.w["alerts"][s]["webhooks"]]
    return ok({"results": res})


def integ(a: MockAdmin, kind: str) -> dict[str, Any]:
    if kind not in a.w["integrations"]:
        raise ApiError(404, "not_found", "no such integration")
    return a.w["integrations"][kind]


def r_integ_get(a: MockAdmin, r: Req) -> Resp:
    return ok(integ(a, r.params["kind"]))


def r_integ_put(a: MockAdmin, r: Req) -> Resp:
    i = integ(a, r.params["kind"])
    d = r.json("IntegrationPut")
    now = seed.iso(a.now())
    i["config"] = d["config"]
    if "credentials" in d:
        i["credentials"] = {"set": True, "updated_at": now}
    if "allowlist" in d:
        i["allowlist"] = d["allowlist"]
    i["updated_at"] = now
    a.audit(r.email, "integration.update", f"integration:{i['kind']}", {"credentials_changed": "credentials" in d})
    a.mutated()
    return ok(i)


def r_integ_test(a: MockAdmin, r: Req) -> Resp:
    i = integ(a, r.params["kind"])
    good = i["credentials"]["set"]
    return ok({"ok": good, "detail": "mock: inventory fetched" if good else "mock: no credentials configured",
               "inventory_count": 42 if good else None})


def pw_out(a: MockAdmin) -> dict[str, Any]:
    p = a.w["platform_webhook"]
    return {"format": p["format"], "url": {"set": bool(p.get("_url")), "updated_at": p.get("_updated")}}


def r_pw_get(a: MockAdmin, r: Req) -> Resp:
    return ok(pw_out(a))


def r_pw_put(a: MockAdmin, r: Req) -> Resp:
    d = r.json("PlatformWebhookPut")
    p = a.w["platform_webhook"]
    p["format"] = d["format"]
    if "url" in d:
        p["_url"], p["_updated"] = d["url"], seed.iso(a.now())
    a.audit(r.email, "platform_webhook.update", "settings:platform-webhook", {"format": d["format"]})
    a.mutated()
    return ok(pw_out(a))


def r_pw_test(a: MockAdmin, r: Req) -> Resp:
    if not a.w["platform_webhook"].get("_url"):
        raise ApiError(409, "webhook_not_set", "no platform webhook is configured")
    return ok({"ok": True, "http_status": 200, "error": None})


# --- drills
def drill(a: MockAdmin, did: str) -> dict[str, Any]:
    for d in a.w["drills"]:
        if d["drl_id"] == did:
            return d
    raise ApiError(404, "not_found", "no such drill")


def run_view(a: MockAdmin, run: dict[str, Any]) -> dict[str, Any]:
    if run["state"] in ("scheduled", "active", "preflight", "reverting") and not run["abort_requested"]:
        now = a.now()
        start, until = exp_ts(run["start"]), exp_ts(run["until"])
        if now >= until:
            run["state"] = "done"
            run["report"] = {"result": "pass", "observed": {"ttd_s": 12.0, "ttr_s": 20.0, "lines_impacted": ["dns"]}}
            drill(a, run["drl_id"])["state"] = "done"
        elif now >= start:
            run["state"] = "active"
            drill(a, run["drl_id"])["state"] = "active"
    return seed.public(run)


def r_drills_list(a: MockAdmin, r: Req) -> Resp:
    site, state = r.q.slug("site"), r.q.text("state", 32)
    for d in a.w["drills"]:
        if d.get("last_run_id") in a.w["runs"]:
            run_view(a, a.w["runs"][d["last_run_id"]])
    items = [seed.public(d) for d in a.w["drills"] if (not site or d["site"] == site) and (not state or d["state"] == state)]
    return ok(paginate(r.q, items))


def r_drill_create(a: MockAdmin, r: Req) -> Resp:
    dry = r.q.enum("dry_run", ("true", "false"), "false") == "true"
    st = a.w["settings"]
    if not st["drills_enabled"]:
        raise ApiError(403, "drills_disabled", "drills are disabled for this org")
    raw = r.json()
    if isinstance(raw, dict) and isinstance(raw.get("duration_s"), int) and raw["duration_s"] > 900:
        raise ApiError(422, "duration_exceeds_cap", "duration over the 900 s cap")
    check_body(raw, "DrillCreate")
    a.site(raw["site"])
    target = raw["params"].get("target")
    if isinstance(target, str) and target not in DRILL_TARGET_ALLOWLIST:
        raise ApiError(422, "target_not_allowlisted", f"target {target[:64]} is not in the allowlist")
    if not re.fullmatch(r"[a-z0-9_]+(\.[a-z0-9_]+)+", raw["type"]):
        raise ApiError(422, "invalid_drill", "invalid drill type")
    if raw["type"].startswith("ec.") or raw["type"].startswith("mist."):
        for d in a.w["drills"]:
            if d["site"] == raw["site"] and d["state"] in ("active", "scheduled") and d["type"].split(".")[0] in ("ec", "mist"):
                raise ApiError(409, "external_drill_active", "an external drill is already active for this site")
    if dry:
        return ok({"ok": True, "checks": [{"name": "allowlist", "ok": True, "detail": "target allowed"},
                                          {"name": "site_online", "ok": True, "detail": "collector reachable"}]})
    now = seed.iso(a.now())
    two = st["drills_two_person"]
    d = {"drl_id": exp_ids.new_id("drl_"), "name": raw["name"], "type": raw["type"], "site": raw["site"],
         "params": raw["params"], "duration_s": raw.get("duration_s", 120),
         "expectation": raw.get("expectation", {}), "schedule": raw.get("schedule", {"mode": "once", "start_at": None, "every_s": None}),
         "state": "pending_approval" if two else "approved", "created_by": r.email,
         "approved_by": None if two else r.email, "last_run_id": None, "created_at": now, "updated_at": now}
    a.w["drills"].append(d)
    a.audit(r.email, "drill.create", f"drill:{d['name']}", {"type": d["type"], "site": d["site"]})
    a.mutated()
    return ok(seed.public(d), 201)


def r_drill_approve(a: MockAdmin, r: Req) -> Resp:
    d = drill(a, r.params["id"])
    if d["state"] != "pending_approval":
        raise ApiError(409, "invalid_state", "drill is not waiting for approval")
    if a.w["settings"]["drills_two_person"] and d["created_by"] == r.email:
        raise ApiError(409, "second_approver_required", "a second person must approve this drill")
    d.update(state="approved", approved_by=r.email, updated_at=seed.iso(a.now()))
    a.audit(r.email, "drill.approve", f"drill:{d['name']}")
    a.mutated()
    return ok(seed.public(d))


def r_drill_start(a: MockAdmin, r: Req) -> Resp:
    d = drill(a, r.params["id"])
    body = r.json("DrillStart", optional=True)
    if d["state"] in ("pending_approval",):
        raise ApiError(409, "not_approved", "drill is not approved")
    if d["state"] not in ("approved", "done", "failed", "aborted"):
        raise ApiError(409, "invalid_state", f"drill is {d['state']}")
    now = a.now()
    start = exp_ts(body["start_at"]) if "start_at" in body else now + 15
    if start < now + 10:
        raise ApiError(422, "start_too_soon", "start_at must be at least 10 s in the future")
    rid = exp_ids.new_id("run_")
    run = {"run_id": rid, "drl_id": d["drl_id"], "state": "scheduled", "start": seed.iso(start),
           "until": seed.iso(start + d["duration_s"]), "abort_requested": False, "reason": None, "report": None}
    a.w["runs"][rid] = run
    d.update(state="scheduled", last_run_id=rid, updated_at=seed.iso(now))
    a.audit(r.email, "drill.start", f"drill:{d['name']}", {"run_id": rid})
    a.mutated()
    return ok(seed.public(run), 202)


def r_drills_abort_all(a: MockAdmin, r: Req) -> Resp:
    body = r.json("AbortAll", optional=True)
    aborted = []
    for run in a.w["runs"].values():
        d = drill(a, run["drl_id"])
        run_view(a, run)
        if run["state"] in ("scheduled", "active", "preflight") and (not body.get("site") or d["site"] == body["site"]):
            run.update(state="aborted", abort_requested=True, reason=f"abort-all by {r.email}")
            d["state"] = "aborted"
            aborted.append(run["run_id"])
    a.audit(r.email, "drill.abort_all", "drills", {"count": len(aborted), "site": body.get("site")})
    a.mutated()
    return ok({"aborted_runs": aborted}, 202)


def r_drill_run(a: MockAdmin, r: Req) -> Resp:
    drill(a, r.params["id"])
    run = a.w["runs"].get(r.params["run"])
    if run is None or run["drl_id"] != r.params["id"]:
        raise ApiError(404, "not_found", "no such run")
    return ok(run_view(a, run))


# --- overview / fleet
def r_overview(a: MockAdmin, r: Req) -> Resp:
    snap = a.snap()
    hosts = a.live_hosts()
    sites = []
    for s in sorted(a.w["sites"].values(), key=lambda s: s["site"]):
        sh = [h for h in hosts if h["site"] == s["site"]]
        comps = [c for h in sh for c in a.host_comps(h["host_id"])]
        sites.append({"site": s["site"], "name": s["name"], "release_version": s["release_version"],
                      "hosts_total": len(sh), "hosts_by_state": a.state_counts(sh),
                      "components_by_health": a.health_counts(comps)})
    out_hosts = []
    versions: dict[str, int] = {}
    for h in sorted(hosts, key=lambda h: h["name"]):
        out_hosts.append({"host_id": h["host_id"], "name": h["name"], "site": h["site"], "state": h["state"],
                          "health": a.host_health(h), "agent_version": h["agent_version"],
                          "desired_version": h["desired_version"], "applied_version": h["applied_version"],
                          "components": [{"component_id": c["component_id"], "type": c["type"], "id": c["id"],
                                          "health": c["health"], "version": c["version"]} for c in a.host_comps(h["host_id"])]})
        if h["agent_version"]:
            versions[h["agent_version"]] = versions.get(h["agent_version"], 0) + 1
    return ok({"as_of": seed.iso(snap), "sites": sites, "hosts": out_hosts, "versions": versions})


def r_fleet_summary(a: MockAdmin, r: Req) -> Resp:
    snap = a.snap()
    hosts = a.live_hosts()
    by_type: dict[str, dict[str, int]] = {}
    for h in hosts:
        for c in a.host_comps(h["host_id"]):
            by_type.setdefault(c["type"], {"ok": 0, "degraded": 0, "fail": 0, "unknown": 0})[c["health"]] += 1
    opens = a.open_issues()
    meas = ing = 0.0
    for c in a.w["components"].values():
        if c["type"] == "probe":
            meas += a.comp_value(c, "measurements_per_min", snap) or 0.0
        elif c["type"] == "collector":
            ing += a.comp_value(c, "ingest_records_per_s", snap) or 0.0
    counts = a.state_counts(hosts)
    return Resp(200, {"as_of": seed.iso(snap), "hosts_by_state": counts, "hosts_total": len(hosts),
                      "hosts_online": counts["enrolled"], "components_by_type_health": by_type,
                      "measurements_per_min": round(meas, 1), "ingest_records_per_s": round(ing, 1),
                      "open_issues": {"warn": sum(1 for i in opens if i["severity"] == "warn"),
                                      "crit": sum(1 for i in opens if i["severity"] == "crit")},
                      "version_drift_hosts": a.drift_hosts(), "open_experience_incidents": 2}, fleet=True)


def r_fleet_sites(a: MockAdmin, r: Req) -> Resp:
    snap = a.snap()
    items = []
    opens = a.open_issues()
    for s in sorted(a.w["sites"].values(), key=lambda s: s["site"]):
        sh = [h for h in a.live_hosts() if h["site"] == s["site"]]
        bar = {"ok": 0, "warn": 0, "fail": 0, "offline": 0}
        for h in sh:
            if h["state"] in ("stale", "offline"):
                bar["offline"] += 1
            elif h["state"] == "enrolled":
                hh = a.host_health(h)
                bar["fail" if hh == "fail" else "warn" if hh == "degraded" else "ok"] += 1
        probes = [c for h in sh for c in a.host_comps(h["host_id"]) if c["type"] == "probe"]
        ing = sum(a.comp_value(c, "ingest_records_per_s", snap) or 0.0 for h in sh for c in a.host_comps(h["host_id"])
                  if c["type"] == "collector")
        site_issues = sorted((i for i in opens if i["site"] == s["site"]),
                             key=lambda i: (0 if i["severity"] == "crit" else 1, i["opened_at"]))
        items.append({"site": s["site"], "name": s["name"], "hosts": len(sh), "health_bar": bar,
                      "probes_reporting": sum(1 for c in probes if c["health"] != "unknown"),
                      "probes_total": len(probes), "ingest_records_per_s": round(ing, 1),
                      "worst_issue": seed.public(site_issues[0]) if site_issues else None,
                      "release_version": s["release_version"], "canary_state": s["canary_state"]})
    return Resp(200, {"items": items, "as_of": seed.iso(snap)}, fleet=True)


SORT_KEYS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "name": lambda r: r["name"], "site": lambda r: r["site"],
    "health": lambda r: HEALTH_RANK[r["health"]], "cpu": lambda r: r["cpu_pct"], "mem": lambda r: r["mem_pct"],
    "disk": lambda r: r["disk_pct_max"], "uptime": lambda r: r["uptime_s"],
    "net": lambda r: (r["net"] or {}).get("rx_pps") if r["net"] else None,
    "work": lambda r: r["work"].get("measurements_per_min") or r["work"].get("ingest_records_per_s"),
    "version": lambda r: r["agent_version"], "last_seen": lambda r: r["last_seen"]}


def r_fleet_hosts(a: MockAdmin, r: Req) -> Resp:
    q = r.q
    snap = a.snap()
    site, ctype = q.slug("site"), q.enum("type", ("probe", "collector", "dashboard", "runner", "speedtest"))
    health, state = q.enum("health", ("ok", "degraded", "fail", "unknown")), q.enum("state", tuple(seed_states()))
    version, text = q.one("version"), q.text("q", 128)
    sort = q.one("sort")
    if version is not None and not _SEMVER.match(version):
        raise ApiError(400, "invalid_request", "'version' must be a semver")
    if sort is not None and not re.fullmatch(r"-?(name|site|health|cpu|mem|disk|uptime|net|work|version|last_seen)", sort):
        raise ApiError(400, "invalid_request", "bad sort")
    rows = []
    for h in a.live_hosts():
        if site and h["site"] != site or state and h["state"] != state or version and h["agent_version"] != version:
            continue
        if ctype and not any(c["type"] == ctype for c in a.host_comps(h["host_id"])):
            continue
        if text and text.lower() not in f"{h['name']} {h['mgmt_ip'] or ''} {h['site']}".lower():
            continue
        row = a.fleet_row(h, snap)
        if health and row["health"] != health:
            continue
        rows.append(row)
    field = (sort or "name").lstrip("-")
    desc = bool(sort and sort.startswith("-"))
    key = SORT_KEYS[field]
    have = sorted((x for x in rows if key(x) is not None), key=key, reverse=desc)
    rows = have + [x for x in rows if key(x) is None]
    return Resp(200, paginate(q, rows), fleet=True)


def metrics_response(a: MockAdmin, r: Req, entity: str, profile: dict[str, Any], keys_all: tuple[str, ...],
                     until: float | None, extra: dict[str, Any]) -> Resp:
    rng = r.q.enum("range", tuple(seed.RANGES), "1h")
    kq = r.q.one("keys")
    if kq is not None and (len(kq) > 512 or not re.fullmatch(r"[a-z0-9_]+(,[a-z0-9_]+)*", kq)):
        raise ApiError(400, "invalid_request", "bad keys")
    keys = [k for k in (kq.split(",") if kq else keys_all) if k in keys_all]
    snap = a.snap()
    series = {} if until is None and extra.get("_pending") else {
        k: seed.series_points(entity, k, profile, rng, snap, until) for k in dict.fromkeys(keys)}
    extra = {k: v for k, v in extra.items() if not k.startswith("_")}
    return Resp(200, {"range": rng, "step_s": seed.RANGES[rng][0], "as_of": seed.iso(snap), "series": series, **extra},
                fleet=True)


def r_fleet_host_metrics(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    if h["state"] == "removed":
        raise ApiError(404, "not_found", "no such host")
    online = h["state"] in ("enrolled", "stale", "offline")
    return metrics_response(a, r, h["host_id"], h.get("_profile", {}), seed.HOST_KEYS,
                            h.get("_last_seen") if h["state"] in ("stale", "offline") else None,
                            {"host_id": h["host_id"], "_pending": not online})


def r_fleet_iface_metrics(a: MockAdmin, r: Req) -> Resp:
    h = a.host(r.params["id"])
    iface = r.params["iface"]
    if h["state"] == "removed":
        raise ApiError(404, "not_found", "no such host")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", iface):
        raise ApiError(404, "not_found", "no such interface")
    rng = r.q.enum("range", tuple(seed.IFACE_RANGES), "24h")
    kq = r.q.one("keys")
    if kq is not None and (len(kq) > 512 or not re.fullmatch(r"[a-z0-9_]+(,[a-z0-9_]+)*", kq)):
        raise ApiError(400, "invalid_request", "bad keys")
    keys = list(dict.fromkeys(kq.split(",") if kq else seed.IFACE_KEYS))
    if any(k not in seed.IFACE_KEYS for k in keys):
        raise ApiError(400, "invalid_request", "unknown metric key")
    snap = a.snap()
    known = {i["name"]: i for i in h["facts"].get("interfaces", [])}
    online = h["state"] in ("enrolled", "stale", "offline")
    until = h.get("_last_seen") if h["state"] in ("stale", "offline") else None
    # an interface the host does not have has no roll-up rows: empty series (the real API answers the same)
    if not online or iface not in known:
        series: dict[str, Any] = {k: [] for k in keys}
    else:
        prof = seed.iface_profile(h["host_id"], iface, is_mgmt(known[iface]), h["_role"])
        series = {k: seed.iface_series(f"{h['host_id']}:{iface}", k, prof, rng, snap, until) for k in keys}
    return Resp(200, {"host_id": h["host_id"], "iface": iface, "range": rng, "step_s": 300, "as_of": seed.iso(snap),
                      "series": series}, fleet=True)


def r_fleet_comp_probes(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    at = a.at_of(h, a.snap())
    if c["type"] != "collector" or at is None:
        return Resp(200, {"component_id": c["component_id"], "as_of": seed.iso(a.snap()), "reported_at": None, "items": []},
                    fleet=True)
    return Resp(200, {"component_id": c["component_id"], "as_of": seed.iso(a.snap()), "reported_at": seed.iso(at),
                      "items": seed.probe_rows(c, at)}, fleet=True)


def r_fleet_comp_metrics(a: MockAdmin, r: Req) -> Resp:
    c = a.comp(r.params["component_id"])
    h = a.w["hosts"][c["host_id"]]
    online = h["state"] in ("enrolled", "stale", "offline")
    keys_all = seed.COMPONENT_KEYS.get(c["type"], ("cpu_pct",))
    if c["type"] == "probe" and r.q.one("keys") is not None:
        keys_all = keys_all + seed.PROBE_BY_TEST_KEYS          # on request only, never in the default key list
    return metrics_response(a, r, c["component_id"], c["_profile"], keys_all,
                            h.get("_last_seen") if h["state"] in ("stale", "offline") else None,
                            {"component_id": c["component_id"], "_pending": not online})


def r_fleet_top(a: MockAdmin, r: Req) -> Resp:
    metric = r.q.enum("metric", ("cpu", "mem", "disk", "net"), "cpu")
    limit = r.q.integer("limit", 1, 1000, 10)
    snap = a.snap()
    items = []
    for h in a.live_hosts():
        if h["state"] != "enrolled":
            continue
        at = a.at_of(h, snap)
        end = int(at // 300) * 300
        ts_list = [end - (35 - i) * 300 for i in range(36)]
        if metric == "net":
            val, out = a.host_value(h, "net_rx_pps", snap), a.host_value(h, "net_tx_pps", snap)
            spark = [seed.metric_value(h["host_id"], "net_rx_pps", h["_profile"], t) for t in ts_list]
            unit = "pps"
        else:
            key = {"cpu": "cpu_pct", "mem": "mem_pct", "disk": "disk_pct"}[metric]
            val, out, unit = a.host_value(h, key, snap), None, "pct"
            spark = [seed.metric_value(h["host_id"], key, h["_profile"], t) for t in ts_list]
        items.append({"host_id": h["host_id"], "name": h["name"], "site": h["site"], "value": val, "unit": unit,
                      "value_out": out, "spark": spark})
    items.sort(key=lambda x: x["value"], reverse=True)
    return Resp(200, {"metric": metric, "as_of": seed.iso(snap), "items": items[:limit]}, fleet=True)


# --- issues
def r_issues(a: MockAdmin, r: Req) -> Resp:
    sev = r.q.enum("severity", ("warn", "crit"))
    site = r.q.slug("site")
    kind = r.q.enum("kind", tuple(seed_issue_kinds()))
    state = r.q.enum("state", ("open", "resolved"))
    items = [i for i in a.w["issues"] if (not sev or i["severity"] == sev) and (not site or i["site"] == site)
             and (not kind or i["kind"] == kind)
             and (not state or (i["resolved_at"] is None) == (state == "open"))]
    items.sort(key=lambda i: i["opened_at"], reverse=True)
    return ok(paginate(r.q, [seed.public(i) for i in items]))


def seed_issue_kinds() -> list[str]:
    return ["host_stale", "host_offline", "disk_high", "storage_runway", "mem_low", "cpu_high", "clock",
            "component_unhealthy", "crash_loop", "reconcile_failed", "version_drift", "probe_ports",
            "probe_push_lag", "probe_spool", "probe_collector", "collector_rejects", "collector_vm",
            "collector_probes", "dashboard_collectors", "iface_errors"]


def issue(a: MockAdmin, iid: str) -> dict[str, Any]:
    for i in a.w["issues"]:
        if i["issue_id"] == iid:
            return i
    raise ApiError(404, "not_found", "no such issue")


def r_snooze(a: MockAdmin, r: Req) -> Resp:
    i = issue(a, r.params["id"])
    d = r.json("SnoozeRequest")
    if i["resolved_at"] is not None:
        raise ApiError(400, "invalid_request", "issue is already resolved")
    until = {"1h": seed.iso(a.now() + 3600), "24h": seed.iso(a.now() + 86400), "resolved": "resolved"}[d["for"]]
    i["snoozed_until"] = until
    sn = {"issue_id": i["issue_id"], "kind": i["kind"], "host_id": i["host_id"], "until": until, "created_by": r.email}
    a.w["snoozes"][i["issue_id"]] = sn
    a.audit(r.email, "issue.snooze", f"issue:{i['issue_id']}", {"for": d["for"], "kind": i["kind"]})
    a.mutated()
    return ok(sn)


def r_unsnooze(a: MockAdmin, r: Req) -> Resp:
    i = issue(a, r.params["id"])
    i["snoozed_until"] = None
    a.w["snoozes"].pop(i["issue_id"], None)
    a.audit(r.email, "issue.unsnooze", f"issue:{i['issue_id']}")
    a.mutated()
    return Resp(204)


# --- settings
def r_thr_get(a: MockAdmin, r: Req) -> Resp:
    return ok(a.w["thresholds"])


def r_thr_put(a: MockAdmin, r: Req) -> Resp:
    d = r.json("FleetThresholds")
    for k, v in d.items():
        a.w["thresholds"][k] = {**a.w["thresholds"].get(k, {}), **v}
    a.audit(r.email, "settings.thresholds", "settings:fleet-thresholds", {"keys": sorted(d)})
    a.mutated()
    return ok(a.w["thresholds"])


def r_audit(a: MockAdmin, r: Req) -> Resp:
    frm, to = r.q.ts("from"), r.q.ts("to")
    actor, resource = r.q.text("actor", 254), r.q.text("resource", 256)
    items = [e for e in a.w["audit"] if (frm is None or exp_ts(e["ts"]) >= frm) and (to is None or exp_ts(e["ts"]) <= to)
             and (not actor or e["actor"] == actor) and (not resource or e["resource"] == resource)]
    items.sort(key=lambda e: e["ts"], reverse=True)
    return ok(paginate(r.q, items))


# Same derivation as the Worker (secrets/crypto.ts keyId), over a fixed fake "key": the id is not secret and no real key exists here.
_MOCK_KEY_ID = hashlib.sha256(b"exp-key-id/v1|mock-admin: no real master key").hexdigest()[:16]


def r_master_key(a: MockAdmin, r: Req) -> Resp:
    """Steady state, no rotation in progress (CR-m3-master-key-rotation)."""
    return ok({"current_key_id": _MOCK_KEY_ID, "previous_key_id": None, "remaining_previous": 0,
               "unknown_key_rows": 0, "safe_to_remove_previous": True})


def r_settings_get(a: MockAdmin, r: Req) -> Resp:
    return ok(a.w["settings"])


def r_settings_patch(a: MockAdmin, r: Req) -> Resp:
    d = r.json("SettingsPatch")
    st = a.w["settings"]
    new = json.loads(json.dumps(st))
    new.update({k: v for k, v in d.items() if k != "owner"})
    if "owner" in d and d["owner"] != st["owner"]:
        for e in new["admins"]:
            if e["email"] == st["owner"] and e["role"] == "owner":
                e["role"] = "admin"
        ent = next((e for e in new["admins"] if e["email"] == d["owner"]), None)
        if ent is None:
            new["admins"].append({"email": d["owner"], "role": "owner", "disabled": False, "last_seen": None})
        else:
            ent.update(role="owner", disabled=False)
        new["owner"] = d["owner"]
    if not any(e["role"] == "owner" and not e.get("disabled") and e["email"] == new["owner"] for e in new["admins"]):
        raise ApiError(409, "last_owner", "the org must keep exactly one active owner")
    new["updated_at"] = seed.iso(a.now())
    a.w["settings"] = new
    a.audit(r.email, "settings.update", "settings", {"fields": sorted(d)})
    a.mutated()
    return ok(new)


# ------------------------------------------------------------------ M6 speedtest settings (admin.yaml tag speedtest)
# INTENT only: this mock, like the manager, has no route for test results or evidence (SR-20).
DEFAULT_CONSENT = ("We measure your connection speed and record technical details of this device and its network path "
                   "(Wi-Fi signal, access point, traffic metadata) to diagnose problems. No name or email address is collected.")
_PNG_MAGIC, _JPEG_MAGIC = b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff"
_SVG_BAD = re.compile(
    rb"<\s*(script|foreignobject|iframe|embed|object|link|animate|set|a)\b|\son[a-z]+\s*=|javascript:|@import|<!(DOCTYPE|ENTITY)", re.I)


def st_state(a: MockAdmin, site: str) -> dict[str, Any]:
    a.site(site)
    return a.w["speedtest"].setdefault(site, {"settings": {}, "consent": None, "paused": False, "logo": None, "updated_at": None})


def st_out(a: MockAdmin, site: str) -> dict[str, Any]:
    st = st_state(a, site)
    out = json.loads(json.dumps(st["settings"]))
    if st["logo"]:
        out.setdefault("branding", {})["logo_artifact"] = st["logo"]["artifact"]
    out["internet_leg"] = {**out.get("internet_leg", {}), "paused": st["paused"]}
    out["consent"] = st["consent"] or {"text": DEFAULT_CONSENT, "version": 1}
    dk = a.w["device_key"]
    out["device_key"] = {"set": dk["set"], "updated_at": dk["updated_at"]}
    if st["updated_at"]:
        out["updated_at"] = st["updated_at"]
    return out


def r_st_get(a: MockAdmin, r: Req) -> Resp:
    return ok(st_out(a, r.params["site"]))


def r_st_put(a: MockAdmin, r: Req) -> Resp:
    site = r.params["site"]
    st = st_state(a, site)
    d = r.json("SpeedtestSettingsPut")
    serve = d.get("serve")
    if serve and (serve["listen_ip"] in ("0.0.0.0", "255.255.255.255") or serve["listen_ip"].startswith("127.")):  # noqa: S104
        raise ApiError(400, "invalid_request", "serve.listen_ip must be a unicast address of the speedtest box")
    if serve and serve.get("require_real_client_ip") and not (serve.get("client_subnets") or d.get("zone_labels", {}).get("subnets")):
        raise ApiError(400, "invalid_request", "serve.require_real_client_ip needs the attendee subnets")
    known = {z["id"] for z in d.get("zones", [])}
    if known:
        for sn in d.get("zone_labels", {}).get("subnets", []):
            if sn["zone"] not in known:
                raise ApiError(400, "invalid_request", f"zone_labels refers to unknown zone {sn['zone']}")
    br = d.get("branding", {})
    if br.get("logo_artifact") and not (st["logo"] and st["logo"]["artifact"] == br["logo_artifact"]):
        raise ApiError(400, "invalid_request", "branding.logo_artifact can only be set by uploading a logo")
    now = seed.iso(a.now())
    consent = d["consent"]
    cur = st["consent"]
    hist = a.w["speedtest_history"].setdefault(site, [])
    if cur is None or consent["text"] != cur["text"]:
        version = 1 if cur is None else cur["version"] + 1
        hist.append({"version": version, "text": consent["text"], "changed_by": r.email, "created_at": now})
        st["consent"] = {"text": consent["text"], "version": version}
    if "logo_artifact" in br and br["logo_artifact"] is None:
        st["logo"] = None
    paused = d.get("internet_leg", {}).get("paused", st["paused"])
    settings = {k: v for k, v in d.items() if k != "consent"}
    if "branding" in settings:
        settings["branding"] = {k: v for k, v in settings["branding"].items() if k != "logo_artifact"}
    if "internet_leg" in settings:
        settings["internet_leg"] = {k: v for k, v in settings["internet_leg"].items() if k != "paused"}
    st["settings"], st["paused"], st["updated_at"] = settings, paused, now
    a.audit(r.email, "speedtest.settings", f"site:{site}", {"fields": sorted(settings), "consent_version": st["consent"]["version"]})
    a.mutated()
    return ok(st_out(a, site))


def r_st_history(a: MockAdmin, r: Req) -> Resp:
    a.site(r.params["site"])
    return ok({"items": list(reversed(a.w["speedtest_history"].get(r.params["site"], [])))})


def r_st_pause(a: MockAdmin, r: Req) -> Resp:
    st = st_state(a, r.params["site"])
    d = r.json("SpeedtestPause")
    st["paused"], st["updated_at"] = d["paused"], seed.iso(a.now())
    a.audit(r.email, "speedtest.internet_pause", f"site:{r.params['site']}", {"paused": d["paused"]})
    a.mutated()
    return ok({"paused": st["paused"], "updated_at": st["updated_at"]})


def r_st_logo(a: MockAdmin, r: Req) -> Resp:
    st = st_state(a, r.params["site"])
    ctype = (r.h.header("Content-Type") or "").split(";")[0].strip().lower()
    if ctype not in ("image/png", "image/svg+xml", "image/jpeg"):
        raise ApiError(415, "unsupported_media_type", "the logo must be image/png, image/svg+xml or image/jpeg")
    body = r.raw(262144)
    if not body:
        raise ApiError(400, "invalid_request", "an image body is required")
    good = (body.startswith(_PNG_MAGIC) if ctype == "image/png" else body.startswith(_JPEG_MAGIC) if ctype == "image/jpeg"
            else b"<svg" in body[:512].lower() and not _SVG_BAD.search(body))
    if not good:
        raise ApiError(400, "invalid_request", "the body is not an acceptable image of that type")
    sha = hashlib.sha256(body).hexdigest()
    st["logo"] = {"artifact": fc.det_id("art_", f"logo:{sha}"), "sha256": sha, "size": len(body), "content_type": ctype}
    st["updated_at"] = seed.iso(a.now())
    a.audit(r.email, "speedtest.logo", f"site:{r.params['site']}", {"size": len(body), "content_type": ctype})
    a.mutated()
    return ok(dict(st["logo"]), 201)


def r_st_qr(a: MockAdmin, r: Req) -> Resp:
    st = st_state(a, r.params["site"])
    s = st["settings"]
    host = (s.get("serve") or {}).get("hostname")
    if not host:
        return ok({"items": []})
    scheme = "https" if (s.get("tls") or {}).get("mode") == "provided" else "http"
    return ok({"items": [{"zone": z["id"], "name": z["name"], "url": f"{scheme}://{host}/?z={z['id']}"} for z in s.get("zones", [])]})


def _st_tls_view(a: MockAdmin, site: str) -> dict[str, Any]:
    a.site(site)
    t = a.w["speedtest_tls"].get(site)
    if not t:
        return {"set": False, "updated_at": None, "cert": None}
    return {"set": True, "updated_at": t["updated_at"], "cert": t["cert"]}


def r_st_tls_get(a: MockAdmin, r: Req) -> Resp:
    return ok(_st_tls_view(a, r.params["site"]))


def r_st_tls_put(a: MockAdmin, r: Req) -> Resp:
    site = r.params["site"]
    a.site(site)
    d = r.json("SpeedtestTlsPut")
    if "BEGIN CERTIFICATE" not in d["cert_pem"] or "PRIVATE KEY" not in d["key_pem"]:
        raise ApiError(422, "invalid_config", "the certificate or key is not a PEM block")
    now = a.now()
    a.w["speedtest_tls"][site] = {"updated_at": seed.iso(now), "cert": {
        "subject": "CN=speed.summit.example", "issuer": "CN=speed.summit.example", "not_before": seed.iso(now - 86400),
        "not_after": seed.iso(now + 365 * 86400), "sha256": seed.fingerprint(f"speedtest-tls:{site}"), "san": ["speed.summit.example"]}}
    a.audit(r.email, "speedtest.tls", f"site:{site}", {"secret_set": True})
    a.mutated()
    return ok(_st_tls_view(a, site))


def r_st_device_key(a: MockAdmin, r: Req) -> Resp:
    dk = a.w["device_key"]
    dk.update(set=True, updated_at=seed.iso(a.now()), version=dk.get("version", 0) + 1)
    a.audit(r.email, "speedtest.device_key", "settings", {"rotated": dk["version"] > 1})
    a.mutated()
    return ok({"set": True, "updated_at": dk["updated_at"], "key_id": f"k{dk['version']}"})


def _routes() -> list[tuple[str, re.Pattern[str], str, Callable[[MockAdmin, Req], Resp]]]:
    spec = [
        ("GET", "/me", "viewer", r_me),
        ("GET", "/sites", "viewer", r_sites_list), ("POST", "/sites", "admin", r_sites_create),
        ("GET", "/sites/{site}", "viewer", r_site_get), ("PATCH", "/sites/{site}", "admin", r_site_patch),
        ("DELETE", "/sites/{site}", "admin", r_site_delete),
        ("GET", "/hosts", "viewer", r_hosts_list), ("POST", "/hosts", "admin", r_hosts_create),
        ("GET", "/hosts/{id}", "viewer", r_host_get), ("PATCH", "/hosts/{id}", "admin", r_host_patch),
        ("DELETE", "/hosts/{id}", "admin", r_host_delete),
        ("POST", "/hosts/{id}/enrol-token", "admin", r_host_enrol_token),
        ("POST", "/hosts/{id}/decommission", "admin", r_host_decommission),
        ("GET", "/hosts/{id}/components", "viewer", r_host_components),
        ("POST", "/hosts/{id}/components", "admin", r_comp_create),
        ("PATCH", "/components/{component_id}", "admin", r_comp_patch),
        ("DELETE", "/components/{component_id}", "admin", r_comp_delete),
        ("POST", "/components/{component_id}/restart", "admin", r_comp_restart),
        ("PUT", "/components/{component_id}/ports", "admin", r_comp_ports),
        ("GET", "/releases", "viewer", r_releases_list), ("POST", "/releases/import", "admin", r_release_import),
        ("POST", "/releases/upload", "admin", r_release_upload),
        ("PATCH", "/sites/{site}/release", "admin", r_site_release),
        ("POST", "/components/{component_id}/rotate", "admin", r_comp_rotate),
        ("POST", "/hosts/{id}/rotate-agent", "admin", r_host_rotate_agent),
        ("GET", "/dashboards/{dashboard_id}/users", "admin", r_dash_users),
        ("POST", "/dashboards/{dashboard_id}/users", "admin", r_dash_user_create),
        ("DELETE", "/dashboards/{dashboard_id}/users/{usr}", "admin", r_dash_user_delete),
        ("GET", "/dashboards/{dashboard_id}/tls", "admin", r_dash_tls_get),
        ("PUT", "/dashboards/{dashboard_id}/tls", "admin", r_dash_tls_put),
        ("GET", "/dashboards/{dashboard_id}/noc-tokens", "admin", r_noc_list),
        ("POST", "/dashboards/{dashboard_id}/noc-tokens", "admin", r_noc_create),
        ("DELETE", "/dashboards/{dashboard_id}/noc-tokens/{noc}", "admin", r_noc_revoke),
        ("POST", "/dashboards/{dashboard_id}/sso", "viewer", r_dash_sso),
        ("POST", "/dashboards/{dashboard_id}/sso/launch", "viewer", r_dash_sso_launch),
        ("GET", "/dashboards/{dashboard_id}/sso/page", "viewer", r_dash_sso_page),
        ("GET", "/sites/{site}/alerts", "viewer", r_alerts_get), ("PUT", "/sites/{site}/alerts", "admin", r_alerts_put),
        ("POST", "/sites/{site}/alerts/test", "admin", r_alerts_test),
        ("GET", "/integrations/{kind}", "viewer", r_integ_get), ("PUT", "/integrations/{kind}", "owner", r_integ_put),
        ("POST", "/integrations/{kind}/test", "owner", r_integ_test),
        ("GET", "/drills", "viewer", r_drills_list), ("POST", "/drills", "admin", r_drill_create),
        ("POST", "/drills/abort-all", "operator", r_drills_abort_all),
        ("POST", "/drills/{id}/approve", "admin", r_drill_approve), ("POST", "/drills/{id}/start", "operator", r_drill_start),
        ("GET", "/drills/{id}/runs/{run}", "viewer", r_drill_run),
        ("GET", "/overview", "viewer", r_overview), ("GET", "/hosts/{id}/status", "viewer", r_host_status),
        ("GET", "/fleet/summary", "viewer", r_fleet_summary), ("GET", "/fleet/sites", "viewer", r_fleet_sites),
        ("GET", "/fleet/hosts", "viewer", r_fleet_hosts),
        ("GET", "/fleet/hosts/{id}/metrics", "viewer", r_fleet_host_metrics),
        ("GET", "/fleet/hosts/{id}/interfaces/{iface}/metrics", "viewer", r_fleet_iface_metrics),
        ("GET", "/fleet/components/{component_id}/probes", "viewer", r_fleet_comp_probes),
        ("GET", "/fleet/components/{component_id}/metrics", "viewer", r_fleet_comp_metrics),
        ("GET", "/fleet/top", "viewer", r_fleet_top),
        ("GET", "/issues", "viewer", r_issues), ("POST", "/issues/{id}/snooze", "admin", r_snooze),
        ("DELETE", "/issues/{id}/snooze", "admin", r_unsnooze),
        ("GET", "/settings/fleet-thresholds", "viewer", r_thr_get), ("PUT", "/settings/fleet-thresholds", "admin", r_thr_put),
        ("GET", "/settings/platform-webhook", "viewer", r_pw_get), ("PUT", "/settings/platform-webhook", "admin", r_pw_put),
        ("POST", "/settings/platform-webhook/test", "admin", r_pw_test),
        ("GET", "/settings/master-key", "admin", r_master_key),
        ("GET", "/audit", "admin", r_audit),
        ("GET", "/sites/{site}/speedtest", "viewer", r_st_get), ("PUT", "/sites/{site}/speedtest", "admin", r_st_put),
        ("GET", "/sites/{site}/speedtest/consent-history", "admin", r_st_history),
        ("POST", "/sites/{site}/speedtest/logo", "admin", r_st_logo),
        ("POST", "/sites/{site}/speedtest/internet-pause", "operator", r_st_pause),
        ("GET", "/sites/{site}/speedtest/qr", "viewer", r_st_qr),
        ("GET", "/sites/{site}/speedtest/tls", "admin", r_st_tls_get), ("PUT", "/sites/{site}/speedtest/tls", "admin", r_st_tls_put),
        ("POST", "/settings/speedtest-device-key", "owner", r_st_device_key),
        ("GET", "/settings", "viewer", r_settings_get), ("PATCH", "/settings", "owner", r_settings_patch),
    ]
    out = []
    for method, tmpl, role, fn in spec:
        rx = re.sub(r"\{(\w+)\}", lambda m: f"(?P<{m.group(1)}>[A-Za-z0-9_.:-]{{1,128}})", tmpl)
        out.append((method, re.compile(rx), role, fn))
    return out


ROUTES = _routes()


# ------------------------------------------------------------------------------------ entry points

class FakeAdmin(fc.FakeServer):
    pass


def start(*, host: str = "127.0.0.1", port: int = 0, tls: bool = False, state_dir: str | Path | None = None,
          **app_kwargs: Any) -> FakeAdmin:
    """Start mock_admin in-process; returns the server (``.port``, ``.app``, ``.stop()``).

    ``tls=True`` serves HTTPS with a self-signed certificate generated in ``state_dir``."""
    app = MockAdmin(**app_kwargs)
    tls_files = None
    if tls:
        if state_dir is None:
            raise ValueError("tls=True needs state_dir (the self-signed cert is generated there)")
        cert, key, _ = fc.prepare_tls(Path(state_dir))
        tls_files = (cert, key)
    srv = FakeAdmin(Handler, app, host=host, port=port, tls=tls_files, name="mock_admin")
    srv.start()
    return srv


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:8787", help="host:port (default 127.0.0.1:8787)")
    ap.add_argument("--tls", action=argparse.BooleanOptionalAction, default=False,
                    help="serve HTTPS with a self-signed cert generated in --state-dir (prints its fingerprint)")
    ap.add_argument("--state-dir", help="directory for the TLS certificate (only used with --tls)")
    ap.add_argument("--no-auth", action="store_true", help="do not require Cf-Access-Jwt-Assertion")
    ap.add_argument("--enrol-delay-s", type=float, default=10.0,
                    help="seconds after an enrol command is created until the host appears enrolled (default 10)")
    ap.add_argument("--no-enrol-sim", action="store_true", help="pending hosts never enrol on their own")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    host, _, port_s = args.listen.rpartition(":")
    srv = start(host=host or "127.0.0.1", port=int(port_s or 0), tls=args.tls, state_dir=args.state_dir,
                auth=not args.no_auth, enrol_delay_s=None if args.no_enrol_sim else args.enrol_delay_s)
    fc.run_forever(srv, lambda: f"mock_admin listening on {srv.base_url}{BASE}/ "
                                f"(auth {'off' if args.no_auth else 'on: send any Cf-Access-Jwt-Assertion'}; "
                                f"CORS for {CORS_ORIGIN})" + (f"\ntls fingerprint (sha256): {srv.fingerprint}" if srv.fingerprint else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
