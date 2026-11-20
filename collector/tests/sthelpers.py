"""Test plumbing for the M6 speedtest analytics: an app with speedtests enabled, result/evidence builders in the
shapes of the c0 fixtures and the c1 fakes' scenarios (test/fixtures/{speedtest,evidence}, test/fakes)."""
from __future__ import annotations

import copy
import json
import sqlite3
import time
from typing import Any

from colhelpers import ROOT, Env, Resp, https, iso
from exp_common import ids
from exp_common import speedtest as st_helpers

from exp_collector.app import CollectorApp

FIX = ROOT / "test" / "fixtures"
SITE = "hall-b"
BOX = "spd-core"
RUNNER = "run-core"
BASE = "/api/v1/speedtests"


def fixture(rel: str) -> dict[str, Any]:
    return json.loads((FIX / rel).read_text("utf-8"))


# ---------------------------------------------------------------------------------------------- results
def result(*, down: float = 20.0, up: float = 8.0, loaded: float = 120.0, i_down: float | None = 8.0,
           i_up: float | None = 3.0, i_loaded: float = 200.0, cv: float = 0.2, ended_ago_s: float = 30.0,
           duration_s: float = 16.0, ip: str = "10.60.14.77", zone: str = "hallb-row12", zone_source: str = "subnet",
           flags: list[str] | None = None, os_family: str = "iOS", site: str = SITE, server_id: str = BOX,
           comment: str | None = None, now: float | None = None) -> dict[str, Any]:
    """A fresh valid ``exp.speedtest/1`` (degraded by default: score well under 80). ``i_down=None`` drops the
    internet leg's numbers (status unavailable)."""
    d = fixture("speedtest/result.ok.json")
    now = time.time() if now is None else now
    end = now - ended_ago_s
    d["id"] = st_helpers.new_speedtest_id()
    d["site"], d["zone"], d["zone_source"] = site, zone, zone_source
    d["started"], d["ended"] = iso(end - duration_s), iso(end)
    d["observed"]["server_id"] = server_id
    d["observed"]["received_at"] = iso(now)
    d["client"]["ip"] = ip
    d["client"]["ua"]["os_family"] = os_family
    loc = d["legs"]["local"]
    loc.update(down_mbps=down, up_mbps=up, loaded_down_ms=loaded, loaded_up_ms=loaded, cv=cv, failures=0)
    net = d["legs"]["internet"]
    if i_down is None:
        d["legs"]["internet"] = {"status": "unavailable"}
    else:
        net.update(down_mbps=i_down, up_mbps=i_up, loaded_down_ms=i_loaded, loaded_up_ms=i_loaded, cv=cv, failures=0)
    d["flags"] = list(flags or [])
    d["score"] = st_helpers.compute_score(d["legs"]) or None
    if comment is not None:
        d["comment"] = comment
    return d


def healthy_result(**kw: Any) -> dict[str, Any]:
    kw.setdefault("down", 400.0)
    kw.setdefault("up", 300.0)
    kw.setdefault("loaded", 25.0)
    kw.setdefault("i_down", 300.0)
    kw.setdefault("i_up", 200.0)
    kw.setdefault("i_loaded", 25.0)
    kw.setdefault("cv", 0.02)
    return result(**kw)


# --------------------------------------------------------------------------------------------- evidence
def evidence(kind: str, test: dict[str, Any], variant: str = "ok", *, status: str | None = None,
             **data_mods: Any) -> dict[str, Any]:
    """The c0 fixture of ``kind`` re-addressed to ``test``; ``data_mods`` replace top-level ``data`` keys."""
    name = {"identity": "identity.mist", "security": "security.policy-block"}.get(kind, f"{kind}.{variant}")
    d = fixture(f"evidence/{name}.json")
    d["test_id"] = test["id"]
    end = iso_to_s(test["ended"])
    d["collected_at"] = iso(end + 20)
    d["window"] = {"from": iso(iso_to_s(test["started"]) - 300), "to": iso(end + 120)}
    for k, v in data_mods.items():
        d["data"][k] = v
    if status:
        d["status"] = status
    return d


def iso_to_s(ts: str) -> float:
    from exp_common.schema import iso_to_ms
    return iso_to_ms(ts) / 1000.0


def wifi(test: dict[str, Any], *, rssi: float = -61, snr: float = 34, util: int = 81, clients: int = 74,
         band: str = "5", width: int = 80, proto: str = "ax", power_saving: bool = False, tx_rate: float = 433.3,
         roams: list[dict[str, Any]] | None = None, auth_failures: int = 0, events: list[dict[str, Any]] | None = None,
         ap_name: str = "hallb-ap-12") -> dict[str, Any]:
    d = evidence("wifi", test)
    c, ap = d["data"]["client"], d["data"]["ap"]
    c.update(rssi=rssi, snr=snr, band=band, proto=proto, power_saving=power_saving, tx_rate_mbps=tx_rate)
    ap["ap_name"] = ap_name
    ap["num_clients"] = clients
    ap["radio"].update(util_all=util, bandwidth_mhz=width, band=band, num_clients=clients)
    mid = iso_to_s(test["ended"])
    d["data"]["roams"] = roams if roams is not None else []
    d["data"]["roam_count"] = len(d["data"]["roams"])
    d["data"]["events"] = events if events is not None else []
    d["data"]["auth_failures"] = auth_failures
    del mid
    return d


# ------------------------------------------------------------------------------------------------- app
class StEnv:
    def __init__(self, env: Env, app: CollectorApp) -> None:
        self.env, self.app = env, app
        self.port = app.address[1]
        self.tokens = env.st_tokens

    # raw
    def req(self, method: str, path: str, token: str | None, body: Any = None, headers: dict[str, str] | None = None,
            raw: bytes | None = None) -> Resp:
        h = dict(headers or {})
        if token:
            h["Authorization"] = f"Bearer {token}"
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        return https(self.port, method, BASE + path, body=data, headers=h)

    # box
    def ingest(self, doc: dict[str, Any], token: str | None = None) -> Resp:
        return self.req("POST", "", token or self.tokens["exps"], doc)

    def status(self, test_id: str, token: str | None = None) -> Resp:
        return self.req("GET", f"/{test_id}/status", token or self.tokens["exps"])

    def comment(self, test_id: str, text: str, token: str | None = None) -> Resp:
        return self.req("POST", f"/{test_id}/comment", token or self.tokens["exps"], {"comment": text})

    # runner
    def put_ev(self, doc: dict[str, Any], test_id: str | None = None, token: str | None = None) -> Resp:
        return self.req("POST", f"/{test_id or doc['test_id']}/evidence", token or self.tokens["expr"], doc)

    def complete(self, test_id: str, kinds: list[str] | None = None, status: str = "ok") -> Resp:
        return self.req("POST", f"/{test_id}/evidence/complete", self.tokens["expr"],
                        {"kinds": kinds or [], "status": status})

    def feed(self, query: str = "") -> Resp:
        return self.req("GET", "/feed" + query, self.tokens["expr"])

    # dashboard
    def get(self, path: str, user: str | None = None) -> Resp:
        h = {"X-Exp-User": user} if user else {}
        return self.req("GET", path, self.tokens["expd"], headers=h)

    def purge(self, by: str, value: str, dry_run: bool = False, user: str | None = "ada") -> Resp:
        h = {"X-Exp-User": user} if user else {}
        return self.req("POST", "/purge", self.tokens["expd"], {"by": by, "value": value, "dry_run": dry_run}, h)

    # flow helpers
    def run(self, doc: dict[str, Any], evs: list[dict[str, Any]] | None = None, *, complete: bool = True
            ) -> dict[str, Any]:
        """Ingest ``doc``, post ``evs`` and (by default) complete; returns the final ``GET speedtests/{id}`` body."""
        r = self.ingest(doc)
        assert r.status in (200, 201), r.body
        for e in evs or []:
            rr = self.put_ev(e)
            assert rr.status == 200, rr.body
        if complete:
            rr = self.complete(doc["id"], sorted({e["kind"] for e in evs or []}))
            assert rr.status == 200, rr.body
        out = self.get(f"/{doc['id']}")
        assert out.status == 200, out.body
        return out.json()

    def db(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.app.paths.db_path)
        c.row_factory = sqlite3.Row
        return c

    def db_dump(self) -> str:
        """Every text value of the speedtest tables plus the raw file bytes (identifier leak checks)."""
        c = self.db()
        parts = []
        for t in ("speedtests", "evidence", "diagnoses", "speedtest_audit"):
            for row in c.execute(f"SELECT * FROM {t}"):  # noqa: S608
                parts.append(json.dumps([str(v) for v in tuple(row)]))
        c.close()
        return "\n".join(parts)


def make_stenv(env: Env, *, speedtests: dict[str, Any] | None = None, device_secret: bool = True,
               **app_kw: Any) -> StEnv:
    cfg = {"enabled": True, "speedtests": [BOX], "runners": [RUNNER], "retention_days": 30,
           "scrub_after_diagnosis": False, "targets": {"down_mbps": 25, "up_mbps": 10}, "max_evidence_kib": 256,
           "stream_replay_s": 300}
    cfg.update(speedtests or {})
    env.cfg_doc["speedtests"] = cfg
    toks = {"exps": ids.new_token("exps"), "expr": ids.new_token("expr"), "expd": env.dash_token}
    env.st_tokens = toks
    (env.creds / "speedtest_tokens.json").write_text(json.dumps({BOX: ids.token_hash(toks["exps"])}))
    (env.creds / "runner_tokens.json").write_text(json.dumps({RUNNER: ids.token_hash(toks["expr"])}))
    env.device_secret = ids.new_token("expk")
    if device_secret:
        (env.creds / "device_key_secret").write_text(env.device_secret)
    app = env.start(**app_kw)
    return StEnv(env, app)


def clone(d: Any) -> Any:
    return copy.deepcopy(d)


def device_key(env: Env, mac: str) -> str:
    return st_helpers.device_key(env.device_secret, mac)


def parse_sse(buf: bytes) -> list[dict[str, Any]]:
    out = []
    for block in buf.decode().split("\n\n"):
        if not block.strip() or block.startswith(":") or block.startswith("retry:"):
            continue
        ev: dict[str, Any] = {}
        for line in block.split("\n"):
            k, _, v = line.partition(": ")
            ev[k] = v
        if "data" in ev:
            ev["json"] = json.loads(ev["data"])
        out.append(ev)
    return out


