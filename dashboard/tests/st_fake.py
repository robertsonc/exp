"""The `speedtests` routes of the collector API on top of the shared fake collector (test/fakes/fake_collector.py).

The dashboard tests run against this stand-in (the real collector's tests cover its own behaviour): same paths,
parameters and response shapes as `shared/openapi/collector.yaml`, `identifiers=true` needs `X-Exp-User` (403
otherwise), the non-admin view runs the evidence through the collector's own `privacy.redact_evidence`, and every
call is recorded so tests can assert what the dashboard asked for. Data is built from the shared fixtures
(`test/fixtures/{speedtest,evidence}`), re-addressed to deterministic tests relative to "now".
"""
from __future__ import annotations

import base64
import copy
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for _p in (ROOT / "collector", ROOT / "shared" / "python", ROOT / "test" / "fakes"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import fake_collector  # noqa: E402
from exp_collector.speedtest import privacy  # noqa: E402

FIX = ROOT / "test" / "fixtures"
XSS = "<img src=x onerror=alert(1)>"
ZONES = ("hallb-row12", "hallb-row3", "lobby")
APS = ("hallb-ap-12", "hallb-ap-3", "lobby-ap-1", "hallb-ap-7")
CAUSES = ("wifi_signal", "wifi_congestion", "wan_saturation", None, "dns")
ALPHA = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

DEVICE_KEY = "231b3838d0007bf24d5b048d8a17a19495b0fb11b94a792fa99b1deb58b9e082"
RAW_MAC = "f0:18:98:aa:bb:01"
RAW_IP = "10.60.14.77"
RAW_HOST = "alices-iphone"
RAW_USER = "guest-portal-7731"


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t * 1000) % 1000:03d}Z"


def fixture(rel: str) -> dict[str, Any]:
    return json.loads((FIX / rel).read_text("utf-8"))


def st_id(n: int) -> str:
    """A valid st_ id (st_ + 26 Crockford chars) that is stable per index."""
    tail = "".join(ALPHA[(n >> (5 * i)) & 31] for i in range(8))
    return "st_" + "0" * 18 + tail


class StData:
    """Deterministic speedtests of one fake collector."""

    def __init__(self, site: str, probe: str, *, now: float | None = None, count: int = 36, leaky: bool = False,
                 base: int = 0) -> None:
        self.site, self.probe, self.base = site, probe, base
        self.now = time.time() if now is None else now
        self.leaky = leaky                       # a misbehaving collector that ignores identifiers=false
        self.calls: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []
        self.enabled = True
        self.docs: dict[str, dict[str, Any]] = {}
        self.rows: list[dict[str, Any]] = []
        for i in range(count):
            self._add(i)
        self._add_hostile(count)

    # ------------------------------------------------------------------------------------- building
    def _add(self, i: int) -> None:
        zone, ap = ZONES[i % 3], APS[i % 4]
        cause = CAUSES[i % 5]
        ended = self.now - 120 - i * 9 * 60            # one test every 9 minutes into the past
        score = [92, 81, 55, 38, 71][i % 5]
        self._make(i, zone=zone, ap=ap, cause=cause, ended=ended, score=score,
                   down=[310.0, 120.0, 18.0, 9.0, 60.0][i % 5], up=[200.0, 80.0, 8.0, 3.0, 30.0][i % 5],
                   ssid="Summit-Guest" if i % 4 else "Summit-Staff", band=["5", "6", "24"][i % 3],
                   os_family=["iOS", "Android", "Windows", "macOS"][i % 4], comment=None)

    def _add_hostile(self, i: int) -> None:
        self._make(i, zone=ZONES[0], ap=XSS, cause="wifi_signal", ended=self.now - 60, score=33, down=5.0, up=2.0,
                   ssid=XSS, band="5", os_family="iOS", comment="slow " + XSS, hostname=XSS)

    def _make(self, i: int, *, zone: str, ap: str, cause: str | None, ended: float, score: int, down: float,
              up: float, ssid: str, band: str, os_family: str, comment: str | None,
              hostname: str = RAW_HOST) -> None:
        tid = st_id(self.base + i + 1)
        t = fixture("speedtest/result.ok.json")
        t["id"], t["site"], t["zone"] = tid, self.site, zone
        t["started"], t["ended"] = iso(ended - 16), iso(ended)
        t["client"]["ip"] = RAW_IP
        t["client"]["ua"]["os_family"] = os_family
        t["legs"]["local"].update(down_mbps=down, up_mbps=up, loaded_down_ms=40.0 + (100 - score))
        t["legs"]["internet"].update(down_mbps=down * 0.6, up_mbps=up * 0.6)
        t["score"] = {"total": score, "speed": min(100, score + 5), "responsiveness": score, "stability": 60}
        if comment:
            t["comment"] = comment
        diag = {"stage": "final", "updated": iso(ended + 130), "cause": [], "user_text": "Your Wi-Fi signal was weak.",
                "noc_text": f"AP {ap} RSSI -78 dBm, 5 GHz util 81%."}
        if cause:
            diag["cause"] = [{"id": cause, "confidence": 0.8,
                              "cites": [{"kind": "wifi", "ref": "client.rssi"}, {"kind": "baseline", "ref": "lines"}]}]
        ev: list[dict[str, Any]] = []
        for name in ("wifi.ok", "wired.ok", "flows.ok", "wan.ok", "security.policy-block", "baseline.ok",
                     "dns.ok", "identity.mist"):
            d = fixture(f"evidence/{name}.json")
            d["test_id"] = tid
            d["window"] = {"from": iso(ended - 316), "to": iso(ended + 120)}
            d["collected_at"] = iso(ended + 20)
            ev.append(d)
        for d in ev:
            data = d["data"]
            if d["kind"] == "wifi":
                data["ap"]["ap_name"], data["client"]["ssid"], data["client"]["band"] = ap, ssid, band
                data["client"]["mac"] = RAW_MAC
                for r in data["roams"]:
                    r["timestamp"] = int(ended - 40)
                for e in data["events"]:
                    e["timestamp"] = int(ended - 40)
            elif d["kind"] == "flows":
                for f in data["flows"]:
                    f["start_s"], f["end_s"] = int(ended - 16), int(ended)
            elif d["kind"] == "wan":
                a = data["appliances"][0]
                a["timeseries"]["rows"] = [[int(ended - 90 + 60 * k), 180e6, 59e6] for k in range(4)]
                for al in a["alarms"]:
                    al["time_occurred_ms"] = int((ended - 120) * 1000)
            elif d["kind"] == "security":
                for k, e in enumerate(data["events"]):
                    e["ts"] = iso(ended - 14 + k)
            elif d["kind"] == "baseline":
                d["data"]["probe"], d["data"]["site"], d["data"]["at"] = self.probe, self.site, iso(ended)
            elif d["kind"] == "identity":
                data.update(zone=zone, ap_name=ap, ssid=ssid, hostname=hostname)
        self.docs[tid] = {"test": t, "diagnosis": diag, "evidence": ev, "device_key": DEVICE_KEY,
                          "evidence_state": {"state": "final", "kinds_done": sorted({e["kind"] for e in ev}),
                                             "final_at": iso(ended + 130)}}
        self.rows.append({
            "id": tid, "site": self.site, "zone": zone, "zone_source": "mist", "started": t["started"],
            "ended": t["ended"], "score": score, "local_down_mbps": down, "local_up_mbps": up,
            "internet_down_mbps": down * 0.6, "internet_up_mbps": up * 0.6,
            "loaded_ms": 40.0 + (100 - score), "flags": [], "cause": cause, "ap_name": ap, "ssid": ssid,
            "band": band, "os_family": os_family, "device_key": DEVICE_KEY, "evidence_state": "final",
            "has_comment": bool(comment),
            "_raw": {"client_ip": RAW_IP, "mac": RAW_MAC, "hostname": hostname, "username": RAW_USER}})
        self.rows.sort(key=lambda r: (r["ended"], r["id"]), reverse=True)

    # ------------------------------------------------------------------------------------- queries
    def public(self, r: dict[str, Any], ident: bool) -> dict[str, Any]:
        out = {k: v for k, v in r.items() if k != "_raw"}
        if ident or self.leaky:
            out.update(r["_raw"])
        return out

    def filtered(self, q: dict[str, str], ident: bool) -> list[dict[str, Any]]:
        out = []
        for r in self.rows:
            if q.get("site") and r["site"] != q["site"]:
                continue
            if any(q.get(k) and r[k] != q[k] for k in ("zone", "ssid", "cause")):
                continue
            if q.get("ap") and r["ap_name"] != q["ap"]:
                continue
            if q.get("from") and r["ended"] < q["from"]:
                continue
            if q.get("to") and r["ended"] >= q["to"]:
                continue
            if "min_score" in q and (r["score"] is None or r["score"] < int(q["min_score"])):
                continue
            if "max_score" in q and (r["score"] is None or r["score"] > int(q["max_score"])):
                continue
            if q.get("q"):
                hay = [r["id"], r["zone"], r["ap_name"], r["ssid"], self.docs[r["id"]]["test"].get("comment", "")]
                if ident:
                    hay += list(r["_raw"].values())
                if not any(q["q"].lower() in str(h).lower() for h in hay):
                    continue
            out.append(r)
        return out

    def aggregate(self, q: dict[str, str]) -> dict[str, Any]:
        gb, metric, leg = q["group_by"], q["metric"], q.get("leg", "local")
        groups: dict[str, list[dict[str, Any]]] = {}
        for r in self.filtered(q, False):
            key = {"zone": r["zone"], "ap": r["ap_name"], "ssid": r["ssid"], "band": r["band"],
                   "os_family": r["os_family"], "cause": r["cause"] or "unknown",
                   "hour": r["ended"][:13] + ":00:00Z"}[gb]
            groups.setdefault(str(key), []).append(r)
        items = []
        for k, rows in groups.items():
            col = {"down_p50": f"{leg}_down_mbps", "up_p50": f"{leg}_up_mbps", "loaded_p50": "loaded_ms",
                   "score_p50": "score"}.get(metric)
            vals = [r[col] for r in rows if col and r[col] is not None]
            val = float(len(rows)) if metric == "count" else (statistics.median(vals) if vals else 0.0)
            items.append({"key": k[:128], "value": round(val, 3), "count": len(rows)})
        return {"group_by": gb, "metric": metric, "leg": leg, "from": q.get("from", iso(0)),
                "to": q.get("to", iso(self.now + 3600)), "items": items}

    def purge(self, by: str, value: str, dry: bool, user: str) -> dict[str, Any]:
        def hit(r: dict[str, Any]) -> bool:
            raw = r["_raw"]
            return {"device_key": r["device_key"] == value, "mac": raw["mac"].lower() == value.lower(),
                    "ip": raw["client_ip"] == value, "test": r["id"] == value}[by]

        victims = [r for r in self.rows if hit(r)]
        if not dry:
            gone = {r["id"] for r in victims}
            self.rows = [r for r in self.rows if r["id"] not in gone]
            for g in gone:
                self.docs.pop(g, None)
        self.audit.append({"actor": user, "by": by, "dry_run": dry, "matched": len(victims)})
        return {"dry_run": dry, "matched_tests": len(victims),
                "deleted": {"tests": 0 if dry else len(victims), "evidence": 0 if dry else 8 * len(victims),
                            "diagnoses": 0 if dry else len(victims)},
                "device_key_matched": by == "device_key", "audited_by": f"{user}"}

    def detail(self, tid: str, ident: bool) -> dict[str, Any] | None:
        d = self.docs.get(tid)
        if d is None:
            return None
        out = copy.deepcopy(d)
        if ident or self.leaky:
            return out
        out["test"]["client"].pop("ip", None)
        raw = next(r["_raw"] for r in self.rows if r["id"] == tid)
        pids = privacy.collect(raw["client_ip"], raw["mac"], raw["hostname"], raw["username"], out["evidence"])
        out["evidence"] = [privacy.redact_evidence(e, pids) for e in out["evidence"]]
        return out


class StHandler(fake_collector.Handler):
    """Adds `speedtests` routes in front of the stock routes."""

    def _api(self, method: str, rest: str, query: dict[str, list[str]]) -> None:
        segs = rest.strip("/").split("/")
        if segs[0] != "speedtests":
            return super()._api(method, rest, query)
        app = self.app
        st: StData | None = getattr(app, "st", None)
        self._forced("api")
        self._auth(app.dashboard_tokens)
        user = self.header("X-Exp-User")
        q = {k: v[0] for k, v in query.items() if v}
        rec = {"method": method, "path": rest, "query": dict(q), "user": user}
        if st is None or not st.enabled:
            return self.send_err(404, "not_found", "speedtests are not enabled")
        st.calls.append(rec)
        ident = q.get("identifiers") == "true"
        if ident and not user:
            return self.send_err(403, "forbidden", "X-Exp-User is required to read raw identifiers")
        if segs == ["speedtests"] and method == "GET":
            rows = st.filtered(q, ident)
            limit = int(q.get("limit", 100))
            off = 0
            if q.get("cursor"):
                off = int(base64.urlsafe_b64decode(q["cursor"] + "==").decode().split(":")[1])
            page = rows[off:off + limit]
            nxt = base64.urlsafe_b64encode(f"o:{off + limit}".encode()).decode().rstrip("=") \
                if off + limit < len(rows) else None
            return self.send_json(200, {"items": [st.public(r, ident) for r in page], "next_cursor": nxt})
        if segs == ["speedtests", "aggregate"] and method == "GET":
            return self.send_json(200, st.aggregate(q))
        if segs == ["speedtests", "purge"] and method == "POST":
            if not user:
                return self.send_err(403, "forbidden", "X-Exp-User is required")
            body = json.loads(self.read_body(4096) or b"{}")
            return self.send_json(200, st.purge(body["by"], body["value"], bool(body.get("dry_run")), user))
        if len(segs) == 2 and method == "GET":
            d = st.detail(segs[1], ident)
            if d is None:
                return self.send_err(404, "not_found", "no such test")
            return self.send_json(200, d)
        return self.send_err(404, "not_found", "no such endpoint")


def install(monkeypatch: Any) -> None:
    """Make fake_collector.start() serve the speedtest routes (call before building a World)."""
    monkeypatch.setattr(fake_collector, "Handler", StHandler)


def attach(world: Any, **kw: Any) -> dict[str, StData]:
    """One StData per fake collector (its site and probe). Returns {collector_id: StData}."""
    out = {}
    for cid, f in world.fakes.items():
        ch = cid[-1]
        out[cid] = StData(f"hall-{ch}", f"probe-{ch}1", base=(ord(ch) - 96) * 1000, **kw)
        f.app.st = out[cid]
    return out

