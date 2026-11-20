"""The speedtest service: result ingest, evidence, diagnosis, query, purge, retention (WP-11).

HTTP handlers live in ``api.py``; this module owns the behaviour and raises ``HttpError`` for contract errors.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from exp_common import config as exp_config
from exp_common import speedtest as st_helpers
from exp_common.schema import iso_to_ms

from ..config import CollectorConfig
from ..server import HttpError
from ..store import Store
from ..vmwriter import VMWriter, point_to_line
from . import diagnosis as dx
from . import privacy
from .metrics import StMetrics
from .repo import KINDS, Repo
from .settings import SpeedtestSettings
from .stream import StHub

log = logging.getLogger(__name__)
audit = logging.getLogger("exp-collector.audit")

MAX_FUTURE_S = 300
MAX_AGGREGATE_RANGE_S = 366 * 86400
JOB_INTERVAL_S = 15.0
RETENTION_INTERVAL_S = 3600.0
AUDIT_KEEP_DAYS = 400

ProbeState = Callable[[str, "int | None"], "dict[str, Any] | None"]


def iso(ms: float) -> str:
    return (datetime.datetime.fromtimestamp(ms / 1000.0, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _loaded(leg: Mapping[str, Any] | None) -> float | None:
    vals = [x for x in (_num((leg or {}).get("loaded_down_ms")), _num((leg or {}).get("loaded_up_ms")))
            if x is not None]
    return max(vals) if vals else None


def subject_hash(value: str) -> str:
    """What the audit trail and the logs keep of a purge subject: a short digest, never the identifier itself."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


class SpeedtestService:
    def __init__(self, config: CollectorConfig, store: Store, vm: VMWriter | None, *,
                 clock: Callable[[], float] = time.time, device_key_secret: Callable[[], str | None] = lambda: None,
                 probe_state: ProbeState | None = None) -> None:
        self.cfg = config
        self.settings = SpeedtestSettings.from_config(config.speedtests)
        self.store = store
        self.repo = Repo(store)
        self.vm = vm
        self.clock = clock
        self.device_key_secret = device_key_secret
        self.probe_state = probe_state or (lambda _p, _a: None)
        self.hub = StHub(clock=clock, replay_s=float(self.settings.stream_replay_s))
        self.metrics = StMetrics(self.settings.metric_label_limit)
        self.cond = threading.Condition()
        self._travel = threading.BoundedSemaphore(4)      # concurrent time-travel evaluations (SQLite-heavy)
        self.stats = {"ingested": 0, "duplicates": 0, "evidence": 0, "finalized": 0, "purged": 0}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_retention = 0.0

    # ---------------------------------------------------------------------------------------- guards
    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    def require_enabled(self) -> None:
        if not self.settings.enabled:
            raise HttpError(404, "not_found", "speedtest analytics are not enabled on this collector")

    def now_ms(self) -> int:
        return int(self.clock() * 1000)

    def allowed_speedtest(self, ident: str) -> bool:
        return ident in self.settings.speedtests

    def allowed_runner(self, ident: str) -> bool:
        return ident in self.settings.runners

    # ------------------------------------------------------------------------------------------ views
    @staticmethod
    def evidence_state(row: Mapping[str, Any], kinds: list[str] | None = None) -> dict[str, Any]:
        st = row["state"]
        if st == "final":
            state = "final" if row["evidence_n"] else "unavailable"
        else:
            state = "correlating" if row["evidence_n"] else "pending"
        return {"state": state, "kinds_done": sorted(kinds or []) if kinds is not None else [],
                "final_at": iso(row["final_ms"]) if row["final_ms"] else None}

    def public_row(self, r: Mapping[str, Any], identifiers: bool = False) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": r["id"], "site": r["site"], "zone": r["zone"], "zone_source": r["zone_source"],
            "started": iso(r["started_ms"]), "ended": iso(r["ended_ms"]), "score": r["score"],
            "local_down_mbps": r["local_down"], "local_up_mbps": r["local_up"],
            "internet_down_mbps": r["internet_down"], "internet_up_mbps": r["internet_up"],
            "loaded_ms": r["local_loaded"], "flags": json.loads(r["flags"]), "cause": r["cause"],
            "ap_name": r["ap_name"], "ssid": r["ssid"], "band": r["band"], "os_family": r["os_family"],
            "device_key": r["device_key"], "evidence_state": self.evidence_state(r)["state"],
            "has_comment": bool(r["comment"])}
        if identifiers:
            out.update({"client_ip": r["client_ip"], "mac": r["mac"], "hostname": r["hostname"],
                        "username": r["username"]})
        return out

    def stored_doc(self, r: Mapping[str, Any], identifiers: bool) -> dict[str, Any]:
        """The stored ``exp.speedtest/1`` with the row's current zone/flags/score/comment merged back in."""
        doc = json.loads(r["doc"])
        doc["zone"], doc["zone_source"] = r["zone"], r["zone_source"]
        doc["flags"] = json.loads(r["flags"])
        if r["comment"]:
            doc["comment"] = r["comment"]
        if identifiers and r["client_ip"]:
            doc["client"]["ip"] = r["client_ip"]
        return doc

    # ------------------------------------------------------------------------------------ baseline
    def baseline(self, site: str, zone: str | None, ap: str | None, at_ms: int) -> dict[str, Any] | None:
        """The nearest probe's state at ``at_ms`` from the collector's own records (the ``baseline`` evidence data)."""
        cands = [e for e in self.cfg.probes.values() if e.site == site]
        if not cands:
            return None

        def dist(label: str) -> str:
            lab = label.lower()
            if ap and ap.lower() in lab:
                return "same_ap"
            if zone and zone != "unresolved" and zone.lower() in lab:
                return "same_zone"
            return "same_site"
        order = {"same_ap": 0, "same_zone": 1, "same_site": 2}
        ranked = sorted((order[dist(e.label)], e.probe_id, dist(e.label)) for e in cands)
        live = abs(self.now_ms() - at_ms) <= 90_000
        for _o, pid, d in ranked[:3]:
            if not live and not self._travel.acquire(timeout=2.0):
                log.warning("baseline skipped: too many time-travel evaluations in flight")
                return None
            try:
                state = self.probe_state(pid, None if live else at_ms)
            except Exception:  # noqa: BLE001 - a probe state failure must not fail an ingest
                log.exception("probe state for the baseline failed")
                state = None
            finally:
                if not live:
                    self._travel.release()
            if not state:
                continue
            newest = state.get("newest_s")
            if newest is None or newest > self.settings.thresholds.network_wide_age_s:
                continue
            return self._baseline_doc(pid, site, d, at_ms, state)
        return None

    def _baseline_doc(self, probe: str, site: str, distance: str, at_ms: int, state: Mapping[str, Any]
                      ) -> dict[str, Any]:
        sev = (state.get("verdict") or {}).get("severity")
        keys = ("network", "dhcp", "dns", "internet", "apps", "wifi", "path")
        lines = []
        for ln in state.get("lines") or []:
            if ln.get("key") not in keys:
                continue
            st = ln.get("state") if ln.get("state") in ("ok", "warn", "fail") else "unknown"
            item = {"key": ln["key"], "state": st}
            det = dx.clean(ln.get("detail") or "", 256)
            if det:
                item["detail"] = det
            lines.append(item)
        out: dict[str, Any] = {"probe": probe, "site": site, "distance": distance, "at": iso(at_ms),
                               "severity": sev if sev in ("ok", "warn", "fail") else "unknown", "lines": lines[:8]}
        tp = self._last_metrics(probe, "throughput", at_ms, 30 * 60_000)
        if tp is not None:
            ts, labels, m = tp
            out["throughput"] = {"down_mbps": _num(m.get("down_mbps")), "up_mbps": _num(m.get("up_mbps")),
                                 "latency_idle_ms": _num(m.get("latency_idle_ms")),
                                 "latency_loaded_ms": _num(m.get("latency_loaded_ms")), "ts": iso(ts)}
        wf = self._last_metrics(probe, "wifi_hb", at_ms, 60_000)
        if wf is not None:
            _ts, labels, m = wf
            out["wifi"] = {"ssid": dx.clean(labels.get("ssid", ""), 64), "band": dx.clean(labels.get("band", ""), 16),
                           "rssi_dbm": _num(m.get("rssi_dbm")), "snr_db": _num(m.get("snr_db"))}
        return out

    def _last_metrics(self, probe: str, test: str, at_ms: int, within_ms: int
                      ) -> tuple[int, dict[str, Any], dict[str, Any]] | None:
        try:
            rows = self.store.read_records(probe, at_ms - within_ms, at_ms + 60_000, test=test, limit=1000)
        except Exception:  # noqa: BLE001
            return None
        for ts, _rid, body in reversed(rows):
            try:
                d = json.loads(body)
            except ValueError:
                continue
            m = d.get("metrics")
            if isinstance(m, dict) and d.get("outcome") in ("ok", "degraded"):
                labels = d.get("labels") if isinstance(d.get("labels"), dict) else {}
                return ts, labels, m
        return None

    # ----------------------------------------------------------------------------------- diagnose
    def _baseline_for_doc(self, doc: Mapping[str, Any], zone: str | None, ap: str | None) -> dict[str, Any] | None:
        s_ms, e_ms = iso_to_ms(doc["started"]), iso_to_ms(doc["ended"])
        return self.baseline(doc["site"], zone, ap, (s_ms + e_ms) // 2)

    def _diagnose(self, doc: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]], stage: str,
                  base: Mapping[str, Any] | None) -> dict[str, Any]:
        s_ms, e_ms = iso_to_ms(doc["started"]), iso_to_ms(doc["ended"])
        return dx.diagnose(doc, evidence, base, self.settings.targets, self.settings.thresholds, stage,
                           iso(self.now_ms()), started_s=s_ms / 1000.0, ended_s=e_ms / 1000.0)

    # ------------------------------------------------------------------------------------- ingest
    def ingest(self, identity: str, doc: Any) -> tuple[int, dict[str, Any]]:
        self.require_enabled()
        errs = exp_config.iter_errors(doc, "speedtest.schema.json")
        if errs:
            raise HttpError(400, "invalid_request", "; ".join(str(e) for e in errs[:3])[:500])
        ip = (doc.get("client") or {}).get("ip")
        if not ip:
            raise HttpError(400, "invalid_request", "client.ip is required at ingest")
        if doc["observed"]["server_id"] != identity or doc["site"] != self.cfg.site:
            raise HttpError(403, "identity_mismatch", "observed.server_id and site must match the token's speedtest")
        try:
            started_ms, ended_ms = iso_to_ms(doc["started"]), iso_to_ms(doc["ended"])
        except ValueError:
            raise HttpError(400, "invalid_request", "started/ended are not valid timestamps") from None
        now = self.now_ms()
        if ended_ms < started_ms:
            raise HttpError(400, "invalid_request", "ended is before started")
        if ended_ms > now + MAX_FUTURE_S * 1000:
            raise HttpError(400, "invalid_request", "ended is in the future")
        if ended_ms < now - self.settings.retention_days * 86400_000:
            raise HttpError(400, "invalid_request", "the test is older than the retention window")
        existing = self.repo.get(doc["id"])
        if existing is not None:
            return self._duplicate(existing, identity)
        legs = doc["legs"]
        basis = st_helpers.score_basis(legs)
        failures = int(basis[1].get("failures") or 0) if basis else 0
        score = st_helpers.compute_score(legs, self.settings.targets, failures)
        stored = json.loads(json.dumps(doc))
        stored["score"] = score
        stored["client"].pop("ip", None)
        comment = stored.pop("comment", None)
        ua = (doc["client"].get("ua") or {})
        local, internet = legs.get("local") or {}, legs.get("internet") or {}
        quick = self._diagnose(stored, {}, "quick", self._baseline_for_doc(
            stored, doc["zone"] if doc["zone_source"] == "qr" else None, None))
        row = {
            "id": doc["id"], "site": doc["site"], "speedtest_id": identity, "started_ms": started_ms,
            "ended_ms": ended_ms, "received_ms": now, "zone": doc["zone"], "zone_source": doc["zone_source"],
            "score": score["total"] if score else None,
            "local_down": _num(local.get("down_mbps")), "local_up": _num(local.get("up_mbps")),
            "internet_down": _num(internet.get("down_mbps")), "internet_up": _num(internet.get("up_mbps")),
            "local_loaded": _loaded(local), "internet_loaded": _loaded(internet),
            "flags": json.dumps(sorted(doc.get("flags") or [])), "comment": comment,
            "os_family": ua.get("os_family"), "client_ip": ip,
            "cause": quick["cause"][0]["id"] if quick["cause"] else None,
            "state": "submitted", "doc": json.dumps(stored, separators=(",", ":"), ensure_ascii=False)}
        created = self.repo.insert(row, quick)
        if not created:
            return self._duplicate(self.repo.get(doc["id"]) or row, identity)
        self.stats["ingested"] += 1
        self.hub.publish("speedtest", doc["site"], self.public_row({**row, "seq": 0, "evidence_n": 0,
                                                                     "final_ms": None, "ap_name": None, "ssid": None,
                                                                     "band": None, "device_key": None,
                                                                     "mac": None, "hostname": None,
                                                                     "username": None}))
        self.hub.publish("diagnosis", doc["site"], {"id": doc["id"], "stage": "quick",
                                                    "cause": row["cause"] or "unknown"})
        with self.cond:
            self.cond.notify_all()
        return 201, {"id": doc["id"], "status": "stored", "diagnosis": quick}

    def _duplicate(self, existing: Mapping[str, Any], identity: str) -> tuple[int, dict[str, Any]]:
        if existing["speedtest_id"] != identity:
            raise HttpError(409, "conflict", "a test with this id was stored by another speedtest")
        self.stats["duplicates"] += 1
        return 200, {"id": existing["id"], "status": "duplicate",
                     "diagnosis": self.repo.latest_diagnosis(existing["id"])}

    # --------------------------------------------------------------------------------- user status
    def _own_test(self, identity: str, test_id: str) -> dict[str, Any]:
        self.require_enabled()
        row = self.repo.get(test_id)
        if row is None or row["speedtest_id"] != identity:
            raise HttpError(404, "not_found", "no such test")
        return row

    def status(self, identity: str, test_id: str) -> dict[str, Any]:
        row = self._own_test(identity, test_id)
        ev = {d["kind"]: d for d in self.repo.evidence(test_id)}
        diag = self.repo.latest_diagnosis(test_id)
        est = self.evidence_state(row, list(ev))
        final = row["state"] == "final"
        attention = {cite["kind"] for c in (diag or {}).get("cause", [])[:1] if c["id"] != "none"
                     for cite in c["cites"]}
        checks = []
        for kind in KINDS:
            d = ev.get(kind)
            if d is None:
                checks.append({"kind": kind, "state": "unavailable" if final else "checking"})
                continue
            if d["status"] in ("unavailable", "error"):
                state = "unavailable"
            elif d["status"] == "partial" or kind in attention:
                state = "attention"
            else:
                state = "ok"
            check = {"kind": kind, "state": state}
            if state == "attention" and diag and diag["cause"]:
                check["text"] = dx.USER_TEXT[diag["cause"][0]["id"]][:160]
            checks.append(check)
        details = None
        wifi = (ev.get("wifi") or {}).get("data") or {}
        ident = (ev.get("identity") or {}).get("data") or {}
        ap_name = row["ap_name"] or (wifi.get("ap") or {}).get("ap_name")
        band = row["band"] or (wifi.get("client") or {}).get("band")
        chan = (wifi.get("client") or {}).get("channel")
        if ap_name or band or ident.get("band"):
            details = {k: v for k, v in (("ap_name", dx.clean(ap_name, 128) if ap_name else None),
                                         ("band", dx.clean(band, 16) if band else None),
                                         ("channel", chan if isinstance(chan, int) else None)) if v is not None}
        return {"id": row["id"], "state": "final" if final else ("correlating" if row["evidence_n"] else "submitted"),
                "zone": row["zone"], "zone_name": None if row["zone"] == "unresolved" else row["zone"],
                "zone_source": row["zone_source"],
                "diagnosis": None if not diag else {
                    "stage": diag["stage"], "updated": diag["updated"],
                    "cause": [{"id": c["id"], "confidence": c["confidence"]} for c in diag["cause"]],
                    "user_text": diag["user_text"]},
                "evidence": est, "checks": checks, "network_details": details, "comment": row["comment"]}

    def comment(self, identity: str, test_id: str, text: str) -> None:
        self._own_test(identity, test_id)
        if not self.repo.set_comment(test_id, text):
            raise HttpError(404, "not_found", "no such test")

    # ------------------------------------------------------------------------------------- runner
    def feed(self, site: str, after_seq: int, limit: int, wait_s: int) -> tuple[list[dict[str, Any]], int]:
        self.require_enabled()
        deadline = time.monotonic() + wait_s
        while True:
            rows = self.repo.feed(site, after_seq, limit)
            if rows or wait_s <= 0 or time.monotonic() >= deadline or self._stop.is_set():
                break
            with self.cond:
                self.cond.wait(min(1.0, max(0.05, deadline - time.monotonic())))
        items = []
        for r in rows:
            s_ms, e_ms = r["started_ms"], r["ended_ms"]
            item: dict[str, Any] = {
                "id": r["id"], "site": r["site"], "started": iso(s_ms), "ended": iso(e_ms),
                "client_ip": r["client_ip"], "zone_hint": r["zone"] if r["zone_source"] == "qr" else None,
                "zone": r["zone"], "zone_source": r["zone_source"],
                "window": {"from": iso(s_ms - self.settings.window_before_s * 1000),
                           "to": iso(e_ms + self.settings.window_after_s * 1000)}}
            item["observed_server"] = r["speedtest_id"]
            items.append(item)
        return items, (rows[-1]["seq"] if rows else after_seq)

    def _site_test(self, site: str, test_id: str) -> dict[str, Any]:
        self.require_enabled()
        row = self.repo.get(test_id)
        if row is None:
            raise HttpError(404, "not_found", "no such test")
        if row["site"] != site:
            raise HttpError(403, "identity_mismatch", "the test belongs to another site")
        return row

    def put_evidence(self, site: str, test_id: str, doc: Any) -> dict[str, Any]:
        self.require_enabled()
        errs = exp_config.iter_errors(doc, "evidence.schema.json")
        if errs:
            raise HttpError(400, "invalid_request", "; ".join(str(e) for e in errs[:3])[:500])
        if doc["test_id"] != test_id:
            raise HttpError(400, "id_mismatch", "test_id does not equal the path id")
        row = self._site_test(site, test_id)
        try:
            collected_ms = iso_to_ms(doc["collected_at"])
        except ValueError:
            raise HttpError(400, "invalid_request", "collected_at is not a valid timestamp") from None
        res = self.repo.put_evidence(test_id, doc, collected_ms=collected_ms,
                                     max_total=self.settings.max_evidence_bytes, derive=self._derive)
        code = res["code"]
        if code == "missing":
            raise HttpError(404, "not_found", "no such test")
        if code == "final":
            raise HttpError(409, "evidence_final", "evidence is final")
        if code == "too_large":
            raise HttpError(413, "evidence_too_large",
                            f"evidence for this test would exceed {self.settings.max_evidence_bytes // 1024} KiB")
        if code == "ok" and not res.get("dedup"):
            self.stats["evidence"] += 1
            self.hub.publish("evidence", row["site"], {"id": test_id, "kind": doc["kind"]})
        return {"test_id": test_id, "kind": doc["kind"], "stored_bytes": res["stored_bytes"],
                "total_bytes": res["total_bytes"]}

    def _derive(self, t: Mapping[str, Any], docs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
        """Row columns derived from the evidence so far (zone, AP, SSID, band, device key, raw identifiers, flags)."""
        out: dict[str, Any] = {}
        data = {k: (d.get("data") or {}) for k, d in docs.items() if d.get("status") in ("ok", "partial")}
        ident, wifi = data.get("identity", {}), data.get("wifi", {})
        client, ap = wifi.get("client") or {}, wifi.get("ap") or {}
        orig = json.loads(t["doc"])
        flags = set(orig.get("flags") or [])
        if ident:
            if ident.get("nat_suspected"):
                out["zone"], out["zone_source"] = "unresolved", "unresolved"
                flags.add("nat_suspected")
            elif ident.get("zone"):
                out["zone"], out["zone_source"] = ident["zone"], ident.get("zone_source") or "unresolved"
                if (orig.get("zone_source") == "qr" and ident["zone"] != orig.get("zone")
                        and ident["zone"] != "unresolved"):
                    flags.add("zone_hint_conflict")
        out["flags"] = json.dumps(sorted(flags))
        for col, val in (("ap_name", ident.get("ap_name") or ap.get("ap_name")),
                         ("ssid", ident.get("ssid") or client.get("ssid")),
                         ("band", ident.get("band") or client.get("band")),
                         ("os_family", orig.get("client", {}).get("ua", {}).get("os_family") or ident.get("os_family")),
                         ("device_key", ident.get("device_key")),
                         ("mac", ident.get("mac") or client.get("mac")),
                         ("hostname", ident.get("hostname")), ("username", ident.get("username"))):
            if val:
                out[col] = dx.clean(val, 128)
        return out

    def complete(self, site: str, test_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        row = self._site_test(site, test_id)
        res = self._finalize(row, str(body["status"]))
        if res["code"] == "already_final":
            raise HttpError(409, "already_final", "the evidence is already final")
        if res["code"] == "missing":
            raise HttpError(404, "not_found", "no such test")
        return {"id": test_id, "diagnosis": res["diagnosis"]}

    def _finalize(self, row: Mapping[str, Any], status: str) -> dict[str, Any]:
        stored = json.loads(row["doc"])
        scrub = self._scrub_fn() if self.settings.scrub_after_diagnosis else None
        # the probe baseline is read here, not inside the writer-thread job (probe state can take a while)
        base = self._baseline_for_doc(stored, row["zone"] if row["zone"] != "unresolved" else None, row["ap_name"])

        def diag(test: dict[str, Any], docs: dict[str, dict[str, Any]]) -> dict[str, Any]:
            t = json.loads(test["doc"])
            t["zone"], t["zone_source"] = test["zone"], test["zone_source"]
            t["flags"] = json.loads(test["flags"])
            return self._diagnose(t, docs, "final", base)
        res = self.repo.finalize(row["id"], now_ms=self.now_ms(), status=status, diagnose=diag, scrub=scrub)
        if res["code"] != "ok":
            return res
        self.stats["finalized"] += 1
        fresh = self.repo.get(row["id"])
        if fresh is not None:
            if res["metrics_due"]:
                self._emit_metrics(fresh, stored, res["diagnosis"])
            top = res["diagnosis"]["cause"][0]["id"] if res["diagnosis"]["cause"] else "unknown"
            self.hub.publish("diagnosis", row["site"], {"id": row["id"], "stage": "final", "cause": top})
        return res

    def _emit_metrics(self, row: Mapping[str, Any], stored: Mapping[str, Any], diag: Mapping[str, Any]) -> None:
        if self.vm is None:
            return
        series = self.metrics.observe({
            "site": row["site"], "zone": row["zone"], "ssid": row["ssid"], "band": row["band"], "ap": row["ap_name"],
            "os_family": row["os_family"], "legs": stored.get("legs"), "score": stored.get("score"),
            "cause": diag["cause"][0]["id"] if diag["cause"] else "unknown"})
        ts = self.now_ms()
        try:
            self.vm.enqueue_lines([point_to_line(n, lab, v, ts) for n, lab, v in series])
        except Exception:  # noqa: BLE001 - metrics must never fail the request
            log.exception("could not queue speedtest metrics")

    def _scrub_fn(self) -> Callable[[dict[str, Any], list[dict[str, Any]]], list[dict[str, Any]]]:
        def scrub(test: dict[str, Any], docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
            ids = privacy.collect(test["client_ip"], test["mac"], test["hostname"], test["username"], docs)
            return [privacy.redact_evidence(d, ids) for d in docs]
        return scrub

    # ----------------------------------------------------------------------------------- dashboard
    def detail(self, test_id: str, identifiers: bool) -> dict[str, Any]:
        self.require_enabled()
        row = self.repo.get(test_id)
        if row is None:
            raise HttpError(404, "not_found", "no such test")
        evidence = self.repo.evidence(test_id)
        if not identifiers:
            ids = privacy.collect(row["client_ip"], row["mac"], row["hostname"], row["username"], evidence)
            evidence = [privacy.redact_evidence(d, ids) for d in evidence]
        return {"test": self.stored_doc(row, identifiers), "diagnosis": self.repo.latest_diagnosis(test_id),
                "evidence": evidence, "evidence_state": self.evidence_state(row, [d["kind"] for d in evidence]),
                "device_key": row["device_key"]}

    def baseline_for_runner(self, site: str, zone: str | None, ap: str | None, at_ms: int) -> dict[str, Any]:
        self.require_enabled()
        data = self.baseline(site, zone, ap, at_ms)
        if data is None:
            raise HttpError(404, "not_found", "no probe near that location")
        return data

    # -------------------------------------------------------------------------------------- purge
    def purge(self, by: str, value: str, dry_run: bool, actor: str, *, cli: bool = False) -> dict[str, Any]:
        """Data-subject purge (12 section 9): the matching tests, their evidence and diagnoses are deleted. The CLI
        purges even when the analytics are disabled (rows may outlive the setting)."""
        if not cli:
            self.require_enabled()
        dk: str | None = None
        dk_matched = True
        if by == "mac":
            secret = self.device_key_secret()
            try:
                if secret:
                    dk = st_helpers.device_key(secret, value)
                else:
                    dk_matched = False
                value = st_helpers.normalize_mac(value)
            except ValueError:
                raise HttpError(400, "invalid_request", "value is not a MAC address") from None
        elif by == "device_key":
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise HttpError(400, "invalid_request", "device_key must be 64 lower-case hex characters")
        elif by == "ip":
            import ipaddress
            try:
                value = str(ipaddress.ip_address(value.strip()))
            except ValueError:
                raise HttpError(400, "invalid_request", "value is not an IP address") from None
        elif by == "test":
            if not st_helpers.is_speedtest_id(value):
                raise HttpError(400, "invalid_request", "value is not a speedtest id")
        ids = self.repo.find_for_purge(by, value, dk)
        deleted = {"tests": 0, "evidence": 0, "diagnoses": 0}
        if ids and not dry_run:
            deleted = self.repo.delete_tests(ids)
            self.stats["purged"] += deleted["tests"]
        self.repo.audit(self.now_ms(), actor, "purge", f"{by}:{subject_hash(value)}", len(ids), dry_run)
        audit.info("speedtest purge by=%s subject=%s:%s matched=%d dry_run=%s", actor, by, subject_hash(value),
                   len(ids), dry_run)
        return {"dry_run": dry_run, "matched_tests": len(ids), "deleted": deleted, "device_key_matched": dk_matched,
                "audited_by": actor[:128]}

    def audit_identifiers_view(self, actor: str, what: str) -> None:
        self.repo.audit(self.now_ms(), actor, "view_identifiers", what[:128], 0, False)
        audit.info("speedtest identifiers viewed by=%s what=%s", actor, what[:64])

    # ------------------------------------------------------------------------- maintenance jobs
    def finalize_due(self) -> int:
        """Tests whose evidence was never marked final: finalize them once ``finalize_after_s`` has passed."""
        cutoff = self.now_ms() - self.settings.finalize_after_s * 1000
        n = 0
        for tid in self.repo.pending_due(cutoff):
            row = self.repo.get(tid)
            if row is None:
                continue
            if self._finalize(row, "failed" if not row["evidence_n"] else "partial")["code"] == "ok":
                n += 1
        return n

    def retention_once(self) -> dict[str, int]:
        """Delete tests, device metadata and evidence older than ``retention_days``; scrub what is due."""
        cutoff = self.now_ms() - self.settings.retention_days * 86400_000
        total = {"tests": 0, "evidence": 0, "diagnoses": 0, "scrubbed": 0}
        while True:
            ids = self.repo.expired_ids(cutoff)
            if not ids:
                break
            got = self.repo.delete_tests(ids)
            for k in ("tests", "evidence", "diagnoses"):
                total[k] += got[k]
            if len(ids) < 5000:
                break
        if self.settings.scrub_after_diagnosis:
            scrub = self._scrub_fn()
            for tid in self.repo.unscrubbed_final():
                if self.repo.scrub_one(tid, scrub):
                    total["scrubbed"] += 1
        self.repo.prune_audit(self.now_ms() - AUDIT_KEEP_DAYS * 86400_000)
        if total["tests"] or total["scrubbed"]:
            log.info("speedtest retention: %d tests, %d evidence, %d diagnoses removed, %d scrubbed", total["tests"],
                     total["evidence"], total["diagnoses"], total["scrubbed"])
        return total

    def run_jobs_once(self) -> None:
        self.finalize_due()
        now = time.monotonic()
        if now - self._last_retention >= RETENTION_INTERVAL_S or self._last_retention == 0.0:
            self._last_retention = now
            self.retention_once()

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="speedtest-jobs", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.hub.close()
        with self.cond:
            self.cond.notify_all()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def _loop(self) -> None:
        wait = 5.0
        while not self._stop.wait(wait):
            try:
                self.run_jobs_once()
            except Exception:  # noqa: BLE001 - the job thread must never die
                log.exception("speedtest maintenance failed")
            wait = JOB_INTERVAL_S


