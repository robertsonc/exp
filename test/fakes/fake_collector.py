#!/usr/bin/env python3
"""fake_collector: an in-memory collector for probe (WP-1) and dashboard (WP-3) development.

Implements shared/openapi/ingest.yaml (probe -> collector) and shared/openapi/collector.yaml (dashboard ->
collector) with the real enforcement: bearer token maps (sha256, constant-time), identity binding,
Measurement validation (require id), time window, dedupe on (probe,id), size/line limits, gzip, SSE.

Run:   python test/fakes/fake_collector.py --listen 127.0.0.1:8443 --tls --state-dir /tmp/fc
Import: ``from fake_collector import start; fake = start(...); port = fake.port; ...; fake.stop()``

Not a real collector: nothing is durable beyond an optional records.ndjson in --state-dir, VictoriaMetrics
does not exist (query_range is canned), and there is no rules engine beyond "latest beat per line".
"""
from __future__ import annotations

import argparse
import base64
import collections
import dataclasses
import json
import logging
import re
import shutil
import sys
import threading
import time
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared" / "python"))
from exp_common import config as exp_config  # noqa: E402
from exp_common import ids as exp_ids  # noqa: E402
from exp_common.schema import Measurement, iso_to_ms  # noqa: E402

import fakes_common as fc  # noqa: E402

log = logging.getLogger("exp.fakes.collector")

MAX_LINES = 1000
MAX_WIRE = 4 * 1024 * 1024
MAX_DECOMPRESSED = 16 * 1024 * 1024
MAX_LINE = 64 * 1024
FUTURE_SLACK_S = 60
REPLAY_WINDOW_S = 300
MAX_QUERY_LEN = 2048
MAX_RANGE_S = 30 * 86400
MIN_STEP_S = 10
MAX_BEATS_RANGE_S = 6 * 3600
MAX_SERIES = 500
MAX_POINTS = 11000

LINE_KEYS = ("network", "dhcp", "dns", "internet", "apps", "wifi", "path")
LINE_LABELS = {"network": "Network", "dhcp": "DHCP", "dns": "DNS", "internet": "Internet",
               "apps": "Apps", "wifi": "Wi-Fi", "path": "Path"}
# test kind -> line it feeds (01-contracts.md section 3)
LINE_OF = {"gateway": "network", "dhcp_hb": "dhcp", "dhcp": "dhcp", "dns_hb": "dns", "dns": "dns",
           "trace": "internet", "ping": "internet", "app": "apps", "throughput": "apps",
           "path": "path", "wifi_hb": "wifi", "wifi_join": "wifi"}
BEAT_OF = {"ok": 0, "degraded": 1, "fail": 2, "error": 3}
STATE_OF_BEAT = {0: "ok", 1: "warn", 2: "fail", 3: "unknown"}
STATE_RANK = {"ok": 0, "unknown": 1, "warn": 2, "fail": 3}
WORD_OF = {"ok": "ok", "warn": "unstable", "fail": "down", "unknown": "unknown"}

_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z\Z")
_STEP = re.compile(r"([0-9]+)(s|m|h)?\Z")
_TEXT_BAD = re.compile(r"[\x00-\x1f\x7f]")
_PROBES_CSV = re.compile(r"[a-z0-9][a-z0-9-]{0,63}(,[a-z0-9][a-z0-9-]{0,63})*\Z")
_PROM_KEYWORDS = frozenset({"by", "without", "on", "ignoring", "group_left", "group_right", "bool", "offset",
                            "and", "or", "unless", "with", "if", "ifnot", "default", "keep_metric_names",
                            "inf", "nan", "limit", "tenant", "atan2", "start", "end", "step"})


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.headers = status, code, message, headers


class _TooLarge(Exception):
    pass


@dataclasses.dataclass
class Event:
    seq: int
    ts: float
    kind: str  # beat | state | incident
    probe: str
    site: str
    data: dict[str, Any]


def gunzip_bounded(data: bytes, limit: int) -> bytes:
    """gzip-decode `data`, stopping (raising _TooLarge) as soon as output would exceed `limit`."""
    d = zlib.decompressobj(31)  # gzip container only
    out = bytearray()
    buf = data
    while not d.eof:
        room = limit + 1 - len(out)
        if room <= 0:
            raise _TooLarge
        produced = d.decompress(buf, room)
        out += produced
        buf = d.unconsumed_tail
        if len(out) > limit:
            raise _TooLarge
        if not produced and not buf:
            break
    if not d.eof:
        raise ValueError("truncated gzip stream")
    if d.unused_data:
        raise ValueError("trailing data after gzip stream")
    return bytes(out)


def _enc_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"o": offset}).encode()).decode().rstrip("=")


def _dec_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        off = json.loads(raw)["o"]
        if isinstance(off, int) and not isinstance(off, bool) and off >= 0:
            return off
    except (ValueError, KeyError, TypeError):
        pass
    raise ApiError(400, "invalid_request", "invalid cursor")


class CollectorApp:
    """All collector state + behaviour; HTTP handlers are thin wrappers."""

    def __init__(self, *, ingest_tokens: dict[str, str], dashboard_tokens: dict[str, str],
                 site: str = "hall-b", probe_sites: dict[str, str] | None = None,
                 probe_labels: dict[str, str] | None = None, retention_days: int = 7,
                 now_fn: Callable[[], float] = time.time, keepalive_s: float = 15.0,
                 state_dir: str | Path | None = None, fixtures: bool = True,
                 scenario: str | None = None, voice: str = "sysadmin") -> None:
        self.ingest_tokens = dict(ingest_tokens)
        self.dashboard_tokens = dict(dashboard_tokens)
        self.site = site
        self.probe_sites = dict(probe_sites or {})
        self.probe_labels = dict(probe_labels or {})
        self.retention_days = retention_days
        self.now = now_fn
        self.keepalive_s = keepalive_s
        self.voice = voice
        self.state_dir = Path(state_dir) if state_dir else None
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.records: list[dict[str, Any]] = []
        self.seen: set[tuple[str, str]] = set()
        self.lines: dict[str, dict[str, list[tuple[int, int]]]] = collections.defaultdict(dict)
        self.last_line_states: dict[str, dict[str, str]] = {}
        self.line_tests: dict[str, dict[str, dict[str, Any]]] = collections.defaultdict(dict)
        self.incidents: list[dict[str, Any]] = []
        self.open_incidents: dict[tuple[str, str], dict[str, Any]] = {}
        self.events: list[Event] = []
        self.seq = 0
        self.state_docs: dict[str, dict[str, Any]] = {}
        self.drill_reports: dict[str, dict[str, Any]] = {}
        self.drill_aborts: list[str] = []
        self.audit: list[dict[str, Any]] = []
        self.force: dict[str, Any] | None = None
        self.accepted_times: collections.deque[float] = collections.deque(maxlen=100000)
        self.reject_times: collections.deque[float] = collections.deque(maxlen=100000)
        self.requests = 0
        self.fixture_beats: dict[str, dict[str, list[tuple[int, int]]]] = {}
        self._records_fh = None
        if fixtures:
            self._load_fixtures(scenario)
        if self.state_dir:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            self._load_records(self.state_dir / "records.ndjson")

    # ------------------------------------------------------------------------------- fixtures/state
    def _load_fixtures(self, scenario: str | None) -> None:
        for path in sorted((fc.FIXTURES_DIR / "incidents").glob("*.json")):
            doc = json.loads(path.read_text("utf-8"))
            self.incidents.append(doc)
        beats = fc.load_fixture("beats/beats.json")
        self.fixture_beats[beats["probe"]] = {
            k: [(int(t), int(v)) for t, v in pts] for k, pts in beats["lines"].items()}
        if scenario:
            doc = fc.load_fixture(f"state/{scenario}.json")
            self.state_docs[doc["probe"]] = doc

    def _load_records(self, path: Path) -> None:
        if path.is_file():
            for raw in path.read_text("utf-8").splitlines():
                if raw.strip():
                    m = Measurement.from_dict(json.loads(raw), require_id=True)
                    self._store(m, emit=False)
        self._records_fh = open(path, "a", encoding="utf-8")  # noqa: SIM115 - closed in close()

    def close(self) -> None:
        with self.lock:
            if self._records_fh is not None:
                self._records_fh.close()
                self._records_fh = None

    def known_probes(self) -> list[str]:
        names = set(self.ingest_tokens) | set(self.probe_sites) | set(self.state_docs) | set(self.lines)
        names |= {i["probe"] for i in self.incidents}
        return sorted(names)

    def site_of(self, probe: str) -> str:
        return self.probe_sites.get(probe) or self._site_from_data(probe) or self.site

    def _site_from_data(self, probe: str) -> str | None:
        if probe in self.state_docs:
            return self.state_docs[probe]["site"]
        for inc in self.incidents:
            if inc["probe"] == probe:
                return inc["site"]
        return None

    # --------------------------------------------------------------------------------- force modes
    def set_force(self, status: int | None, retry_after: int = 1, count: int | None = None,
                  scope: str = "ingest") -> None:
        """Make the next `count` (all, if None) requests in `scope` (ingest|api|all) answer 429/503."""
        if status not in (None, 429, 503):
            raise ValueError("force status must be 429, 503 or None")
        if scope not in ("ingest", "api", "all"):
            raise ValueError("scope must be ingest, api or all")
        with self.lock:
            self.force = None if status is None else {
                "status": status, "retry_after": int(retry_after), "count": count, "scope": scope}

    def take_force(self, surface: str) -> dict[str, Any] | None:
        with self.lock:
            f = self.force
            if not f or f["scope"] not in (surface, "all"):
                return None
            if f["count"] is not None:
                if f["count"] <= 0:
                    self.force = None
                    return None
                f["count"] -= 1
            return dict(f)

    # ------------------------------------------------------------------------------------ ingest
    def ingest(self, identity: str, body: bytes) -> dict[str, Any]:
        """Process one decoded NDJSON body for an authenticated probe identity (limits already applied)."""
        if not body:
            raise ApiError(400, "not_ndjson", "empty body")
        if b"\x00" in body:
            raise ApiError(400, "not_ndjson", "body contains NUL bytes")
        try:
            body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ApiError(400, "not_ndjson", "body is not UTF-8") from exc
        lines = body.split(b"\n")
        if lines and lines[-1] == b"":
            lines.pop()
        if not lines:
            raise ApiError(400, "not_ndjson", "no lines")
        if len(lines) > MAX_LINES:
            raise ApiError(400, "too_many_lines", f"more than {MAX_LINES} lines")
        accepted = duplicates = 0
        rejected: list[dict[str, Any]] = []
        now = self.now()
        with self.lock:
            for n, raw in enumerate(lines, start=1):
                status, info = self._ingest_line(identity, raw, now)
                if status == "accepted":
                    accepted += 1
                elif status == "duplicate":
                    duplicates += 1
                else:
                    rejected.append({"line": n, "id": info["id"],
                                    "error": {"code": info["code"], "message": info["message"][:512]}})
            t = time.monotonic()
            self.accepted_times.extend([t] * accepted)
            self.reject_times.extend([t] * len(rejected))
            self.cond.notify_all()
        return {"accepted": accepted, "duplicates": duplicates, "rejected": rejected,
                "server_time": fc.iso_from_epoch(now)}

    def _ingest_line(self, identity: str, raw: bytes, now: float) -> tuple[str, dict[str, Any]]:
        def rej(code: str, msg: str, rid: str | None = None) -> tuple[str, dict[str, Any]]:
            return "rejected", {"code": code, "message": msg, "id": rid}

        if len(raw) > MAX_LINE:
            return rej("line_too_long", f"line exceeds {MAX_LINE} bytes")
        if not raw.strip():
            return rej("invalid_json", "empty line")
        try:
            doc = exp_config.parse_json(raw, "line")
        except ValueError as exc:
            return rej("invalid_json", str(exc))
        rid = doc.get("id") if isinstance(doc, dict) and exp_ids.is_ulid(doc.get("id")) else None
        try:
            m = Measurement.from_dict(doc, require_id=True)
        except ValueError as exc:
            return rej("invalid_measurement", str(exc), rid)
        if m.probe != identity:
            return rej("identity_mismatch", f"probe '{m.probe}' does not match token identity", rid)
        want_site = self.probe_sites.get(identity, self.site)
        if m.site != want_site:
            return rej("identity_mismatch", f"site '{m.site}' does not match configured site", rid)
        ts_ms = iso_to_ms(m.ts)
        if ts_ms > (now + FUTURE_SLACK_S) * 1000:
            return rej("ts_future", f"ts is more than {FUTURE_SLACK_S} s in the future", rid)
        if ts_ms < (now - self.retention_days * 86400) * 1000:
            return rej("ts_too_old", f"ts is older than {self.retention_days} days retention", rid)
        key = (m.probe, m.id)
        if key in self.seen:
            return "duplicate", {}
        self._store(m, emit=True)
        if self._records_fh is not None:
            self._records_fh.write(json.dumps(m.to_dict(), separators=(",", ":")) + "\n")
            self._records_fh.flush()
        return "accepted", {}

    def _store(self, m: Measurement, emit: bool) -> None:
        rec = m.to_dict()
        self.seen.add((m.probe, m.id))
        self.records.append(rec)
        line = LINE_OF.get(m.test)
        if not line:
            return
        v = BEAT_OF[m.outcome]
        t = iso_to_ms(m.ts)
        self.lines[m.probe].setdefault(line, []).append((t, v))
        info = self.line_tests[m.probe].setdefault(line, {"tests": {}, "ports": set(), "text": "", "t": 0})
        if v in (1, 2, 3) and t >= info["t"]:
            info["text"] = m.error or f"{m.test} {m.outcome}" + (f" on {m.target}" if m.target else "")
            info["t"] = t
            info["tests"][m.test] = True
            port = m.labels.get("port", "")
            if port and _SLUG.match(port):
                info["ports"].add(port)
        if emit:
            self._emit("beat", m.probe, m.site, {"probe": m.probe, "line": line, "t": t, "v": v})
            self._after_beat(m.probe, m.site, line)

    def _emit(self, kind: str, probe: str, site: str, data: dict[str, Any]) -> None:
        self.seq += 1
        self.events.append(Event(self.seq, self.now(), kind, probe, site, data))
        cutoff = self.now() - 2 * REPLAY_WINDOW_S
        while self.events and (self.events[0].ts < cutoff or len(self.events) > 5000):
            self.events.pop(0)

    def _after_beat(self, probe: str, site: str, line: str) -> None:
        cur = self.current_line_states(probe)
        prev = self.last_line_states.get(probe)
        self.last_line_states[probe] = cur
        if prev == cur:
            return
        self._emit("state", probe, site, self.state_lite(probe))
        key = (probe, line)
        st = cur.get(line)
        if st == "fail" and key not in self.open_incidents:
            inc = {"id": "inc_" + exp_ids.new_ulid(), "probe": probe, "site": site, "line": line,
                   "kind": "down", "start": self._line_since(probe, line), "end": None,
                   "where": None, "facts": [self.line_tests[probe][line]["text"][:200] or f"{line} failing"],
                   "folded_into": None, "acked_by": None,
                   "link": f"https://localhost/probe/{probe}?at={fc.iso_from_epoch(self.now())}"}
            self.incidents.append(inc)
            self.open_incidents[key] = inc
            self._emit("incident", probe, site, dict(inc))
        elif st in ("ok", "warn") and key in self.open_incidents:
            inc = self.open_incidents.pop(key)
            inc["end"] = fc.iso_from_epoch(self.now())
            inc["kind"] = "back"
            self._emit("incident", probe, site, dict(inc))

    # ------------------------------------------------------------------------------- derived views
    def _merged_lines(self, probe: str) -> dict[str, list[tuple[int, int]]]:
        out: dict[str, list[tuple[int, int]]] = {}
        for src in (self.fixture_beats.get(probe, {}), self.lines.get(probe, {})):
            for k, pts in src.items():
                out.setdefault(k, []).extend(pts)
        return {k: sorted(set(v)) for k, v in out.items()}

    def current_line_states(self, probe: str, at_ms: int | None = None) -> dict[str, str]:
        res: dict[str, str] = {}
        for k, pts in self.lines.get(probe, {}).items():
            cand = [p for p in pts if at_ms is None or p[0] <= at_ms]
            if cand:
                res[k] = STATE_OF_BEAT[max(cand)[1]]
        return res

    def _line_since(self, probe: str, line: str) -> str:
        pts = sorted(self.lines.get(probe, {}).get(line, []))
        if not pts:
            return fc.iso_from_epoch(self.now())
        cur = pts[-1][1]
        since = pts[-1][0]
        for t, v in reversed(pts):
            if v != cur:
                break
            since = t
        return fc.iso_from_epoch(since / 1000)

    def _newest_ms(self, probe: str, at_ms: int | None = None) -> int | None:
        best: int | None = None
        for pts in self.lines.get(probe, {}).values():
            for t, _ in pts:
                if (at_ms is None or t <= at_ms) and (best is None or t > best):
                    best = t
        return best

    def build_state(self, probe: str, voice: str | None = None, at_ms: int | None = None) -> dict[str, Any]:
        voice = voice or self.voice
        at_ms_eff = at_ms if at_ms is not None else int(self.now() * 1000)
        site = self.site_of(probe)
        newest = self._newest_ms(probe, at_ms)
        if newest is None and probe in self.state_docs:
            doc = json.loads(json.dumps(self.state_docs[probe]))
            doc["verdict"]["voice"] = voice
            return doc
        states = self.current_line_states(probe, at_ms)
        if newest is None or not states:
            return {"schema": "exp.state/1", "probe": probe, "site": site, "at": fc.iso_from_epoch(at_ms_eff / 1000),
                    "live": False, "newest_s": None,
                    "verdict": {"severity": "unknown", "headline": "No recent data.", "sub": "",
                                "voice": voice, "where": None},
                    "lines": [], "failing": []}
        lines: list[dict[str, Any]] = []
        failing: list[dict[str, Any]] = []
        for k in LINE_KEYS:
            if k not in states:
                continue
            st = states[k]
            info = self.line_tests[probe].get(k, {})
            since = None if st == "ok" else self._line_since(probe, k)
            lines.append({"key": k, "label": LINE_LABELS[k], "state": st, "word": WORD_OF[st], "since": since,
                          "detail": info.get("text", "") if st != "ok" else "", "last_outage": None,
                          "flaps": self._flaps(probe, k)})
            if st in ("warn", "fail"):
                failing.append({"line": k, "items": [{
                    "text": (info.get("text") or f"{k} {st}")[:512], "count": 1,
                    "ports": sorted(info.get("ports", ()))[:256], "tests": sorted(info.get("tests", {}))[:32]}]})
        worst = max((s for s in states.values()), key=lambda s: STATE_RANK[s])
        bad = [LINE_LABELS[k] for k in LINE_KEYS if states.get(k) == worst] if worst != "ok" else []
        headline = ("Everything looks good." if worst == "ok"
                    else f"{', '.join(bad)} {'is' if len(bad) == 1 else 'are'} "
                         f"{'failing' if worst == 'fail' else 'unstable' if worst == 'warn' else 'unknown'}.")
        newest_s = max(0, int((at_ms_eff - newest) / 1000))
        return {"schema": "exp.state/1", "probe": probe, "site": site,
                "at": fc.iso_from_epoch(at_ms_eff / 1000), "live": newest_s <= 60, "newest_s": newest_s,
                "verdict": {"severity": worst, "headline": headline, "sub": "", "voice": voice, "where": None},
                "lines": lines, "failing": failing}

    def _flaps(self, probe: str, line: str) -> int:
        pts = sorted(self.lines.get(probe, {}).get(line, []))
        return sum(1 for a, b in zip(pts, pts[1:], strict=False) if a[1] == 0 and b[1] == 2)

    def state_lite(self, probe: str, voice: str | None = None, at_ms: int | None = None) -> dict[str, Any]:
        s = self.build_state(probe, voice, at_ms)
        return {"probe": probe, "site": s["site"], "severity": s["verdict"]["severity"],
                "headline": s["verdict"]["headline"],
                "lines": [{"key": ln["key"], "state": ln["state"]} for ln in s["lines"]]}

    def probe_summary(self, probe: str) -> dict[str, Any]:
        recs = [r for r in self.records if r["probe"] == probe]
        last = max(recs, key=lambda r: iso_to_ms(r["ts"])) if recs else None
        last_ms = iso_to_ms(last["ts"]) if last else None
        sev = self.build_state(probe)["verdict"]["severity"]
        return {"probe": probe, "site": self.site_of(probe), "label": self.probe_labels.get(probe, probe)[:128],
                "last_seen": fc.iso_from_epoch(last_ms / 1000) if last_ms is not None else None,
                "newest_s": max(0.0, self.now() - last_ms / 1000) if last_ms is not None else None,
                "version": (last or {}).get("agent_ver") or None, "state": sev}

    def beats_doc(self, probe: str, frm: str, to: str, from_ms: int, to_ms: int) -> dict[str, Any]:
        lines: dict[str, list[list[int]]] = {}
        for k, pts in self._merged_lines(probe).items():
            sel = [[t, v] for t, v in pts if from_ms <= t <= to_ms]
            if sel:
                lines[k] = sel
        markers = []
        for inc in self.incidents:
            if inc["probe"] != probe:
                continue
            t = iso_to_ms(inc["start"])
            if from_ms <= t <= to_ms:
                markers.append({"t": t, "kind": "incident", "text": f"{inc['line']} {inc['kind']}", "ref": inc["id"]})
        return {"schema": "exp.beats/1", "probe": probe, "from": frm, "to": to, "lines": lines, "markers": markers}

    # ------------------------------------------------------------------------------ test hooks
    def inject_incident(self, doc: dict[str, Any]) -> None:
        exp_config.validate(doc, "incident.schema.json")
        with self.lock:
            self.incidents.append(doc)
            self._emit("incident", doc["probe"], doc["site"], dict(doc))
            self.cond.notify_all()

    def set_state_doc(self, probe: str, doc: dict[str, Any]) -> None:
        exp_config.validate(doc, "state.schema.json")
        with self.lock:
            self.state_docs[probe] = doc

    def add_drill_report(self, doc: dict[str, Any]) -> None:
        with self.lock:
            self.drill_reports[doc["run_id"]] = doc

    def records_for(self, probe: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            return [r for r in self.records if probe is None or r["probe"] == probe]

    def health(self) -> dict[str, Any]:
        t = time.monotonic()
        rps = sum(1 for x in self.accepted_times if t - x <= 10) / 10.0
        rej = sum(1 for x in self.reject_times if t - x <= 60)
        probes = self.known_probes()
        reporting = sum(1 for p in probes if (self._newest_ms(p) or 0) > (self.now() - 120) * 1000)
        try:
            free = shutil.disk_usage(self.state_dir or ".").free // (1024 * 1024)
        except OSError:
            free = 100000
        return {"status": "ok", "version": fc.VERSION, "vm": {"up": True, "lag_s": 0.0},
                "ingest": {"rps": rps, "rejects_1m": rej}, "probes": {"total": len(probes), "reporting": reporting},
                "disk_free_mb": int(free)}


# ---------------------------------------------------------------------------------- query guards

def check_metricsql(query: str) -> None:
    """The collector's query_range guard: only exp_* metric names, <= 2 KiB. Raises ApiError(400)."""
    if len(query.encode("utf-8")) > MAX_QUERY_LEN:
        raise ApiError(400, "invalid_query", f"query exceeds {MAX_QUERY_LEN} bytes")
    if _TEXT_BAD.search(query):
        raise ApiError(400, "invalid_query", "query contains control characters")
    if "__name__" in query:
        raise ApiError(400, "invalid_query", "__name__ selectors are not allowed")
    q = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`[^`]*`', '""', query)   # string literals
    q = re.sub(r"\{[^{}]*\}", "", q)                                              # label selectors
    q = re.sub(r"\[[^\]]*\]", "", q)                                              # durations
    q = re.sub(r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^()]*\)", " ", q)
    metrics = 0
    for m in re.finditer(r"[A-Za-z_:][A-Za-z0-9_:]*", q):
        name = m.group(0)
        if name in _PROM_KEYWORDS or re.fullmatch(r"[0-9.]+(e[0-9]+)?[a-z]*", name):
            continue
        if q[m.end():].lstrip().startswith("("):   # function call
            continue
        if not name.startswith("exp_"):
            raise ApiError(400, "invalid_query", f"metric '{name[:64]}' is not allowed: only exp_* metrics")
        metrics += 1
    if metrics == 0:
        raise ApiError(400, "invalid_query", "query must select at least one exp_* metric")


def parse_step(step: str) -> int:
    m = _STEP.match(step)
    if not m or len(step) > 16:
        raise ApiError(400, "invalid_request", "step must match ^[0-9]+(s|m|h)?$")
    secs = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, None: 1}[m.group(2)]
    if secs < MIN_STEP_S:
        raise ApiError(400, "step_too_small", f"step must be at least {MIN_STEP_S}s")
    return secs


# --------------------------------------------------------------------------------------- handler

class Handler(fc.BaseHandler):
    app: CollectorApp  # type: ignore[assignment]

    # --- auth ---------------------------------------------------------------------------------
    def _auth(self, tokens: dict[str, str]) -> str:
        ident = fc.match_token(fc.bearer_token(self.header("Authorization")), tokens)
        if ident is None:
            raise ApiError(401, "invalid_token", "missing or invalid token", {"WWW-Authenticate": "Bearer"})
        return ident

    # --- routing ------------------------------------------------------------------------------
    def dispatch(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        app = self.app
        with app.lock:
            app.requests += 1
        try:
            if path == "/healthz":
                return self._healthz(method)
            if path.startswith("/_fake/"):
                return self._control(method, path, query)
            if path == "/ingest/v1/measurements":
                return self._ingest(method)
            if path.startswith("/api/v1/"):
                return self._api(method, path[len("/api/v1/"):], query)
            raise ApiError(404, "not_found", "no such path")
        except ApiError as e:
            self.send_err(e.status, e.code, e.message, headers=e.headers)

    def _forced(self, surface: str) -> None:
        f = self.app.take_force(surface)
        if f is None:
            return
        code = "rate_limited" if f["status"] == 429 else "unavailable"
        self.drain(self.content_length() or 0) if (self.content_length() or 0) > 0 else None
        raise ApiError(f["status"], code, code.replace("_", " "), {"Retry-After": str(f["retry_after"])})

    def _healthz(self, method: str) -> None:
        if method not in ("GET", "HEAD"):
            raise ApiError(405, "method_not_allowed", "GET only", {"Allow": "GET, HEAD"})
        self.send_text(200, "ok")

    # --- ingest -------------------------------------------------------------------------------
    def _ingest(self, method: str) -> None:
        app = self.app
        if method != "POST":
            raise ApiError(405, "method_not_allowed", "POST only", {"Allow": "POST"})
        self._forced("ingest")
        try:
            identity = self._auth(app.ingest_tokens)
        except ApiError:
            self.drain(min(self.content_length() or 0, MAX_WIRE))
            raise
        ctype = (self.header("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/x-ndjson":
            self.drain(min(self.content_length() or 0, MAX_WIRE))
            raise ApiError(415, "unsupported_media_type", "Content-Type must be application/x-ndjson")
        enc = (self.header("Content-Encoding") or "identity").strip().lower()
        if enc not in ("gzip", "identity"):
            self.drain(min(self.content_length() or 0, MAX_WIRE))
            raise ApiError(415, "unsupported_media_type", "Content-Encoding must be gzip or identity")
        n = self.content_length()
        if n is None:
            raise ApiError(400, "length_required", "Content-Length is required")
        if n < 0:
            raise ApiError(400, "invalid_request", "bad Content-Length")
        if n > MAX_WIRE:
            self.drain(n)
            raise ApiError(413, "payload_too_large", f"body exceeds {MAX_WIRE} bytes")
        body = self.read_body(MAX_WIRE)
        if body is None:  # pragma: no cover - guarded above
            raise ApiError(413, "payload_too_large", "body too large")
        if enc == "gzip":
            try:
                body = gunzip_bounded(body, MAX_DECOMPRESSED)
            except _TooLarge:
                raise ApiError(413, "decompressed_too_large",
                               f"decompressed body exceeds {MAX_DECOMPRESSED} bytes") from None
            except (zlib.error, ValueError, EOFError) as exc:
                raise ApiError(400, "bad_gzip", f"corrupt gzip: {exc}"[:200]) from exc
        result = app.ingest(identity, body)
        self.send_json(200, result)

    # --- query API ----------------------------------------------------------------------------
    def _api(self, method: str, rest: str, query: dict[str, list[str]]) -> None:
        app = self.app
        self._forced("api")
        segs = rest.strip("/").split("/")
        if segs == ["drills", "control"]:
            self._need(method, "GET")
            self._auth(app.ingest_tokens)
            with app.lock:
                return self.send_json(200, {"abort": list(app.drill_aborts)[:64]})
        self._auth(app.dashboard_tokens)
        user = self.header("X-Exp-User")
        if user is not None and (len(user) > 128 or _TEXT_BAD.search(user)):
            raise ApiError(400, "invalid_request", "bad X-Exp-User")
        q = _Q(query)
        name = segs[0]
        if len(segs) == 1:
            table: dict[str, Callable[[_Q], None]] = {
                "health": self._h_health, "probes": self._h_probes, "state": self._h_state,
                "states": self._h_states, "beats": self._h_beats, "records": self._h_records,
                "incidents": self._h_incidents, "summary": self._h_summary,
                "query_range": self._h_query_range, "stream": self._h_stream}
            fn = table.get(name)
            if fn is None:
                raise ApiError(404, "not_found", "no such endpoint")
            self._need(method, "GET")
            return fn(q)
        if name == "incidents" and len(segs) == 3 and segs[2] == "ack":
            self._need(method, "POST")
            return self._h_ack(segs[1], user)
        if name == "drills" and len(segs) == 2:
            self._need(method, "GET")
            return self._h_drill(segs[1])
        if name == "drills" and len(segs) == 3 and segs[2] == "abort":
            self._need(method, "POST")
            return self._h_drill_abort(segs[1], user)
        raise ApiError(404, "not_found", "no such endpoint")

    @staticmethod
    def _need(method: str, want: str) -> None:
        if method != want:
            raise ApiError(405, "method_not_allowed", f"{want} only", {"Allow": want})

    def _probe_param(self, q: _Q, must_exist: bool = True) -> str:
        probe = q.slug("probe", required=True)
        if must_exist and probe not in self.app.known_probes():
            raise ApiError(404, "probe_not_found", f"unknown probe '{probe}'")
        return probe

    def _h_health(self, q: _Q) -> None:
        self.send_json(200, self.app.health())

    def _page(self, q: _Q, items: list[Any]) -> dict[str, Any]:
        limit = q.integer("limit", 1, 1000, 100)
        off = _dec_cursor(q.one("cursor"))
        page = items[off:off + limit]
        nxt = _enc_cursor(off + limit) if off + limit < len(items) else None
        return {"items": page, "next_cursor": nxt}

    def _h_probes(self, q: _Q) -> None:
        site = q.slug("site")
        with self.app.lock:
            items = [self.app.probe_summary(p) for p in self.app.known_probes()]
        if site:
            items = [i for i in items if i["site"] == site]
        self.send_json(200, self._page(q, items))

    def _h_state(self, q: _Q) -> None:
        probe = self._probe_param(q)
        at = q.ts("at")
        voice = q.enum("voice", ("plain", "sysadmin"))
        with self.app.lock:
            doc = self.app.build_state(probe, voice, iso_to_ms(at) if at else None)
        self.send_json(200, doc)

    def _h_states(self, q: _Q) -> None:
        site = q.slug("site")
        at = q.ts("at")
        voice = q.enum("voice", ("plain", "sysadmin"))
        with self.app.lock:
            items = [self.app.state_lite(p, voice, iso_to_ms(at) if at else None)
                     for p in self.app.known_probes() if not site or self.app.site_of(p) == site]
        self.send_json(200, self._page(q, items))

    def _h_beats(self, q: _Q) -> None:
        probe = self._probe_param(q)
        frm, to = q.ts("from", required=True), q.ts("to", required=True)
        f_ms, t_ms = iso_to_ms(frm), iso_to_ms(to)  # type: ignore[arg-type]
        if t_ms < f_ms:
            raise ApiError(400, "invalid_request", "'to' is before 'from'")
        if t_ms - f_ms > MAX_BEATS_RANGE_S * 1000:
            raise ApiError(400, "range_too_large", "to - from must be at most 6 hours")
        with self.app.lock:
            doc = self.app.beats_doc(probe, frm, to, f_ms, t_ms)  # type: ignore[arg-type]
        self.send_json(200, doc)

    def _h_records(self, q: _Q) -> None:
        probe = self._probe_param(q)
        test = q.ident("test")
        outcome = q.enum("outcome", ("ok", "degraded", "fail", "error"))
        frm, to = q.ts("from"), q.ts("to")
        with self.app.lock:
            recs = [r for r in self.app.records if r["probe"] == probe]
        if test:
            recs = [r for r in recs if r["test"] == test]
        if outcome:
            recs = [r for r in recs if r["outcome"] == outcome]
        if frm:
            recs = [r for r in recs if iso_to_ms(r["ts"]) >= iso_to_ms(frm)]
        if to:
            recs = [r for r in recs if iso_to_ms(r["ts"]) <= iso_to_ms(to)]
        recs.sort(key=lambda r: (iso_to_ms(r["ts"]), r["id"]))
        self.send_json(200, self._page(q, recs))

    def _h_incidents(self, q: _Q) -> None:
        probe, site = q.slug("probe"), q.slug("site")
        frm, to = q.ts("from"), q.ts("to")
        op = q.enum("open", ("true", "false"))
        with self.app.lock:
            items = [dict(i) for i in self.app.incidents]
        if probe:
            items = [i for i in items if i["probe"] == probe]
        if site:
            items = [i for i in items if i["site"] == site]
        if frm:
            items = [i for i in items if iso_to_ms(i["start"]) >= iso_to_ms(frm)]
        if to:
            items = [i for i in items if iso_to_ms(i["start"]) <= iso_to_ms(to)]
        if op:
            items = [i for i in items if (i["end"] is None) == (op == "true")]
        items.sort(key=lambda i: (iso_to_ms(i["start"]), i["id"]))
        self.send_json(200, self._page(q, items))

    def _h_ack(self, inc_id: str, user: str | None) -> None:
        if not re.fullmatch(r"inc_[0-9A-HJKMNP-TV-Z]{26}", inc_id):
            raise ApiError(400, "invalid_request", "malformed incident id")
        note = None
        body = self.read_body(8192)
        if body is None:
            raise ApiError(413, "payload_too_large", "body too large")
        if body.strip():
            try:
                doc = exp_config.parse_json(body, "body")
            except ValueError as exc:
                raise ApiError(400, "invalid_request", str(exc)[:200]) from exc
            if not isinstance(doc, dict):
                raise ApiError(400, "invalid_request", "body must be an object")
            note = doc.get("note")
            if note is not None and (not isinstance(note, str) or len(note) > 512 or _TEXT_BAD.search(note)):
                raise ApiError(400, "invalid_request", "note must be a string up to 512 chars, no control chars")
        with self.app.lock:
            inc = next((i for i in self.app.incidents if i["id"] == inc_id), None)
            if inc is None:
                raise ApiError(404, "not_found", "no such incident")
            inc["acked_by"] = user or "dashboard"
            self.app.audit.append({"action": "incident.ack", "incident": inc_id, "user": user, "note": note})
        self.send_empty(204)

    def _h_summary(self, q: _Q) -> None:
        probe = self._probe_param(q)
        q.integer("minutes", 1, 1440, 60)
        base = {"probe": probe}
        self.send_json(200, {
            "clients": [{**base, "mac": "aa:bb:cc:00:00:01", "ip": "10.1.0.31", "hostname": "client-1",
                         "rssi_dbm": -52}],
            "dhcp": [{**base, "server": "10.1.0.1", "offer_ms": 12.5, "offers": 1}],
            "dns": [{**base, "resolver": "10.1.0.1", "rtt_ms": 8.2, "failures": 0}],
            "apps": [{**base, "app": "example", "total_ms": 180.0, "apdex": 0.97}],
            "throughput": [{**base, "down_mbps": 920.0, "up_mbps": 880.0}],
            "servers": [{**base, "server": "10.1.0.2", "requests": 120, "errors": 0}]})

    def _h_query_range(self, q: _Q) -> None:
        query = q.one("query")
        if not query:
            raise ApiError(400, "invalid_request", "query is required")
        check_metricsql(query)
        start, end = q.ts("start", required=True), q.ts("end", required=True)
        step_raw = q.one("step")
        if step_raw is None:
            raise ApiError(400, "invalid_request", "step is required")
        step = parse_step(step_raw)
        s, e = iso_to_ms(start) / 1000, iso_to_ms(end) / 1000  # type: ignore[arg-type]
        if e <= s:
            raise ApiError(400, "invalid_request", "end must be after start")
        if e - s > MAX_RANGE_S:
            raise ApiError(400, "range_too_large", "range must be at most 30 days")
        npts = int((e - s) // step) + 1
        if npts > MAX_POINTS:
            raise ApiError(400, "invalid_request", f"too many points ({npts} > {MAX_POINTS}); raise step")
        name = re.search(r"exp_[A-Za-z0-9_:]*", query).group(0)  # type: ignore[union-attr]
        probes = self.app.known_probes()[:MAX_SERIES] or ["probe-a1"]
        result = []
        for pi, p in enumerate(probes):
            vals = [[s + i * step, f"{(10 + 3 * ((i + pi) % 7)):.1f}"] for i in range(npts)]
            result.append({"metric": {"__name__": name, "probe": p, "site": self.app.site_of(p)}, "values": vals})
        self.send_json(200, {"status": "success", "data": {"resultType": "matrix", "result": result[:MAX_SERIES]}})

    def _h_drill(self, run_id: str) -> None:
        if not re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run_id):
            raise ApiError(400, "invalid_request", "malformed run id")
        with self.app.lock:
            doc = self.app.drill_reports.get(run_id)
        if doc is None:
            raise ApiError(404, "not_found", "no such drill run")
        self.send_json(200, doc)

    def _h_drill_abort(self, run_id: str, user: str | None) -> None:
        if not re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", run_id):
            raise ApiError(400, "invalid_request", "malformed run id")
        with self.app.lock:
            if run_id not in self.app.drill_reports:
                raise ApiError(404, "not_found", "no such drill run")
            if run_id not in self.app.drill_aborts:
                self.app.drill_aborts.append(run_id)
            self.app.audit.append({"action": "drill.abort", "run": run_id, "user": user})
        self.send_empty(202)

    # --- SSE ----------------------------------------------------------------------------------
    def _h_stream(self, q: _Q) -> None:
        probes_raw, site = q.one("probes"), q.slug("site")
        if bool(probes_raw) == bool(site):
            raise ApiError(400, "invalid_request", "provide exactly one of probes or site")
        probes: set[str] | None = None
        if probes_raw:
            if len(probes_raw) > 4096 or not _PROBES_CSV.match(probes_raw):
                raise ApiError(400, "invalid_request", "probes must be a comma-separated list of slugs")
            probes = set(probes_raw.split(","))
        last = self.header("Last-Event-ID")
        if last is not None and len(last) > 128:
            raise ApiError(400, "invalid_request", "Last-Event-ID too long")
        app, fake = self.app, self.fake

        def match(e: Event) -> bool:
            return (e.probe in probes) if probes is not None else (e.site == site)

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        out = self.wfile
        out.write(b"retry: 3000\n\n")
        out.flush()
        with app.lock:
            head = app.events[-1].seq if app.events else 0
            cursor = head
            replay_from = None
            if last is not None and last.isdigit():
                replay_from = int(last)
                cursor = min(replay_from, head)
        last_write = time.monotonic()
        first = True
        while not fake.stopping.is_set():
            with app.cond:
                batch = [e for e in app.events if e.seq > cursor]
                if not batch:
                    wait = max(0.02, min(0.2, app.keepalive_s - (time.monotonic() - last_write)))
                    app.cond.wait(wait)
                    batch = [e for e in app.events if e.seq > cursor]
            if batch and first and replay_from is not None:
                horizon = app.now() - REPLAY_WINDOW_S
                batch = [e for e in batch if e.ts >= horizon]
            for e in batch:
                cursor = max(cursor, e.seq)
                if match(e):
                    out.write(f"event: {e.kind}\nid: {e.seq}\ndata: "
                              f"{json.dumps(e.data, separators=(',', ':'))}\n\n".encode())
                    last_write = time.monotonic()
            if batch:
                first = False
            if time.monotonic() - last_write >= app.keepalive_s:
                out.write(b": keepalive\n\n")
                last_write = time.monotonic()
            out.flush()

    # --- /_fake control (loopback only) --------------------------------------------------------
    def _control(self, method: str, path: str, query: dict[str, list[str]]) -> None:
        if not self.client_is_loopback():
            raise ApiError(403, "forbidden", "control API is loopback-only")
        app = self.app
        op = path[len("/_fake/"):]
        if method == "GET" and op == "stats":
            with app.lock:
                return self.send_json(200, {"records": len(app.records), "requests": app.requests,
                                            "incidents": len(app.incidents), "events": app.seq})
        if method == "GET" and op == "records":
            probe = (query.get("probe") or [None])[0]
            return self.send_json(200, {"items": app.records_for(probe)})
        if method == "POST":
            doc, ok = self.read_json()
            if not ok:
                return None
            try:
                if op == "force":
                    app.set_force(doc.get("status"), int(doc.get("retry_after", 1)), doc.get("count"),
                                  doc.get("scope", "ingest"))
                elif op == "incident":
                    app.inject_incident(doc)
                elif op == "state":
                    app.set_state_doc(doc["probe"], doc["doc"])
                elif op == "abort":
                    with app.lock:
                        app.drill_aborts.extend(r for r in doc.get("run_ids", []) if r not in app.drill_aborts)
                elif op == "drill_report":
                    app.add_drill_report(doc)
                else:
                    raise ApiError(404, "not_found", "no such control op")
            except (ValueError, KeyError, TypeError) as exc:
                raise ApiError(400, "invalid_request", str(exc)[:300]) from exc
            return self.send_json(200, {"ok": True})
        raise ApiError(404, "not_found", "no such control op")


class _Q:
    """Validated single-valued query parameters."""

    def __init__(self, query: dict[str, list[str]]) -> None:
        self.q = query

    def one(self, name: str) -> str | None:
        vals = self.q.get(name)
        if not vals:
            return None
        if len(vals) > 1:
            raise ApiError(400, "invalid_request", f"parameter '{name}' given more than once")
        return vals[0]

    def slug(self, name: str, required: bool = False) -> str | None:
        v = self.one(name)
        if v is None:
            if required:
                raise ApiError(400, "invalid_request", f"'{name}' is required")
            return None
        if not _SLUG.match(v):
            raise ApiError(400, "invalid_request", f"'{name}' must be a slug")
        return v

    def ident(self, name: str) -> str | None:
        v = self.one(name)
        if v is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", v):
            raise ApiError(400, "invalid_request", f"'{name}' must be an identifier")
        return v

    def ts(self, name: str, required: bool = False) -> str | None:
        v = self.one(name)
        if v is None:
            if required:
                raise ApiError(400, "invalid_request", f"'{name}' is required")
            return None
        if not _TS.match(v):
            raise ApiError(400, "invalid_request", f"'{name}' must be a UTC timestamp ending in Z")
        try:
            iso_to_ms(v)
        except ValueError as exc:
            raise ApiError(400, "invalid_request", f"'{name}' is not a valid timestamp") from exc
        return v

    def enum(self, name: str, allowed: tuple[str, ...]) -> str | None:
        v = self.one(name)
        if v is not None and v not in allowed:
            raise ApiError(400, "invalid_request", f"'{name}' must be one of {', '.join(allowed)}")
        return v

    def integer(self, name: str, lo: int, hi: int, default: int) -> int:
        v = self.one(name)
        if v is None:
            return default
        if not re.fullmatch(r"[0-9]{1,9}", v) or not lo <= int(v) <= hi:
            raise ApiError(400, "invalid_request", f"'{name}' must be an integer in {lo}..{hi}")
        return int(v)


# ------------------------------------------------------------------------------------ entry points

def default_tokens() -> tuple[dict[str, str], dict[str, str]]:
    ingest = {"probe-a1": fc.token_hash(fc.fixture_token("expi", "probe-a1"))}
    dash = {"dash-main": fc.token_hash(fc.fixture_token("expd", "dash-main"))}
    return ingest, dash


def start(*, ingest_tokens: dict[str, str] | None = None, dashboard_tokens: dict[str, str] | None = None,
          host: str = "127.0.0.1", port: int = 0, tls: bool = False, state_dir: str | Path | None = None,
          **app_kwargs: Any) -> fc.FakeServer:
    """Start a fake collector in-process; returns the running FakeServer (``.port``, ``.app``, ``.stop()``)."""
    di, dd = default_tokens()
    app = CollectorApp(ingest_tokens=di if ingest_tokens is None else ingest_tokens,
                       dashboard_tokens=dd if dashboard_tokens is None else dashboard_tokens,
                       state_dir=state_dir, **app_kwargs)
    tls_files = None
    if tls:
        if state_dir is None:
            raise ValueError("tls=True needs state_dir (the self-signed cert is generated there)")
        cert, key, _ = fc.prepare_tls(Path(state_dir))
        tls_files = (cert, key)
    server = FakeCollector(Handler, app, host=host, port=port, tls=tls_files, name="fake_collector")
    server.start()
    return server


class FakeCollector(fc.FakeServer):
    def stop(self) -> None:
        super().stop()
        self.app.close()
        with self.app.cond:
            self.app.cond.notify_all()


def _load_hash_map(path: str) -> dict[str, str]:
    doc = exp_config.load_json(path)
    if not isinstance(doc, dict) or not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                                            for v in doc.values()):
        raise SystemExit(f"{path}: expected a JSON object of {{id: sha256-hex}}")
    return doc


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--listen", default="127.0.0.1:0", help="host:port (default 127.0.0.1, ephemeral port)")
    ap.add_argument("--tls", action=argparse.BooleanOptionalAction, default=False,
                    help="serve HTTPS with a self-signed cert generated in --state-dir (needs --state-dir)")
    ap.add_argument("--state-dir", help="directory for the TLS cert and records.ndjson persistence")
    ap.add_argument("--scenario", choices=["all-ok", "dns-fail", "gateway-fail", "no-data"],
                    help="state fixture served for probes that have not pushed data")
    ap.add_argument("--ingest-tokens", help="JSON file {probe_id: sha256(expi_ token)}")
    ap.add_argument("--dashboard-tokens", help="JSON file {dashboard_id: sha256(expd_ token)}")
    ap.add_argument("--config", help="exp.collector.config/1 JSON: takes site and probe list/sites from it")
    ap.add_argument("--site", default=None, help="configured site slug (default hall-b)")
    ap.add_argument("--keepalive-s", type=float, default=15.0, help="SSE keepalive interval (tests lower it)")
    ap.add_argument("--force", choices=["429", "503"], help="answer every ingest request with this status")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    host, _, port_s = args.listen.rpartition(":")
    kw: dict[str, Any] = {}
    if args.config:
        cfg = exp_config.load_config(args.config, "collector.config.schema.json")
        kw["site"] = cfg["site"]
        kw["probe_sites"] = {p["probe_id"]: p["site"] for p in cfg["probes"]}
        kw["probe_labels"] = {p["probe_id"]: p.get("label", p["probe_id"]) for p in cfg["probes"]}
    if args.site:
        kw["site"] = args.site
    di, dd = default_tokens()
    if args.ingest_tokens:
        di = _load_hash_map(args.ingest_tokens)
    if args.dashboard_tokens:
        dd = _load_hash_map(args.dashboard_tokens)
    state_dir = Path(args.state_dir) if args.state_dir else None
    srv = start(ingest_tokens=di, dashboard_tokens=dd, host=host or "127.0.0.1", port=int(port_s or 0),
                tls=args.tls, state_dir=state_dir, keepalive_s=args.keepalive_s, scenario=args.scenario, **kw)
    if args.force:
        srv.app.set_force(int(args.force), scope="ingest")

    def banner() -> str:
        lines = [f"fake_collector listening on {srv.base_url}"]
        if srv.fingerprint:
            lines.append(f"tls fingerprint (sha256): {srv.fingerprint}")
        if args.ingest_tokens is None:
            lines.append(f"default probe ingest token (fake): {fc.fixture_token('expi', 'probe-a1')}")
        if args.dashboard_tokens is None:
            lines.append(f"default dashboard token (fake):    {fc.fixture_token('expd', 'dash-main')}")
        return "\n".join(lines)

    fc.run_forever(srv, banner)
    return 0


if __name__ == "__main__":
    sys.exit(main())
