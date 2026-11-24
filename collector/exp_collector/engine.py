"""The live rules engine and time travel (03-collector.md section 5).

* ``RulesEngine.observe`` is the ingest observer hook: accepted records go into one in-memory ring
  buffer (``rules.BeatStore``) per configured probe.
* Every 2 s ``tick`` evaluates every probe (``rules.evaluate``), caches the result for the API and SSE,
  and runs the incident engine (``incidents.ProbeIncidents``).
* ``state(probe, at)`` with an explicit `at` is TIME TRAVEL: evaluated purely from the records of the
  SQLite store in [at - history, at]. Same records -> same output, whatever the live buffers hold.
* ``state_doc`` builds the exp.state/1 document, ``beats_doc`` the exp.beats/1 document.
"""
from __future__ import annotations

import collections
import datetime
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from exp_common import schema as exp_schema

from . import verdict as vt
from .alerts import WebhookSender
from .incidents import IncidentConfig, ProbeIncidents, incident_doc
from .rules import (
    HISTORY_MS,
    LABELS,
    LINE_KEYS,
    LINE_SPECS,
    MAX_WINDOW_MS,
    STREAMS,
    BeatStore,
    Evaluation,
    Rec,
    evaluate,
    failing_items,
)
from .store import Store

log = logging.getLogger(__name__)

TICK_S = 2.0
MIN_GAP_S = 0.5
MAX_LOAD_RECORDS = 400_000
EXTRA_TESTS = ("drill", "ext_mist", "ext_ec")      # timeline markers
_WORDS = {"fail": {"network": "unstable"}, "warn": {"network": "shaky"}}


def iso_ms(ms: int | float) -> str:
    return (datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def line_word(state: str, key: str) -> str:
    if state == "fail":
        return _WORDS["fail"].get(key, "down")
    if state == "warn":
        return _WORDS["warn"].get(key, "degraded")
    return "ok" if state == "ok" else "no data"


# ----------------------------------------------------------------------------------------- documents
def state_doc(ev: Evaluation, *, voice: str = "sysadmin", tz: str = "UTC", edge_label: str = "EC",
              live: bool = False, lines: Iterable[str] = LINE_KEYS) -> dict[str, Any]:
    """The exp.state/1 document of an Evaluation."""
    keys = [k for k in LINE_KEYS if k in set(lines)]
    v = vt.verdict(ev, ev.where, voice, tz, edge_label)
    out_lines: list[dict[str, Any]] = []
    failing: list[dict[str, Any]] = []
    for k in keys:
        le = ev.lines[k]
        lo = le.last_outage
        out_lines.append({
            "key": k, "label": LABELS[k], "state": le.state, "word": line_word(le.state, k),
            "since": iso_ms(le.since) if le.since is not None and le.state in ("fail", "warn") else None,
            "detail": vt.line_detail(ev, k)[:512],
            "last_outage": ({"start": iso_ms(lo.start), "end": iso_ms(lo.end), "open": bool(lo.open)}
                            if lo and lo.start is not None else None),
            "flaps": le.flaps, "window_s": (le.window_ms or LINE_SPECS[k].window_ms) // 1000})
        if le.state in ("fail", "warn"):
            items = failing_items(ev, k)
            if not items:           # never "no error text" next to a failing line: say what the counts say
                n_what = "failed" if le.state == "fail" else "were slow"
                n = le.f if le.state == "fail" else le.d
                win_s = (le.window_ms or LINE_SPECS[k].window_ms) // 1000
                items = [{"text": f"{n} of {le.n} checks {n_what} in the last {win_s} s",
                          "count": n, "ports": [], "tests": []}]
            failing.append({"line": k, "items": [dict(i, text=str(i["text"])[:512]) for i in items]})
    return {"schema": "exp.state/1", "probe": ev.probe, "site": ev.site, "at": iso_ms(ev.at), "live": live,
            "newest_s": None if ev.newest_s is None else round(ev.newest_s, 1),
            "cadence_s": None if ev.cadence_ms is None else round(ev.cadence_ms / 1000, 1),
            "verdict": v, "lines": out_lines, "failing": failing}


def state_lite(doc: Mapping[str, Any]) -> dict[str, Any]:
    """State-lite for GET states and SSE: probe, site, severity, headline, lines:[{key,state}]."""
    return {"probe": doc["probe"], "site": doc["site"], "severity": doc["verdict"]["severity"],
            "headline": doc["verdict"]["headline"],
            "lines": [{"key": x["key"], "state": x["state"]} for x in doc["lines"]]}


def beats_from_store(store: BeatStore, probe: str, from_ms: int, to_ms: int,
                     lines: Iterable[str] = LINE_KEYS) -> dict[str, Any]:
    out: dict[str, list[list[int]]] = {}
    for k in lines:
        bs, ts = store.line(k)
        import bisect
        lo, hi = bisect.bisect_left(ts, from_ms), bisect.bisect_right(ts, to_ms)
        out[k] = [[b.t, b.v] for b in bs[lo:hi]]
    return {"schema": "exp.beats/1", "probe": probe, "from": iso_ms(from_ms), "to": iso_ms(to_ms), "lines": out,
            "markers": []}


def marker_for(rec: Rec) -> dict[str, Any] | None:
    """A timeline marker from a drill / external-event record (text is probe data: clipped and cleaned)."""
    if rec.test == "drill":
        phase = rec.labels.get("phase", "")
        text = vt.fin(f"Drill {vt.clean(phase, 16)}: {vt.clean(rec.labels.get('type', ''), 32)}")
        return {"t": rec.ts, "kind": "drill", "text": text[:512], "ref": vt.clean(rec.labels.get("run", ""), 64)}
    if rec.test in ("ext_mist", "ext_ec"):
        who = "Mist" if rec.test == "ext_mist" else "EC"
        kind, sev = vt.clean(rec.labels.get("kind", ""), 32), vt.clean(rec.labels.get("severity", ""), 16)
        text = vt.fin(f"{who} event: {kind} ({sev})")
        return {"t": rec.ts, "kind": "ext", "text": text[:512], "ref": ""}
    return None


def incident_markers(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        if r["folded_into"]:
            continue
        label = "Probe" if r["line"] == "probe" else LABELS.get(r["line"], r["line"])
        words = {"down": "down", "again": "failing again", "flapping": "flapping", "back": "back"}
        what = words.get(r["kind"], r["kind"])
        t = r["end_ms"] if r["kind"] == "back" and r["end_ms"] else r["start_ms"]
        out.append({"t": int(t), "kind": "incident", "text": f"{label} {what}", "ref": r["id"]})
    return sorted(out, key=lambda m: (m["t"], m["ref"]))


# ----------------------------------------------------------------------------------------- DB loading
def load_records(store: Store, probe: str, from_ms: int, to_ms: int, tests: Iterable[str] | None = None,
                 limit: int = MAX_LOAD_RECORDS) -> list[Rec]:
    """Records of one probe in [from_ms, to_ms] from SQLite, ordered, bounded."""
    wanted = list(tests) if tests is not None else sorted({s.test for s in STREAMS.values()})
    out: list[Rec] = []
    for test in wanted:
        after: tuple[int, str] | None = None
        while len(out) < limit:
            rows = store.read_records(probe, from_ms, to_ms, test=test, limit=5000, after=after)
            for _ts, rid, body in rows:
                try:
                    r = Rec.from_dict(json.loads(body))
                except ValueError:
                    r = None
                if r is not None:
                    r.id = r.id or rid
                    out.append(r)
            if len(rows) < 5000:
                break
            after = (rows[-1][0], rows[-1][1])
    return out


def evaluate_from_store(store: Store, probe: str, site: str, at_ms: int, history_ms: int = HISTORY_MS) -> Evaluation:
    """Time travel: evaluation purely from the records in [at - history, at]."""
    bs = BeatStore()
    bs.extend(load_records(store, probe, at_ms - history_ms, at_ms))
    newest = _newest_before(store, probe, at_ms)
    if newest is not None:
        bs.add_ts(newest)
    return evaluate(bs, at_ms, probe=probe, site=site)


def _newest_before(store: Store, probe: str, at_ms: int) -> int | None:
    with store.reader() as conn:
        row = conn.execute("SELECT MAX(ts_ms) FROM records WHERE probe=? AND ts_ms<=?", (probe, at_ms)).fetchone()
    return int(row[0]) if row and row[0] is not None else None


# ------------------------------------------------------------------------------------------- the sink
class StoreSink:
    """Incident sink backed by SQLite (rows, rules-state checkpoints in `meta`) and the webhook sender."""

    def __init__(self, store: Store, sender: WebhookSender | None = None,
                 on_incident: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.store, self.sender, self.on_incident = store, sender, on_incident

    def record(self, row: dict[str, Any]) -> None:
        self.store.insert_incident(row)
        if self.on_incident is not None:
            try:
                self.on_incident(row)
            except Exception:  # noqa: BLE001
                log.exception("incident listener failed")

    def end(self, ids: list[str], end_ms: int) -> None:
        self.store.end_incidents(ids, end_ms)

    def page(self, message: dict[str, Any]) -> None:
        if self.sender is not None:
            self.sender.post(message)

    def save_state(self, probe: str, doc: str) -> None:
        self.store.set_meta(f"incidents:{probe}", doc)


class _DeferredSink:
    """Incident sink used inside the engine lock: SQLite and webhook work is queued and run after the lock is
    released, so ingest threads (which take the lock to feed the ring buffer) never wait for the database."""

    def __init__(self, real: StoreSink) -> None:
        self.real = real
        self.pending: list[Callable[[], None]] = []

    def record(self, row: dict[str, Any]) -> None:
        self.pending.append(lambda: self.real.record(row))

    def end(self, ids: list[str], end_ms: int) -> None:
        self.pending.append(lambda: self.real.end(ids, end_ms))

    def page(self, message: dict[str, Any]) -> None:
        self.pending.append(lambda: self.real.page(message))

    def save_state(self, probe: str, doc: str) -> None:
        self.pending.append(lambda: self.real.save_state(probe, doc))

    def flush(self) -> None:
        todo, self.pending = self.pending, []
        for fn in todo:
            try:
                fn()
            except Exception:  # noqa: BLE001 - one failed write must not lose the rest or stop the tick
                log.exception("incident write failed")


# ------------------------------------------------------------------------------------------- the engine
class RulesEngine:
    def __init__(self, config: Any, store: Store, *, sender: WebhookSender | None = None,
                 clock: Callable[[], float] = time.time, tick_s: float = TICK_S,
                 history_ms: int = HISTORY_MS, min_gap_s: float = MIN_GAP_S,
                 wake_on_ingest: bool = True) -> None:
        self.config, self.store, self.clock, self.tick_s, self.history_ms = config, store, clock, tick_s, history_ms
        alerts = dict(getattr(config, "alerts", {}) or {})
        self.tz = alerts.get("timezone", "UTC")
        self.voice = alerts.get("voice", "sysadmin")
        self.edge_label = getattr(config, "edge_label", "EC")
        self.lines: tuple[str, ...] = tuple(k for k in LINE_KEYS if k in getattr(config, "lines", LINE_KEYS))
        self.icfg = IncidentConfig.from_collector(config)
        self._events: list[Callable[[str, dict[str, Any]], None]] = []
        self.sink = StoreSink(store, sender, on_incident=self._on_incident_row)
        self._defer = _DeferredSink(self.sink)
        self._lock = threading.RLock()
        self._buffers: dict[str, BeatStore] = {}
        self._incidents: dict[str, ProbeIncidents] = {}
        self._cache: dict[str, Evaluation] = {}
        self._docs: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {}
        self._announced: dict[tuple[str, str], int] = {}
        self._lite: dict[str, dict[str, Any]] = {}
        self._seq = 0
        self.eval_ms = 0.0
        self._eval_samples: collections.deque[float] = collections.deque(maxlen=300)
        self.last_tick: float | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.min_gap_s = min_gap_s
        self.wake_on_ingest = wake_on_ingest
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self.warm()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="rules", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def warm(self) -> None:
        """Fill the ring buffers from SQLite and restore each probe's open incidents."""
        now = int(self.clock() * 1000)
        for pid, entry in self.config.probes.items():
            bs = BeatStore()
            try:
                bs.extend(load_records(self.store, pid, now - self.history_ms, now))
                newest = self.store.newest_ts_ms(pid)
                if newest is not None and newest <= now + 60_000:
                    bs.add_ts(newest)
            except Exception:  # noqa: BLE001 - a bad database must not stop the collector starting
                log.exception("cannot warm the rules buffer of %s", pid)
            with self._lock:
                self._buffers[pid] = bs
                self._incidents[pid] = ProbeIncidents(pid, entry.site, self.icfg, self._defer, label=entry.label,
                                                      state=self._load_state(pid))

    def _load_state(self, probe: str) -> dict[str, Any] | None:
        try:
            raw = self.store.get_meta(f"incidents:{probe}")
            return json.loads(raw) if raw else None
        except (ValueError, OSError):
            log.warning("incident state of %s is unreadable; starting clean", probe)
            return None

    def _loop(self) -> None:
        """Tick every `tick_s`, or sooner (but at most every `min_gap_s`) when records arrive, so a state
        change reaches the dashboard within about a second of the batch that caused it."""
        last = 0.0
        while not self._stop.is_set():
            self._wake.wait(self.tick_s)
            if self._stop.is_set():
                return
            gap = self.min_gap_s - (time.monotonic() - last)
            if gap > 0 and self._wake.is_set():
                self._stop.wait(gap)
            self._wake.clear()
            last = time.monotonic()
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - judgement must keep running
                log.exception("rules tick failed")

    # --------------------------------------------------------------------------------------- feeding
    def observe(self, records: Iterable[exp_schema.Measurement]) -> None:
        """Ingest observer: accepted records go to their probe's ring buffer."""
        by: dict[str, list[Rec]] = {}
        for m in records:
            r = Rec.from_measurement(m)
            if r is not None:
                by.setdefault(m.probe, []).append(r)
        for pid, recs in by.items():
            with self._lock:
                buf = self._buffers.get(pid)
                if buf is None:
                    if pid not in self.config.probes:
                        continue
                    buf = self._buffers[pid] = BeatStore()
                for r in recs:
                    buf.add(r)
        if self.wake_on_ingest:
            self._wake.set()

    # ------------------------------------------------------------------------------------------ tick
    def tick(self, now_ms: int | None = None) -> None:
        t0 = time.perf_counter()
        now = int(self.clock() * 1000) if now_ms is None else now_ms
        for pid, entry in self.config.probes.items():
            with self._lock:
                buf = self._buffers.setdefault(pid, BeatStore())
                inc = self._incidents.get(pid)
                if inc is None:
                    inc = self._incidents[pid] = ProbeIncidents(pid, entry.site, self.icfg, self._defer,
                                                                label=entry.label, state=self._load_state(pid))
                buf.trim(now - self.history_ms)
                ev = evaluate(buf, now, probe=pid, site=entry.site)
                self._cache[pid] = ev
                self._seq += 1
                try:
                    inc.tick(ev, now)
                except Exception:  # noqa: BLE001 - one probe's bad day must not stop the others
                    log.exception("incident engine failed for %s", pid)
            self._defer.flush()                                  # SQLite + webhooks, outside the lock
            self._publish(pid, ev)
        self.eval_ms = (time.perf_counter() - t0) * 1000.0
        self._eval_samples.append(self.eval_ms)
        self.last_tick = self.clock()

    def _publish(self, pid: str, ev: Evaluation) -> None:
        if not self._events:
            return
        doc = self.state(pid)
        lite = state_lite(doc)
        if self._lite.get(pid) != lite:
            self._lite[pid] = lite
            self._emit("state", lite)
        for k in self.lines:
            bs = ev.lines[k].beats
            last = self._announced.get((pid, k))
            for b in bs[-20:]:
                if b.t <= ev.at and (last is None or b.t > last) and b.v != 3:
                    self._emit("beat", {"probe": pid, "line": k, "t": b.t, "v": b.v})
                    last = b.t
            if last is not None:
                self._announced[(pid, k)] = last

    def eval_ms_p95(self) -> float:
        xs = sorted(self._eval_samples)
        return round(xs[min(len(xs) - 1, int(len(xs) * 0.95))], 2) if xs else 0.0

    # ---------------------------------------------------------------------------------- subscriptions
    def subscribe(self, cb: Callable[[str, dict[str, Any]], None]) -> None:
        """cb(kind, payload): kind is `state` (State-lite), `beat` ({probe,line,t,v}) or `incident`."""
        self._events.append(cb)

    def _emit(self, kind: str, payload: dict[str, Any]) -> None:
        for cb in list(self._events):
            try:
                cb(kind, payload)
            except Exception:  # noqa: BLE001
                log.exception("rules listener failed")

    def _on_incident_row(self, row: dict[str, Any]) -> None:
        if self._events:
            self._emit("incident", incident_doc(row, self.icfg.board_url))

    # ------------------------------------------------------------------------------------------ reads
    def evaluation(self, probe: str, at_ms: int | None = None) -> Evaluation | None:
        """The live Evaluation (at None) or a time-travel evaluation from SQLite. None: unknown probe."""
        entry = self.config.probes.get(probe)
        if entry is None:
            return None
        if at_ms is None:
            with self._lock:
                ev = self._cache.get(probe)
            if ev is not None:
                return ev
            now = int(self.clock() * 1000)
            with self._lock:
                buf = self._buffers.setdefault(probe, BeatStore())
                return evaluate(buf, now, probe=probe, site=entry.site)
        return evaluate_from_store(self.store, probe, entry.site, at_ms, self.history_ms)

    def state(self, probe: str, at_ms: int | None = None, voice: str | None = None) -> dict[str, Any] | None:
        ev = self.evaluation(probe, at_ms)
        if ev is None:
            return None
        v = voice if voice in vt.VOICES else self.voice
        if at_ms is None:
            hit = self._docs.get((probe, v))
            if hit is not None and hit[0] == self._seq and self._cache.get(probe) is ev:
                return hit[1]
        if at_ms is None:       # reads the shared ring buffer: serialise with the feeders
            with self._lock:
                doc = state_doc(ev, voice=v, tz=self.tz, edge_label=self.edge_label, live=True, lines=self.lines)
                self._docs[(probe, v)] = (self._seq, doc)
            return doc
        return state_doc(ev, voice=v, tz=self.tz, edge_label=self.edge_label, live=False, lines=self.lines)

    def states(self, site: str | None = None, at_ms: int | None = None,
               voice: str | None = None) -> list[dict[str, Any]]:
        out = []
        for pid, entry in sorted(self.config.probes.items()):
            if site is not None and entry.site != site:
                continue
            doc = self.state(pid, at_ms, voice)
            if doc is not None:
                out.append(state_lite(doc))
        return out

    def cadence_s(self, probe: str) -> float | None:
        """The probe's measured heartbeat cadence (CR-heartbeat-cadence), None while unknown."""
        doc = self.state(probe)
        v = doc.get("cadence_s") if doc else None
        return float(v) if isinstance(v, (int, float)) else None

    def severity(self, probe: str) -> str:
        """ok | warn | fail | unknown for the probe list."""
        doc = self.state(probe)
        return str(doc["verdict"]["severity"]) if doc else "unknown"

    def beats(self, probe: str, from_ms: int, to_ms: int) -> dict[str, Any] | None:
        """exp.beats/1 for [from, to] (the caller enforces the 6 h limit) with incident/drill/ext markers."""
        entry = self.config.probes.get(probe)
        if entry is None:
            return None
        bs = BeatStore()
        bs.extend(load_records(self.store, probe, from_ms - MAX_WINDOW_MS, to_ms))
        doc = beats_from_store(bs, probe, from_ms, to_ms, self.lines)
        markers = [m for r in load_records(self.store, probe, from_ms, to_ms, tests=EXTRA_TESTS)
                   if (m := marker_for(r)) is not None]
        markers += incident_markers(self.store.list_incidents(probe=probe, from_ms=from_ms, to_ms=to_ms, limit=200))
        doc["markers"] = sorted(markers, key=lambda m: (m["t"], m["kind"], m["ref"]))[:1000]
        return doc
