"""The correlation loop (12 section 5, 01 section 14.6).

Poll the collector feed every ``poll_interval_s`` (the runner token has no SSE route: the feed is the contract), wait until a
test's window has closed, resolve identity (NAT guard), run every configured connector concurrently with a deadline, normalize to
``exp.evidence/1`` (validated and bounded), POST one document per kind, then ``evidence/complete``.

Idempotency: evidence replaces per kind until final and ``complete`` is tolerant of "already final"; the local ``done`` table
(``runner.db``) additionally stops a restarted runner from touching tests it already finished, so evidence is never duplicated.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import ipaddress
import logging
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from exp_common import schema as exp_schema

from . import evidence as ev
from .collector_client import AuthError, CollectorClient, CollectorError
from .config import RunnerConfig
from .connectors import CallBudget, Connector, Context, EvidenceResult, PullerStats, SpeedtestRef, Window, merge_cross_kind
from .identity import Identity, IdentityResolver
from .ring import Ring

log = logging.getLogger(__name__)

READY_GRACE_S = 2.0
RESYNC_S = 60.0
MAX_ATTEMPTS = 8
DONE_KEEP_S = 7 * 86400
METRIC_KEEP = 2000


class StateStore:
    """``done`` table: tests whose evidence this runner completed (restart idempotency)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None

    def open(self) -> StateStore:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=10)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS done(test_id TEXT PRIMARY KEY, completed_at REAL NOT NULL)")
        self._db = db
        return self

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    def _conn(self) -> sqlite3.Connection:
        if self._db is None:
            raise RuntimeError("state store is not open")
        return self._db

    def is_done(self, test_id: str) -> bool:
        with self._lock:
            return self._conn().execute("SELECT 1 FROM done WHERE test_id=?", (test_id,)).fetchone() is not None

    def mark_done(self, test_id: str, now: float) -> None:
        with self._lock:
            db = self._conn()
            db.execute("INSERT OR REPLACE INTO done(test_id, completed_at) VALUES(?,?)", (test_id, now))
            db.execute("DELETE FROM done WHERE completed_at<?", (now - DONE_KEEP_S,))


@dataclasses.dataclass
class _Pending:
    item: dict[str, Any]
    ready_at: float
    attempts: int = 0
    next_at: float = 0.0


def device_tokens(mac: str | None, hostname: str | None) -> list[str]:
    """Every spelling of a device's MAC (colon, dash, Cisco dotted, bare; either case) plus its hostname, for the ring scrub."""
    out: list[str] = []
    if mac:
        bare = "".join(c for c in mac.lower() if c in "0123456789abcdef")
        if len(bare) == 12:
            pairs = [bare[i:i + 2] for i in range(0, 12, 2)]
            out += [":".join(pairs), "-".join(pairs), bare, ".".join(bare[i:i + 4] for i in range(0, 12, 4))]
    if hostname and len(hostname.strip()) >= 3:
        out.append(hostname.strip())
    return out


def _iso_epoch(text: str) -> float:
    return exp_schema.iso_to_ms(text) / 1000.0


def to_testref(item: dict[str, Any], cfg: RunnerConfig) -> SpeedtestRef:
    ip = str(ipaddress.ip_address(item["client_ip"]))
    started, ended = _iso_epoch(item["started"]), _iso_epoch(item["ended"])
    w = item.get("window") or {}
    wf = _iso_epoch(w["from"]) if w.get("from") else started - cfg.window_before_s
    wt = _iso_epoch(w["to"]) if w.get("to") else ended + cfg.window_after_s
    window = Window(wf, wt, ev._fmt(wf), ev._fmt(wt))
    return SpeedtestRef(id=item["id"], site=str(item.get("site", cfg.site)), started=started, ended=ended, client_ip=ip, window=window,
                   zone_hint=item.get("zone_hint"), zone=item.get("zone") or "unresolved", zone_source=item.get("zone_source") or "unresolved")


class Correlator:
    def __init__(self, cfg: RunnerConfig, client: CollectorClient, ring: Ring, resolver: IdentityResolver,
                 connectors: Sequence[Connector], state: StateStore, *, now_fn: Callable[[], float] = time.time,
                 workers: int = 4) -> None:
        self.cfg, self.client, self.ring, self.resolver = cfg, client, ring, resolver
        self.connectors = list(connectors)
        self.state = state
        self.now = now_fn
        self.workers = workers
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._inflight: set[str] = set()
        self._cursor: str | None = None
        self._last_resync = 0.0
        self._completions: deque[float] = deque(maxlen=METRIC_KEEP)
        self._lags: deque[tuple[float, float]] = deque(maxlen=METRIC_KEEP)
        self.puller_stats: dict[str, PullerStats] = {c.name: PullerStats(c.name) for c in self.connectors}
        self.feed_ok: float | None = None
        self.feed_error: str | None = None
        self.auth_failed = False
        self.posted = 0
        self._conn_pool = concurrent.futures.ThreadPoolExecutor(max_workers=16, thread_name_prefix="connector")
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="correlate")

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
        self._conn_pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------------------------ discovery
    def poll_once(self) -> int:
        """Fetch new tests from the feed; returns how many were queued."""
        now = self.now()
        if now - self._last_resync >= RESYNC_S:
            self._cursor, self._last_resync = None, now
        try:
            items, nxt = self.client.feed(after=self._cursor, limit=50, wait_s=0)
        except AuthError as exc:
            self.auth_failed, self.feed_error = True, str(exc)
            log.error("collector refused the runner token: %s", exc)
            return 0
        except CollectorError as exc:
            self.feed_error = str(exc)
            log.warning("feed poll failed: %s", exc)
            return 0
        self.auth_failed, self.feed_error, self.feed_ok = False, None, now
        if nxt:
            self._cursor = nxt
        queued = 0
        for it in items:
            tid = it["id"]
            with self._lock:
                if tid in self._pending or tid in self._inflight:
                    continue
            if self.state.is_done(tid):
                continue
            try:
                ref = to_testref(it, self.cfg)
            except (KeyError, ValueError, TypeError) as exc:
                log.warning("feed item %r skipped: %s", str(tid)[:40], type(exc).__name__)
                continue
            with self._lock:
                self._pending[tid] = _Pending(it, ref.window.to_ts + READY_GRACE_S)
            queued += 1
        return queued

    # ------------------------------------------------------------------------------------ processing
    def process_ready(self, wait: bool = True) -> int:
        """Start every test that is due; returns the number started. ``wait`` blocks until they finish (tests, shutdown)."""
        now = self.now()
        due: list[_Pending] = []
        with self._lock:
            for tid, p in list(self._pending.items()):
                if p.ready_at <= now and p.next_at <= now and tid not in self._inflight:
                    due.append(p)
                    self._inflight.add(tid)
        futs = [self._pool.submit(self._run_one, p) for p in due]
        if wait:
            concurrent.futures.wait(futs, timeout=300)
        return len(due)

    def tick(self, wait: bool = True) -> int:
        self.poll_once()
        return self.process_ready(wait=wait)

    def _run_one(self, p: _Pending) -> None:
        tid = p.item["id"]
        try:
            self.process(p.item)
        except AuthError as exc:
            self.auth_failed = True
            log.error("test %s: collector refused the runner token: %s", tid, exc)
            self._reschedule(p, 60.0, final=False)
        except CollectorError as exc:
            log.warning("test %s: %s", tid, exc)
            self._reschedule(p, min(5.0 * (2 ** p.attempts), 120.0))
        except Exception:  # noqa: BLE001 - never lose the loop to one test
            log.exception("test %s: correlation failed", tid)
            self._reschedule(p, min(5.0 * (2 ** p.attempts), 120.0))
        else:
            with self._lock:
                self._pending.pop(tid, None)
        finally:
            with self._lock:
                self._inflight.discard(tid)

    def _reschedule(self, p: _Pending, delay: float, final: bool = True) -> None:
        if final:
            p.attempts += 1
        if p.attempts >= MAX_ATTEMPTS:
            log.error("test %s: giving up locally after %d attempts (it stays in the collector feed)", p.item["id"], p.attempts)
            with self._lock:
                self._pending.pop(p.item["id"], None)
            return
        p.next_at = self.now() + delay

    def _run_connectors(self, ctx: Context) -> dict[str, EvidenceResult]:
        out: dict[str, EvidenceResult] = {}
        futs: dict[concurrent.futures.Future[list[EvidenceResult]], Connector] = {}
        for c in self.connectors:
            if not c.configured():
                continue
            futs[self._conn_pool.submit(c.collect, ctx)] = c
        started = time.monotonic()
        for fut, c in futs.items():
            stats = self.puller_stats.setdefault(c.name, PullerStats(c.name))
            try:
                results = fut.result(timeout=max(0.05, c.timeout_s - (time.monotonic() - started)))
            except concurrent.futures.TimeoutError:
                log.warning("connector %s timed out after %.0fs", c.name, c.timeout_s)
                stats.error(self.now())
                self._mark(out, c, "error")
                continue
            except Exception as exc:  # noqa: BLE001
                log.warning("connector %s failed: %s", c.name, type(exc).__name__)
                stats.error(self.now())
                self._mark(out, c, "error")
                continue
            got = False
            for r in results:
                if r.kind in ev.KINDS and r.status in ev.STATUSES:
                    out[r.kind] = r
                    got = got or r.status in ("ok", "partial")
            if got or not any(r.status == "error" for r in results):
                stats.ok(self.now())
            else:
                stats.error(self.now())
            for k in c.kinds:
                if k not in out:
                    out[k] = EvidenceResult(k, ev.DEFAULT_SOURCE[k], "unavailable")
        merge_cross_kind(out)
        return out

    @staticmethod
    def _mark(out: dict[str, EvidenceResult], c: Connector, status: str) -> None:
        for k in c.kinds:
            out[k] = EvidenceResult(k, ev.DEFAULT_SOURCE.get(k, "exp"), status)

    def build_documents(self, test: SpeedtestRef, ident: Identity, ctx: Context) -> list[dict[str, Any]]:
        now = self.now()
        w = test.window.as_dict()
        results = self._run_connectors(ctx)
        docs = [ev.envelope(test.id, "identity", ident.source, ident.evidence_status(), ident.evidence_data(), w, now, ident.raw_refs)]
        for kind in ev.KINDS[1:]:
            r = results.get(kind)
            if r is None:
                docs.append(ev.placeholder(test.id, kind, "unavailable", w, now))
                continue
            docs.append(ev.envelope(test.id, kind, r.source, r.status, r.data if r.status in ("ok", "partial") else {}, w, now, r.raw_refs))
        checked: list[dict[str, Any]] = []
        for d in docs:
            errs = ev.validation_errors(d)
            if errs:
                log.warning("evidence %s/%s failed schema validation (%s); posting an error placeholder", test.id, d["kind"], errs[0])
                d = ev.placeholder(test.id, d["kind"], "error", w, now, d["source"])
                if ev.validation_errors(d):          # an impossible source for the kind: fall back to its default
                    d = ev.placeholder(test.id, d["kind"], "error", w, now)
            checked.append(d)
        return ev.fit_total(checked)

    def process(self, item: dict[str, Any]) -> None:
        test = to_testref(item, self.cfg)
        ctx_budgets: dict[str, CallBudget] = {"mist": CallBudget(int((self.cfg.mist or {}).get("max_calls_per_test", 6)))}
        ident = self.resolver.resolve(test, test.window, ctx_budgets["mist"])
        ctx = Context(test, test.window, ident, self.ring, self.cfg, self.now, ctx_budgets)
        docs = self.build_documents(test, ident, ctx)
        for d in docs:
            r = self.client.post_evidence(test.id, d)
            self.posted += 1
            if r.get("final"):
                log.info("test %s: evidence already final on the collector", test.id)
                self.state.mark_done(test.id, self.now())
                return
        delivered = [d["kind"] for d in docs if d["status"] in ("ok", "partial")]
        statuses = [d["status"] for d in docs]
        if all(s == "error" for s in statuses):
            status = "failed"
        elif any(s in ("error", "partial") for s in statuses):
            status = "partial"
        else:
            status = "ok"
        self.client.complete(test.id, delivered, status)
        done_at = self.now()
        self.state.mark_done(test.id, done_at)
        with self._lock:
            self._completions.append(done_at)
            self._lags.append((done_at, max(0.0, done_at - test.ended)))
        if self.cfg.scrub_after_diagnosis:
            self.ring.delete_ip(test.client_ip)
            # lines that name the device without an IP (DHCPDISCOVER, ...) by its MAC in every spelling and its hostname (A6.6)
            self.ring.delete_mentions(device_tokens(ident.mac, ident.hostname), ip=test.client_ip)
        log.info("test %s correlated (%s, zone %s)", test.id, status, ident.zone)

    # ----------------------------------------------------------------------------------- metrics
    def metrics(self) -> dict[str, Any]:
        now = self.now()
        with self._lock:
            per_hour = sum(1 for t in self._completions if t > now - 3600)
            lags = sorted(lag for t, lag in self._lags if t > now - 3600)
            pending = len(self._pending)
        p95 = lags[min(len(lags) - 1, int(0.95 * len(lags)))] if lags else 0.0
        return {"correlations_per_hour": per_hour, "evidence_lag_s_p95": round(p95, 2), "pending_tests": pending}

    def pullers(self) -> list[dict[str, Any]]:
        now = self.now()
        return [s.as_dict(now) for s in self.puller_stats.values()]

    # -------------------------------------------------------------------------------------- loop
    def run(self, stop: threading.Event) -> None:
        interval = max(1, self.cfg.poll_interval_s)
        while not stop.is_set():
            try:
                self.tick(wait=False)
            except Exception:  # noqa: BLE001
                log.exception("correlation tick failed")
            stop.wait(interval)
