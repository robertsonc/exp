"""VictoriaMetrics writer (03-collector.md section 4) and self-telemetry (section 9).

Accepted records' series are queued in memory and POSTed to ``/api/v1/import`` (JSON lines
``{"metric":{"__name__":..,labels},"values":[v],"timestamps":[ms]}``) every 1 s or 5,000 points.
When VM is down or slow the batch is persisted to SQLite ``vm_backlog`` (never dropped), delivery is
retried with exponential backoff, and on recovery the backlog is drained oldest-first. A VM answer
of 4xx other than 429 means the data itself is bad: that chunk is dropped and logged (it would
otherwise block the drain forever). Every network call has a timeout.
"""
from __future__ import annotations

import collections
import http.client
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .store import Store, StoreError

log = logging.getLogger(__name__)

FLUSH_INTERVAL_S = 1.0
FLUSH_POINTS = 5000
QUEUE_BACKPRESSURE_POINTS = 200_000       # section 3: ingest answers 429 above this
MAX_BACKLOG_POINTS = 20_000_000           # disk guard: ingest answers 429 above this
HTTP_TIMEOUT_S = 10.0
BACKOFF_MIN_S = 1.0
BACKOFF_MAX_S = 60.0
DRAIN_CHUNK_BYTES = 1 << 20
DRAIN_BUDGET_S = 5.0                      # per cycle, so a huge backlog never starves live flushes


def point_to_line(name: str, labels: Mapping[str, str], value: float, ts_ms: int) -> str:
    metric: dict[str, str] = dict(labels)
    metric["__name__"] = name
    return json.dumps({"metric": metric, "values": [value], "timestamps": [ts_ms]},
                      separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def series_to_lines(series: Iterable[Mapping[str, Any]]) -> list[str]:
    """Measurement.series() dicts -> import lines."""
    return [point_to_line(s["metric"], s["labels"], s["value"], s["timestamp_ms"]) for s in series]


class VMWriter:
    def __init__(self, base_url: str, store: Store, *, flush_interval: float = FLUSH_INTERVAL_S,
                 flush_points: int = FLUSH_POINTS, timeout: float = HTTP_TIMEOUT_S,
                 backoff_min: float = BACKOFF_MIN_S, backoff_max: float = BACKOFF_MAX_S,
                 queue_limit: int = QUEUE_BACKPRESSURE_POINTS, backlog_limit: int = MAX_BACKLOG_POINTS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        host_port = base_url.split("://", 1)[-1].rstrip("/")
        host, _, port = host_port.rpartition(":")
        self.host, self.port = host, int(port)
        self.store = store
        self.flush_interval = flush_interval
        self.flush_points = flush_points
        self.timeout = timeout
        self.backoff_min, self.backoff_max = backoff_min, backoff_max
        self.queue_limit, self.backlog_limit = queue_limit, backlog_limit
        self._clock = clock
        self._cond = threading.Condition()
        self._lines: collections.deque[str] = collections.deque()
        self._oldest_enq: float | None = None
        self._stop = False
        self._thread: threading.Thread | None = None
        self._backlog_points = 0
        self._backoff = 0.0
        self._next_attempt = 0.0
        self._last_health_check = float("-inf")
        self.up = False
        self.last_success: float | None = None
        self.points_sent = 0
        self.points_dropped = 0
        self.failures = 0

    # --- public -------------------------------------------------------------------------------
    @property
    def queue_points(self) -> int:
        return len(self._lines)

    @property
    def backlog_points(self) -> int:
        return self._backlog_points

    def backpressure(self) -> bool:
        return len(self._lines) > self.queue_limit or self._backlog_points > self.backlog_limit

    def lag_s(self) -> float:
        """Seconds the oldest undelivered point has waited (queue) or since VM last accepted data."""
        now = self._clock()
        lag = 0.0
        if self._oldest_enq is not None:
            lag = now - self._oldest_enq
        if self._backlog_points > 0 and self.last_success is not None:
            lag = max(lag, now - self.last_success)
        return max(0.0, lag)

    def enqueue_lines(self, lines: list[str]) -> None:
        if not lines:
            return
        with self._cond:
            if self._oldest_enq is None:
                self._oldest_enq = self._clock()
            self._lines.extend(lines)
            if len(self._lines) >= self.flush_points:
                self._cond.notify()

    def enqueue(self, series: Iterable[Mapping[str, Any]]) -> None:
        self.enqueue_lines(series_to_lines(series))

    def start(self) -> None:
        if self._thread is not None:
            return
        try:
            self._backlog_points = self.store.backlog_points()
        except (StoreError, Exception):  # noqa: BLE001
            log.exception("cannot count vm_backlog")
        if self._backlog_points:
            log.info("vm_backlog holds %d points from a previous run", self._backlog_points)
        self._stop = False
        self._thread = threading.Thread(target=self._run, name="vm-writer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop; anything still queued in memory is persisted to the backlog (not lost)."""
        with self._cond:
            self._stop = True
            self._cond.notify_all()
        t = self._thread
        if t is not None:
            t.join(timeout=15)
            self._thread = None
        leftover = self._take(len(self._lines))
        if leftover:
            self._persist(leftover)

    def flush_now(self) -> None:
        """Test hook: wake the loop immediately."""
        with self._cond:
            self._next_attempt = 0.0
            self._cond.notify()

    # --- loop ---------------------------------------------------------------------------------
    def _take(self, n: int) -> list[str]:
        with self._cond:
            batch = [self._lines.popleft() for _ in range(min(n, len(self._lines)))]
            if not self._lines:
                self._oldest_enq = None
        return batch

    def _run(self) -> None:
        while True:
            with self._cond:
                if not self._stop and len(self._lines) < self.flush_points:
                    self._cond.wait(self.flush_interval)
                if self._stop:
                    return
            try:
                self._cycle()
            except Exception:  # noqa: BLE001 - the writer must never die
                log.exception("vm writer cycle failed")
                time.sleep(0.5)

    def _cycle(self) -> None:
        now = self._clock()
        if self._backlog_points > 0 and now >= self._next_attempt:
            self._drain(now)
        while True:
            batch = self._take(self.flush_points)
            if not batch:
                break
            if self._clock() < self._next_attempt:
                self._persist(batch)
                continue
            if not self._post(batch):
                self._persist(batch)
                break
        if (not self._lines and self._backlog_points == 0
                and self._clock() - self._last_health_check >= 5.0):
            self._check_health()

    # --- delivery -----------------------------------------------------------------------------
    def _request(self, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            headers = {"Content-Type": "application/x-ndjson"} if body is not None else {}
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(65536)
            return resp.status, data
        finally:
            conn.close()

    def _post(self, lines: list[str]) -> bool:
        """True if VM took the data (or it was permanently unacceptable and was dropped)."""
        body = ("\n".join(lines) + "\n").encode("utf-8")
        try:
            status, data = self._request("POST", "/api/v1/import", body)
        except (OSError, http.client.HTTPException) as exc:
            self._fail(f"{type(exc).__name__}: {exc}")
            return False
        if 200 <= status < 300:
            self._ok(len(lines))
            return True
        if 400 <= status < 500 and status not in (408, 429):
            self.points_dropped += len(lines)
            log.error("VictoriaMetrics refused %d points (HTTP %d): %s; dropped", len(lines), status,
                      data[:200].decode("utf-8", "replace"))
            self._ok(0)
            return True
        self._fail(f"HTTP {status}")
        return False

    def _ok(self, n: int) -> None:
        if not self.up:
            log.info("VictoriaMetrics reachable again")
        self.up = True
        self._backoff = 0.0
        self._next_attempt = 0.0
        self.last_success = self._clock()
        self.points_sent += n

    def _fail(self, why: str) -> None:
        self.failures += 1
        if self.up or self._backoff == 0:
            log.warning("VictoriaMetrics unavailable (%s); buffering to SQLite", why)
        self.up = False
        self._backoff = min(self.backoff_max, max(self.backoff_min, self._backoff * 2))
        self._next_attempt = self._clock() + self._backoff

    def _persist(self, lines: list[str]) -> None:
        payload = "\n".join(lines) + "\n"
        try:
            self.store.backlog_append(payload)
        except Exception:  # noqa: BLE001
            log.exception("cannot persist %d points to vm_backlog; keeping them in memory", len(lines))
            with self._cond:
                self._lines.extendleft(reversed(lines))
                if self._oldest_enq is None:
                    self._oldest_enq = self._clock()
            time.sleep(0.5)
            return
        self._backlog_points += len(lines)

    def _drain(self, started: float) -> None:
        """Send backlog chunks oldest-first until empty, VM fails, or the time budget is spent."""
        while self._backlog_points > 0 and not self._stop:
            if self._clock() - started > DRAIN_BUDGET_S:
                return
            rows = self.store.backlog_peek(DRAIN_CHUNK_BYTES)
            if not rows:
                self._backlog_points = 0
                return
            lines = [ln for _, payload in rows for ln in payload.split("\n") if ln]
            if not self._post(lines):
                return
            self.store.backlog_delete_upto(rows[-1][0])
            self._backlog_points = max(0, self._backlog_points - len(lines))
        if self._backlog_points == 0:
            log.info("vm_backlog drained")

    def _check_health(self) -> None:
        self._last_health_check = self._clock()
        try:
            status, _ = self._request("GET", "/health")
        except (OSError, http.client.HTTPException) as exc:
            self._fail(f"{type(exc).__name__}: {exc}")
            return
        if status == 200:
            self._ok(0)
        else:
            self._fail(f"/health HTTP {status}")

    # --- queries used by the monitor ----------------------------------------------------------
    def get_json(self, path: str) -> Any:
        status, data = self._request("GET", path)
        if status != 200:
            raise OSError(f"HTTP {status}")
        return json.loads(data.decode("utf-8"))

    def get_text(self, path: str, max_bytes: int = 4 << 20) -> str:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=min(self.timeout, 3.0))
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            if resp.status != 200:
                raise OSError(f"HTTP {resp.status}")
            return resp.read(max_bytes).decode("utf-8", "replace")
        finally:
            conn.close()


class SelfTelemetry:
    """Periodically writes the collector's own series straight into VM (section 9)."""

    def __init__(self, writer: VMWriter, *, interval: float = 15.0,
                 clock_ms: Callable[[], int] | None = None) -> None:
        self.writer = writer
        self.interval = interval
        self._clock_ms = clock_ms or (lambda: int(time.time() * 1000))
        self.sources: list[Callable[[], list[tuple[str, dict[str, str], float]]]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def add_source(self, fn: Callable[[], list[tuple[str, dict[str, str], float]]]) -> None:
        """`fn()` returns [(metric_name, labels, value)]."""
        self.sources.append(fn)

    def emit_once(self) -> int:
        ts = self._clock_ms()
        lines: list[str] = []
        for fn in self.sources:
            try:
                for name, labels, value in fn():
                    lines.append(point_to_line(name, labels, float(value), ts))
            except Exception:  # noqa: BLE001
                log.exception("telemetry source failed")
        self.writer.enqueue_lines(lines)
        return len(lines)

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="telemetry", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.emit_once()
