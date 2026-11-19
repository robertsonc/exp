"""Ingest pipeline (03-collector.md section 3, 01-contracts.md section 4).

Per batch: body limits -> bounded gunzip -> line-count cap -> per line: JSON parse (<= 64 KiB) ->
``Measurement.from_dict(require_id=True)`` (shared/SCHEMA.md rules) -> identity binding (probe =
token identity, site = that probe's configured site) -> time window -> durable dedupe via
``INSERT OR IGNORE`` on (probe, id). Only records that are in SQLite are ever counted as accepted;
their series are then queued for VictoriaMetrics and announced to observers (rules engine / SSE,
later steps). One bad line costs only itself.
"""
from __future__ import annotations

import collections
import json
import logging
import threading
import time
import zlib
from collections.abc import Callable
from typing import Any

from exp_common import config as exp_config
from exp_common import ids as exp_ids
from exp_common import schema as exp_schema

from .config import CollectorConfig
from .store import RecordRow, Store
from .vmwriter import VMWriter, series_to_lines

log = logging.getLogger(__name__)

MAX_DECOMPRESSED = 16 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
FUTURE_SLACK_S = 60
SQLITE_LAG_LIMIT_S = 5.0
RETRY_AFTER_VM_S = 5
RETRY_AFTER_SQLITE_S = 2


class IngestError(Exception):
    """A whole-request failure with its HTTP status and contract error code."""

    def __init__(self, status: int, code: str, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


class _TooLarge(Exception):
    pass


def gunzip_bounded(data: bytes, limit: int = MAX_DECOMPRESSED) -> bytes:
    """Decompress gzip (possibly several members) producing at most `limit` bytes; stops reading
    the moment the cap is exceeded (zip-bomb guard). Raises IngestError 413 / 400."""
    out: list[bytes] = []
    total = 0
    rest = data
    try:
        while rest:
            d = zlib.decompressobj(wbits=31)
            buf = rest
            while buf and not d.eof:
                chunk = d.decompress(buf, min(65536, limit - total + 1))
                total += len(chunk)
                if total > limit:
                    raise _TooLarge
                out.append(chunk)
                buf = d.unconsumed_tail
            if not d.eof:
                raise zlib.error("truncated gzip stream")
            rest = d.unused_data
    except _TooLarge:
        raise IngestError(413, "decompressed_too_large",
                          f"decompressed body exceeds {limit} bytes") from None
    except zlib.error:
        raise IngestError(400, "bad_gzip", "corrupt gzip body") from None
    return b"".join(out)


class IngestStats:
    """Thread-safe counters plus 1-second buckets for the last 5 minutes."""

    WINDOW_S = 300

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: collections.deque[list[float]] = collections.deque()  # [sec, acc, rej, dup, bytes]
        self.totals = {"accepted": 0, "duplicate": 0, "rejected": 0}
        self.bytes_total = 0
        self.requests_total = 0
        self.backpressure_total = 0

    def add(self, accepted: int, duplicates: int, rejected: int, nbytes: int) -> None:
        sec = int(self._clock())
        with self._lock:
            if not self._buckets or self._buckets[-1][0] != sec:
                self._buckets.append([sec, 0, 0, 0, 0])
            b = self._buckets[-1]
            b[1] += accepted
            b[2] += rejected
            b[3] += duplicates
            b[4] += nbytes
            self.totals["accepted"] += accepted
            self.totals["duplicate"] += duplicates
            self.totals["rejected"] += rejected
            self.bytes_total += nbytes
            self.requests_total += 1
            self._trim(sec)

    def _trim(self, sec: int) -> None:
        while self._buckets and self._buckets[0][0] <= sec - self.WINDOW_S:
            self._buckets.popleft()

    def window(self, seconds: int = 60) -> dict[str, float]:
        """Sums over the last `seconds` seconds."""
        sec = int(self._clock())
        acc = rej = dup = nbytes = 0.0
        with self._lock:
            self._trim(sec)
            for b in self._buckets:
                if b[0] > sec - seconds:
                    acc += b[1]
                    rej += b[2]
                    dup += b[3]
                    nbytes += b[4]
        return {"accepted": acc, "rejected": rej, "duplicates": dup, "bytes": nbytes}


Observer = Callable[[list[exp_schema.Measurement]], None]


class Ingestor:
    def __init__(self, config: CollectorConfig, store: Store, vm: VMWriter, *,
                 stats: IngestStats | None = None, now: Callable[[], float] = time.time) -> None:
        self.config = config
        self.store = store
        self.vm = vm
        self.stats = stats or IngestStats(now)
        self._now = now
        self._observers: list[Observer] = []
        self._seen_lock = threading.Lock()
        self.last_seen: dict[str, float] = {}      # probe -> wall time of last delivery
        self.last_agent_ver: dict[str, str] = {}
        self.clock_offset_ms: dict[str, float] = {}
        self.newest_ts_ms: dict[str, int] = {}
        self._rate: dict[str, collections.deque[tuple[int, int]]] = {}   # probe -> (second, accepted) for 60 s

    # --- observers ----------------------------------------------------------------------------
    def subscribe(self, callback: Observer) -> None:
        """Register `callback(records)`; called from the ingest thread after the records are stored.
        Must be fast and non-blocking; exceptions are logged and swallowed."""
        self._observers.append(callback)

    # --- back-pressure ------------------------------------------------------------------------
    def check_backpressure(self) -> None:
        if self.vm.backpressure():
            self.stats.backpressure_total += 1
            raise IngestError(429, "rate_limited", "VictoriaMetrics write queue is full",
                              {"Retry-After": str(RETRY_AFTER_VM_S)})
        if self.store.lag_s() > SQLITE_LAG_LIMIT_S:
            self.stats.backpressure_total += 1
            raise IngestError(429, "rate_limited", "record store is lagging",
                              {"Retry-After": str(RETRY_AFTER_SQLITE_S)})

    # --- the pipeline -------------------------------------------------------------------------
    def process(self, identity: str, body: bytes, wire_bytes: int | None = None) -> dict[str, Any]:
        """Process a decoded NDJSON body for an authenticated probe identity."""
        self.check_backpressure()
        if not body or not body.strip():
            raise IngestError(400, "not_ndjson", "empty body")
        if b"\x00" in body:
            raise IngestError(400, "not_ndjson", "body contains NUL bytes")
        nlines = body.count(b"\n") + (0 if body.endswith(b"\n") else 1)
        if nlines > self.config.max_records:
            raise IngestError(400, "too_many_lines", f"more than {self.config.max_records} lines")
        raw_lines = body.split(b"\n")
        if raw_lines and raw_lines[-1] == b"":
            raw_lines.pop()

        now = self._now()
        site = self.config.site_of(identity)
        rejected: list[dict[str, Any]] = []
        pending: list[tuple[int, exp_schema.Measurement, str]] = []   # (line no, record, body json)
        for n, raw in enumerate(raw_lines, start=1):
            res = self._check_line(identity, site, raw, now)
            if isinstance(res, tuple):
                code, message, rid = res
                rejected.append({"line": n, "id": rid, "error": {"code": code, "message": message[:512]}})
            else:
                pending.append((n, res, json.dumps(res.to_dict(), separators=(",", ":"), ensure_ascii=False)))

        accepted: list[exp_schema.Measurement] = []
        duplicates = 0
        if pending:
            rows = [RecordRow(m.probe, m.id, exp_schema.iso_to_ms(m.ts), m.site, m.test, m.outcome, js)
                    for _, m, js in pending]
            try:
                inserted = self.store.insert_records(rows)
            except Exception as exc:  # noqa: BLE001 - nothing may be accepted unstored
                log.error("record store write failed: %s", type(exc).__name__)
                raise IngestError(503, "unavailable", "record store unavailable",
                                  {"Retry-After": "5"}) from None
            for (_, m, _js), is_new in zip(pending, inserted, strict=True):
                if is_new:
                    accepted.append(m)
                else:
                    duplicates += 1
        # durable first, then everything downstream
        if accepted:
            series: list[str] = []
            for m in accepted:
                series.extend(series_to_lines(m.series()))
            self.vm.enqueue_lines(series)
        self._note_seen(identity, accepted, duplicates)
        self.stats.add(len(accepted), duplicates, len(rejected),
                       wire_bytes if wire_bytes is not None else len(body))
        if accepted:
            for cb in list(self._observers):
                try:
                    cb(accepted)
                except Exception:  # noqa: BLE001
                    log.exception("ingest observer failed")
        return {"accepted": len(accepted), "duplicates": duplicates, "rejected": rejected,
                "server_time": exp_schema_iso(now)}

    def _check_line(self, identity: str, site: str | None, raw: bytes, now: float
                    ) -> exp_schema.Measurement | tuple[str, str, str | None]:
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > MAX_LINE_BYTES:
            return ("line_too_long", f"line exceeds {MAX_LINE_BYTES} bytes", None)
        if not raw.strip():
            return ("invalid_json", "empty line", None)
        try:
            doc = exp_config.parse_json(raw, "line")
        except ValueError as exc:
            return ("invalid_json", str(exc)[:200], None)
        rid = doc.get("id") if isinstance(doc, dict) and exp_ids.is_ulid(doc.get("id")) else None
        try:
            m = exp_schema.Measurement.from_dict(doc, require_id=True)
        except (ValueError, TypeError) as exc:
            return ("invalid_measurement", str(exc), rid)
        if m.probe != identity:
            return ("identity_mismatch", f"probe {m.probe[:64]!r} does not match token identity", rid)
        if site is None:
            return ("identity_mismatch", f"probe {identity!r} has no configured site", rid)
        if m.site != site:
            return ("identity_mismatch", f"site {m.site[:64]!r} does not match the probe's configured site", rid)
        ts_ms = exp_schema.iso_to_ms(m.ts)
        if ts_ms > (now + FUTURE_SLACK_S) * 1000:
            return ("ts_future", f"ts is more than {FUTURE_SLACK_S} s in the future", rid)
        if ts_ms < (now - self.config.records_days * 86400) * 1000:
            return ("ts_too_old", f"ts is older than the {self.config.records_days}-day record retention", rid)
        return m

    def _note_seen(self, identity: str, accepted: list[exp_schema.Measurement], duplicates: int) -> None:
        with self._seen_lock:
            if accepted or duplicates:
                self.last_seen[identity] = self._now()
            if accepted:
                sec = int(self._now())
                dq = self._rate.setdefault(identity, collections.deque())
                if dq and dq[-1][0] == sec:
                    dq[-1] = (sec, dq[-1][1] + len(accepted))
                else:
                    dq.append((sec, len(accepted)))
                while dq and dq[0][0] <= sec - 60:
                    dq.popleft()
            for m in accepted:
                ts = exp_schema.iso_to_ms(m.ts)
                if ts > self.newest_ts_ms.get(identity, 0):
                    self.newest_ts_ms[identity] = ts
                if m.agent_ver:
                    self.last_agent_ver[identity] = m.agent_ver[:64]
                if m.test == "probe_self" and "clock_offset_ms" in m.metrics:
                    self.clock_offset_ms[identity] = float(m.metrics["clock_offset_ms"])

    def probe_rows(self, limit: int = 500, max_bytes: int = 52000) -> list[dict[str, Any]]:
        """Per-probe latest figures for the collector health metrics (`probes[]`, 01 section 8.1): configured
        probes that delivered since this process started, sorted by id, at most `limit` rows and `max_bytes`
        of JSON (the health document is capped at 64 KiB by the agent)."""
        now = self._now()
        sec = int(now)
        rows: list[dict[str, Any]] = []
        used = 2
        with self._seen_lock:
            for pid in sorted(self.config.probes):
                seen = self.last_seen.get(pid)
                if seen is None:
                    continue
                dq = self._rate.get(pid)
                rpm = sum(n for t, n in dq if t > sec - 60) if dq else 0
                off = self.clock_offset_ms.get(pid)
                row = {"probe_id": pid, "last_seen": exp_schema_iso(seen), "records_per_min": rpm,
                       "clock_offset_ms": round(off, 1) if off is not None else None}
                used += len(json.dumps(row, separators=(",", ":"))) + 1
                if len(rows) >= limit or used > max_bytes:
                    break
                rows.append(row)
        return rows

    def reporting_probes(self, within_s: float = 90.0) -> int:
        now = self._now()
        with self._seen_lock:
            return sum(1 for p in self.config.probes if now - self.last_seen.get(p, -1e18) <= within_s)


def exp_schema_iso(epoch: float) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))
