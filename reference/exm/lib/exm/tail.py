"""Read the recent end of the results files without parsing whole days.

Each event line starts with its timestamp ({"ts":"2026-10-26T14:06:58.123Z",...),
because events.make() puts "ts" first. That lets the reader walk a file backwards
and stop at the window edge, and lets the follower hand over new lines as they
are appended. A day's app.jsonl reaches tens of megabytes; reading only the tail
keeps the summary and the web view fast. A window in the past (the dashboard's
rewind) is found by binary search on those timestamps instead of a full scan.
"""
from __future__ import annotations

import datetime
import json
import os

TS_SLICE = slice(7, 31)        # '{"ts":"' is 7 characters; the timestamp is 24
SLACK_S = 300                  # lines are written when a test ends, so ts can lag a little


def iso(dt: datetime.datetime) -> str:
    return dt.astimezone(datetime.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ts(raw: bytes) -> str | None:
    """The leading timestamp, or None for a line not in the written form (skipped, so it cannot end a scan early)."""
    if raw[:7] != b'{"ts":"' or raw[31:32] != b'"':
        return None
    return raw[TS_SLICE].decode("ascii", "replace")


def _reverse_lines(path: str, block: int = 1 << 16):
    """Yield complete lines from the end of a file towards the start, as bytes."""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        pos = fh.tell()
        rest = b""
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            chunk = fh.read(step) + rest
            lines = chunk.split(b"\n")
            rest = lines.pop(0)
            for ln in reversed(lines):
                if ln:
                    yield ln
        if rest:
            yield rest


def lines_since(path: str, since: datetime.datetime) -> list[dict]:
    """Events in one JSON-lines file with ts >= since, oldest first."""
    if not os.path.exists(path):
        return []
    keep = iso(since)
    stop = iso(since - datetime.timedelta(seconds=SLACK_S))
    out = []
    for raw in _reverse_lines(path):
        ts = _ts(raw)
        if ts is None:
            continue
        if ts < stop:
            break
        if ts < keep:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    out.reverse()
    return out


def _offset_before(fh, size: int, target: str) -> int:
    """An offset at or before every line with ts >= target. Lines are in ts order give or take
    SLACK_S (a line is written when its test ends), so callers search for target minus the slack."""
    lo, hi = 0, size
    while hi - lo > 65536:
        mid = (lo + hi) // 2
        fh.seek(mid)
        fh.readline()                                   # finish the line we landed in
        ts = None
        while ts is None:
            ln = fh.readline()
            if not ln:
                break
            ts = _ts(ln)
        if ts is not None and ts < target:
            lo = mid
        else:
            hi = mid
    return lo


def lines_between(path: str, since: datetime.datetime, until: datetime.datetime) -> list[dict]:
    """Events in one JSON-lines file with since <= ts <= until, oldest first, without reading the whole file."""
    if not os.path.exists(path):
        return []
    lo, hi = iso(since), iso(until)
    stop = iso(until + datetime.timedelta(seconds=SLACK_S))
    out = []
    with open(path, "rb") as fh:
        size = os.fstat(fh.fileno()).st_size
        start = _offset_before(fh, size, iso(since - datetime.timedelta(seconds=SLACK_S)))
        fh.seek(start)
        if start:
            fh.readline()
        for raw in fh:
            if not raw.endswith(b"\n"):
                break                                   # a line still being written
            ts = _ts(raw)
            if ts is None:
                continue
            if ts > stop:
                break
            if lo <= ts <= hi:
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
    out.sort(key=lambda e: e.get("ts", ""))
    return out


def newest_matching(path: str, pred, not_before: datetime.datetime):
    """The newest event in a file for which pred(event) is true, or None. Stops at not_before."""
    if not os.path.exists(path):
        return None
    stop = iso(not_before)
    for raw in _reverse_lines(path):
        ts = _ts(raw)
        if ts is None:
            continue
        if ts < stop:
            return None
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if pred(ev):
            return ev
    return None


class Follower:
    """Hands over lines appended to <results_dir>/<today>/<test>.jsonl since the last poll.
    tests None: every *.jsonl in the day (the probe's stream to the collector)."""

    def __init__(self, results_dir: str, tests=None):
        self.results_dir, self.tests = results_dir, (tuple(tests) if tests is not None else None)
        self.offsets: dict[str, int] = {}
        self.partial: dict[str, bytes] = {}
        for path in self._paths():
            try:
                self.offsets[path] = self._last_line_end(path)  # start at the end; history is read separately
            except OSError:
                pass

    @staticmethod
    def _last_line_end(path: str) -> int:
        """Offset just past the last newline, so a line being written now is still delivered."""
        with open(path, "rb") as fh:
            size = fh.seek(0, os.SEEK_END)
            back = min(size, 1 << 16)
            fh.seek(size - back)
            tail_bytes = fh.read(back)
        cut = tail_bytes.rfind(b"\n")
        return size - back + cut + 1 if cut >= 0 else size - back

    def _paths(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        days = sorted({(now - datetime.timedelta(seconds=SLACK_S)).date().isoformat(), now.date().isoformat()})
        if self.tests is None:
            return [os.path.join(self.results_dir, d, f) for d in days
                    for f in (sorted(os.listdir(os.path.join(self.results_dir, d)))
                              if os.path.isdir(os.path.join(self.results_dir, d)) else [])
                    if f.endswith(".jsonl")]
        return [os.path.join(self.results_dir, d, f"{t}.jsonl") for d in days for t in self.tests]

    def poll(self) -> list[tuple[dict, float]]:
        """New events with the file's modification time (when the line was written)."""
        out = []
        live = set(self._paths())
        for path in list(self.offsets):
            if path not in live:
                del self.offsets[path]
                self.partial.pop(path, None)
        for path in live:
            try:
                st = os.stat(path)
            except OSError:
                continue
            off = self.offsets.get(path, 0)
            if st.st_size < off:            # truncated or replaced: start over
                off = 0
            if st.st_size == off:
                self.offsets[path] = off
                continue
            with open(path, "rb") as fh:
                fh.seek(off)
                data = self.partial.pop(path, b"") + fh.read(st.st_size - off)
            self.offsets[path] = st.st_size
            lines = data.split(b"\n")
            if lines[-1]:
                self.partial[path] = lines[-1]
            for ln in lines[:-1]:
                if not ln:
                    continue
                try:
                    out.append((json.loads(ln), st.st_mtime))
                except json.JSONDecodeError:
                    continue
        return out
