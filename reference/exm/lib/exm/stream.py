"""The probe's end of the collector link: `exm stream`.

The collector holds an SSH key this probe accepts only for the exm-stream user,
with a forced command (authorized_keys: restrict,command="/opt/exm/bin/exm stream").
Whatever the collector asks for arrives in SSH_ORIGINAL_COMMAND and is checked
here; only two forms are accepted:

  stream                       the last 10 minutes, then live
  stream since=<UTC time>      everything written after that time, then live

Results go out as they are stored: one JSON object per line, ts first. The
replay merges the day files in "emitted" order without loading them whole, so
a collector that was away for a day catches up without the probe running out of
memory. The collector drops lines it already has, so overlap is harmless.
"""
from __future__ import annotations

import datetime
import heapq
import json
import os
import re
import sys
import time

from . import tail

COMMAND = re.compile(r"^stream(?: since=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z))?$")
DEFAULT_BACKFILL = datetime.timedelta(minutes=10)
POLL_S = 0.25


def parse(command: str, retention_days: int, now: datetime.datetime) -> datetime.datetime:
    """The time to replay from, or SystemExit for anything that isn't a stream request."""
    m = COMMAND.match((command or "stream").strip())
    if not m:
        print("exm stream: this key may only stream results", file=sys.stderr)
        raise SystemExit(2)
    if not m.group(1):
        return now - DEFAULT_BACKFILL
    since = datetime.datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
    return max(since, now - datetime.timedelta(days=retention_days))


def _lines(path: str, since: str, search: str, stop: str):
    """(emitted, raw line) for lines emitted after since, from one file, in file order.
    search: where to start looking, by ts (a line's ts can be up to SLACK_S before its emitted)."""
    try:
        fh = open(path, "rb")
    except OSError:
        return
    with fh:
        size = os.fstat(fh.fileno()).st_size
        start = tail._offset_before(fh, size, search)
        fh.seek(start)
        if start:
            fh.readline()
        for raw in fh:
            if not raw.endswith(b"\n"):
                break                                   # being written: the live follower delivers it
            ts = tail._ts(raw)
            if ts is not None and ts > stop:
                break
            try:
                ev = json.loads(raw)
            except ValueError:
                continue
            emitted = ev.get("emitted") or ev.get("ts")
            if isinstance(emitted, str) and emitted > since:
                yield emitted, raw


def replay(results_dir: str, since: datetime.datetime, until: datetime.datetime, out) -> int:
    """Write every stored line emitted after since, merged across files in emitted order."""
    s = tail.iso(since)
    stop = tail.iso(until + datetime.timedelta(seconds=tail.SLACK_S))
    lo = tail.iso(since - datetime.timedelta(seconds=tail.SLACK_S))
    gens = []
    day = (since - datetime.timedelta(seconds=tail.SLACK_S)).date()
    while day <= until.date():
        d = os.path.join(results_dir, day.isoformat())
        if os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith(".jsonl"):
                    gens.append(_lines(os.path.join(d, f), s, lo, stop))
        day += datetime.timedelta(days=1)
    n = 0
    for _, raw in heapq.merge(*gens, key=lambda x: x[0]):
        out.write(raw)
        n += 1
        if n % 500 == 0:
            out.flush()
    out.flush()
    return n


def run(cfg: dict) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    since = parse(os.environ.get("SSH_ORIGINAL_COMMAND", ""), int(cfg.get("retention_days", 7)), now)
    out = sys.stdout.buffer
    # Start following before the replay, so nothing written during it is missed (overlap is dropped downstream).
    follower = tail.Follower(cfg["results_dir"])
    try:
        replay(cfg["results_dir"], since, now, out)
        while True:
            batch = follower.poll()
            for ev, _ in batch:
                out.write((json.dumps(ev, separators=(",", ":")) + "\n").encode())
            if batch:
                out.flush()
            time.sleep(POLL_S)
    except (BrokenPipeError, ConnectionResetError):
        return 0                                        # the collector went away; it will reconnect
