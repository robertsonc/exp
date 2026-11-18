"""Replay a recorded NDJSON file through the rules and the incident engine (used by `exp-collector replay`
and the golden tests, 03-collector.md sections 10 and 13).

The replay is the EXM unit-test loop: every 2 s of recorded time the records up to that moment are in the
buffer, the probe is evaluated, and the incident engine ticks. Nothing here talks to the network; messages
are collected, not posted.
"""
from __future__ import annotations

import gzip
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from exp_common import schema as exp_schema

from .alerts import payload
from .engine import iso_ms, state_doc
from .incidents import IncidentConfig, MemorySink, ProbeIncidents
from .rules import HISTORY_MS, BeatStore, Evaluation, Rec, evaluate

MAX_LINE_BYTES = 64 * 1024
MAX_RECORDS = 2_000_000
TICK_MS = 2000


class ReplayError(Exception):
    """The file cannot be replayed (unreadable, too large, not measurements)."""


def load_ndjson(path: str) -> list[Rec]:
    """Records of an NDJSON file (plain or gzip). Lines that are not valid measurements are skipped and
    counted by the caller through len(); the file size is bounded."""
    try:
        with open(path, "rb") as probe:
            gz = probe.read(2) == b"\x1f\x8b"
        opener = gzip.open if gz else open
        out: list[Rec] = []
        with opener(path, "rb") as fh:                       # type: ignore[operator]
            for n, line in enumerate(fh, 1):
                if len(line) > MAX_LINE_BYTES:
                    raise ReplayError(f"line {n} is longer than {MAX_LINE_BYTES} bytes")
                if not line.strip():
                    continue
                try:
                    r = Rec.from_dict(json.loads(line))
                except ValueError:
                    r = None
                if r is not None:
                    out.append(r)
                if len(out) > MAX_RECORDS:
                    raise ReplayError("too many records")
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise ReplayError(f"cannot read {path}: {exc}") from exc
    return out


@dataclass
class ReplayResult:
    messages: list[dict[str, Any]] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    message_times: list[int] = field(default_factory=list)
    states: list[dict[str, Any]] = field(default_factory=list)


class _TimedSink(MemorySink):
    """MemorySink that remembers when (replay time) each message was produced."""

    def __init__(self) -> None:
        super().__init__()
        self.now = 0
        self.times: list[int] = []

    def page(self, message: dict[str, Any]) -> None:
        super().page(message)
        self.times.append(self.now)


def state_at(records: Iterable[Rec], at_ms: int, *, probe: str = "", site: str = "", voice: str = "sysadmin",
             tz: str = "UTC", edge_label: str = "EC", history_ms: int = HISTORY_MS,
             live: bool = False) -> dict[str, Any]:
    """Time travel over a bag of records: the State at `at_ms`, pure in (records in [at - history, at])."""
    st = BeatStore()
    st.extend(r for r in records if at_ms - history_ms <= r.ts <= at_ms)
    ev = evaluate(st, at_ms, probe=probe, site=site)
    return state_doc(ev, voice=voice, tz=tz, edge_label=edge_label, live=live)


def evaluation_at(records: Iterable[Rec], at_ms: int, *, probe: str = "", site: str = "",
                  history_ms: int = HISTORY_MS) -> Evaluation:
    st = BeatStore()
    st.extend(r for r in records if at_ms - history_ms <= r.ts <= at_ms)
    return evaluate(st, at_ms, probe=probe, site=site)


def replay(records: Sequence[Rec], *, probe: str, site: str = "lab", cfg: IncidentConfig | None = None,
           start_ms: int | None = None, end_ms: int | None = None, at: Sequence[int] = (),
           voice: str | None = None, history_ms: int = HISTORY_MS, tick_ms: int = TICK_MS,
           alerts: bool = True, label: str = "") -> ReplayResult:
    """Run the rules and (if `alerts`) the incident engine over `records` in recorded time, ticking every
    `tick_ms` from `start_ms` to `end_ms` (default: the whole file). `at`: moments to print a State for."""
    cfg = cfg or IncidentConfig()
    recs = sorted(records, key=lambda r: (r.ts, r.id))
    res = ReplayResult()
    if not recs:
        return res
    t0 = recs[0].ts if start_ms is None else start_ms
    t1 = recs[-1].ts + tick_ms if end_ms is None else end_ms
    sink = _TimedSink()
    eng = ProbeIncidents(probe, site, cfg, sink, label=label)
    buf = BeatStore()
    k = 0
    t = t0
    while alerts and t < t1:
        while k < len(recs) and recs[k].ts <= t:
            buf.add(recs[k])
            k += 1
        buf.trim(t - history_ms)
        sink.now = t
        eng.tick(evaluate(buf, t, probe=probe, site=site), t)
        t += tick_ms
    for a in sorted(at):
        res.states.append(state_at(recs, a, probe=probe, site=site, voice=voice or cfg.voice, tz=cfg.tz,
                                   edge_label=cfg.edge_label, history_ms=history_ms))
    res.messages, res.rows, res.message_times = sink.messages, sink.rows, sink.times
    return res


def render_message(m: dict[str, Any], t_ms: int, tz: str = "UTC") -> str:
    """A message as plain text for the terminal: time, kind, title, lines, link."""
    head = f"[{iso_ms(t_ms)}] {m['kind']} {m['label']}: {m['title']}"
    body = "\n".join("  " + ln for ln in m["lines"])
    return head + "\n" + body + (f"\n  {m['link']}" if m.get("link") else "")


def render_payload(fmt: str, m: dict[str, Any]) -> str:
    return json.dumps(payload(fmt, m), indent=2, ensure_ascii=False)


def parse_ts(text: str) -> int:
    """An ISO-8601 UTC timestamp ('...Z', seconds or milliseconds) to epoch milliseconds."""
    try:
        return exp_schema.iso_to_ms(text)
    except (ValueError, TypeError) as exc:
        raise ReplayError(f"not a UTC ISO-8601 timestamp: {text[:40]!r} ({exc})") from exc


__all__ = ["ReplayError", "ReplayResult", "evaluation_at", "load_ndjson", "parse_ts", "render_message",
           "render_payload", "replay", "state_at"]
