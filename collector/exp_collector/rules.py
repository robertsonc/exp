"""The rules engine (03-collector.md section 5; decision D3: the ONE implementation of the rules).

Pure functions over measurement records: beats -> line states -> since / last outage / flaps ->
where-is-the-fault. The same code answers live queries (ring buffers fed by the ingest observer)
and time travel (records read back from SQLite): same records in, same State out.

Ported from the EXM prior art, with the EXM line numbers replaced by exp line keys:
  # ported from reference/exm/lib/exm/pulse.py (beats, state_of, since_of, series, last_outage,
  #   flaps, where_of) and reference/exm/lib/exm/static/pulse-core.js (the JS twin).
Differences that are deliberate (see CR notes in docs/spec/changes):
  * gateway / dns_hb / trace / ... are one record per port (exp.measurement/1), so a "beat" is a
    cluster of records measured together (multi-port aggregation, section 5 of the spec);
  * EXM's single "Internet" lane is split into `internet` (traceroute/ping) and `apps` (app tests);
  * `outcome: error` (the probe could not run the test) is beat value 3 and never counts as a
    network failure.

Untrusted input: every value read from a record is type-checked here; nothing is eval'd or
formatted into code. Free text only ever leaves this module as data (verdict.py escapes/cleans it).
"""
from __future__ import annotations

import bisect
import ipaddress
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, NamedTuple

from exp_common import schema as exp_schema

# --------------------------------------------------------------------------------------- constants
RECENT_MS = 60_000          # a diagnostic result older than this says nothing about now
TRACE_HOLD_MS = 30_000      # a path is dead only if none of its traces got through in this long
FLAP_SPAN_MS = 600_000      # flap window: 10 minutes
LAST_OUTAGE_MS = 900_000    # "just recovered" lookback: 15 minutes
HISTORY_MS = 70 * 60_000    # how much history one evaluation looks at (EXM alert.py HISTORY_MS)

LINE_KEYS: tuple[str, ...] = ("network", "dhcp", "dns", "internet", "apps", "wifi", "path")
# lines that beat every heartbeat; internet/apps/path also run on their own test intervals
HEARTBEAT_LINES: tuple[str, ...] = ("network", "dhcp", "dns", "wifi")
LABELS: dict[str, str] = {"network": "Network", "dhcp": "DHCP", "dns": "DNS", "internet": "Internet",
                          "apps": "Apps", "wifi": "Wi-Fi", "path": "Path"}

OK, WARN, FAIL, UNKNOWN = "ok", "warn", "fail", "unknown"
BEAT_OK, BEAT_WARN, BEAT_FAIL, BEAT_UNKNOWN = 0, 1, 2, 3
SEGS = ("link", "ports", "switch", "gateway", "lan", "edge", "isp", "wan", "resolver", "dns_path", "dns",
        "apps", "dhcp", "ssid", "wifi", "path")


class LineSpec(NamedTuple):
    key: str
    streams: tuple[str, ...]
    window_ms: int
    slow_third: bool      # warn on "a third of the beats were slow" instead of "any beat slow"


# Defaults of 03-collector.md section 5 (apps/path: 3 x the default test interval of 40 s / 60 s).
LINE_SPECS: dict[str, LineSpec] = {
    "network": LineSpec("network", ("gateway",), 30_000, False),
    "dhcp": LineSpec("dhcp", ("dhcp_hb",), 30_000, False),
    "dns": LineSpec("dns", ("dns_hb",), 30_000, False),
    "internet": LineSpec("internet", ("trace", "ping"), 120_000, True),
    "apps": LineSpec("apps", ("app",), 120_000, True),
    "wifi": LineSpec("wifi", ("wifi_hb",), 30_000, True),
    "path": LineSpec("path", ("path",), 180_000, True),
}
MAX_WINDOW_MS = max(s.window_ms for s in LINE_SPECS.values())


# Heartbeat cadence (CR-heartbeat-cadence): probes beat every 5-60 s (heartbeat.interval_s, default 10). A line's
# state window must hold at least WINDOW_BEATS beats at the probe's real cadence, or a 30 s window over a 60 s heartbeat
# reads "unknown" between beats. The cadence is measured from the probe's own beats, never assumed.
CADENCE_SAMPLES = 9         # newest beat gaps the median is taken over
CADENCE_GAP_MAX_MS = 120_000  # a longer gap is an outage or a restart, not the cadence
WINDOW_BEATS = 2.5
WINDOW_CAP_MS = 180_000
CHAIN_SPAN_MS = 60_000      # a per-port run is cut after this: no endless beat from a client testing back to back


class _StreamSpec(NamedTuple):
    test: str
    anchored: bool        # True: records within gap_ms of the cluster's first record are one beat
    gap_ms: int           # False: chain per port while consecutive records are < gap_ms apart (EXM apps)


STREAMS: dict[str, _StreamSpec] = {
    "gateway": _StreamSpec("gateway", True, 3_000),      # all ports measured together: one beat
    "dhcp_hb": _StreamSpec("dhcp_hb", True, 5_000),
    "dns_hb": _StreamSpec("dns_hb", True, 5_000),        # one query per resolver in the same beat
    "trace": _StreamSpec("trace", True, 5_000),          # path=test
    "trace_ctl": _StreamSpec("trace", True, 5_000),      # path=control (management path)
    "ping": _StreamSpec("ping", True, 5_000),
    "app": _StreamSpec("app", False, 30_000),            # one client run (port) collapses to one beat
    "wifi_hb": _StreamSpec("wifi_hb", True, 5_000),
    "path": _StreamSpec("path", True, 15_000),
}


# ------------------------------------------------------------------------------------------ records
class Rec:
    """The part of a measurement the rules need. Built from the stored JSON body (already validated at
    ingest), but every field is re-checked: records are untrusted data."""

    __slots__ = ("ts", "id", "test", "outcome", "labels", "metrics", "detail", "error", "target", "probe", "site")

    def __init__(self, ts: int, id: str, test: str, outcome: str, labels: Mapping[str, str],
                 metrics: Mapping[str, float], detail: Mapping[str, Any], error: str | None,
                 target: str | None, probe: str = "", site: str = "") -> None:
        self.probe, self.site = probe, site
        self.ts, self.id, self.test, self.outcome = ts, id, test, outcome
        self.labels, self.metrics, self.detail, self.error, self.target = labels, metrics, detail, error, target

    @property
    def port(self) -> str:
        return str(self.labels.get("port", ""))

    @classmethod
    def from_dict(cls, d: Any) -> Rec | None:
        if not isinstance(d, Mapping):
            return None
        try:
            ts = exp_schema.iso_to_ms(str(d["ts"]))
        except (KeyError, ValueError, TypeError):
            return None
        test, outcome = d.get("test"), d.get("outcome")
        if not isinstance(test, str) or outcome not in ("ok", "degraded", "fail", "error"):
            return None
        labels = d.get("labels") if isinstance(d.get("labels"), Mapping) else {}
        metrics_in = d.get("metrics") if isinstance(d.get("metrics"), Mapping) else {}
        metrics = {str(k): float(v) for k, v in metrics_in.items()
                   if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)}
        detail = d.get("detail") if isinstance(d.get("detail"), Mapping) else {}
        err = d.get("error")
        tgt = d.get("target")
        return cls(ts, str(d.get("id", "")), test, str(outcome), {str(k): str(v) for k, v in labels.items()},
                   metrics, detail, err if isinstance(err, str) else None, tgt if isinstance(tgt, str) else None,
                   str(d.get("probe", ""))[:64], str(d.get("site", ""))[:64])

    @classmethod
    def from_measurement(cls, m: exp_schema.Measurement) -> Rec | None:
        return cls.from_dict(m.to_dict())


def stream_of(r: Rec) -> str | None:
    t = r.test
    if t == "trace":
        return "trace_ctl" if r.labels.get("path") == "control" else "trace"
    return t if t in STREAMS and t != "trace_ctl" else None


def _value(stream: str, recs: Sequence[Rec]) -> int:
    """Beat value of a cluster of records (see ``_agg``). On the dns_hb stream the DHCP-given resolver
    decides and the alternate only corroborates (when only alternates were measured, they stand in)."""
    if stream == "dns_hb":
        prim = [r for r in recs if r.labels.get("resolver_kind") != "alternate" and r.outcome != "error"]
        if prim:
            recs = prim
    return _agg(recs)


def _agg(recs: Sequence[Rec]) -> int:
    """all ok 0 / some failing 1 (2 when >= half) / all failing 2; `error` records (the probe could not
    run the test) do not count; only errors -> 3 (unknown)."""
    fail = deg = n = 0
    for r in recs:
        if r.outcome == "ok":
            n += 1
        elif r.outcome == "degraded":
            n += 1
            deg += 1
        elif r.outcome == "fail":
            n += 1
            fail += 1
    if n == 0:
        return BEAT_UNKNOWN
    if fail and fail * 2 >= n:
        return BEAT_FAIL
    if fail or deg:
        return BEAT_WARN
    return BEAT_OK


class Group:
    """A cluster of records measured together: one beat."""

    __slots__ = ("stream", "t0", "t", "recs", "_v")

    def __init__(self, stream: str, rec: Rec) -> None:
        self.stream, self.t0, self.t, self.recs, self._v = stream, rec.ts, rec.ts, [rec], None

    def add(self, rec: Rec) -> None:
        self.recs.append(rec)
        if rec.ts > self.t:
            self.t = rec.ts
        self._v = None

    @property
    def value(self) -> int:
        if self._v is None:
            self._v = _value(self.stream, self.recs)
        return self._v


class Beat(NamedTuple):
    t: int
    v: int          # 0 ok / 1 warn / 2 fail / 3 unknown
    group: Group


def _rkey(r: Rec) -> tuple[int, str]:
    return (r.ts, r.id)


class _Stream:
    def __init__(self, name: str) -> None:
        self.name, self.spec = name, STREAMS[name]
        self.raw: list[Rec] = []
        self.groups: list[Group] = []
        self.open: dict[str, Group] = {}
        self.dirty = False

    def add(self, rec: Rec) -> None:
        if self.raw and _rkey(rec) < _rkey(self.raw[-1]):
            bisect.insort(self.raw, rec, key=_rkey)       # out of order (spool backfill): rebuild lazily
            self.dirty = True
            return
        self.raw.append(rec)
        if not self.dirty:
            self._merge(rec)

    def _merge(self, rec: Rec) -> None:
        sp = self.spec
        if sp.anchored:
            g = self.groups[-1] if self.groups else None
            if g is not None and rec.ts - g.t0 < sp.gap_ms:
                g.add(rec)
            else:
                self.groups.append(Group(self.name, rec))
        else:
            key = rec.port
            g = self.open.get(key)
            if g is not None and rec.ts - g.t < sp.gap_ms and rec.ts - g.t0 < CHAIN_SPAN_MS:
                g.add(rec)
            else:
                g = Group(self.name, rec)
                self.groups.append(g)
                self.open[key] = g

    def ensure(self) -> list[Group]:
        if self.dirty:
            self.groups, self.open, self.dirty = [], {}, False
            for r in self.raw:
                self._merge(r)
        return self.groups

    def trim(self, before: int) -> None:
        i = bisect.bisect_left(self.raw, before, key=lambda r: r.ts)
        if i:
            del self.raw[:i]
            self.dirty = True


class BeatStore:
    """All the beat state of one probe: per-stream clusters, merged per line on demand."""

    def __init__(self) -> None:
        self._streams = {name: _Stream(name) for name in STREAMS}
        self._ids: set[str] = set()
        self._all_ts: list[int] = []
        self._fail_ts: list[int] = []
        self.version = 0
        self._cache: dict[str, tuple[int, list[Beat], list[int]]] = {}

    # --- feeding
    def add(self, rec: Rec) -> bool:
        if rec.id:
            if rec.id in self._ids:
                return False
            self._ids.add(rec.id)
        if not self._all_ts or rec.ts >= self._all_ts[-1]:
            self._all_ts.append(rec.ts)
        else:
            bisect.insort(self._all_ts, rec.ts)
        if rec.outcome == "fail":
            if not self._fail_ts or rec.ts >= self._fail_ts[-1]:
                self._fail_ts.append(rec.ts)
            else:
                bisect.insort(self._fail_ts, rec.ts)
        name = stream_of(rec)
        if name is not None:
            self._streams[name].add(rec)
        self.version += 1
        return True

    def add_ts(self, ts: int) -> None:
        """Register the time of a record of a test the rules do not use (it still counts as 'the probe spoke')."""
        if not self._all_ts or ts >= self._all_ts[-1]:
            self._all_ts.append(ts)
        else:
            bisect.insort(self._all_ts, ts)
        self.version += 1

    def extend(self, recs: Iterable[Rec]) -> None:
        for r in sorted(recs, key=_rkey):
            self.add(r)

    def trim(self, before_ms: int) -> None:
        """Forget records older than before_ms (ring-buffer behaviour for the live engine)."""
        i = bisect.bisect_left(self._all_ts, before_ms)
        if i:
            del self._all_ts[:i]
        j = bisect.bisect_left(self._fail_ts, before_ms)
        if j:
            del self._fail_ts[:j]
        for s in self._streams.values():
            if s.raw and s.raw[0].ts < before_ms:
                s.trim(before_ms)
        for s in self._streams.values():
            s.ensure()
        if len(self._ids) > len(self._all_ts) + 4096:
            self._ids = {r.id for s in self._streams.values() for r in s.raw if r.id}
        self.version += 1

    # --- reading
    @property
    def record_count(self) -> int:
        return len(self._all_ts)

    def newest_ts(self, at: int | None = None) -> int | None:
        if not self._all_ts:
            return None
        if at is None or at >= self._all_ts[-1]:
            return self._all_ts[-1]
        i = bisect.bisect_right(self._all_ts, at)
        return self._all_ts[i - 1] if i else None

    def last_fail_ts(self, at: int) -> int | None:
        """Timestamp of the newest failed record at or before `at` (any test), or None."""
        i = bisect.bisect_right(self._fail_ts, at)
        return self._fail_ts[i - 1] if i else None

    def groups(self, stream: str) -> list[Group]:
        gs = self._streams[stream].ensure()
        # chain-mode groups change their end time when they absorb records: keep them time ordered
        return sorted(gs, key=lambda g: g.t) if not STREAMS[stream].anchored else gs

    def line(self, key: str) -> tuple[list[Beat], list[int]]:
        hit = self._cache.get(key)
        if hit is not None and hit[0] == self.version:
            return hit[1], hit[2]
        bs = [Beat(g.t, g.value, g) for s in LINE_SPECS[key].streams for g in self.groups(s)]
        bs.sort(key=lambda b: b.t)
        ts = [b.t for b in bs]
        self._cache[key] = (self.version, bs, ts)
        return bs, ts


def beats(records: Iterable[Rec | Mapping[str, Any]], line: str) -> list[Beat]:
    """Beats of one line from a bag of records (pure; EXM pulse.beats). Values 0/1/2/3."""
    st = BeatStore()
    st.extend(r for r in (x if isinstance(x, Rec) else Rec.from_dict(x) for x in records) if r is not None)
    return list(st.line(line)[0])


# ------------------------------------------------------------------------------------ line functions
def cadence_ms(ts: Sequence[int], at: int) -> int | None:
    """Median gap between the newest distinct beat times at or before `at` (None with fewer than 3 usable gaps)."""
    hi = bisect.bisect_right(ts, at)
    times: list[int] = []
    for t in reversed(ts[max(0, hi - 4 * (CADENCE_SAMPLES + 1)):hi]):
        if not times or t != times[-1]:
            times.append(t)
            if len(times) > CADENCE_SAMPLES:
                break
    gaps = sorted(a - b for a, b in zip(times, times[1:], strict=False) if 0 < a - b <= CADENCE_GAP_MAX_MS)
    if len(gaps) < 3:
        return None
    return gaps[len(gaps) // 2]


def window_for(line: str, cadence: int | None) -> int:
    """The line's state window: its spec window, widened to WINDOW_BEATS beats of the measured cadence (capped)."""
    w = LINE_SPECS[line].window_ms
    if cadence is None:
        return w
    return max(w, min(WINDOW_CAP_MS, int(WINDOW_BEATS * cadence)))


class LineState(NamedTuple):
    s: str          # ok | warn | fail | unknown
    n: int          # beats in the window (unknown beats excluded)
    f: int
    d: int


def _state(f: int, d: int, n: int, slow_third: bool) -> str:
    if not n:
        return UNKNOWN
    if f * 2 >= n:
        return FAIL
    if f or (d * 3 >= n if slow_third else d):
        return WARN
    return OK


def _prep(bs: Sequence[Beat], ts: Sequence[int] | None) -> list[int]:
    return list(ts) if ts is not None else [b.t for b in bs]


def state_of(bs: Sequence[Beat], line: str, at: int, ts: Sequence[int] | None = None,
             window_ms: int | None = None) -> LineState:
    """fail when >= half the beats in the state window failed; warn on any failure or slow beats
    (a third slow for internet/apps/wifi/path); unknown when no beat in the window (EXM state_of)."""
    spec = LINE_SPECS[line]
    window = spec.window_ms if window_ms is None else window_ms
    tl = _prep(bs, ts)
    lo, hi = bisect.bisect_left(tl, at - window), bisect.bisect_right(tl, at)
    f = d = n = 0
    for b in bs[lo:hi]:
        if b.v == BEAT_UNKNOWN:
            continue
        n += 1
        if b.v == BEAT_FAIL:
            f += 1
        elif b.v == BEAT_WARN:
            d += 1
    return LineState(_state(f, d, n, spec.slow_third), n, f, d)


class Since(NamedTuple):
    t: int | None
    open: bool


def since_of(bs: Sequence[Beat], fails_only: bool, hi: int | None = None) -> Since:
    """When the current problem began: the earliest bad beat since the last three good ones in a row.
    For a failure only failed beats count as bad. open: the loaded history ran out before three good
    ones in a row, so the start is older than we can see (EXM since_of)."""
    ok_run, earliest, found = 0, None, False
    for i in range((len(bs) if hi is None else hi) - 1, -1, -1):
        b = bs[i]
        if b.v == BEAT_UNKNOWN:
            continue
        bad = b.v == BEAT_FAIL if fails_only else b.v != BEAT_OK
        if not bad:
            ok_run += 1
            if ok_run >= 3:
                found = True
                break
        else:
            ok_run, earliest = 0, b.t
    return Since(earliest, earliest is not None and not found)


def _series(bs: Sequence[Beat], ts: Sequence[int], line: str, start: int, t: int,
            window_ms: int | None = None) -> list[tuple[int, int, str]]:
    """(index, t, state) of the line at each of its valid beats in [start, t]; sliding window, O(n).
    Beats with the same timestamp all count in each other's window (as state_of(bs, line, b.t) does)."""
    spec = LINE_SPECS[line]
    window = spec.window_ms if window_ms is None else window_ms
    out: list[tuple[int, int, str]] = []
    j = bisect.bisect_left(ts, start - window)
    hi = bisect.bisect_right(ts, t)
    f = d = n = 0
    lo = k = j
    for i in range(j, hi):
        bt = bs[i].t
        while k < hi and bs[k].t <= bt:
            b = bs[k]
            if b.v != BEAT_UNKNOWN:
                n += 1
                f += b.v == BEAT_FAIL
                d += b.v == BEAT_WARN
            k += 1
        while bs[lo].t < bt - window:
            o = bs[lo]
            if o.v != BEAT_UNKNOWN:
                n -= 1
                f -= o.v == BEAT_FAIL
                d -= o.v == BEAT_WARN
            lo += 1
        if bt >= start and bs[i].v != BEAT_UNKNOWN:
            out.append((i, bt, _state(f, d, n, spec.slow_third)))
    return out


def series(bs: Sequence[Beat], line: str, start: int, t: int, ts: Sequence[int] | None = None) -> list[tuple[int, str]]:
    return [(bt, s) for _, bt, s in _series(bs, _prep(bs, ts), line, start, t)]


class Outage(NamedTuple):
    start: int | None
    end: int
    open: bool


def _last_outage(bs: Sequence[Beat], ts: Sequence[int], ser: list[tuple[int, int, str]]) -> Outage | None:
    if not ser or ser[-1][2] == FAIL:
        return None
    k = max((i for i, x in enumerate(ser) if x[2] == FAIL), default=-1)
    if k < 0:
        return None
    s = since_of(bs, True, hi=bisect.bisect_right(ts, ser[k][1]))
    return Outage(s.t, ser[k + 1][1], s.open)


def last_outage(bs: Sequence[Beat], line: str, t: int, within: int = LAST_OUTAGE_MS,
                ts: Sequence[int] | None = None) -> Outage | None:
    """The newest failure that has since ended, if it ended within `within` ms of t; None while the line
    is still failing or if nothing failed (EXM last_outage; spec: 15 minutes)."""
    tl = _prep(bs, ts)
    return _last_outage(bs, tl, _series(bs, tl, line, t - within, t))


def _flaps(ser: list[tuple[int, int, str]], since_t: int) -> int:
    sub = [x for x in ser if x[1] >= since_t]
    return sum(1 for i in range(1, len(sub)) if sub[i][2] == FAIL and sub[i - 1][2] != FAIL)


def flaps(bs: Sequence[Beat], line: str, t: int, span: int = FLAP_SPAN_MS, ts: Sequence[int] | None = None) -> int:
    """How many times the line went into failure in the last `span` ms; 3 or more is flapping."""
    tl = _prep(bs, ts)
    return _flaps(_series(bs, tl, line, t - span, t), t - span)


# ------------------------------------------------------------------------------------------- facts
def _num(v: Any) -> float | None:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None


def _ip(v: Any) -> str | None:
    """A well-formed IPv4 address or None (addresses end up in chat messages and the UI)."""
    try:
        a = ipaddress.ip_address(str(v))
    except ValueError:
        return None
    return str(a) if a.version == 4 else None


def _txt(v: Any, limit: int = 128) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


@dataclass
class Facts:
    """What the diagnostic streams say around `at`; where_of() is a pure function of this + line states."""

    at: int = 0
    gateway: dict[str, Any] | None = None      # {t, n, nl: [ports], ug: [[ip, bad, total]]}
    dns: dict[str, Any] | None = None          # {t, o, sx, ax, ao}
    trace: dict[str, Any] | None = None        # with the TRACE_HOLD rule applied
    raw_trace: dict[str, Any] | None = None    # the newest trace as it was
    trace_ctl: dict[str, Any] | None = None
    wifi: dict[str, Any] | None = None         # {t, sd, tg, on, gk, err}
    dhcp_server: str | None = None
    trace_unrunnable: bool = False             # the newest traces were all `error`: no client could run them


def _recent_group(groups: Sequence[Group], at: int, within: int, pred: Any = None) -> Group | None:
    """The newest group at or before `at` (and within `within` ms of it) that satisfies `pred`."""
    for i in range(len(groups) - 1, -1, -1):
        g = groups[i]
        if g.t > at:
            continue
        if at - g.t > within:
            return None
        if pred is None or pred(g):
            return g
    return None


def _gateway_fact(g: Group) -> dict[str, Any]:
    nl: list[str] = []
    ug: dict[str, list[int]] = {}
    for r in g.recs:
        if r.outcome == "error":
            continue
        if r.metrics.get("link_up") == 0:
            nl.append(r.port)
            continue
        ip = _ip(r.detail.get("gateway_ip"))
        if ip:
            e = ug.setdefault(ip, [0, 0])
            e[1] += 1
            e[0] += r.outcome == "fail"
    return {"t": g.t, "n": len(g.recs), "nl": sorted(nl),
            "ug": [[ip, b, n] for ip, (b, n) in sorted(ug.items()) if b]}


def _trace_fact(g: Group) -> dict[str, Any] | None:
    valid = [r for r in g.recs if r.outcome != "error"]
    if not valid:
        return None
    reached = [r for r in valid if r.metrics.get("reached") == 1 or (r.outcome == "ok" and "reached" not in r.metrics)]
    failing = [r for r in valid if r not in reached]
    if reached:     # any port that gets through: the path is up
        r = reached[0]
        dt = r.detail.get("dest_ttl") if isinstance(r.detail.get("dest_ttl"), int) else _num(r.metrics.get("hops"))
        return {"t": g.t, "rc": True, "lh": None, "lt": None, "dt": dt, "port": r.port,
                "g": _txt(r.detail.get("target")) or r.target}
    r = max(failing, key=lambda x: x.metrics.get("last_ttl", 0))      # the port that got furthest
    lt = _num(r.metrics.get("last_ttl"))
    return {"t": g.t, "rc": False, "lh": _ip(r.detail.get("last_ip")), "lt": int(lt) if lt is not None else None,
            "dt": None, "port": r.port, "g": _txt(r.detail.get("target")) or r.target}


def _dns_fact(g: Group) -> dict[str, Any] | None:
    prim = [r for r in g.recs if r.labels.get("resolver_kind") != "alternate" and r.outcome != "error"]
    alt = [r for r in g.recs if r.labels.get("resolver_kind") == "alternate" and r.outcome != "error"]
    use = prim or alt
    if not use:
        return None
    v = _agg(use)
    o = "fail" if v == BEAT_FAIL else "slow" if v == BEAT_WARN else "ok"
    failing = [r for r in use if r.outcome == "fail"] or use
    sx = _ip(failing[0].labels.get("resolver")) if prim else None
    ax = _ip(alt[0].labels.get("resolver")) if alt else None
    ao: bool | None = (_agg(alt) != BEAT_FAIL) if alt else None
    return {"t": g.t, "o": o, "sx": sx, "ax": ax, "ao": ao}


def _wifi_fact(g: Group) -> dict[str, Any] | None:
    valid = [r for r in g.recs if r.outcome != "error"]
    if not valid:
        return None
    r = valid[-1]
    sd = _txt(r.labels.get("ssid"), 32)
    if sd and sd.lower() == "none":
        sd = None
    tg = _txt(r.detail.get("target_ssid"), 32)
    on = r.detail.get("on_target")
    if not isinstance(on, bool):
        on = bool(sd) and (not tg or sd == tg)
    return {"t": g.t, "sd": sd, "tg": tg, "on": bool(on and sd), "gk": _num(r.metrics.get("gw_rtt_ms")) is not None,
            "err": r.error}


def facts_at(store: BeatStore, at: int) -> Facts:
    f = Facts(at=at)
    g = _recent_group(store.groups("gateway"), at, RECENT_MS)
    if g is not None:
        f.gateway = _gateway_fact(g)
    g = _recent_group(store.groups("dns_hb"), at, RECENT_MS, lambda x: _dns_fact(x) is not None)
    if g is not None:
        f.dns = _dns_fact(g)
    for name, attr in (("trace", "trace"), ("trace_ctl", "trace_ctl")):
        groups = store.groups(name)
        last = _recent_group(groups, at, RECENT_MS, lambda x: _trace_fact(x) is not None)
        fact = _trace_fact(last) if last is not None else None
        if name == "trace":
            f.raw_trace = fact
            newest = _recent_group(groups, at, RECENT_MS)
            f.trace_unrunnable = bool(newest is not None and fact is None
                                      and all(r.outcome == "error" for r in newest.recs))
        if fact and not fact["rc"]:
            # a lost trace (rate limiting) doesn't outweigh one that got through recently
            ok = _recent_group(groups, at, TRACE_HOLD_MS, lambda x: bool((_trace_fact(x) or {}).get("rc")))
            if ok is not None:
                okf = _trace_fact(ok) or {}
                fact = dict(fact, rc=True, dt=okf.get("dt"))
        setattr(f, attr, fact)
    g = _recent_group(store.groups("wifi_hb"), at, RECENT_MS, lambda x: _wifi_fact(x) is not None)
    if g is not None:
        f.wifi = _wifi_fact(g)
    groups = store.groups("dhcp_hb")
    for i in range(bisect.bisect_right([x.t for x in groups], at) - 1, -1, -1):
        sv = next((_ip(r.labels.get("server")) for r in reversed(groups[i].recs)
                   if r.labels.get("server") not in (None, "", "none") and r.outcome != "error"), None)
        if sv:
            f.dhcp_server = sv
            break
    return f


# ------------------------------------------------------------------------------------------- where
def where_from_facts(f: Facts, st: Mapping[str, str]) -> dict[str, Any] | None:
    """Where the fault is, from the diagnostic facts and the line states. None when nothing is wrong
    (# ported from reference/exm/lib/exm/pulse.py:where_of). seg is one of SEGS; other keys are facts."""
    def bad(k: str) -> bool:
        return st.get(k) in (FAIL, WARN)

    core = [bad(k) for k in ("network", "dhcp", "dns", "internet", "apps", "wifi")]
    if not any(core):
        return {"seg": "path"} if bad("path") else None
    b_net, b_dhcp, b_dns, b_wifi = bad("network"), bad("dhcp"), bad("dns"), bad("wifi")
    b_web = bad("internet") or bad("apps")
    net_fail = st.get("network") == FAIL
    g, d, w = f.gateway, f.dns, f.wifi
    tr, tc = f.trace, f.trace_ctl
    # both resolvers silent corroborate a failed traceroute: then an older success doesn't outweigh it
    if f.raw_trace and not f.raw_trace["rc"] and d and d["o"] == "fail" and d["ao"] is False:
        tr = f.raw_trace
    w_on = bool(w and w["on"])
    if b_net and g:
        nl, ug = g["nl"], g["ug"]
        if nl and len(nl) * 2 >= (g["n"] or 1):
            return {"seg": "link", "ports": nl, "n": g["n"]}
        if ug:
            ip = ug[0][0]
            if w_on and w["gk"]:
                return {"seg": "switch", "ip": ip}
            if w_on and not w["gk"]:
                return {"seg": "gateway", "ip": ip}
            return {"seg": "lan", "ip": ip}
        if nl:
            return {"seg": "ports", "ports": nl, "n": g["n"]}
    if (b_dns or b_web) and not net_fail:
        if tr and not tr["rc"]:
            base = {"lh": tr["lh"], "lt": tr["lt"], "target": tr["g"]}
            if tc and tc["rc"]:
                return {"seg": "edge", **base}
            if tc and not tc["rc"]:
                return {"seg": "isp", **base, "clh": tc["lh"]}
            return {"seg": "wan", **base}
        if b_dns and d and d["o"] == "fail":
            if d["ao"]:
                return {"seg": "resolver", "sx": d["sx"], "ax": d["ax"]}
            if tr and tr["rc"]:
                return {"seg": "dns_path", "sx": d["sx"], "ax": d["ax"]}
            return {"seg": "dns", "sx": d["sx"], "ax": d["ax"]}
        if b_web and not b_dns and tr and tr["rc"]:
            return {"seg": "apps", "target": tr["g"]}
    if b_dhcp and not net_fail:
        return {"seg": "dhcp", "sv": f.dhcp_server}
    if b_wifi and w and not any(core[:5]):
        if not w_on:
            return {"seg": "ssid", "tg": w["tg"], "sd": w["sd"]}
        if not w["gk"]:
            return {"seg": "wifi"}
    return None


def where_of(records: Iterable[Rec | Mapping[str, Any]], at: int, states: Mapping[str, Any],
             store: BeatStore | None = None) -> dict[str, Any] | None:
    """where_of(records, at, states): the path segment holding the fault, or None. `states` maps a line
    key to its state ("ok|warn|fail|unknown" or a LineState); missing lines count as unknown."""
    if store is None:
        store = BeatStore()
        store.extend(r for r in (x if isinstance(x, Rec) else Rec.from_dict(x) for x in records)
                     if r is not None and r.ts <= at)
    st = {k: (v.s if isinstance(v, LineState) else v.get("s") if isinstance(v, Mapping) else str(v))
          for k, v in states.items()}
    return where_from_facts(facts_at(store, at), st)


# ------------------------------------------------------------------------------------------- evaluate
@dataclass
class LineEval:
    key: str
    state: str
    n: int
    f: int
    d: int
    since: int | None = None
    since_open: bool = False
    last_outage: Outage | None = None
    flaps: int = 0
    window_ms: int = 0                      # the window the state was judged on (spec window widened by the cadence)
    cadence_ms: int | None = None           # measured beat spacing of this line, None while too few beats
    beats: list[Beat] = field(default_factory=list, repr=False)
    ts: list[int] = field(default_factory=list, repr=False)


@dataclass
class Evaluation:
    probe: str
    site: str
    at: int
    newest: int | None                      # newest record of any test at or before `at`
    lines: dict[str, LineEval]
    facts: Facts
    where: dict[str, Any] | None
    store: BeatStore = field(repr=False, default_factory=BeatStore)

    @property
    def states(self) -> dict[str, str]:
        return {k: v.state for k, v in self.lines.items()}

    @property
    def cadence_ms(self) -> int | None:
        """The probe's heartbeat cadence: the fastest measured heartbeat line (the app/path tests run slower)."""
        hb = [le.cadence_ms for k, le in self.lines.items() if k in HEARTBEAT_LINES and le.cadence_ms]
        return min(hb) if hb else None

    @property
    def newest_s(self) -> float | None:
        return None if self.newest is None else max(0.0, (self.at - self.newest) / 1000.0)


def evaluate(store: BeatStore, at: int, *, probe: str = "", site: str = "",
             lines: Sequence[str] = LINE_KEYS) -> Evaluation:
    """Everything the rules say about one probe at `at` (pure in (records <= at, at))."""
    out: dict[str, LineEval] = {}
    for key in lines:
        bs, ts = store.line(key)
        cad = cadence_ms(ts, at)
        win = window_for(key, cad)
        stt = state_of(bs, key, at, ts, window_ms=win)
        le = LineEval(key, stt.s, stt.n, stt.f, stt.d, window_ms=win, cadence_ms=cad, beats=bs, ts=ts)
        hi = bisect.bisect_right(ts, at)
        if stt.s in (FAIL, WARN):
            s = since_of(bs, stt.s == FAIL, hi=hi)
            le.since, le.since_open = s.t, s.open
        ser = _series(bs, ts, key, at - LAST_OUTAGE_MS, at, win)
        le.last_outage = _last_outage(bs, ts, ser)
        le.flaps = _flaps(ser, at - FLAP_SPAN_MS)
        out[key] = le
    facts = facts_at(store, at)
    states = {k: v.state for k, v in out.items()}
    for k in LINE_KEYS:
        states.setdefault(k, UNKNOWN)
    return Evaluation(probe, site, at, store.newest_ts(at), out, facts, where_from_facts(facts, states), store)


def evaluate_records(records: Iterable[Rec | Mapping[str, Any]], at: int, *, probe: str = "", site: str = "",
                     lines: Sequence[str] = LINE_KEYS) -> Evaluation:
    """Time travel: a State evaluated purely from records (only those at or before `at` are used)."""
    store = BeatStore()
    store.extend(r for r in (x if isinstance(x, Rec) else Rec.from_dict(x) for x in records)
                 if r is not None and r.ts <= at)
    return evaluate(store, at, probe=probe, site=site, lines=lines)


# ------------------------------------------------------------------------------------ what is failing
def norm_error(s: str) -> str:
    """Group errors that differ only by a timing; repeated causes of multi-step results once; library
    jargon becomes what it means (# ported from reference/exm/lib/exm/static/pulse.html:norm)."""
    seen: list[str] = []
    for p in str(s or "").split("; "):
        p = re.sub(r"\b(\d{4,})(\.\d+)? ?milliseconds\b",
                   lambda m: f"{round(float(m.group(1) + (m.group(2) or '')) / 1000)} s", p)
        p = re.sub(r"\btook \d+(\.\d+)? ?ms \(T \d+ ms\)", "too slow", p)
        p = re.sub(r"\b(gateway|DNS) \d+(\.\d+)? ?ms\b", r"\1 slow", p)
        p = re.sub(r"^gaierror: \[Errno -[23]\] .*$", "name lookup failed (no DNS answer)", p)
        p = re.sub(r"^gaierror: \[Errno -[25]\] .*$", "name lookup failed", p)
        if p not in seen:
            seen.append(p)
    return "; ".join(seen)


def failing_items(ev: Evaluation, line: str, *, limit: int = 5) -> list[dict[str, Any]]:
    """The evidence behind a line that isn't fine: failing/slow records of the last window grouped by
    their (normalised) error text. Free text is data: the UI must insert it with textContent."""
    from exp_common import ids as exp_ids
    spec = LINE_SPECS[line]
    span = max(spec.window_ms, RECENT_MS)
    recs: list[Rec] = []
    streams = spec.streams
    for s in streams:
        gs = ev.store.groups(s)
        if line == "network" and gs:         # the ports failing right now, not a minute of history
            gs = [g for g in gs if g.t <= ev.at][-1:]
        for g in gs:
            if g.t <= ev.at and ev.at - g.t <= span:
                recs.extend(r for r in g.recs if r.outcome in ("fail", "degraded") and r.ts <= ev.at)
    groups: dict[str, dict[str, Any]] = {}
    for r in recs:
        what = norm_error(r.error) if r.error else ("slow" if r.outcome == "degraded" else "failed")
        what = what[:200] or "failed"
        g = groups.setdefault(what, {"count": 0, "ports": set(), "tests": set()})
        g["count"] += 1
        if r.port and exp_ids.is_slug(r.port):
            g["ports"].add(r.port)
        g["tests"].add(r.test)
    items = []
    for what, g in sorted(groups.items(), key=lambda kv: (-kv[1]["count"], kv[0]))[:limit]:
        items.append({"text": what, "count": g["count"], "ports": sorted(g["ports"])[:256],
                      "tests": sorted(t for t in g["tests"] if _is_ident(t))[:32]})
    return items


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


def _is_ident(t: str) -> bool:
    return bool(_IDENT.match(t))
