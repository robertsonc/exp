"""Incident engine (03-collector.md section 6): turns line states into incidents and alert messages.

Ported from reference/exm/lib/exm/alert.py (Alerter.tick / _step / _facts, PARENTS, REOPEN_MS, CALM_MS,
SILENT_MS):

* holds     a line becomes `down` after failing continuously for hold_down_s (20 s) and `back` after
            hold_back_s (60 s) of ok;
* again     a re-failure within reopen_s (5 min) of recovering reopens the same incident (`again`);
* flapping  the third failure inside the flap window gives ONE `flapping` message, then quiet until the
            line has been calm for calm_s (10 min);
* folding   DHCP, DNS, Internet and Apps failures that start while Network fails, Internet while DNS
            fails, Wi-Fi while Network fails with the laptop on its target network, are consequences of
            that cause: recorded with `folded_into`, never paged separately, and listed in the cause's
            page ("Also failing, probably because of this: ..."). A line still failing once its cause
            has recovered pages then, after its own window has caught up;
* silent    no records for 90 s: a "probe silent" incident ("Nothing on this screen is current").

The engine is deterministic: it only looks at the Evaluation handed to ``tick`` and the time of the tick, so
the same records replayed give the same messages (golden tests). Open incidents are exported as JSON
(``export_state``) and restored (``state=``), so a restart in the middle of an outage does not page twice.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from exp_common import ids as exp_ids

from .alerts import build_message
from .rules import LINE_KEYS, Evaluation
from .verdict import cap, clean, fin, hms, what_of

log = logging.getLogger(__name__)

SILENT_MS = 90_000
FLAP_WINDOW_MS = 600_000
PARENTS: dict[str, tuple[str, ...]] = {          # a line's failure is a consequence while these fail
    "dhcp": ("network",), "dns": ("network",), "internet": ("network", "dns"),
    "apps": ("network", "dns", "internet"), "path": ("network",),
}
WIFI_PARENTS = ("network",)                      # only while the laptop is on its target network


@dataclass(frozen=True)
class IncidentConfig:
    hold_down_s: float = 20
    hold_back_s: float = 60
    reopen_s: float = 300
    calm_s: float = 600
    silent_s: float = SILENT_MS / 1000
    lines: tuple[str, ...] = LINE_KEYS
    on_warn: bool = False
    enabled: bool = True                         # False: incidents are recorded, nothing is posted
    tz: str = "UTC"
    voice: str = "sysadmin"
    edge_label: str = "EC"
    board_url: str | None = None

    @classmethod
    def from_collector(cls, cfg: Any) -> IncidentConfig:
        """From a CollectorConfig (its `alerts` and `rules` sections)."""
        a = dict(getattr(cfg, "alerts", {}) or {})
        return cls(hold_down_s=a.get("hold_down_s", 20), hold_back_s=a.get("hold_back_s", 60),
                   reopen_s=a.get("reopen_s", 300), calm_s=a.get("calm_s", 600),
                   lines=tuple(getattr(cfg, "lines", LINE_KEYS)), on_warn=bool(a.get("warn", False)),
                   enabled=bool(a.get("enabled", True)), tz=a.get("timezone", "UTC"),
                   voice=a.get("voice", "sysadmin"), edge_label=getattr(cfg, "edge_label", "EC"),
                   board_url=a.get("board_url"))


class Sink(Protocol):
    def record(self, row: dict[str, Any]) -> None: ...
    def end(self, ids: list[str], end_ms: int) -> None: ...
    def page(self, message: dict[str, Any]) -> None: ...
    def save_state(self, probe: str, doc: str) -> None: ...


@dataclass
class MemorySink:
    """Collects everything the engine does (golden tests, `replay`)."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    states: dict[str, str] = field(default_factory=dict)

    def record(self, row: dict[str, Any]) -> None:
        self.rows.append(dict(row))

    def end(self, ids: list[str], end_ms: int) -> None:
        for r in self.rows:
            if r["id"] in ids and r.get("end_ms") is None:
                r["end_ms"] = end_ms

    def page(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    def save_state(self, probe: str, doc: str) -> None:
        self.states[probe] = doc


class ProbeIncidents:
    """The incident state machine of ONE probe."""

    def __init__(self, probe: str, site: str, cfg: IncidentConfig, sink: Sink, *, label: str = "",
                 state: Mapping[str, Any] | None = None) -> None:
        self.probe, self.site, self.cfg, self.sink, self.label = probe, site, cfg, sink, label
        self.hold_down = int(cfg.hold_down_s * 1000)
        self.hold_back = int(cfg.hold_back_s * 1000)
        self.reopen = int(cfg.reopen_s * 1000)
        self.calm = int(cfg.calm_s * 1000)
        self.silent = int(cfg.silent_s * 1000)
        self.lanes = [k for k in LINE_KEYS if k in cfg.lines]
        self.inc: dict[str, dict[str, Any]] = {}
        if state:
            self.inc = json.loads(json.dumps(state.get("inc", {})))       # deep copy, JSON types only
        self._saved = ""

    # --------------------------------------------------------------------------------- persistence
    def export_state(self) -> dict[str, Any]:
        return {"inc": self.inc}

    def open_keys(self) -> list[str]:
        return [k for k, v in self.inc.items() if v.get("phase") == "open"]

    # ------------------------------------------------------------------------------------- the tick
    def tick(self, ev: Evaluation | None, t: int) -> None:
        newest = ev.newest if ev is not None else None
        silent = newest is not None and t - newest > self.silent
        self._step("probe", silent, newest is not None, t,
                   lambda: {"since": newest, "sev": "fail", "what": None, "where": None, "also": []}, None)
        if ev is None or newest is None or silent:
            self._save()
            return
        states = ev.states
        c = self.cfg
        bad = {k: states.get(k) == "fail" or (c.on_warn and states.get(k) == "warn") for k in LINE_KEYS}
        w = ev.facts.wifi
        wifi_home = bool(w and w["on"])
        parents: dict[str, tuple[str, ...]] = dict(PARENTS)
        if wifi_home:
            parents["wifi"] = WIFI_PARENTS
        for key in self.lanes:
            s = states.get(key, "unknown")
            good = s == "ok" or (s == "warn" and not c.on_warn)
            blocked = any(bad[p] or self.inc.get(p, {}).get("phase") in ("pending", "open")
                          for p in parents.get(key, ()))
            also = [k for k in self.lanes if bad[k] and key in parents.get(k, ())]
            self._step(key, bad[key], good, t, lambda key=key, also=also: self._facts(ev, key, also), ev,
                       blocked, _window(key, ev), parents.get(key, ()))
        self._save()

    def _facts(self, ev: Evaluation, key: str, also: list[str]) -> dict[str, Any]:
        le = ev.lines[key]
        where = ev.where
        if key == "wifi":                                   # the laptop's own story, not the wired one
            w = ev.facts.wifi
            if not w:
                where = None
            elif not w["on"]:
                where = {"seg": "ssid", "tg": w["tg"], "sd": w["sd"]}
            elif not w["gk"] and ev.states.get("network") == "ok":
                where = {"seg": "wifi"}
            else:
                where = None
        return {"line": key, "sev": le.state, "since": le.since, "since_open": le.since_open,
                "what": what_of(ev, key), "where": where, "also": [k for k in also]}

    # ------------------------------------------------------------------------------ the state machine
    def _step(self, key: str, bad: bool, good: bool, t: int, facts: Callable[[], dict[str, Any]],
              ev: Evaluation | None, blocked: bool = False, window: int = 0,
              parents: tuple[str, ...] = ()) -> None:
        inc = self.inc.get(key)
        if bad:
            if inc and inc["phase"] == "closed" and t - inc["end"] < self.reopen:
                inc.update(phase="pending", bad_since=t, reopen=True)       # failing again soon: same incident
            elif not inc or inc["phase"] == "closed":
                f = facts()
                inc = self.inc[key] = {"phase": "pending", "bad_since": t, "start": f.get("since") or t, "facts": f,
                                       "rows": []}
            if inc["phase"] == "pending":
                if blocked:
                    inc["blocked_at"] = t                                   # its cause is paging for it
                held = t - inc["bad_since"] >= self.hold_down
                caught_up = t - inc.get("blocked_at", 0) >= max(self.hold_down, window or 0)
                if blocked and held and not inc.get("reopen") and not inc.get("fold_row"):
                    self._fold(key, inc, t, parents, facts)
                if held and caught_up and not blocked:
                    self._open(key, inc, t, facts)
            else:
                inc["ok_since"] = None
        elif good:
            if inc and inc["phase"] == "pending":
                if inc.get("reopen"):
                    inc.update(phase="closed", reopen=False)               # a blip after recovery: still closed
                else:
                    if inc.get("fold_row"):
                        self.sink.end([inc["fold_row"]], t)
                    del self.inc[key]                                       # never paged: a blip
            elif inc and inc["phase"] == "open":
                if not inc.get("ok_since"):
                    inc["ok_since"] = t
                elif t - inc["ok_since"] >= (self.calm if inc.get("muted") else self.hold_back):
                    inc.update(phase="closed", end=inc["ok_since"], muted=False)
                    self._emit("resolved", key, inc, t)
                    self.sink.end(list(inc["rows"]), inc["end"])
            elif inc and inc["phase"] == "closed" and t - inc["end"] >= self.reopen:
                del self.inc[key]
        # neither (no data for a line): an open incident stays open until it is seen to be fine

    def _open(self, key: str, inc: dict[str, Any], t: int, facts: Callable[[], dict[str, Any]]) -> None:
        if inc.get("fold_row"):                                             # its cause cleared: it pages on its own
            self.sink.end([inc.pop("fold_row")], t)
        if inc.get("reopen"):
            fails = [x for x in inc.get("fails", []) if t - x < FLAP_WINDOW_MS] + [t]
            inc.update(phase="open", ok_since=None, reopen=False, fails=fails, flaps=len(fails) - 1)
            if len(fails) >= 3 and not inc.get("muted"):
                inc["muted"] = True
                self._emit("flapping", key, inc, t)
            elif not inc.get("muted"):
                self._emit("again", key, inc, t)
        else:
            f = facts()
            inc.update(phase="open", facts=f, ok_since=None, flaps=0, fails=[t], start=f.get("since") or inc["start"])
            self._emit("down", key, inc, t)

    def _fold(self, key: str, inc: dict[str, Any], t: int, parents: tuple[str, ...],
              facts: Callable[[], dict[str, Any]]) -> None:
        """Record (never page) an incident that is a consequence of an open cause."""
        cause = next((p for p in parents if self.inc.get(p, {}).get("phase") == "open"
                      and self.inc[p].get("row")), None)
        if cause is None:
            return                                                         # the cause has not paged yet
        folded = self.inc[cause].setdefault("folded", [])                 # one row per line per cause
        if key in folded:
            return
        folded.append(key)
        parent = self.inc[cause]["row"]
        f = dict(inc.get("facts") or facts())
        row = self._row("down", key, inc, t, folded_into=parent, facts=f)
        inc["fold_row"] = row["id"]

    # ------------------------------------------------------------------------------------ messages
    def _row(self, kind: str, key: str, inc: Mapping[str, Any], t: int, *, folded_into: str | None = None,
             facts: Mapping[str, Any] | None = None) -> dict[str, Any]:
        f = facts if facts is not None else (inc.get("facts") or {})
        what = f.get("what")
        fact_lines = [fin(f"{cap(clean(what, 200))} since {hms(int(inc['start']), self.cfg.tz)}")] if what else []
        row = {"id": "inc_" + exp_ids.new_ulid(t), "probe": self.probe, "site": self.site,
               "line": key, "kind": kind, "start_ms": int(inc["start"]),
               "end_ms": inc.get("end") if kind == "back" else None,
               "where_json": json.dumps(f.get("where"), sort_keys=True) if f.get("where") else None,
               "facts_json": json.dumps(fact_lines), "folded_into": folded_into, "acked_by": None, "acked_at": None}
        self.sink.record(row)
        return row

    def _emit(self, kind: str, key: str, inc: dict[str, Any], t: int) -> None:
        """Write the incident row and post the message (resolved -> kind `back` in the incident log)."""
        row = self._row("back" if kind == "resolved" else kind, key, inc, t)
        inc["rows"].append(row["id"])
        if kind == "down":
            inc["row"] = row["id"]
        c = self.cfg
        msg = build_message(kind, key, inc, t, probe=self.probe, label=self.label, tz=c.tz, voice=c.voice,
                            edge_label=c.edge_label, board_url=c.board_url, incident_id=row["id"])
        if c.enabled:
            self.sink.page(msg)
        else:
            log.info("alert %s for %s recorded (alerts disabled)", kind, key)

    def _save(self) -> None:
        doc = json.dumps(self.export_state(), sort_keys=True, separators=(",", ":"))
        if doc != self._saved:
            self._saved = doc
            self.sink.save_state(self.probe, doc)


def iso_ms(ms: int | float) -> str:
    import datetime
    return (datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def _window(key: str, ev: Evaluation | None = None) -> int:
    """The line's state window: as evaluated (widened for a slow heartbeat), else the spec window."""
    from .rules import LINE_SPECS
    le = ev.lines.get(key) if ev is not None else None
    return le.window_ms if le is not None and le.window_ms else LINE_SPECS[key].window_ms


# ---------------------------------------------------------------------------------------- documents
def incident_doc(row: Mapping[str, Any], board_url: str | None = None) -> dict[str, Any]:
    """An Incident of 01-contracts.md section 5 from an `incidents` row (a dict or sqlite Row)."""
    from .alerts import board_link
    from .verdict import where_summary
    where = json.loads(row["where_json"]) if row["where_json"] else None
    try:
        facts = [str(x) for x in json.loads(row["facts_json"] or "[]")]
    except ValueError:
        facts = []
    return {"id": row["id"], "probe": row["probe"], "site": row["site"], "line": row["line"], "kind": row["kind"],
            "start": iso_ms(row["start_ms"]), "end": iso_ms(row["end_ms"]) if row["end_ms"] is not None else None,
            "where": where_summary(where), "facts": facts, "folded_into": row["folded_into"],
            "acked_by": row["acked_by"],
            "link": board_link(board_url, row["probe"], row["start_ms"], row["start_ms"])}
