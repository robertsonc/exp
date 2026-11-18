"""Seeded browser-test world: history for three probes, a live feeder, a rich/hostile probe, incidents."""
from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path
from typing import Any

from exp_common import ids

ROOT = Path(__file__).resolve().parents[2]
XSS = "<img src=x onerror=alert(1)>"
LINES = {"network": "gateway", "dhcp": "dhcp_hb", "dns": "dns_hb", "internet": "trace"}
SITE = {"probe-a1": "hall-a", "probe-b1": "hall-b", "probe-c1": "hall-c"}
FAKE_OF = {"probe-a1": "col-a", "probe-b1": "col-b", "probe-c1": "col-c"}


def meas(probe: str, test: str, outcome: str, ts_ms: int, error: str | None = None) -> dict[str, Any]:
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts_ms // 1000)) + f".{ts_ms % 1000:03d}Z"
    doc: dict[str, Any] = {"schema": "exp.measurement/1", "id": ids.new_ulid(), "ts": iso, "probe": probe,
                           "site": SITE[probe], "test": test, "outcome": outcome, "labels": {"port": "c01"},
                           "agent_ver": "0.1.0"}
    if error:
        doc["error"] = error
    return doc


def ingest(world: Any, probe: str, docs: list[dict[str, Any]]) -> dict[str, Any]:
    body = ("\n".join(json.dumps(d, separators=(",", ":")) for d in docs) + "\n").encode()
    res = world.fakes[FAKE_OF[probe]].app.ingest(probe, body)
    assert not res["rejected"], res["rejected"]
    return res


class Feeder(threading.Thread):
    """Emits one beat per line every `period` seconds for the live probes; outcomes can be overridden."""

    def __init__(self, world: Any, probes: tuple[str, ...], period: float = 1.5) -> None:
        super().__init__(daemon=True)
        self.world, self.probes, self.period = world, probes, period
        self.override: dict[tuple[str, str], str] = {}
        self.stop_ev = threading.Event()

    def beat(self, probe: str) -> None:
        now = int(time.time() * 1000)
        docs = []
        for line, test in LINES.items():
            out = self.override.get((probe, line), "ok")
            docs.append(meas(probe, test, out, now, None if out == "ok" else f"{line} check failed (injected)"))
        try:
            ingest(self.world, probe, docs)
        except (AssertionError, OSError):
            pass                                   # a collector the test stopped on purpose

    def run(self) -> None:
        while not self.stop_ev.wait(self.period):
            for p in self.probes:
                self.beat(p)

    def set(self, probe: str, line: str, outcome: str | None) -> None:
        if outcome is None:
            self.override.pop((probe, line), None)
        else:
            self.override[(probe, line)] = outcome
        self.beat(probe)

    def stop(self) -> None:
        self.stop_ev.set()
        self.join(timeout=3)


def seed(world: Any) -> dict[str, Any]:
    """History: a1 has a DNS outage from now-14 min to now-8 min; b1 went silent 4 min ago; c1 is always fine.
    Returns the timeline plus a started Feeder for a1 and c1."""
    now = int(time.time() * 1000) // 1000 * 1000
    fail_from, fail_to = now - 14 * 60000, now - 8 * 60000
    for probe, end in (("probe-a1", now - 3000), ("probe-b1", now - 4 * 60000), ("probe-c1", now - 3000)):
        docs = []
        t = now - 25 * 60000
        while t <= end:
            for line, test in LINES.items():
                bad = probe == "probe-a1" and line == "dns" and fail_from <= t < fail_to
                docs.append(meas(probe, test, "fail" if bad else "ok", t, "no answers from 1.1.1.1" if bad else None))
            t += 10000
        for i in range(0, len(docs), 500):
            ingest(world, probe, docs[i:i + 500])
    # a rich, hostile probe served from a state document (labels and texts are attacker-controlled)
    col_a = world.fakes["col-a"].app
    doc = json.loads((ROOT / "test/fixtures/state/gateway-fail.json").read_text())
    doc.update({"probe": "probe-g1", "site": "hall-a"})
    doc["verdict"]["sub"] = "Gateway 10.1.0.1 isn't answering " + XSS
    doc["failing"][0]["items"][0]["text"] = "no reply " + XSS
    lines = doc["lines"]
    for key, label in (("dhcp", "DHCP"), ("dns", "DNS"), ("internet", "Internet")):
        extra = copy.deepcopy(lines[0])
        extra.update({"key": key, "label": label, "state": "ok", "word": "ok", "since": None, "detail": ""})
        lines.append(extra)
    lines[0]["detail"] = "10.1.0.1 not answering " + XSS
    col_a.set_state_doc("probe-g1", doc)
    col_a.probe_labels["probe-g1"] = XSS
    col_a.probe_labels["probe-a1"] = "Registration desk"
    # incidents: one open (a1, dns), one resolved (c1, network)
    for probe, line, kind, start, end, facts in (
            ("probe-a1", "dns", "down", fail_from, None, ["No answers from 1.1.1.1 " + XSS]),
            ("probe-c1", "network", "back", now - 20 * 60000, now - 18 * 60000, ["Gateway answered again"]),
            ("probe-c1", "probe", "down", now - 40 * 60000, now - 30 * 60000, ["Probe went silent"])):
        iso = lambda ms: time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms // 1000)) + ".000Z"  # noqa: E731
        world.fakes[FAKE_OF[probe]].app.inject_incident({
            "id": "inc_" + ids.new_ulid(), "probe": probe, "site": SITE[probe], "line": line, "kind": kind,
            "start": iso(start), "end": iso(end) if end else None, "where": {"seg": "edge", "ip": "10.1.0.2"},
            "facts": facts, "folded_into": None, "acked_by": None,
            "link": f"https://10.32.98.30/probe/{probe}?at={iso(start)}"})
    feeder = Feeder(world, ("probe-a1", "probe-c1"))
    feeder.start()
    return {"now": now, "fail_from": fail_from, "fail_to": fail_to, "feeder": feeder}
