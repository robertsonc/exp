"""A2.6 - rotate a probe ingest token and the agent secret without data loss.

A converged all-in-one host (agent, collector, dashboard, probe on a veth LAN). `POST components/{id}/rotate` and
`POST hosts/{id}/rotate-agent` are driven through the admin API; the observations are the collector's own records API
(the probe's heartbeat beats, counted by record id: no duplicates, no gap longer than 2 beats), the collector's ingest
endpoint (which token it accepts), the manager's agent API (which agent secret it accepts) and the host's credential
files. Grace periods are shortened by moving the stored `previous_valid_until` into the past (D1) and running the
manager's cron through wrangler dev's scheduled-event endpoint.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pytest
from expharness.dockerhost import wait_for

import m2lib
from m2lib import agent_call, agent_secret, host_row, provision_full

SITE = "rot-e2e"
BEAT_S = 10  # the probe's heartbeat interval in this scenario (m2lib probe intent)
TEST = "gateway"  # one record per beat


@dataclass
class Rot:
    full: m2lib.Full
    coll: tuple[str, int, str, dict[str, str]]
    probe: str
    notes: dict[str, Any] = field(default_factory=dict)


@pytest.fixture(scope="module")
def rot(stack, host_image):
    full = provision_full(stack, SITE, "a26", "e2e-rot")
    try:
        yield Rot(full, full.collector(stack), full.ids["probe"])
    finally:
        try:
            (stack.artifacts / "a26-host-diagnostics.txt").write_text(full.host.diagnostics())
            (stack.artifacts / "a26-host-journal.txt").write_text(full.host.journal(None, 600))
        finally:
            full.host.remove()


def beats(r: Rot, t0: float, t1: float) -> list[dict[str, Any]]:
    return sorted(m2lib.fetch_records(r.coll, r.probe, t0, t1, TEST), key=lambda x: x["ts"])


def epoch(ts: str) -> float:
    return datetime.fromisoformat(ts).timestamp()


def max_gap(rows: list[dict[str, Any]], t0: float, t1: float) -> float:
    ts = sorted([epoch(x["ts"]) for x in rows] + [t0, t1])
    return max(b - a for a, b in zip(ts, ts[1:], strict=False))


def reporting(stack, r: Rot) -> bool:
    rec = beats(r, time.time() - 40, time.time() + 60)
    return len(rec) >= 2


def test_probe_is_reporting_before_rotation(stack, rot):
    wait_for(lambda: reporting(stack, rot), 180, 5, "heartbeat records from the probe", rot.full.host.diagnostics)


def test_probe_token_rotation_keeps_data_flowing(stack, rot):
    host = rot.full.host
    old = m2lib.probe_token(host)
    assert m2lib.ingest_one(rot.coll, old, rot.probe, SITE)[0] == 200
    t_start = time.time() - 30
    before = beats(rot, t_start, time.time() + 5)
    assert len(before) >= 2

    t_rot = time.time()
    r = stack.admin.call("POST", f"/components/{rot.full.cids['probe']}/rotate", None, ok=(200,)).json()
    assert r["component_id"] == rot.full.cids["probe"] and r["previous_valid_until"]
    # the probe's credential file switches to the new token (agent restarts the unit: CR-wp2-cred-rotation-loadcredential)
    new = wait_for(lambda: (t := _try_token(host)) and t != old and t, 180, 2, "the probe's new ingest token", host.diagnostics)
    rot.notes.update(old=old, new=new, t_rot=t_rot)
    assert old not in host.run("cat /etc/exp/probe/creds/* /etc/exp/probe/config.json").out

    # old and new are both accepted during the grace period (overlap), at the collector itself
    assert m2lib.ingest_one(rot.coll, new, rot.probe, SITE)[0] == 200
    assert m2lib.ingest_one(rot.coll, old, rot.probe, SITE)[0] == 200, "the previous token must stay valid during the overlap"

    # records keep arriving through the switch: wait until beats under the NEW token are stored, then audit the stream
    t_after = time.time()
    wait_for(lambda: len(beats(rot, t_after, time.time() + 5)) >= 3, 120, 5, "heartbeats after the rotation", host.diagnostics)
    t_end = time.time()
    rows = beats(rot, t_start, t_end + 5)
    ids = [x["id"] for x in rows]
    assert len(ids) == len(set(ids)), "duplicate record ids"
    assert len(rows) > len(before), "no new records after the rotation"
    assert {x["id"] for x in before} <= set(ids), "records that were stored before the rotation disappeared"
    gap = max_gap(rows, t_start, t_end)
    (stack.artifacts / "a26-probe-rotation.txt").write_text(
        f"records {len(before)} -> {len(rows)}; max gap {gap:.1f}s over {t_end - t_start:.0f}s (limit {2 * BEAT_S}s)\n"
    )
    assert gap <= 2 * BEAT_S + 2, f"a gap of {gap:.1f}s ({gap / BEAT_S:.1f} beats) in the probe's heartbeat across the rotation"
    assert rot.full.host.run("systemctl is-active exp-probe").out.strip() == "active"
    h = stack.admin.get(f"/hosts/{rot.full.host_id}/status")["report"]
    assert {c["type"]: c["health"] for c in h["components"]}["probe"] in ("ok", "degraded")


def _try_token(host) -> str | None:
    try:
        return m2lib.probe_token(host)
    except AssertionError:
        return None


def test_old_probe_token_stops_working_after_the_grace_period(stack, rot):
    old, new = rot.notes["old"], rot.notes["new"]
    assert m2lib.ingest_one(rot.coll, old, rot.probe, SITE)[0] == 200  # still inside the 10 minutes
    past = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 60))
    stack.mgr.sql(f"UPDATE secrets SET previous_valid_until = '{past}' WHERE previous_valid_until IS NOT NULL")
    assert stack.mgr.run_cron("*/5 * * * *").status == 200
    # the collector learns about the dropped overlap through its next desired state (credential file change -> restart)

    def old_refused():
        return m2lib.ingest_one(rot.coll, old, rot.probe, SITE)[0] == 401

    wait_for(old_refused, 240, 5, "the collector refusing the old probe token", rot.full.host.diagnostics)
    assert m2lib.ingest_one(rot.coll, new, rot.probe, SITE)[0] == 200
    # and the probe is still delivering with the new token
    t = time.time()
    wait_for(lambda: len(beats(rot, t, time.time() + 5)) >= 2, 120, 5, "heartbeats with the new token", rot.full.host.diagnostics)


def test_agent_secret_rotation(stack, rot):
    host, hid = rot.full.host, rot.full.host_id
    old = agent_secret(host)
    t0 = time.time()
    r = stack.admin.call("POST", f"/hosts/{hid}/rotate-agent", None, ok=(202,)).json()
    assert r["host_id"] == hid and r["action_id"].startswith("act_")
    new = wait_for(lambda: (s := agent_secret(host)) != old and s, 180, 2, "the agent storing its new secret", host.diagnostics)
    assert new.startswith("expa_") and new != old
    mode = host.run("stat -c '%a %U' /etc/exp/agent.json").out.strip()
    assert mode == "600 root", mode
    # the manager accepts the new secret, and the old one only during the overlap
    assert agent_call(stack, "GET", "/desired", new)[0] in (200, 304, 404)
    st_old, _ = agent_call(stack, "GET", "/desired", old)
    assert st_old in (200, 304, 404), "the previous agent secret must stay valid during the grace period"
    # the agent keeps reporting with the new secret (no lock-out)
    seen = host_row(stack, hid)["last_seen"]
    wait_for(lambda: host_row(stack, hid)["last_seen"] > seen, 150, 5, "a status report after the rotation", host.diagnostics)
    assert host_row(stack, hid)["state"] == "enrolled"
    # rotation action consumed: asking again with nothing pending is refused
    assert agent_call(stack, "POST", "/rotate", new, b"{}")[0] == 409
    # grace over (D1 time travel + the cron that drops expired previous values): the old secret is dead
    past = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - 60))
    stack.mgr.sql(f"UPDATE agent_creds SET previous_valid_until = '{past}' WHERE host_id = '{hid}'")
    assert agent_call(stack, "GET", "/desired", old)[0] == 401
    assert stack.mgr.run_cron("*/5 * * * *").status == 200
    assert agent_call(stack, "GET", "/desired", old)[0] == 401
    assert agent_call(stack, "GET", "/desired", new)[0] in (200, 304)
    # the secret never reached the journal or the host's own status
    assert old not in host.journal(None, 3000) and new not in host.journal(None, 3000)
    assert json.loads(host.read("/etc/exp/agent.json"))["agent_secret"] == new
    assert time.time() - t0 < 900
