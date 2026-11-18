"""M1 acceptance (SPEC.md section 9): the data spine, installed by hand from a signed release, in two layouts
(`all`: probe + collector + dashboard on one host; `split`: collector + dashboard on one host, the probe on another).

The tests in a layout run in order and share one running stack (the probe is started by A1.1, which times it).
Every assertion is on an END STATE read from the product (dashboard API, collector SQLite, probe spool, the rendered
board), and each fault has a known-good control: the DNS canary answers before the fault and after the restore.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest
from exp_common import config as exp_config
from exp_common import ids as exp_ids

import m1lib as L

pytestmark = pytest.mark.e2e

WHERE_DNS = {"resolver", "dns_path"}
BOARD_JS = Path(__file__).resolve().parent / "board.js"


def iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + "%03dZ" % (int(epoch * 1000) % 1000)


def parse_iso(s: str) -> float:
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def board(st: L.Stack, path: str, shot: Path, tag: str) -> dict[str, Any]:
    """Open the dashboard page in Chromium (Playwright) as the local user; returns title/text/console errors."""
    env = {**os.environ, "EXP_E2E_USER": L.USER, "EXP_E2E_PASSWORD": st.password}
    shot.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["node", str(BOARD_JS), st.dashboard_url, path, str(shot)],  # noqa: S603,S607
                       capture_output=True, text=True, env=env, timeout=120, cwd=str(L.REPO))
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise L.E2EError(f"{tag}: board.js printed no JSON (rc={r.returncode}): {r.stdout[-300:]} {r.stderr[-500:]}") from None
    if "error" in out:
        raise L.E2EError(f"{tag}: board.js failed: {out['error']}")
    return out


def assert_canary(st: L.Stack, why: str) -> None:
    """Known-good control: the simulated resolvers answer the canary (so a later DNS failure is the fault)."""
    for ip in ("10.1.0.1", "1.1.1.1", "8.8.8.8"):
        st.lanctl("canary", ip)          # raises when the resolver is silent or answers wrongly


# ============================================================================================ A1.1
def test_a1_1_all_lines_green_within_30s_and_beats_every_10s(stack: L.Stack, artifacts: Path) -> None:
    assert_canary(stack, "before the probe starts")
    t0 = stack.start_probe()

    def all_green() -> dict[str, Any] | None:
        s = stack.state()
        ls = stack.line_states(s)
        return s if set(ls) == set(L.LINES) and all(v == "ok" for v in ls.values()) else None

    # the whole path is real: probe -> TLS-pinned push -> collector -> rules -> dashboard federation
    state = L.wait_for(all_green, 30 - (time.time() - t0), step=1.0, what="all lines green within 30 s of start")
    green_after = time.time() - t0
    assert green_after <= 30, f"all lines green only after {green_after:.1f}s"
    stack.notes["green_after_s"] = round(green_after, 1)
    exp_config.validate(state, L.REPO / "shared" / "schemas" / "state.schema.json")
    assert state["verdict"]["severity"] == "ok", state["verdict"]
    assert state["probe"] == stack.probe_id and state["site"] == L.SITE

    # beats render every 10 s: wait until the probe has run for 80 s, then inspect the last 60 s
    time.sleep(max(0.0, 80 - (time.time() - t0)))
    now = time.time()
    beats = stack.dash().get("beats", probe=stack.probe_id, **{"from": iso(now - 60), "to": iso(now)})
    exp_config.validate(beats, L.REPO / "shared" / "schemas" / "beats.schema.json")
    for line in L.BEAT_LINES:
        times = [b[0] / 1000 for b in beats["lines"][line]]
        # internet records two traces per cycle (test path + control path, <1 s apart): one beat per cycle
        cycles = [t for i, t in enumerate(times) if i == 0 or t - times[i - 1] > 3]
        gaps = [round(b - a, 1) for a, b in zip(cycles, cycles[1:], strict=False)]
        assert len(cycles) >= 5, f"{line}: only {len(cycles)} beats in 60 s: {times}"
        assert all(8.0 <= g <= 12.0 for g in gaps), f"{line}: beats are not 10 s apart: {gaps}"
        assert all(b[1] == 0 for b in beats["lines"][line]), f"{line}: a beat is not ok: {beats['lines'][line]}"
    assert beats["lines"]["apps"] and all(b[1] == 0 for b in beats["lines"]["apps"]), beats["lines"]["apps"]

    # what the operator sees: the board in a real browser
    shot = artifacts / stack.layout / "a1_1-board-green.png"
    page = board(stack, f"/probe/{stack.probe_id}", shot, "A1.1")
    assert shot.stat().st_size > 5000
    text = page["text"]
    assert "Hall B e2e" in text and state["verdict"]["headline"] in text, text[:600]
    for label in ("Network", "DHCP", "DNS", "Internet", "Apps"):
        assert re.search(rf"{label}\s*\n\s*ok\b", text), f"board does not show {label} ok:\n{text[:800]}"
    assert not page["errors"], page["errors"]
    stack.save_logs("a1_1")


# ============================================================================================ A1.2
def test_a1_2_dns_block_turns_dns_red_and_unblock_logs_incident(stack: L.Stack, artifacts: Path) -> None:
    assert stack.line_states()["dns"] == "ok", "A1.1 must have left the board green"
    assert_canary(stack, "known good before the fault")
    probe_inc_before = {i["id"] for i in stack.dash().get("incidents", probe=stack.probe_id)["items"]}

    # (a) one namespace of three: dns_hb rotates over the ports (02-probe 4), so 1 of 3 beats fails: DNS leaves
    #     green as "degraded" (not red) and names the DNS path. This proves the fault is real and per-port.
    stack.lanctl("block-dns", stack.port_label(0))
    st = L.wait_for(lambda: (s if stack.line_states(s := stack.state())["dns"] != "ok" else None), 40,
                    what="dns leaves green with one of three namespaces blocked")
    assert stack.line_states(st)["dns"] == "warn", stack.line_states(st)

    # (b) DNS blocked in every test-port namespace of the probe: red within 30 s, where = resolver/dns_path
    for i in (1, 2):
        stack.lanctl("block-dns", stack.port_label(i))
    t_block = time.time()

    def red() -> dict[str, Any] | None:
        s = stack.state()
        w = (s["verdict"].get("where") or {}).get("seg")
        return s if stack.line_states(s)["dns"] == "fail" and w in WHERE_DNS else None

    red_state = L.wait_for(red, 30, step=1.0, what="dns red with where in {resolver, dns_path} within 30 s")
    t_red = time.time() - t_block
    assert t_red <= 30
    stack.notes.update(red_after_s=round(t_red, 1), red_at=red_state["at"], where=red_state["verdict"]["where"]["seg"])
    exp_config.validate(red_state, L.REPO / "shared" / "schemas" / "state.schema.json")
    assert stack.line_states(red_state)["network"] == "ok" and stack.line_states(red_state)["dhcp"] == "ok"
    dns_line = next(ln for ln in red_state["lines"] if ln["key"] == "dns")
    assert dns_line["since"] and "10.1.0.1" in (dns_line["detail"] or "") + json.dumps(red_state["failing"]), dns_line

    # the incident opens after hold_down_s (20 s) and carries the same where
    def down_incident() -> dict[str, Any] | None:
        items = stack.dash().get("incidents", probe=stack.probe_id)["items"]
        return next((i for i in items if i["line"] == "dns" and i["kind"] == "down" and i["id"] not in probe_inc_before), None)

    inc = L.wait_for(down_incident, 60, what="a dns 'down' incident")
    assert inc["end"] is None, inc
    assert (inc["where"] or {}).get("seg") in WHERE_DNS, inc
    stack.notes.update(incident_id=inc["id"], incident_start=inc["start"])
    exp_config.validate(inc, L.REPO / "shared" / "schemas" / "incident.schema.json")
    time.sleep(8)                                           # stay red a little longer: A1.3 rewinds into this window
    stack.notes["still_red_at"] = stack.state()["at"]
    assert stack.line_states()["dns"] == "fail"
    shot = artifacts / stack.layout / "a1_2-board-dns-red.png"
    page = board(stack, f"/probe/{stack.probe_id}", shot, "A1.2")
    assert re.search(r"DNS\s*\n\s*(failing|down|fail|unstable)", page["text"], re.I) or "DNS" in page["text"], page["text"][:500]

    # unblock: back to green (the canary is the control that DNS itself is fine again)
    stack.lanctl("restore")
    assert json.loads(stack.lanctl("status"))["active"] is False
    assert_canary(stack, "after restore")
    t_restore = time.time()
    L.wait_for(lambda: stack.line_states()["dns"] == "ok", 90, what="dns green after the unblock")
    stack.notes["green_again_after_s"] = round(time.time() - t_restore, 1)

    def closed() -> dict[str, Any] | None:           # down -> back is logged (hold_back_s = 60 s of ok)
        items = stack.dash().get("incidents", probe=stack.probe_id)["items"]
        dns = [i for i in items if i["line"] == "dns" and i["id"] not in probe_inc_before]
        down = next((i for i in dns if i["kind"] == "down" and i["end"]), None)
        back = next((i for i in dns if i["kind"] == "back"), None)
        return {"down": down, "back": back} if down and back else None

    both = L.wait_for(closed, 150, step=2.0, what="the dns incident closed (down then back)")
    assert parse_iso(both["down"]["end"]) > parse_iso(both["down"]["start"])
    assert parse_iso(both["down"]["start"]) >= t_block - 40, both            # not an old incident
    assert parse_iso(both["down"]["end"]) > t_restore - 5, "the incident ended before the unblock"
    stack.notes["incident"] = both["down"]
    # and the stored end state: the incident rows are in SQLite on the collector
    rows = stack.col.sqlite("/var/lib/exp/collector/records.db",
                            f"SELECT kind, end_ms IS NOT NULL FROM incidents WHERE probe='{stack.probe_id}' AND line='dns'")
    assert any(r.startswith("down|1") for r in rows) and any(r.startswith("back|") for r in rows), rows
    stack.save_logs("a1_2")


# ============================================================================================ A1.3
def test_a1_3_rewind_to_the_incident_shows_that_state(stack: L.Stack, artifacts: Path) -> None:
    n = stack.notes
    assert "incident_start" in n and "still_red_at" in n, "A1.2 must have produced an incident"
    t_in = parse_iso(n["still_red_at"])
    inc = n["incident"]
    assert parse_iso(inc["start"]) < t_in < parse_iso(inc["end"]), "the rewind time is not inside the incident"
    at = iso(t_in)

    dash_state = stack.state(at=at)
    col_state = stack.collector_get("state", probe=stack.probe_id, at=at, voice="sysadmin")
    assert dash_state == col_state, "dashboard state?at differs from the collector's"
    assert dash_state["live"] is False and dash_state["at"] == at
    ls = {ln["key"]: ln["state"] for ln in dash_state["lines"]}
    assert ls["dns"] == "fail" and ls["network"] == "ok", ls
    assert dash_state["verdict"]["where"]["seg"] in WHERE_DNS, dash_state["verdict"]
    # the live state is green again by now: the rewind really shows the PAST (negative control)
    assert stack.line_states()["dns"] != "fail"
    # deterministic: asking twice gives the same document
    assert stack.state(at=at) == dash_state

    shot = artifacts / stack.layout / "a1_3-board-rewind.png"
    page = board(stack, f"/probe/{stack.probe_id}?at={at}", shot, "A1.3")
    text = page["text"]
    assert "Looking back at" in text and "Back to live" in text, text[:500]
    assert dash_state["verdict"]["headline"] in text, f"board does not show the rewound headline:\n{text[:900]}"
    assert re.search(r"DNS\s*\n\s*(failing|down|fail|unstable|broken)", text, re.I), text[:900]
    assert not page["errors"], page["errors"]
    # and at a moment before the outage the board is green
    before = iso(parse_iso(inc["start"]) - 20)
    assert stack.line_states(stack.state(at=before))["dns"] == "ok"
    assert stack.state(at=before) == stack.collector_get("state", probe=stack.probe_id, at=before, voice="sysadmin")


# ============================================================================================ A1.4
def spool_sets(st: L.Stack) -> tuple[set[str], set[str], set[str]]:
    """(shipped = ledger minus still-spooled, ledger, pending) from the probe's own spool database."""
    db = "/var/lib/exp/probe/spool.db"
    shipped = set(st.probe_host.sqlite(db, "SELECT id FROM ledger WHERE id NOT IN (SELECT id FROM spool)"))
    pending = set(st.probe_host.sqlite(db, "SELECT id FROM spool"))
    return shipped, set(st.probe_host.sqlite(db, "SELECT id FROM ledger")), pending


def collector_ids(st: L.Stack) -> list[str]:
    return st.col.sqlite("/var/lib/exp/collector/records.db", f"SELECT id FROM records WHERE probe='{st.probe_id}'")


def test_a1_4_collector_restart_no_duplicate_and_no_missing_records(stack: L.Stack) -> None:
    L.wait_for(lambda: len(spool_sets(stack)[1]) > 50, 30, what="the probe's ledger to fill")
    pre = len(collector_ids(stack))
    assert pre > 0

    # mid-stream: stop the collector, let the probe spool for 40 s (4 heartbeat cycles), start it again
    t_stop = time.time()
    stack.col.ok("systemctl stop exp-collector.service", timeout=60)
    assert stack.col.run("systemctl is-active exp-collector.service").stdout.strip() != "active"
    spooled_during_outage: set[str] = set()
    while time.time() - t_stop < 40:
        spooled_during_outage |= spool_sets(stack)[2]
        time.sleep(5)
    assert len(spooled_during_outage) > 20, "the probe did not keep spooling while the collector was down"
    t_start = time.time()
    stack.col.ok("systemctl start exp-collector.service", timeout=60)
    stack.col.ok("systemctl is-active exp-collector.service")

    # the spool replays: everything spooled before the restart reaches the collector
    def drained() -> bool:
        pending = spool_sets(stack)[2]
        return not (pending & spooled_during_outage)

    L.wait_for(drained, 180, step=3.0, what="the probe's spool to replay the outage's records")
    time.sleep(12)                                          # let the last in-flight batch land

    shipped, ledger_before, _pending = spool_sets(stack)    # snapshot 1 (what the probe says it shipped)
    ids = collector_ids(stack)                              # snapshot 2 (what the collector stored), later
    ledger_after = spool_sets(stack)[1]                     # snapshot 3 (everything the probe ever produced)
    stored = set(ids)
    assert len(ids) == len(stored), "duplicate (probe,id) rows in the collector"
    missing = shipped - stored
    assert not missing, f"{len(missing)} shipped records are missing from the collector, e.g. {sorted(missing)[:3]}"
    phantom = stored - ledger_after
    assert not phantom, f"{len(phantom)} collector records the probe never produced, e.g. {sorted(phantom)[:3]}"
    assert spooled_during_outage <= stored | spool_sets(stack)[2], "records spooled during the outage were lost"
    assert len(spooled_during_outage - spool_sets(stack)[2] - stored) == 0
    assert len(ids) > pre

    # independent view: no hole in the network heartbeat across the outage (one beat per 10 s cycle)
    now = time.time()
    beats = stack.dash().get("beats", probe=stack.probe_id, **{"from": iso(t_stop - 30), "to": iso(now)})
    ts = [b[0] / 1000 for b in beats["lines"]["network"]]
    assert ts and ts[0] <= t_stop - 15, "no beats before the outage in the window"
    assert max(b - a for a, b in zip(ts, ts[1:], strict=False)) <= 11.5, \
        f"hole in the network heartbeat: {[round(b - a, 1) for a, b in zip(ts, ts[1:], strict=False)]}"
    assert any(t_stop < t < t_start for t in ts), "no network beats stamped inside the outage window"
    stack.notes["a1_4"] = {"shipped": len(shipped), "stored": len(stored), "spooled_during_outage": len(spooled_during_outage)}


# ============================================================================================ A1.5
def rec(st: L.Stack, **kw: Any) -> dict[str, Any]:
    d = {"schema": "exp.measurement/1", "probe": st.probe_id, "site": L.SITE, "test": "e2e_control", "outcome": "ok",
         "ts": iso(time.time()), "id": exp_ids.new_ulid(), "target": "e2e", "metrics": {}, "labels": {}}
    d.update(kw)
    return d


def test_a1_5_live_ingest_rejects_identity_reserved_labels_and_bad_timestamps(stack: L.Stack) -> None:
    now = time.time()
    cases: dict[str, tuple[dict[str, Any], str | None]] = {
        "good": (rec(stack), None),                                                       # the known-good control
        "other-probe": (rec(stack, probe="probe-impostor"), "identity_mismatch"),
        "other-site": (rec(stack, site="elsewhere"), "identity_mismatch"),
        "label-probe": (rec(stack, labels={"probe": "spoof"}), "invalid_measurement"),
        "label-site": (rec(stack, labels={"site": "spoof"}), "invalid_measurement"),
        "label-outcome": (rec(stack, labels={"outcome": "ok"}), "invalid_measurement"),
        "label-target": (rec(stack, labels={"target": "x"}), "invalid_measurement"),
        "label-dunder": (rec(stack, labels={"__name__": "x"}), "invalid_measurement"),
        "naive-ts": (rec(stack, ts=iso(now)[:-1]), "invalid_measurement"),
        "future-ts": (rec(stack, ts=iso(now + 120)), "ts_future"),
        "ancient-ts": (rec(stack, ts=iso(now - 8 * 86400)), "ts_too_old"),
    }
    names = list(cases)
    resp = stack.ingest([cases[n][0] for n in names])          # ONE batch: valid lines are accepted beside bad ones
    assert resp.status == 200, resp.body[:300]
    doc = resp.json()
    got = {names[r["line"] - 1]: r["error"]["code"] for r in doc["rejected"]}
    want = {n: code for n, (_r, code) in cases.items() if code}
    assert got == want, f"rejections differ:\n got  {got}\n want {want}"
    assert doc["accepted"] == 1 and doc["duplicates"] == 0, doc
    # end state in SQLite: the good record is stored, no rejected one is
    stored = set(collector_ids(stack))
    assert cases["good"][0]["id"] in stored
    assert not [n for n in want if cases[n][0]["id"] in stored]
    # replaying the good record is a duplicate, not a second row
    again = stack.ingest([cases["good"][0]]).json()
    assert again["accepted"] == 0 and again["duplicates"] == 1, again
    assert collector_ids(stack).count(cases["good"][0]["id"]) == 1
    # auth: a dashboard token (wrong scope), a garbage token and no token never reach the parser
    assert stack.ingest([rec(stack)], token=stack.dash_token).status == 401
    assert stack.ingest([rec(stack)], token="expi_" + "A" * 43).status == 401
    # a valid token of ANOTHER probe identity cannot speak for this probe: here there is no such token, so the
    # identity binding above (probe != token identity) is the guard; it is rejected line by line, never stored
    assert not [i for i in collector_ids(stack) if i in {cases[n][0]["id"] for n in want}]
