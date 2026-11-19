"""A3.1 (SPEC.md section 9, M3): one dashboard federates three collectors over two sites.

* the overview shows every probe of both sites, grouped by site, with the right state (API and the rendered page);
* probe-scoped calls (state, beats, records) are answered by the collector that owns the probe;
* one collector stopped: partial results are flagged for exactly that collector, the other probes' board keeps
  working and live updates (SSE) keep arriving; started again, everything recovers.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

import pytest

import m3lib as M

pytestmark = pytest.mark.e2e

PROBES = [n["probe"] for n in M.NODES]


def states(m: M.Multi) -> dict[str, Any]:
    return m.dash().get("states", voice="sysadmin")


def collectors_ok(doc: dict[str, Any]) -> dict[str, bool]:
    return {c["collector_id"]: c["ok"] for c in doc["collectors"]}


def test_a3_1_overview_shows_every_probe_of_both_sites_grouped_by_site(stack: M.Multi, artifacts: Path) -> None:
    for lan in (1, 2):                                       # known-good control per LAN: the resolvers answer
        stack.canary(lan)
    t0 = stack.start_probes()

    def green() -> dict[str, Any] | None:
        doc = states(stack)
        return doc if M.all_green(doc["items"], PROBES) and all(collectors_ok(doc).values()) else None

    doc = M.wait_for(green, 60, step=2.0, what="every probe of both sites green on the federated overview")
    stack.notes["green_after_s"] = round(time.time() - t0, 1)
    assert collectors_ok(doc) == {n.cid: True for n in stack.nodes}, doc["collectors"]
    by = {i["probe"]: i for i in doc["items"]}
    assert set(by) == set(PROBES), sorted(by)
    for n in stack.nodes:
        assert by[n.probe]["site"] == n.site and by[n.probe]["collector_id"] == n.cid, by[n.probe]
        assert by[n.probe]["severity"] == "ok", by[n.probe]
    # sorted by site: the list the overview groups
    assert [i["site"] for i in doc["items"]] == sorted(i["site"] for i in doc["items"])

    probes = stack.dash().get("probes")
    assert {p["probe"]: (p["site"], p["label"]) for p in probes["items"]} == {n.probe: (n.site, n.label) for n in stack.nodes}

    # what the operator sees: the overview in a real browser, grouped by site
    shot = artifacts / "a3_1-overview-all-green.png"
    page = M.board(stack, "/", shot, "A3.1 overview")
    assert shot.stat().st_size > 5000
    text = page["text"]
    assert "All 3 probes are good" in text, text[:600]
    assert not page["errors"], page["errors"]
    for site, labels, count in (("Hall B", ("Hall B east", "Hall B west"), "2 probes, all good"),
                                ("Hall C", ("Hall C main",), "1 probe, all good")):
        sec = re.search(rf"^{site}[ \t]*$[\s\S]{{0,30}}?{re.escape(count)}[\s\S]*?(?=^Hall [BC][ \t]*$|\Z)", text, re.M)
        assert sec, f"no '{site}' group with '{count}' in the overview:\n{text[:900]}"
        assert all(lb in sec.group(0) for lb in labels), (site, sec.group(0)[:400])
    assert "unreachable" not in text
    # a probe label with markup is text on the board (textContent), never an element
    assert M.HOSTILE_LABEL in text, text[:900]


def test_a3_1_probe_scoped_calls_route_to_the_owning_collector(stack: M.Multi) -> None:
    for n in stack.nodes:                                    # let every probe produce a minute of heartbeat history
        M.wait_for(lambda n=n: len(stack.dash().get("beats", probe=n.probe, **{
            "from": M.iso(time.time() - 90), "to": M.iso(time.time())})["lines"]["network"]) >= 6, 90, step=3.0,
            what=f"{n.probe}: six network beats")
    now = time.time()
    frm, to = M.iso(now - 90), M.iso(now)
    for n in stack.nodes:
        via_dash = stack.dash().get("state", probe=n.probe, voice="sysadmin")
        direct = stack.collector_get(n, "state", probe=n.probe, voice="sysadmin")
        assert via_dash["probe"] == direct["probe"] == n.probe and via_dash["site"] == n.site
        assert M.line_states(via_dash) == M.line_states(direct) and set(M.line_states(via_dash)) >= set(M.LINES)
        at = M.iso(now - 20)
        assert stack.dash().get("state", probe=n.probe, at=at, voice="sysadmin") == \
            stack.collector_get(n, "state", probe=n.probe, at=at, voice="sysadmin"), f"state?at differs for {n.probe}"

        beats = stack.dash().get("beats", probe=n.probe, **{"from": frm, "to": to})
        assert beats == stack.collector_get(n, "beats", probe=n.probe, **{"from": frm, "to": to})
        assert beats["probe"] == n.probe and len(beats["lines"]["network"]) >= 4, beats["lines"]["network"]

        recs = stack.dash().get("records", probe=n.probe, test="gateway", **{"from": frm, "to": to})
        assert recs["items"] and all(r["probe"] == n.probe and r["site"] == n.site for r in recs["items"]), recs["items"][:2]
        assert {r["id"] for r in recs["items"]} <= {r["id"] for r in stack.collector_get(
            n, "records", probe=n.probe, test="gateway", **{"from": frm, "to": to})["items"]}
        # the OTHER collectors do not know this probe: the data really lives on its owner only
        for other in stack.nodes:
            if other is not n:
                with pytest.raises(M.E2EError, match=r"-> 404 .*unknown_probe"):
                    stack.collector_get(other, "records", probe=n.probe, **{"from": frm, "to": to})


def read_stream(m: M.Multi, query: str, seconds: float) -> list[tuple[str, dict[str, Any]]]:
    d = m.dash()
    return M.read_sse(m.dashboard_url, m.dash_fp, d.cookie, query, seconds)


def test_a3_1_one_collector_down_flags_that_collector_only_and_the_rest_keeps_working(stack: M.Multi, artifacts: Path) -> None:
    victim = stack.node("probe-b2")
    others = [n for n in stack.nodes if n is not victim]
    assert M.line_states(stack.dash().get("state", probe=victim.probe, voice="sysadmin"))["dns"] == "ok"
    stack.save_logs("a3_1-before-stop")
    t_stop = time.time()
    victim.host.ok("systemctl stop exp-collector.service", timeout=60)
    assert victim.host.run("systemctl is-active exp-collector.service").stdout.strip() != "active"
    try:
        def partial() -> dict[str, Any] | None:
            doc = states(stack)
            return doc if collectors_ok(doc).get(victim.cid) is False else None

        doc = M.wait_for(partial, 20, step=1.0, what="the federated states flag the stopped collector")
        assert collectors_ok(doc) == {victim.cid: False, **{n.cid: True for n in others}}, doc["collectors"]
        assert next(c for c in doc["collectors"] if c["collector_id"] == victim.cid)["error"]
        assert {i["probe"] for i in doc["items"]} == {n.probe for n in others}, "the other probes must stay on the board"
        assert all(i["severity"] == "ok" for i in doc["items"]), doc["items"]
        pr = stack.dash().get("probes")
        assert pr["items"] and {c["collector_id"]: c["ok"] for c in pr["collectors"]}[victim.cid] is False

        # probe-scoped calls: the live probes' board works, the one on the dead collector fails (no stale answer)
        for n in others:
            assert M.line_states(stack.dash().get("state", probe=n.probe, voice="sysadmin"))["network"] == "ok"
        with pytest.raises(M.E2EError, match=r"-> 5\d\d"):
            stack.dash().get("state", probe=victim.probe, voice="sysadmin")

        # what the operator sees: the partial banner naming exactly the Hall B collector, the other rows intact
        shot = artifacts / "a3_1-overview-collector-down.png"
        page = M.board(stack, "/", shot, "A3.1 partial")
        text = page["text"]
        assert "Partial results" in text and text.count("collector unreachable") == 1, text[:700]
        assert "Hall B collector unreachable" in text, text[:700]
        assert "Hall B east" in text and "Hall C main" in text and "Hall B west" not in text, text[:900]
        assert not page["errors"], page["errors"]

        # live updates continue for the probes that are served: beats keep arriving through the dashboard's stream
        events = read_stream(stack, "probes=" + ",".join(n.probe for n in others), 25)
        beat_probes = {d["probe"] for e, d in events if e == "beat"}
        assert beat_probes == {n.probe for n in others}, f"live beats from {sorted(beat_probes)}: {[e for e, _ in events][:20]}"
        down = [d for e, d in events if e == "collector" and d.get("ok") is False]
        assert any(d["collector_id"] == victim.cid for d in down), events[:6]
        # the dead collector's probe keeps measuring: it spools, so nothing is lost
        spooled = victim.host.sqlite("/var/lib/exp/probe/spool.db", "SELECT count(*) FROM spool")
        assert int(spooled[0]) > 5, spooled
        time.sleep(max(0.0, 45 - (time.time() - t_stop)))      # a minute-class outage (< the 90 s of a silent probe)
    finally:
        victim.host.ok("systemctl start exp-collector.service", timeout=60)

    # restart: everything recovers (federation, the probe's spool replays, the board is green again)
    def recovered() -> dict[str, Any] | None:
        doc = states(stack)
        return doc if all(collectors_ok(doc).values()) and M.all_green(doc["items"], PROBES) else None

    doc = M.wait_for(recovered, 120, step=2.0, what="all three collectors back and every probe green again")
    assert {i["probe"] for i in doc["items"]} == set(PROBES)
    shot = artifacts / "a3_1-overview-recovered.png"
    page = M.board(stack, "/", shot, "A3.1 recovered")
    assert "All 3 probes are good" in page["text"] and "unreachable" not in page["text"], page["text"][:600]
    M.wait_for(lambda: M.line_states(stack.dash().get("state", probe=victim.probe, voice="sysadmin"))["dns"] == "ok", 60,
               what="the probe on the restarted collector routes again")
    # the spool replayed: the outage is not a hole in the heartbeat history
    now = time.time()

    def replayed() -> dict[str, Any] | None:
        b = stack.dash().get("beats", probe=victim.probe, **{"from": M.iso(t_stop - 20), "to": M.iso(now)})
        return b if len(b["lines"]["network"]) >= 8 else None

    beats = M.wait_for(replayed, 90, step=3.0, what="the outage's beats replayed")
    ts = [x[0] / 1000 for x in beats["lines"]["network"]]
    assert any(t_stop < t < t_stop + 40 for t in ts), "no network beats stamped inside the outage window"
    stack.save_logs("a3_1-after-restart")
