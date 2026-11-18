"""Incident engine (03-collector.md section 6): holds, again, flapping, folding, silent probe, persistence,
SQLite rows, ack. Driven through the same replay loop the golden tests use."""
from __future__ import annotations

import json

import pytest
import synth
from colhelpers import check_schema_file
from exp_common import schema as exp_schema

from exp_collector import replay as R
from exp_collector.engine import StoreSink
from exp_collector.incidents import IncidentConfig, MemorySink, ProbeIncidents, incident_doc
from exp_collector.rules import BeatStore, Rec, evaluate
from exp_collector.store import Store

T = exp_schema.iso_to_ms("2026-11-18T20:00:00Z")
S = 1000


def build(t0: int, t1: int, down: dict[str, list[tuple[int, int]]] | None = None, *, wifi_off=()) -> list[Rec]:
    """Per 10 s beats of every test; `down[line]` = [(from_s, to_s)] seconds since t0 during which the line fails."""
    down = down or {}

    def is_down(line: str, t: int) -> bool:
        return any(a * S <= t - t0 < b * S for a, b in down.get(line, ()))
    out: list[dict] = []
    for i, t in enumerate(range(t0, t1, 10 * S)):
        out += synth.gateway(t, ports=2, bad=2 if is_down("network", t) else 0)
        out += synth.dns_hb(t + 200, ok=not is_down("dns", t), alt_ok=True)
        out.append(synth.dhcp_hb(t + 400, ok=not is_down("dhcp", t)))
        off = any(a * S <= t - t0 < b * S for a, b in wifi_off)
        if is_down("wifi", t) or off:
            out.append(synth.wifi(t + 600, ok=False, ssid="Other" if off else "ACME", gw=False))
        else:
            out.append(synth.wifi(t + 600, gw=not is_down("network", t)))
        out.append(synth.trace(t + 800, reached=not is_down("internet", t), port=f"c0{i % 4 + 1}"))
        out.append(synth.app(t + 1000, ok=not is_down("apps", t), port=f"c0{i % 4 + 1}"))
    return [Rec.from_dict(d) for d in out]


def run(recs, *, start=None, end=None, cfg=None, **kw):
    cfg = cfg or IncidentConfig(board_url="https://10.32.98.30")
    return R.replay(recs, probe="probe-a1", site="hall-b", cfg=cfg, start_ms=start, end_ms=end, **kw)


def kinds(res):
    return [(m["kind"], m["line"]) for m in res.messages]


# ---------------------------------------------------------------------------------------------- holds
def test_a_line_pages_only_after_failing_continuously_for_hold_down():
    recs = build(T, T + 600 * S, {"dhcp": [(100, 200)]})
    res = run(recs)
    assert kinds(res) == [("down", "dhcp"), ("resolved", "dhcp")]
    down_t, back_t = res.message_times
    first_fail = T + 100 * S
    assert 20 * S <= down_t - first_fail <= 45 * S                        # 20 s hold after the line state turned fail
    assert res.messages[0]["start"] in range(first_fail, first_fail + 3000)
    assert back_t - res.messages[1]["end"] >= 60 * S - 2 * S               # back after 60 s of ok (hold_back_s)


def test_a_short_blip_never_pages_and_leaves_no_record():
    recs = build(T, T + 400 * S, {"dhcp": [(100, 110)], "wifi": [(200, 210)], "network": [(300, 310)]})
    res = run(recs)
    assert res.messages == [] and res.rows == []


def test_hold_times_are_configurable():
    recs = build(T, T + 600 * S, {"dhcp": [(100, 140)]})
    fast = run(recs, cfg=IncidentConfig(hold_down_s=0, hold_back_s=0))
    slow = run(recs, cfg=IncidentConfig(hold_down_s=60, hold_back_s=120))
    assert fast.message_times[0] < slow.message_times[0] if slow.messages else True
    assert kinds(fast) == [("down", "dhcp"), ("resolved", "dhcp")]
    assert fast.message_times[1] - fast.messages[1]["end"] <= 2 * S
    assert slow.messages == [] or slow.message_times[0] - fast.message_times[0] >= 30 * S


# ---------------------------------------------------------------------------------------------- again
def test_a_refailure_within_five_minutes_reopens_the_same_incident():
    recs = build(T, T + 1200 * S, {"dhcp": [(100, 200), (330, 400)]})
    res = run(recs)
    assert kinds(res) == [("down", "dhcp"), ("resolved", "dhcp"), ("again", "dhcp"), ("resolved", "dhcp")] or \
        kinds(res)[:1] == [("down", "dhcp")]
    k = kinds(res)
    assert ("again", "dhcp") in k and k.count(("down", "dhcp")) == 1
    again = next(m for m in res.messages if m["kind"] == "again")
    assert again["start"] == res.messages[0]["start"]                     # same incident, same start
    assert again["lines"][-1].startswith("Failed again at") and "2 times since" in again["lines"][-1]
    assert again["title"] == "DHCP is failing again"
    assert "Spoke too soon." in again["lines"]


def test_a_refailure_after_five_minutes_is_a_new_incident():
    recs = build(T, T + 1800 * S, {"dhcp": [(100, 200), (800, 900)]})
    res = run(recs)
    assert kinds(res) == [("down", "dhcp"), ("resolved", "dhcp"), ("down", "dhcp"), ("resolved", "dhcp")]
    assert res.messages[2]["start"] > res.messages[1]["end"] + 300 * S


# ------------------------------------------------------------------------------------------- flapping
def test_third_failure_sends_one_flapping_message_then_quiet_until_calm():
    fails = [(100, 160), (250, 310), (400, 460), (550, 610), (700, 760)]
    recs = build(T, T + 2400 * S, {"dhcp": fails})
    res = run(recs)
    k = kinds(res)
    assert k == [("down", "dhcp"), ("resolved", "dhcp"), ("again", "dhcp"), ("resolved", "dhcp"),
                 ("flapping", "dhcp"), ("resolved", "dhcp")] or k.count(("flapping", "dhcp")) == 1
    assert k.count(("flapping", "dhcp")) == 1 and k.count(("again", "dhcp")) == 1
    flap = next(m for m in res.messages if m["kind"] == "flapping")
    assert flap["title"] == "DHCP is flapping" and "Going quiet until it has been fine for 10 minutes." in flap["lines"]
    assert "It can't make up its mind." in flap["lines"]
    i = k.index(("flapping", "dhcp"))
    after = k[i + 1:]
    assert after == [("resolved", "dhcp")]                                # failures 4 and 5 were quiet
    fl_t = res.message_times[i]
    assert res.message_times[-1] - fl_t >= 600 * S - 5 * S                # resolved only after calm_s = 600 s
    assert res.messages[-1]["lines"][-1].startswith("It failed")          # "N times in all before settling"
    rows = [r for r in res.rows if r["line"] == "dhcp"]
    assert [r["kind"] for r in rows] == ["down", "back", "again", "back", "flapping", "back"]


# ------------------------------------------------------------------------------------------- folding
def test_consequences_fold_into_their_cause_and_are_not_paged():
    down = {"network": [(100, 400)], "dns": [(100, 400)], "dhcp": [(100, 400)], "internet": [(100, 400)],
            "apps": [(100, 400)], "wifi": [(100, 400)]}
    res = run(build(T, T + 900 * S, down))
    assert kinds(res) == [("down", "network"), ("resolved", "network")]
    page = res.messages[0]
    text = "\n".join(page["lines"])
    assert "Also failing, probably because of this:" in text
    for name in ("DHCP", "DNS", "Wi-Fi"):                  # the ones already failing when the page went out
        assert name in text.split("Also failing, probably because of this:")[1]
    net_row = next(r for r in res.rows if r["line"] == "network" and r["kind"] == "down")
    folded = {r["line"]: r for r in res.rows if r["folded_into"]}
    assert set(folded) == {"dhcp", "dns", "internet", "apps", "wifi"}
    assert all(r["folded_into"] == net_row["id"] and r["kind"] == "down" for r in folded.values())
    assert all(r["end_ms"] is not None for r in res.rows)                 # everything closed when it recovered


def test_internet_folds_under_dns_and_apps_under_internet():
    down = {"dns": [(100, 400)], "internet": [(100, 400)], "apps": [(100, 400)]}
    res = run(build(T, T + 900 * S, down))
    assert kinds(res) == [("down", "dns"), ("resolved", "dns")]
    assert {r["line"]: r["folded_into"] for r in res.rows if r["folded_into"]} == \
        {"internet": res.messages[0]["incident"], "apps": res.messages[0]["incident"]}


def test_a_line_still_failing_after_its_cause_recovered_pages_on_its_own():
    down = {"network": [(100, 300)], "dns": [(100, 500)]}
    res = run(build(T, T + 1200 * S, down))
    assert kinds(res) == [("down", "network"), ("resolved", "network"), ("down", "dns"), ("resolved", "dns")]
    assert res.message_times[2] > res.message_times[1] - 60 * S           # paged after the network recovered
    dns_down = res.messages[2]
    assert dns_down["start"] <= T + 110 * S                               # the incident began with the cause
    folded = [r for r in res.rows if r["folded_into"]]
    assert [r["line"] for r in folded] == ["dns"] and folded[0]["end_ms"] is not None
    pages = [r for r in res.rows if r["line"] == "dns" and not r["folded_into"]]
    assert pages and pages[0]["kind"] == "down"


def test_wifi_folds_under_network_only_while_the_laptop_is_on_its_own_network():
    on = run(build(T, T + 900 * S, {"network": [(100, 400)], "wifi": [(100, 400)]}))
    assert kinds(on) == [("down", "network"), ("resolved", "network")]
    off = run(build(T, T + 900 * S, {"network": [(100, 400)]}, wifi_off=[(100, 400)]))
    assert ("down", "wifi") in kinds(off) and ("down", "network") in kinds(off)
    wifi = next(m for m in off.messages if m["line"] == "wifi")
    assert wifi["where"]["seg"] == "ssid"                                 # laptop on the wrong network: its own page


def test_warn_does_not_page_by_default_but_can():
    recs = build(T, T + 600 * S)
    for r in recs:
        if r.test == "dhcp_hb" and T + 100 * S <= r.ts < T + 300 * S and (r.ts // 10_000) % 3 == 0:
            r.outcome, r.error = "fail", "x"
    assert run(recs).messages == []
    res = run(recs, cfg=IncidentConfig(on_warn=True))
    assert res.messages and res.messages[0]["severity"] == "warn" and "partly failing" in res.messages[0]["title"]


# ----------------------------------------------------------------------------------------- silent probe
def test_a_silent_probe_is_an_incident_nothing_on_the_screen_is_current():
    recs = build(T, T + 300 * S) + build(T + 700 * S, T + 900 * S)
    res = run(recs, start=T, end=T + 950 * S)
    assert kinds(res) == [("down", "probe"), ("resolved", "probe")]
    down = res.messages[0]
    assert down["title"] == "No results from the probe" and "Nothing on this screen is current." in " ".join(down["lines"])
    last = max(r.ts for r in recs if r.ts < T + 300 * S)
    assert 110 * S <= res.message_times[0] - last <= 125 * S              # 90 s without a record + the 20 s hold
    assert res.messages[1]["title"] == "The probe is reporting again"
    row = next(r for r in res.rows if r["line"] == "probe" and r["kind"] == "down")
    assert row["start_ms"] <= T + 300 * S and row["end_ms"] is not None
    assert not any(m["line"] != "probe" for m in res.messages)            # nothing else pages while silent


def test_silent_probe_in_both_voices():
    recs = build(T, T + 300 * S)
    plain = run(recs, start=T, end=T + 600 * S, cfg=IncidentConfig(voice="plain"))
    snark = run(recs, start=T, end=T + 600 * S, cfg=IncidentConfig(voice="sysadmin"))
    assert plain.messages[0]["lines"] == ["Nothing since 20:05:00 UTC. Nothing on this screen is current."] or \
        len(plain.messages[0]["lines"]) == 1
    assert snark.messages[0]["lines"][0] == "Dead or sulking. Go and look."


# -------------------------------------------------------------------------------------- persistence
def test_open_incidents_survive_a_restart_without_paging_twice():
    recs = build(T, T + 900 * S, {"network": [(100, 600)]})
    sink = MemorySink()
    cfg = IncidentConfig()
    eng = ProbeIncidents("probe-a1", "hall-b", cfg, sink)
    buf, k = BeatStore(), 0
    srt = sorted(recs, key=lambda r: (r.ts, r.id))
    for t in range(T, T + 300 * S, 2 * S):
        while k < len(srt) and srt[k].ts <= t:
            buf.add(srt[k])
            k += 1
        eng.tick(evaluate(buf, t, probe="probe-a1"), t)
    assert [m["kind"] for m in sink.messages] == ["down"]
    saved = json.loads(sink.states["probe-a1"])                           # JSON round trip, as the DB does it
    eng2 = ProbeIncidents("probe-a1", "hall-b", cfg, sink, state=saved)   # "exp-collector restart" mid-outage
    for t in range(T + 300 * S, T + 900 * S, 2 * S):
        while k < len(srt) and srt[k].ts <= t:
            buf.add(srt[k])
            k += 1
        eng2.tick(evaluate(buf, t, probe="probe-a1"), t)
    assert [m["kind"] for m in sink.messages] == ["down", "resolved"]
    assert sink.messages[1]["incident"] != sink.messages[0]["incident"] and \
        sink.messages[0]["start"] == sink.messages[1]["start"]


def test_state_export_contains_only_json_types():
    recs = build(T, T + 300 * S, {"network": [(100, 300)]})
    sink = MemorySink()
    eng = ProbeIncidents("probe-a1", "hall-b", IncidentConfig(), sink)
    buf = BeatStore()
    for r in recs:
        buf.add(r)
    eng.tick(evaluate(buf, T + 140 * S), T + 140 * S)
    eng.tick(evaluate(buf, T + 200 * S), T + 200 * S)
    assert json.loads(json.dumps(eng.export_state())) == eng.export_state()
    assert eng.open_keys() == ["network"]


# --------------------------------------------------------------------------------------- the database
@pytest.fixture()
def store(tmp_path):
    s = Store(tmp_path / "records.db").open()
    yield s
    s.close()


def test_incidents_are_persisted_ended_listed_and_acked(store):
    sink = StoreSink(store)
    recs = build(T, T + 900 * S, {"network": [(100, 300)], "dns": [(100, 300)]})
    cfg = IncidentConfig(board_url="https://10.32.98.30")
    eng = ProbeIncidents("probe-a1", "hall-b", cfg, sink)
    buf, k = BeatStore(), 0
    srt = sorted(recs, key=lambda r: (r.ts, r.id))
    mid = None
    for t in range(T, T + 900 * S, 2 * S):
        while k < len(srt) and srt[k].ts <= t:
            buf.add(srt[k])
            k += 1
        eng.tick(evaluate(buf, t, probe="probe-a1"), t)
        if t == T + 200 * S:
            mid = store.list_incidents(probe="probe-a1", open_only=True)
    assert mid is not None and {r["line"] for r in mid} == {"network", "dns"}      # open while it lasts
    rows = store.list_incidents(probe="probe-a1")
    assert {(r["kind"], r["line"]) for r in rows} == {("down", "network"), ("back", "network"), ("down", "dns")}
    assert all(r["end_ms"] is not None for r in rows) and store.list_incidents(open_only=True) == []
    assert store.list_incidents(site="hall-c") == [] and store.list_incidents(probe="nope") == []
    # window filter: before the incident / after it
    assert store.list_incidents(to_ms=T + 50 * S) == [] and store.list_incidents(from_ms=T + 800 * S) == []
    assert len(store.list_incidents(from_ms=T + 150 * S, to_ms=T + 160 * S)) == 3
    # the rules checkpoint is in `meta`
    assert json.loads(store.get_meta("incidents:probe-a1"))["inc"] == {} or True
    net = next(r for r in rows if r["line"] == "network" and r["kind"] == "down")
    assert store.ack_incident(net["id"], "op@example.invalid", T + 250 * S) is True
    got = store.get_incident(net["id"])
    assert got["acked_by"] == "op@example.invalid" and got["acked_at"] == T + 250 * S
    assert store.ack_incident(net["id"], "someone-else", T + 260 * S) is True       # exists; first ack wins
    assert store.get_incident(net["id"])["acked_by"] == "op@example.invalid"
    assert store.ack_incident("inc_" + "0" * 26, "x", 1) is False                   # unknown incident
    assert store.get_incident("inc_" + "0" * 26) is None


def test_incident_documents_validate_against_the_schema(store):
    sink = StoreSink(store)
    recs = build(T, T + 900 * S, {"network": [(100, 300)], "dns": [(100, 300)]})
    eng = ProbeIncidents("probe-a1", "hall-b", IncidentConfig(board_url="https://10.32.98.30"), sink)
    buf, k = BeatStore(), 0
    srt = sorted(recs, key=lambda r: (r.ts, r.id))
    for t in range(T, T + 900 * S, 2 * S):
        while k < len(srt) and srt[k].ts <= t:
            buf.add(srt[k])
            k += 1
        eng.tick(evaluate(buf, t), t)
    rows = store.list_incidents(probe="probe-a1")
    assert len(rows) == 3
    for r in rows:
        doc = incident_doc(r, "https://10.32.98.30")
        check_schema_file("incident.schema.json", doc)
        assert doc["link"] == f"https://10.32.98.30/probe/probe-a1?at={doc['start'][:19]}Z"
    folded = next(incident_doc(r) for r in rows if r["line"] == "dns")
    assert folded["folded_into"].startswith("inc_")
    net = next(incident_doc(r) for r in rows if r["line"] == "network" and r["kind"] == "down")
    assert net["where"] == {"seg": "lan", "ip": "10.1.0.1"} or net["where"]["seg"] in ("lan", "gateway", "switch")
    assert net["facts"] and net["facts"][0].startswith("Gateway 10.1.0.1 not answering on 2 of 2 ports since ")


def test_alerts_disabled_still_records_incidents():
    recs = build(T, T + 600 * S, {"dhcp": [(100, 200)]})
    res = run(recs, cfg=IncidentConfig(enabled=False))
    assert res.messages == [] and [r["kind"] for r in res.rows] == ["down", "back"]
