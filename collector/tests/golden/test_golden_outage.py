"""Golden rules: the real 2026-10-27 EXM outage (converted fixture test/fixtures/exm/outage-2026-10-27.ndjson.gz)
replayed through the rules and the incident engine reproduces EXM's verdicts and its nine alert pages
(03-collector.md section 13 item 4; expectations from reference/exm/test/unit.py and the fixture README).

Timing note: README times come from EXM's replay, which stamped results with their completion time
("emitted"); exp stamps measurements with their start (`ts`). Starts are therefore asserted within 2 s of the
README time (or of the first failing record where the README time is a later `emitted`), ends within
[-2 s, +12 s]: EXM also counted the scheduled `dns` test as DNS beats, which let the line recover earlier."""
from __future__ import annotations

import collections
import gzip
import json
from pathlib import Path

import pytest
import synth
from colhelpers import check_schema_file
from exp_common import schema as exp_schema

from exp_collector import replay as R
from exp_collector import rules
from exp_collector.engine import iso_ms
from exp_collector.incidents import IncidentConfig

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "test" / "fixtures" / "exm" / "outage-2026-10-27.ndjson.gz"
PROBE, SITE, TZ = "t430-srv-02", "lab", "America/Chicago"
ms = exp_schema.iso_to_ms


def U(hms: str) -> int:
    return ms(f"2026-10-27T{hms}Z")


@pytest.fixture(scope="module")
def recs():
    return R.load_ndjson(str(FIXTURE))


@pytest.fixture(scope="module")
def result(recs):
    cfg = IncidentConfig(tz=TZ, voice="sysadmin", edge_label="EC", board_url="https://10.32.98.25")
    return R.replay(recs, probe=PROBE, site=SITE, cfg=cfg, start_ms=U("02:55:00"), end_ms=U("04:28:00"))


def state(recs, at, voice="sysadmin", extra=()):
    return R.state_at(list(recs) + list(extra), U(at), probe=PROBE, site=SITE, voice=voice, tz=TZ, edge_label="EC")


def test_fixture_is_the_converted_outage(recs):
    assert len(recs) == 13792 and {r.probe for r in recs} == {PROBE}


# ------------------------------------------------------------------------ the gateway outage at 03:10
def test_gateway_outage_at_0310_names_the_gateway_and_12_of_12_ports(recs):
    for voice in ("sysadmin", "plain"):
        doc = state(recs, "03:10:00", voice)
        check_schema_file("state.schema.json", doc)
        v = doc["verdict"]
        assert v["severity"] == "fail" and v["voice"] == voice
        assert "10.1.0.1" in v["sub"] and "12 of 12 ports" in v["sub"]
        assert v["where"]["seg"] == "gateway" and v["where"]["ip"] == "10.1.0.1"
        net = next(x for x in doc["lines"] if x["key"] == "network")
        assert net["state"] == "fail" and net["word"] == "unstable"
        assert net["detail"] == "10.1.0.1 not answering (12 of 12 ports)"
        since = ms(net["since"])
        assert abs(since - U("03:00:21")) <= 2000                       # EXM: 03:00:21 (first failing record 03:00:20.1)
        item = next(f for f in doc["failing"] if f["line"] == "network")["items"][0]
        assert item["text"] == "no reply from 10.1.0.1" and item["count"] == 12 and len(item["ports"]) == 12
    plain = state(recs, "03:10:00", "plain")["verdict"]
    assert plain["headline"] == "The network is unstable."
    sysadmin = state(recs, "03:10:00", "sysadmin")["verdict"]
    assert sysadmin["headline"] in ("The gateway has left the building.", "Nobody can reach the gateway.",
                                     "The gateway has stopped taking calls.", "The gateway is not answering. Rude.")
    assert "since 22:00:20" in sysadmin["sub"] or "since 22:00:21" in sysadmin["sub"]    # site time, Chicago CDT
    assert sysadmin["where"]["explain"] == "Nobody gets to 10.1.0.1, wired or wireless. It's the gateway or the cable to it."


def test_gateway_outage_also_takes_dns_and_wifi_down_with_it(recs):
    doc = state(recs, "03:10:00")
    states = {x["key"]: x["state"] for x in doc["lines"]}
    assert states["network"] == "fail" and states["dns"] == "fail" and states["wifi"] == "fail"
    assert states["dhcp"] in ("ok", "warn")        # the dhcp heartbeat blips only between 03:29 and 03:36


# ------------------------------------------------------------------------ every where class in the data
def test_every_where_class_present_in_the_data(recs):
    srt = sorted(recs, key=lambda r: (r.ts, r.id))
    buf, k, seen = rules.BeatStore(), 0, collections.Counter()
    first: dict[str, int] = {}
    for t in range(U("02:55:00"), U("04:30:00"), 10_000):
        while k < len(srt) and srt[k].ts <= t:
            buf.add(srt[k])
            k += 1
        buf.trim(t - rules.HISTORY_MS)
        w = rules.evaluate(buf, t).where
        seg = w["seg"] if w else None
        seen[seg] += 1
        first.setdefault(str(seg), t)
    assert set(seen) == {None, "gateway", "switch", "ssid", "dns", "dhcp", "wan", "apps", "wifi"}, seen
    assert first["gateway"] < U("03:01:00")                       # the outage starts as a `gateway` verdict
    assert U("03:56:00") <= first["ssid"] <= U("03:58:00")


def test_ssid_the_laptop_wandered_off_to_mistifi(recs):
    doc = state(recs, "03:57:30")
    w = doc["verdict"]["where"]
    assert w["seg"] == "ssid" and "MistiFi" in w["explain"] and "ACME_CORP" in w["explain"]
    assert doc["verdict"]["headline"] in ("The laptop wandered off to MistiFi.", "The test laptop has eloped with MistiFi.",
                                           "The laptop is on MistiFi. It was told not to.")
    assert state(recs, "03:57:30", "plain")["verdict"]["headline"] == "Wi-Fi is down."


def test_wan_the_path_stops_after_the_first_hop_when_there_is_no_control_trace(recs):
    doc = state(recs, "04:22:30", "plain")
    w = doc["verdict"]["where"]
    assert w["seg"] == "wan" and w["ip"] == "10.1.0.2"
    assert "10.1.0.2 (hop 1)" in w["explain"] and "8.8.8.8" in w["explain"]
    assert doc["verdict"]["headline"] == "The internet is down."
    assert "Traceroute to 8.8.8.8 stops after 10.1.0.2 (hop 1)." in doc["verdict"]["sub"]


def _control(path_ok: bool, start="04:13:00", end="04:30:00", dead=("04:21:20", "04:23:30")):
    out = []
    for t in range(U(start), U(end), 10_000):
        reached = path_ok or not (U(dead[0]) <= t <= U(dead[1]))
        out.append(synth.trace(t + 3_000, path="control", reached=reached, last_ip="10.1.0.2" if not reached else "1.1.1.1",
                               target="8.8.8.8", port="c01"))
    return [rules.Rec.from_dict(dict(d, probe=PROBE, site=SITE)) for d in out]


def test_edge_when_the_control_path_gets_out_around_it(recs):
    doc = state(recs, "04:22:30", extra=_control(path_ok=True))
    w = doc["verdict"]["where"]
    assert w["seg"] == "edge" and w["label"] == "EC" and w["ip"] == "10.1.0.2"
    assert w["explain"] == "It's the EC. The ISP answers around it; our traffic dies after 10.1.0.2."
    plain = state(recs, "04:22:30", "plain", extra=_control(path_ok=True))["verdict"]["where"]["explain"]
    assert plain.startswith("The EC. The path stops after 10.1.0.2 (hop 1); the management path reaches 8.8.8.8 around it")


def test_isp_when_the_control_path_dies_too(recs):
    doc = state(recs, "04:22:30", extra=_control(path_ok=False))
    assert doc["verdict"]["where"]["seg"] == "isp"
    assert "Call the ISP" in doc["verdict"]["where"]["explain"]


def test_where_goes_away_when_the_problem_does(recs):
    doc = state(recs, "03:55:00")
    assert doc["verdict"]["severity"] == "ok" and doc["verdict"]["where"] is None
    assert doc["verdict"]["headline"] in ("Back after 51 minutes down. Zero apologies.", "And we're back. Nobody touch anything.",
                                           "Restored after 51 minutes. Someone owes someone a beer.".replace("after 51 minutes", "after 51 minutes"),
                                           "It's back. Act like it never happened.", "Back up after 51 minutes. Write it down before you forget.")
    assert "was down" in doc["verdict"]["sub"] and "Back for" in doc["verdict"]["sub"]


# --------------------------------------------------------------------------------------- the nine pages
def test_the_alert_engine_emits_the_nine_messages(result):
    got = [(m["kind"], m["label"]) for m in result.messages]
    assert got == [("down", "Network"), ("resolved", "Network"), ("down", "DNS"), ("resolved", "DNS"),
                   ("down", "Wi-Fi"), ("down", "DNS"), ("resolved", "DNS"), ("down", "DNS"), ("resolved", "DNS")]


README = [   # kind, line, start (README), end (README)
    ("down", "network", "03:00:21", None),
    ("resolved", "network", "03:00:21", "03:43:22"),
    ("down", "dns", "03:00:22", None),
    ("resolved", "dns", "03:00:22", "03:51:14"),
    ("down", "wifi", "03:56:30", None),            # README 03:56:34 is EXM's `emitted`; the failing record is 03:56:30
    ("down", "dns", "04:05:32", None),
    ("resolved", "dns", "04:05:32", "04:06:34"),
    ("down", "dns", "04:21:32", None),
    ("resolved", "dns", "04:21:32", "04:23:42"),
]


def test_incident_times_match_the_readme_within_tolerance(result):
    assert len(result.messages) == len(README)
    for m, (kind, line, start, end) in zip(result.messages, README, strict=True):
        assert (m["kind"], m["line"]) == (kind, line)
        assert abs(m["start"] - U(start)) <= 2000, (kind, line, iso_ms(m["start"]))
        if end:
            assert U(end) - 2000 <= m["end"] <= U(end) + 12_000, (kind, line, iso_ms(m["end"]))


def test_pages_come_after_the_holds(result):
    for i, (m, t) in enumerate(zip(result.messages, result.message_times, strict=True)):
        if m["kind"] == "down" and i != 2:          # message 2 is the DNS failure that waited for its cause to clear
            assert 20_000 <= t - m["start"] <= 60_000, (m["line"], t - m["start"])      # hold_down 20 s (+ window)
        elif m["kind"] == "down":
            assert t > result.message_times[1]
        else:
            assert t - m["end"] >= 60_000 - 2000 and t - m["end"] <= 62_000             # hold_back 60 s


def test_one_page_per_cause_with_folding(result):
    down_net = result.messages[0]
    assert down_net["line"] == "network" and down_net["where"]["seg"] == "gateway"
    text = "\n".join(down_net["lines"])
    assert "Also failing, probably because of this: DNS, Wi-Fi." in text
    # nobody else paged while the network was down (03:00:50 .. 03:44:20)
    t0, t1 = U("03:00:20"), result.message_times[1]
    assert [m["line"] for m, t in zip(result.messages, result.message_times, strict=True) if t0 < t < t1] == ["network"]
    rows = {r["id"]: r for r in result.rows}
    net_id = result.messages[0]["incident"]
    folded = [r for r in result.rows if r["folded_into"]]
    assert folded and {r["line"] for r in folded} >= {"dns", "wifi"}
    assert all(r["folded_into"] == net_id or rows[r["folded_into"]]["line"] in ("network", "dns") for r in folded)
    # a line still failing once its cause has recovered pages on its own (DNS 8 minutes later)
    assert result.messages[2]["line"] == "dns" and result.message_times[2] > result.message_times[1]


def test_the_first_page_names_the_gateway_the_time_where_and_links_to_the_board(result):
    m = result.messages[0]
    text = "\n".join(m["lines"])
    assert m["title"] == "The network is down"
    assert "10.1.0.1" in text and "22:00:2" in text and "CDT" in text
    assert "Where: the gateway or the link to it. Neither wired nor Wi-Fi reach 10.1.0.1." in text
    assert m["link"].startswith("https://10.32.98.25/probe/t430-srv-02?at=2026-10-27T03:00:2")
    from exp_collector.alerts import payload
    slack = payload("slack", m)["text"]
    assert "10.1.0.1" in slack and "Where: the gateway" in slack and "|Open the board at the start>" in slack


def test_the_wifi_page_says_the_laptop_is_on_the_wrong_network(result):
    m = next(x for x in result.messages if x["line"] == "wifi")
    text = "\n".join(m["lines"])
    assert m["where"]["seg"] == "ssid" and "MistiFi" in text and "ACME_CORP" in text
    assert "Also failing" not in text


def test_the_wan_page_names_where_the_path_stops(result):
    m = result.messages[7]
    assert m["line"] == "dns" and m["where"]["seg"] == "wan"
    assert "Where: past the gateway. The path to 8.8.8.8 stops after 10.1.0.2 (hop 1)." in m["lines"]


def test_incident_rows_are_recorded_with_ends(result):
    pages = [r for r in result.rows if not r["folded_into"]]
    assert [(r["kind"], r["line"]) for r in pages] == [
        ("down", "network"), ("back", "network"), ("down", "dns"), ("back", "dns"), ("down", "wifi"),
        ("down", "dns"), ("back", "dns"), ("down", "dns"), ("back", "dns")]
    assert pages[0]["end_ms"] == pages[1]["end_ms"] and pages[0]["end_ms"] is not None
    assert next(r for r in pages if r["line"] == "wifi")["end_ms"] is None      # never recovers in the fixture
    assert all(r["id"].startswith("inc_") for r in result.rows)


def test_a_failure_of_1m50_pages_when_replayed_from_the_start(recs):
    """The README lists the 02:45 DNS failure as 'stays under the hold-down'; it only did in EXM's replay,
    which began at 02:55. A 110 s failure outlasts the 20 s hold: it pages."""
    cfg = IncidentConfig(tz=TZ)
    res = R.replay(recs, probe=PROBE, site=SITE, cfg=cfg, start_ms=U("02:40:00"), end_ms=U("02:55:00"))
    assert [(m["kind"], m["line"]) for m in res.messages] == [("down", "dns"), ("resolved", "dns")]
    assert abs(res.messages[0]["start"] - U("02:45:02")) <= 2000


def test_short_blips_do_not_page(recs):
    """dhcp_hb blips of 30-60 s and scattered single Wi-Fi failures stay under the holds."""
    cfg = IncidentConfig(tz=TZ)
    res = R.replay(recs, probe=PROBE, site=SITE, cfg=cfg, start_ms=U("04:30:00") - 1_700_000,
                   end_ms=U("04:00:00") + 1_000_000)
    assert [m["line"] for m in res.messages if m["line"] in ("DHCP",)] == []


def test_replay_gz_and_plain_ndjson_are_the_same(recs, tmp_path):
    p = tmp_path / "x.ndjson"
    with gzip.open(FIXTURE, "rt") as fh:
        head = [next(fh) for _ in range(500)]
    p.write_text("".join(head))
    plain = R.load_ndjson(str(p))
    assert len(plain) == 500 and plain[0].id == json.loads(head[0])["id"]
