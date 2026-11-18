"""Verdict text (03-collector.md section 13 item 5): no doubled punctuation across every sentence template
in both voices with adversarial interpolations; the EXM text bugs stay fixed; State/Beats documents validate."""
from __future__ import annotations

import itertools
import re

import synth
from colhelpers import check_schema_file
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from exp_collector import verdict as vt
from exp_collector.alerts import build_message
from exp_collector.engine import beats_from_store, state_doc, state_lite
from exp_collector.rules import BeatStore, Rec, evaluate, evaluate_records

T = 1_800_000_000_000
TZ = "America/Chicago"
DOUBLED = re.compile(r"[.!?,;:]\s*[.!?,;:]")
HOSTILE = ["ACME_CORP..", "1 a.m.", "x?", "!", "", "…", "a.", "." * 5, "ünï.cøde!?", "‮", "\n.\n",
           ",.", "?.", "null", "None", "  ", "a  b", "<b>x</b>.", "10.1.0.1.", "end:", ":start", "..a..b..", "。"]
EVIL = st.one_of(st.text(max_size=40), st.sampled_from(HOSTILE),
                 st.builds(lambda a, b: a + b, st.sampled_from(HOSTILE), st.text(max_size=8)))


def check_text(s: str, *inputs: str) -> None:
    assert not DOUBLED.search(s), repr(s)
    assert "  " not in s and s == s.strip(), repr(s)
    assert not re.search(r"\{\w+\}", s), repr(s)                        # an unfilled placeholder
    for bad in ("None", "null", "undefined", "No error text"):
        if not any(bad in i for i in inputs):
            assert bad not in s, (bad, s)
    assert not re.search(r"\bfrom\s*(\.|$)", s), repr(s)           # "from null" / "from ."
    assert not re.search(r"\s[.!?,;:]", s), repr(s)                # nothing hangs off a space


# ---------------------------------------------------------------------------------- scenario builders
def _base(t0: int, t1: int) -> list[dict]:
    return synth.healthy(t0, t1, ports=2)


def _with_errors(recs: list[dict], e: str) -> list[dict]:
    for d in recs:
        if d["outcome"] in ("fail", "degraded") and d.get("error") is not None:
            d["error"] = e or None
    return recs


def scenarios(e: str) -> list[tuple[str, list[dict], int]]:
    """(name, records, at) covering every branch of the verdict text, with `e` in every probe-supplied field."""
    out: list[tuple[str, list[dict], int]] = []
    pre = _base(T, T + 120_000)
    at = T + 160_000

    def add(name: str, recs: list[dict], when: int = at) -> None:
        out.append((name, _with_errors(pre + recs, e), when))

    gw_bad = [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.gateway(t, ports=2, bad=2)]
    add("net_gw", gw_bad)
    nolink = [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.gateway(t, ports=2, nolink=2)]
    for d in nolink:
        d["labels"]["port"] = (e or "c")[:60] + d["labels"]["port"]
    add("net_link", nolink)
    add("net_other", [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.gateway(t, ports=4, nolink=1, bad=2)])
    add("net_warn", [x for t in range(T + 120_000, T + 160_000, 10_000)
                     for x in synth.gateway(t, ports=4, bad=1 if t % 20_000 == 0 else 0)])
    add("dhcp_dns", [synth.dhcp_hb(t, ok=False) for t in range(T + 120_000, T + 160_000, 10_000)]
        + [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.dns_hb(t, ok=False)])
    add("dhcp", [synth.dhcp_hb(t, ok=False) for t in range(T + 120_000, T + 160_000, 10_000)])
    add("dhcp_warn", [synth.dhcp_hb(t, ok=t % 20_000 == 0) for t in range(T + 120_000, T + 160_000, 10_000)])
    tr = [synth.trace(t, reached=False, target=e or "8.8.8.8", port="c01") for t in range(T + 120_000, T + 160_000, 10_000)]
    add("internet", tr)
    add("internet_dns", tr + [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.dns_hb(t, ok=False)])
    add("internet_unrunnable", [synth.trace(t, error=True) for t in range(T + 120_000, T + 160_000, 10_000)]
        + [synth.app(t, ok=False) for t in range(T + 120_000, T + 160_000, 10_000)])
    add("apps_reached", [synth.app(t, ok=False, name=e or "x") for t in range(T + 120_000, T + 160_000, 10_000)])
    add("dns", [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.dns_hb(t, ok=False)])
    add("dns_warn", [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.dns_hb(t, ok=t % 20_000 != 0)])
    add("wifi_off", [synth.wifi(t, ok=False, ssid=e or "other", target_ssid="ACME", gw=False, error=e)
                     for t in range(T + 120_000, T + 160_000, 10_000)])
    add("wifi_gone", [synth.wifi(t, ok=False, ssid="", target_ssid=e or "ACME", gw=False, error=e)
                      for t in range(T + 120_000, T + 160_000, 10_000)])
    add("wifi_down", [synth.wifi(t, ok=False, ssid="ACME", target_ssid=None, gw=False, error=e)
                      for t in range(T + 120_000, T + 160_000, 10_000)])
    add("wifi_warn", [dict(synth.wifi(t, ok=True), outcome="degraded", error=e or "weak")
                      for t in range(T + 120_000, T + 160_000, 10_000)])
    add("path_fail", [synth.mk("path", t, "fail", labels={"peer": "col", "proto": "udp"}, error=e)
                      for t in range(T + 100_000, T + 160_000, 20_000)])
    add("path_warn", [synth.mk("path", t, "degraded" if t % 40_000 == 0 else "ok", labels={"peer": "col", "proto": "udp"},
                               error=e) for t in range(T + 100_000, T + 160_000, 20_000)])
    for d in out[-2][1]:
        pass
    add("apps_warn_slow", [dict(synth.app(t), outcome="degraded") for t in range(T + 100_000, T + 160_000, 5_000)])
    add("apps_warn_fail", [synth.app(t, ok=t % 15_000 != 0, name="a") for t in range(T + 100_000, T + 160_000, 5_000)])
    add("all_good", [])
    add("laptop_away", [], T + 400_000)
    add("silent", [], T + 120_000 + 200_000)
    add("no_data", [], T)
    out.append(("empty", [], T))
    # recovered: outage then ok
    rec = [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.gateway(t, ports=2, bad=2)]
    rec += _base(T + 160_000, T + 400_000)
    add("recovered", rec, T + 330_000)
    # flapping: three outages inside ten minutes
    flap: list[dict] = []
    for k in range(3):
        base = T + 130_000 + k * 120_000
        flap += [x for t in range(base, base + 40_000, 10_000) for x in synth.gateway(t, ports=2, bad=2)]
        flap += _base(base + 40_000, base + 120_000)
    add("flap", flap, T + 130_000 + 2 * 120_000 + 30_000)
    return out


def all_texts(doc: dict) -> list[str]:
    v = doc["verdict"]
    out = [v["headline"], v["sub"]] if v["sub"] else [v["headline"]]
    if v["where"]:
        out.append(v["where"]["explain"])
    return out


@given(EVIL)
@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
def test_no_doubled_punctuation_in_any_template_either_voice(e):
    for name, recs, at in scenarios(e):
        ev = evaluate_records(recs, at, probe="p", site="s")
        for voice in ("plain", "sysadmin"):
            doc = state_doc(ev, voice=voice, tz=TZ, edge_label=e or "EC")
            for s in all_texts(doc):
                try:
                    check_text(s, e)
                except AssertionError as exc:
                    raise AssertionError(f"{name}/{voice}: {exc}") from None
            assert doc["verdict"]["headline"] and len(doc["verdict"]["headline"]) <= 256
            assert len(doc["verdict"]["sub"]) <= 512


@given(EVIL, EVIL, EVIL)
@settings(max_examples=60, deadline=None)
def test_every_where_and_quip_template_with_adversarial_values(a, b, c):
    f = {"edge": a, "ip": a, "ports": [a, b], "lh": b, "lt": c, "target": c, "sx": a, "ax": b, "tg": a, "sd": b, "sv": c,
         "clh": c}
    for seg in vt.WHERE_P:
        for voice in ("plain", "sysadmin"):
            s = vt.where_text(dict(f, seg=seg), voice, a)
            check_text(s, a, b, c)
            assert s, seg
    fields = {"sd": a, "tg": b, "lane": c, "hour": vt.Raw("1 a.m."), "dur": vt.Raw("over 5 minutes"), "since": 1}
    for kind, pool in vt.LINES.items():
        pools = pool if isinstance(pool, list) else [p for v in pool.values() for p in v]
        for tpl in pools:
            check_text(vt.fill(tpl, fields, vt._DEFAULTS), a, b, c)


def test_alert_messages_have_no_doubled_punctuation_either_voice():
    for e in ("ACME_CORP..", "1 a.m.", "", "\u202e?.", "<@U1> [x](http://e.example)."):
        for name, recs, at in scenarios(e):
            ev = evaluate_records(recs, at, probe="p", site="s")
            for key in ("network", "dhcp", "dns", "internet", "apps", "wifi", "path"):
                le = ev.lines[key]
                facts = {"line": key, "sev": le.state if le.state in ("fail", "warn") else "fail", "since": T,
                         "since_open": True, "what": vt.what_of(ev, key), "where": ev.where, "also": ["dns", "wifi"]}
                inc = {"start": T, "end": T + 120_000, "flaps": 3, "facts": facts}
                for kind, voice in itertools.product(("down", "again", "flapping", "resolved"), ("plain", "sysadmin")):
                    m = build_message(kind, key, inc, T + 200_000, probe="p", label=e, tz=TZ, voice=voice, edge_label=e)
                    for ln in m["lines"]:
                        check_text(ln, e)


# --------------------------------------------------------------------------------------- the EXM bugs
def _doc(recs, at, voice="sysadmin"):
    return state_doc(evaluate_records(recs, at, probe="p", site="s"), voice=voice, tz=TZ, edge_label="EC")


def test_doubled_period_after_a_name_ending_in_a_dot_is_fixed():
    for name, recs, at in scenarios("ACME_CORP."):
        for voice in ("plain", "sysadmin"):
            for s in all_texts(_doc(recs, at, voice)):
                assert ".." not in s.replace("…", ""), (name, s)
    d = _doc([synth.wifi(T + i * 10_000, ok=False, ssid="MistiFi", target_ssid="ACME_CORP.", gw=False) for i in range(8)],
             T + 70_000, "plain")
    assert "ACME_CORP.." not in d["verdict"]["where"]["explain"] and "ACME_CORP" in d["verdict"]["where"]["explain"]


def test_one_a_m_does_not_get_two_periods():
    midnight = T - (T % 86_400_000)
    h = vt.hour_text(midnight + 3_600_000, "UTC")
    assert h == "1 a.m."
    assert vt.fill("It's {hour}. Of course it's DNS.", {"hour": vt.Raw(h)}) == "It's 1 a.m. Of course it's DNS."
    assert vt.fill("DNS, at {hour}. Naturally.", {"hour": vt.Raw(h)}) == "DNS, at 1 a.m. Naturally."
    assert vt.hour_text(midnight + 13 * 3_600_000, "UTC") == "1 p.m." and vt.hour_text(midnight, "UTC") == "midnight"
    assert vt.hour_text(midnight + 12 * 3_600_000, "UTC") == "noon"


def test_no_traceroute_from_null_when_no_client_could_run_it():
    recs = _base(T, T + 120_000) + [synth.trace(t, error=True) for t in range(T + 120_000, T + 200_000, 10_000)]
    recs += [synth.app(t, ok=False) for t in range(T + 120_000, T + 200_000, 10_000)]
    doc = _doc(recs, T + 200_000)
    blob = " ".join(all_texts(doc)) + " " + " ".join(x["detail"] for x in doc["lines"])
    assert "null" not in blob and "None" not in blob and "from ." not in blob
    assert "No client could run the traceroute" in blob
    # and with a trace that did run: the port is named only when there is one
    ok = _doc(_base(T, T + 100_000) + [synth.trace(T + 100_000, reached=False)] * 0 +
              [synth.trace(t, reached=False, port="c01") for t in range(T + 100_000, T + 150_000, 10_000)], T + 150_000)
    assert "null" not in " ".join(all_texts(ok))


def test_never_no_error_text_next_to_a_line_that_lists_errors():
    for e in ("", "boom"):
        for name, recs, at in scenarios(e):
            doc = _doc(recs, at)
            blob = str(doc)
            assert "No error text" not in blob, name
            for f in doc["failing"]:
                assert f["items"] and all(i["text"] for i in f["items"]), (name, f)


def test_failing_line_without_error_text_says_how_many_checks_failed():
    recs = _base(T, T + 120_000) + [synth.dhcp_hb(t, ok=False) for t in range(T + 120_000, T + 160_000, 10_000)]
    for d in recs:
        if d["test"] == "dhcp_hb" and d["outcome"] == "fail":
            d.pop("error", None)
    doc = _doc(recs, T + 160_000)
    item = next(f for f in doc["failing"] if f["line"] == "dhcp")["items"][0]
    assert item["text"] == "failed" and item["count"] == 4


def test_headline_is_deterministic_per_incident_and_voices_agree_on_facts():
    recs = _base(T, T + 120_000) + [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.gateway(t, ports=2, bad=2)]
    ev = evaluate_records(recs, T + 160_000)
    a = state_doc(ev, voice="sysadmin", tz=TZ)
    b = state_doc(evaluate_records(recs, T + 160_000), voice="sysadmin", tz=TZ)
    assert a == b                                              # same records: same document, same quip
    later = state_doc(evaluate_records(recs + [x for t in range(T + 160_000, T + 170_000, 10_000)
                                               for x in synth.gateway(t, ports=2, bad=2)], T + 170_000), voice="sysadmin", tz=TZ)
    assert later["verdict"]["headline"] == a["verdict"]["headline"]       # does not change every second
    p = state_doc(ev, voice="plain", tz=TZ)
    assert p["verdict"]["severity"] == a["verdict"]["severity"] == "fail"
    assert p["verdict"]["sub"] == a["verdict"]["sub"]
    assert p["verdict"]["where"]["seg"] == a["verdict"]["where"]["seg"]


def test_stale_and_empty_states():
    ev = evaluate(BeatStore(), T, probe="p", site="s")
    doc = state_doc(ev, voice="plain", tz=TZ)
    assert doc["verdict"]["severity"] == "unknown" and doc["newest_s"] is None and doc["verdict"]["where"] is None
    check_schema_file("state.schema.json", doc)
    recs = _base(T, T + 60_000)
    doc = _doc(recs, T + 60_000 + 200_000, "plain")
    assert doc["verdict"]["severity"] == "unknown" and doc["verdict"]["headline"].startswith("No data for")
    assert "Nothing on this screen is current." in doc["verdict"]["sub"]
    assert all(x["state"] == "unknown" for x in doc["lines"] if x["key"] in ("network", "dhcp", "dns"))


# ---------------------------------------------------------------------------------------- the documents
def test_state_documents_validate_against_the_schema_for_every_scenario():
    n = 0
    for name, recs, at in scenarios("boom."):
        for voice in ("plain", "sysadmin"):
            doc = _doc(recs, at, voice)
            check_schema_file("state.schema.json", doc)
            assert doc["schema"] == "exp.state/1" and [x["key"] for x in doc["lines"]] == \
                ["network", "dhcp", "dns", "internet", "apps", "wifi", "path"]
            lite = state_lite(doc)
            assert lite["severity"] == doc["verdict"]["severity"]
            n += 1
    assert n >= 50


def test_state_lines_carry_since_detail_last_outage_and_flaps():
    recs = _base(T, T + 120_000) + [x for t in range(T + 120_000, T + 160_000, 10_000) for x in synth.gateway(t, ports=2, bad=2)]
    doc = _doc(recs, T + 160_000)
    net = doc["lines"][0]
    assert net["state"] == "fail" and net["word"] == "unstable" and net["since"].endswith("Z") and net["last_outage"] is None
    assert net["detail"] == "10.1.0.1 not answering (2 of 2 ports)"
    recs += _base(T + 160_000, T + 300_000)
    doc = _doc(recs, T + 290_000)
    net = doc["lines"][0]
    assert net["state"] == "ok" and net["since"] is None and net["last_outage"]["open"] is False
    assert net["last_outage"]["start"] < net["last_outage"]["end"]
    assert doc["verdict"]["headline"] and doc["verdict"]["sub"].startswith("Network was down for ")


def test_flapping_changes_the_story():
    for name, recs, at in scenarios(""):
        if name == "flap":
            doc = _doc(recs, at, "plain")
            assert doc["lines"][0]["flaps"] >= 3
            assert doc["verdict"]["sub"].startswith("It has failed 3 times in the last 10 minutes.")
            sysadmin = _doc(recs, at, "sysadmin")["verdict"]["headline"]
            assert sysadmin in ("The network can't make up its mind.", "The network keeps falling over and getting back up.",
                                "The network is flapping. Pick a state, any state.", "Network can't make up its mind.",
                                "Network keeps falling over and getting back up.", "Network is flapping. Pick a state, any state.")
            return
    raise AssertionError("no flap scenario")


def test_beats_document_validates_and_marks_probe_errors():
    recs = [d for d in _base(T, T + 120_000) if d["test"] != "trace"]
    recs += [synth.trace(T + 50_000, error=True), synth.trace(T + 60_000, error=True), synth.trace(T + 70_000)]
    st_ = BeatStore()
    st_.extend(Rec.from_dict(d) for d in recs)
    doc = beats_from_store(st_, "probe-a1", T, T + 120_000)
    check_schema_file("beats.schema.json", doc)
    assert all(v in (0, 1, 2, 3) for line in doc["lines"].values() for _, v in line)
    assert any(v == 3 for _, v in doc["lines"]["internet"])               # the probe error is beat 3
    assert [t for t, _ in doc["lines"]["network"]] == sorted(t for t, _ in doc["lines"]["network"])
