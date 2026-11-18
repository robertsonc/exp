"""Golden `where` cases: every EXM verdict class from small hand-made record sequences
(# ported from reference/exm/test/unit.py "where: every verdict" and the 15:14 lesson)."""
from __future__ import annotations

import synth

from exp_collector import verdict as vt
from exp_collector.rules import LINE_KEYS, where_of

T0 = 1_793_000_000_000      # an arbitrary moment; `at` is 5 s later, like the EXM cases
AT = T0 + 5_000


def W(recs, at=AT, **st):
    states = {k: "ok" for k in LINE_KEYS}
    states.update(st)
    return where_of(recs, at, states)


def seg(recs, **st):
    w = W(recs, **st)
    return w["seg"] if w else None


GW_DOWN = synth.gateway(T0, ports=4, bad=4)


def test_link_no_carrier_on_half_the_ports_or_more():
    w = W(synth.gateway(T0, ports=4, nolink=3), network="fail")
    assert w["seg"] == "link" and w["ports"] == ["c01", "c02", "c03"] and w["n"] == 4


def test_ports_with_a_minority_without_link():
    w = W(synth.gateway(T0, ports=4, nolink=1), network="warn")
    assert w["seg"] == "ports" and w["ports"] == ["c01"]


def test_switch_wifi_reaches_the_gateway_but_the_ports_do_not():
    w = W(GW_DOWN + [synth.wifi(T0, gw=True)], network="fail", wifi="ok")
    assert w == {"seg": "switch", "ip": "10.1.0.1"}


def test_gateway_neither_wired_nor_wifi_reach_it():
    w = W(GW_DOWN + [synth.wifi(T0, gw=False, ok=False)], network="fail", dns="fail", internet="fail", wifi="fail")
    assert w == {"seg": "gateway", "ip": "10.1.0.1"}


def test_lan_when_there_is_no_wifi_to_compare():
    assert W(GW_DOWN, network="fail") == {"seg": "lan", "ip": "10.1.0.1"}


def test_edge_the_path_dies_after_the_first_hop_while_the_control_path_gets_out():
    recs = [synth.trace(T0, reached=False), synth.trace(T0, path="control", reached=True)]
    w = W(recs, internet="fail")
    assert w == {"seg": "edge", "lh": "10.99.0.1", "lt": 1, "target": "8.8.8.8"}


def test_isp_both_paths_die():
    recs = [synth.trace(T0, reached=False), synth.trace(T0, path="control", reached=False, last_ip="10.99.0.9")]
    w = W(recs, dns="fail", internet="fail")
    assert w["seg"] == "isp" and w["clh"] == "10.99.0.9" and w["lh"] == "10.99.0.1"


def test_wan_the_path_dies_and_there_is_no_control_path_to_compare():
    w = W([synth.trace(T0, reached=False)], internet="fail")
    assert w["seg"] == "wan" and w["lh"] == "10.99.0.1" and w["lt"] == 1 and w["target"] == "8.8.8.8"


def test_resolver_the_dhcp_resolver_is_silent_the_alternate_answers():
    recs = [synth.trace(T0, reached=True)] + synth.dns_hb(T0, ok=False, alt_ok=True)
    assert W(recs, dns="fail", internet="fail") == {"seg": "resolver", "sx": "8.8.8.8", "ax": "1.1.1.1"}


def test_dns_path_the_path_is_up_but_no_resolver_answers():
    recs = [synth.trace(T0, reached=True)] + synth.dns_hb(T0, ok=False, alt_ok=False)
    assert W(recs, dns="fail", internet="fail") == {"seg": "dns_path", "sx": "8.8.8.8", "ax": "1.1.1.1"}


def test_dns_when_nothing_says_why():
    assert seg(synth.dns_hb(T0, ok=False), dns="fail") == "dns"


def test_apps_path_and_dns_fine_apps_failing():
    assert W([synth.trace(T0, reached=True)], apps="fail") == {"seg": "apps", "target": "8.8.8.8"}


def test_dhcp_the_gateway_answers_offers_do_not_come():
    recs = [synth.dhcp_hb(T0 - 20_000, server="10.1.0.2"), synth.dhcp_hb(T0, ok=False)]
    assert W(recs, dhcp="fail") == {"seg": "dhcp", "sv": "10.1.0.2"}


def test_ssid_the_laptop_cannot_get_on_the_network_it_monitors():
    w = W([synth.wifi(T0, ok=False, ssid="MistiFi", target_ssid="ACME", gw=False)], wifi="fail")
    assert w == {"seg": "ssid", "tg": "ACME", "sd": "MistiFi"}
    w = W([synth.wifi(T0, ok=False, ssid="", target_ssid="ACME", gw=False)], wifi="fail")
    assert w["seg"] == "ssid" and w["sd"] is None


def test_wifi_on_the_network_but_cannot_reach_the_gateway_while_wired_can():
    assert seg([synth.wifi(T0, ok=False, gw=False)], wifi="fail") == "wifi"


def test_path_only_the_path_line_is_bad():
    assert seg([], path="fail") == "path"


def test_nothing_wrong_nothing_to_say():
    assert W([synth.trace(T0)]) is None


def test_every_seg_of_the_contract_is_covered():
    got = {
        "link": seg(synth.gateway(T0, ports=4, nolink=3), network="fail"),
        "ports": seg(synth.gateway(T0, ports=4, nolink=1), network="warn"),
        "switch": seg(GW_DOWN + [synth.wifi(T0)], network="fail"),
        "gateway": seg(GW_DOWN + [synth.wifi(T0, gw=False)], network="fail"),
        "lan": seg(GW_DOWN, network="fail"),
        "edge": seg([synth.trace(T0, reached=False), synth.trace(T0, path="control")], internet="fail"),
        "isp": seg([synth.trace(T0, reached=False), synth.trace(T0, path="control", reached=False)], internet="fail"),
        "wan": seg([synth.trace(T0, reached=False)], internet="fail"),
        "resolver": seg([synth.trace(T0)] + synth.dns_hb(T0, ok=False, alt_ok=True), dns="fail"),
        "dns_path": seg([synth.trace(T0)] + synth.dns_hb(T0, ok=False, alt_ok=False), dns="fail"),
        "dns": seg(synth.dns_hb(T0, ok=False), dns="fail"),
        "apps": seg([synth.trace(T0)], apps="fail"),
        "dhcp": seg([synth.dhcp_hb(T0, ok=False)], dhcp="fail"),
        "ssid": seg([synth.wifi(T0, ssid="Other", ok=False)], wifi="fail"),
        "wifi": seg([synth.wifi(T0, gw=False, ok=False)], wifi="fail"),
        "path": seg([], path="fail"),
    }
    assert {k: v for k, v in got.items() if k != v} == {}


# --------------------------------------------------------------------------- the carried-over rules
def test_one_lost_traceroute_does_not_blame_the_edge():
    lost = [synth.trace(T0, reached=True), synth.trace(T0 + 5_000, reached=False),
            synth.trace(T0, path="control", reached=True)]
    w = W(lost, dns="fail", internet="fail")
    assert w is None or w["seg"] != "edge"
    assert w is None or w["seg"] in ("resolver", "dns_path", "dns", "apps")


def test_unless_both_resolvers_are_silent_too_the_1514_lesson():
    lost = [synth.trace(T0, reached=True), synth.trace(T0 + 5_000, reached=False),
            synth.trace(T0, path="control", reached=True)]
    both_silent = synth.dns_hb(AT - 200, ok=False, alt_ok=False)
    w = W(lost + both_silent, dns="fail", internet="fail")
    assert w["seg"] == "edge" and w["lh"] == "10.99.0.1"


def test_a_good_trace_outweighs_a_lost_one_only_for_trace_hold():
    old_ok = synth.trace(AT - 31_000, reached=True)               # older than TRACE_HOLD (30 s)
    lost = synth.trace(AT - 1_000, reached=False)
    ctl = synth.trace(AT - 1_000, path="control", reached=True)
    assert seg([old_ok, lost, ctl], internet="fail") == "edge"
    fresh_ok = synth.trace(AT - 29_000, reached=True)
    assert seg([fresh_ok, lost, ctl], internet="fail") != "edge"


def test_diagnostics_older_than_recent_say_nothing_about_now():
    assert W([synth.trace(AT - 61_000, reached=False)], internet="fail") is None


def test_a_failing_network_blames_the_gateway_not_the_path():
    recs = GW_DOWN + [synth.trace(T0, reached=False)]
    assert W(recs, network="fail", internet="fail")["seg"] == "lan"


def test_error_traces_never_blame_the_network():
    recs = [synth.trace(T0, error=True)]
    assert W(recs, internet="fail") is None


# ------------------------------------------------------------------------------------- the words
def test_where_sentences_in_both_voices_and_the_edge_label():
    w = {"seg": "edge", "lh": "10.99.0.1", "lt": 1, "target": "8.8.8.8"}
    assert vt.where_text(w, "sysadmin", "EC") == "It's the EC. The ISP answers around it; our traffic dies after 10.99.0.1."
    assert vt.where_text(w, "plain", "EC").startswith("Where: the EC. The path stops after 10.99.0.1 (hop 1)")
    assert vt.where_text({"seg": "isp", "target": "8.8.8.8"}, "plain", "Edge").startswith("Where: upstream of the Edge.")
    assert vt.where_text({"seg": "gateway", "ip": "10.1.0.1"}, "sysadmin") == \
        "Nobody gets to 10.1.0.1, wired or wireless. It's the gateway or the cable to it."


def test_where_doc_matches_the_state_schema_shape():
    from colhelpers import check_schema_file
    doc = vt.where_doc({"seg": "gateway", "ip": "10.1.0.1"}, "sysadmin", "EC")
    assert doc["chain"][2] == {"seg": "gateway", "state": "fail"} and doc["chain"][1]["state"] == "ok"
    assert doc["ip"] == "10.1.0.1" and doc["label"] == "Gateway"
    # a hostile gateway ip never reaches the ip field
    assert vt.where_doc({"seg": "lan", "ip": "<script>"}, "plain", "EC")["ip"] is None
    for s in ("edge", "wan", "resolver", "dhcp", "ssid", "wifi", "apps", "link", "ports", "path", "dns", "dns_path",
              "isp", "switch", "lan"):
        d = vt.where_doc({"seg": s, "lh": "10.99.0.1", "sx": "8.8.8.8", "ports": ["c01"]}, "plain", "EC")
        assert d["seg"] == s and d["explain"]
        check_schema_file("state.schema.json", {
            "schema": "exp.state/1", "probe": "p", "site": "s", "at": "2026-11-18T20:00:00.000Z", "live": False,
            "newest_s": 0, "verdict": {"severity": "fail", "headline": "x", "voice": "plain", "where": d},
            "lines": [], "failing": []})


def test_ports_measured_together_one_that_gets_through_means_the_path_is_up():
    recs = [synth.trace(T0, reached=False, port="c01"), synth.trace(T0, reached=True, port="c02")]
    assert seg(recs, internet="fail") != "wan"
    recs = [synth.trace(T0, reached=False, port="c01"), synth.trace(T0, reached=False, port="c02", last_ttl=3,
                                                                    last_ip="10.99.0.3")]
    w = W(recs, internet="fail")
    assert w["seg"] == "wan" and w["lh"] == "10.99.0.3" and w["lt"] == 3      # the port that got furthest
