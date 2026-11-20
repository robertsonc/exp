"""VictoriaMetrics aggregates (12 section 6, Principle 8): histogram series, labels, bounded cardinality."""
from __future__ import annotations

import json
import math

import pytest
from colhelpers import wait_for
from sthelpers import evidence, make_stenv, result, wifi

from exp_collector.speedtest.metrics import BOUNDED, LABELS, StMetrics, vmrange

ALLOWED_LABELS = set(LABELS) | {"vmrange", "cause", "__name__"}
NAMES = {"exp_st_down_mbps", "exp_st_up_mbps", "exp_st_loaded_latency_ms", "exp_st_score"}


def st_lines(vm):
    vm_lines = [ln for ln in vm.lines if ln["metric"]["__name__"].startswith("exp_st_")]
    return vm_lines


def settle(st, vm):
    st.app.vm.flush_now()
    assert wait_for(lambda: st_lines(vm), timeout=10)
    st.app.vm.flush_now()


def one_test(st, **kw):
    t = result(**kw)
    wf = wifi(t, rssi=-80, snr=14, util=30, clients=20)
    st.run(t, [wf, evidence("identity", t)])
    return t


def test_vmrange_buckets_are_contiguous_and_contain_the_value():
    assert vmrange(0) == "0...1.000e-09"
    for v in (0.5, 1, 6.2, 41.0, 212.4, 999.9, 100000):
        lo, hi = (float(x) for x in vmrange(v).split("..."))
        assert lo <= v * (1 + 1e-3) and v < hi * (1 + 1e-3), (v, lo, hi)
    his, los = [], []
    for v in (10 ** (i / 36) for i in range(0, 180)):
        lo, hi = (float(x) for x in vmrange(v).split("..."))
        los.append(lo)
        his.append(hi)
    assert all(math.isfinite(x) for x in los + his)
    # 18 buckets per decade: the upper bound is 10**(1/18) times the lower one
    lo, hi = (float(x) for x in vmrange(50).split("..."))
    assert hi / lo == pytest.approx(10 ** (1 / 18), rel=1e-2)


def test_nothing_is_written_before_the_evidence_is_final(st, vm):
    t = result()
    st.ingest(t)
    st.put_ev(wifi(t))
    st.app.vm.flush_now()
    assert not st_lines(vm)
    st.complete(t["id"], ["wifi"])
    settle(st, vm)
    assert st_lines(vm)


def test_series_and_labels_after_a_final_test(st, vm):
    one_test(st, down=60.0, up=20.0, i_down=30.0, i_up=9.0)
    settle(st, vm)
    lines = st_lines(vm)
    names = {ln["metric"]["__name__"] for ln in lines}
    for base in NAMES:
        assert {base + "_bucket", base + "_sum", base + "_count"} <= names, base
    assert "exp_st_tests_total" in names
    for ln in lines:
        assert set(ln["metric"]) <= ALLOWED_LABELS, ln["metric"]
        assert len(ln["values"]) == len(ln["timestamps"]) == 1 and ln["values"][0] > 0
    down = [ln for ln in lines if ln["metric"]["__name__"] == "exp_st_down_mbps_bucket"]
    assert {ln["metric"]["leg"] for ln in down} == {"local", "internet"}
    loc = next(ln for ln in down if ln["metric"]["leg"] == "local")
    assert (loc["metric"]["site"], loc["metric"]["zone"], loc["metric"]["ssid"], loc["metric"]["band"],
            loc["metric"]["ap"], loc["metric"]["os_family"]) == ("hall-b", "hallb-row12", "Summit-Guest", "5",
                                                                  "hallb-ap-12", "iOS")
    lo, hi = (float(x) for x in loc["metric"]["vmrange"].split("..."))
    assert lo <= 60.0 < hi
    tot = [ln for ln in lines if ln["metric"]["__name__"] == "exp_st_tests_total"]
    assert len(tot) == 1 and set(tot[0]["metric"]) == {"__name__", "site", "zone", "cause"} and tot[0]["values"] == [1.0]
    assert tot[0]["metric"]["cause"] == "wifi_signal"
    sc = [ln for ln in lines if ln["metric"]["__name__"] == "exp_st_score_count"]
    assert sc and sc[0]["metric"]["leg"] == "internet"                  # the score's basis leg
    sums = {ln["metric"]["leg"]: ln["values"][0] for ln in lines if ln["metric"]["__name__"] == "exp_st_down_mbps_sum"}
    assert sums == {"local": 60.0, "internet": 30.0}


def test_series_are_cumulative_across_tests(st, vm):
    one_test(st, down=60.0)
    one_test(st, down=60.0)
    settle(st, vm)
    st.app.vm.flush_now()
    last = {}
    for ln in st_lines(vm):
        key = (ln["metric"]["__name__"], tuple(sorted(ln["metric"].items())))
        last[key] = ln["values"][0]
    counts = [v for (n, lab), v in last.items() if n == "exp_st_down_mbps_count" and ("leg", "local") in lab]
    assert counts == [2.0]
    tot = [v for (n, _l), v in last.items() if n == "exp_st_tests_total"]
    assert tot == [2.0]


def test_no_per_user_or_per_device_value_ever_reaches_victoriametrics(st, vm):
    t = one_test(st, ip="10.60.14.77")
    st.comment(t["id"], "my phone is alices-iphone")
    settle(st, vm)
    blob = json.dumps(st_lines(vm))
    for raw in ("10.60.14.77", "f0:18:98:aa:bb:01", "231b3838d0007bf24d5b048d8a17a19495b0fb11b94a792fa99b1deb58b9e082",
                "alices-iphone", "guest-portal-7731", t["id"], "device_key", "mac", "username", "client_ip"):
        assert raw not in blob, raw


def test_label_cardinality_is_bounded_and_overflow_is_other(env, vm):
    st = make_stenv(env, speedtests={"metric_label_limit": 4})
    for i in range(10):
        t = result(down=50.0 + i, zone=f"zone-{i}")
        wf = wifi(t, ap_name=f"ap-{i}", util=30, clients=10)
        wf["data"]["client"]["ssid"] = f"ssid-{i}"
        ident = evidence("identity", t, zone=f"zone-{i}", zone_source="mist", ap_name=f"ap-{i}", ssid=f"ssid-{i}")
        st.run(t, [wf, ident])
    settle(st, vm)
    st.app.vm.flush_now()
    seen = {k: set() for k in BOUNDED}
    for ln in st_lines(vm):
        for k in BOUNDED:
            if k in ln["metric"]:
                seen[k].add(ln["metric"][k])
    for k in ("zone", "ssid", "ap"):
        assert len(seen[k]) <= 5 and "other" in seen[k], (k, seen[k])
    assert seen["site"] == {"hall-b"} and len(seen["os_family"]) == 1
    names = {ln["metric"]["__name__"] for ln in st_lines(vm)}
    assert len({ln["metric"].get("zone") for ln in st_lines(vm) if ln["metric"]["__name__"] == "exp_st_tests_total"}) <= 5
    assert names


def test_the_series_count_is_bounded_by_the_combination_cap():
    m = StMetrics(label_limit=1000, combo_limit=50)
    for i in range(500):
        m.observe({"site": "s", "zone": f"z{i}", "ssid": f"w{i}", "band": "5", "ap": f"a{i}", "os_family": f"o{i}",
                   "cause": "none", "legs": {"local": {"status": "ok", "down_mbps": 10.0 + i}}, "score": None})
    series = {(n, tuple(sorted(lab.items()))) for n, lab, _v in m.observe(
        {"site": "s", "zone": "zz", "ssid": "ww", "band": "5", "ap": "aa", "os_family": "oo", "cause": "none",
         "legs": {"local": {"status": "ok", "down_mbps": 10.0}}, "score": None})}
    assert m.series_count() < 50 * 40 and series
    labels = {dict(lab).get("zone") for n, lab in series if n == "exp_st_down_mbps_count"}
    assert labels == {"other"}


def test_label_values_are_cleaned():
    m = StMetrics()
    out = m.observe({"site": "s", "zone": "z", "ssid": "bad\x00ssid\n" + "x" * 200, "band": None, "ap": "",
                     "os_family": None, "cause": "none", "legs": {"local": {"status": "ok", "down_mbps": 1.0}},
                     "score": None})
    labs = [lab for n, lab, _ in out if n == "exp_st_down_mbps_count"][0]
    assert len(labs["ssid"]) == 64 and "\x00" not in labs["ssid"] and "\n" not in labs["ssid"]
    assert labs["band"] == "unknown" and labs["ap"] == "unknown" and labs["os_family"] == "unknown"


def test_non_ok_legs_are_not_observed():
    m = StMetrics()
    out = m.observe({"site": "s", "zone": "z", "ssid": "w", "band": "5", "ap": "a", "os_family": "o", "cause": "none",
                     "legs": {"local": {"status": "ok", "down_mbps": 5.0},
                              "internet": {"status": "paused", "down_mbps": 9.0}}, "score": None})
    legs = {lab["leg"] for n, lab, _ in out if n.startswith("exp_st_down")}
    assert legs == {"local"}


def test_vm_down_does_not_fail_the_request_and_the_points_are_kept(st, vm):
    vm.mode = "503"
    t = one_test(st)
    assert st.get(f"/{t['id']}").status == 200
    st.app.vm.flush_now()
    assert wait_for(lambda: st.app.vm.backlog_points > 0 or st.app.vm.queue_points > 0, timeout=10)
    vm.mode = "up"
