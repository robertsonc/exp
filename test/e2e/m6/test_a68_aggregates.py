"""A6.8: aggregates in VictoriaMetrics carry no per-device / per-user labels (cardinality queries against the box's own VictoriaMetrics),
and the dashboard's breakdowns match the SQLite ground truth (12-speedtest-analytics.md sections 6, 8, 11).

Runs after the other tests of the session, so the box holds a dozen tests from distinct devices (distinct IPs, MACs, device keys): if any
identifier were a label the series count would grow with the number of devices; here every label name and value is checked instead.
"""
from __future__ import annotations

import json
import re
import statistics
from collections import Counter

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
ALLOWED_LABELS = {"__name__", "site", "zone", "leg", "ssid", "band", "ap", "os_family", "cause", "vmrange"}
BOUNDED = ("site", "zone", "ssid", "band", "ap", "os_family")
FORBIDDEN_NAMES = re.compile(r"device|mac|^ip$|client|user|host|^id$|test|session|key", re.I)
MAC_RE = re.compile(r"(?i)\b([0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b|\b[0-9a-f]{12}\b")
IP_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
VM = "http://127.0.0.1:8428"


def vm_get(core: M.Core, path: str, **params: str) -> dict:
    q = " ".join(f"--data-urlencode {M.L._q(k + '=' + v)}" for k, v in params.items())
    out = core.col.ok(f"curl -s -m 20 -G {q} {VM}{path}")
    doc = json.loads(out)
    assert doc.get("status") == "success", doc
    return doc


def box_rows(core: M.Core) -> list[dict]:
    out = core.col.ok("sqlite3 -readonly -json /var/lib/exp/collector/records.db "
                      "\"select id, site, zone, ap_name, ssid, band, os_family, cause, device_key, client_ip, mac, started_ms, "
                      "local_down, local_up, internet_down, internet_up, score from speedtests\"") or "[]"
    return json.loads(out)


def test_a68_vm_series_have_no_device_or_user_labels(core: M.Core):
    rows = box_rows(core)
    assert len(rows) >= 8, f"the earlier tests of the session left only {len(rows)} stored tests"
    for r in rows:      # every test final: its observation reached the aggregates
        core.wait_final(r["id"], 120)
    series = vm_get(core, "/api/v1/series", **{"match[]": '{__name__=~"exp_st_.*"}', "start": "-3d"})["data"]
    assert series, "no exp_st_* series in VictoriaMetrics"
    names = {s["__name__"] for s in series}
    assert {"exp_st_score_count", "exp_st_down_mbps_count", "exp_st_tests_total"} <= names, names
    labels = {k for s in series for k in s}
    assert labels <= ALLOWED_LABELS, f"unexpected labels: {sorted(labels - ALLOWED_LABELS)}"
    assert not [k for k in labels if k != "__name__" and FORBIDDEN_NAMES.search(k)], labels
    # the label VALUES: no MAC, no IP, no device key, no test id, nothing the tests' own rows name
    secrets = {v for r in rows for v in (r["device_key"], r["client_ip"], r["mac"], r["id"]) if v}
    macs = {r["mac"].replace(":", "") for r in rows if r["mac"]}
    for s in series:
        for k, v in s.items():
            if k in ("__name__", "vmrange"):
                continue
            assert v not in secrets and not MAC_RE.search(v) and not IP_RE.search(v), f"{k}={v!r} looks like an identifier"
            assert v.replace(":", "") not in macs
    # cardinality: bounded label values, and the series count follows the (zone, ap, ssid, band, os) combinations -- not the devices
    for lab in BOUNDED:
        assert len({s[lab] for s in series if lab in s}) <= 65, lab
    combos = {(r["site"], r["zone"], r["ap_name"] or "unknown", r["ssid"] or "unknown", r["band"] or "unknown", r["os_family"] or "unknown")
              for r in rows}
    devices = {r["device_key"] for r in rows if r["device_key"]}
    count_series = [s for s in series if s["__name__"] == "exp_st_score_count"]
    assert len(devices) >= 6, f"need distinct devices to make this a cardinality test: {len(devices)}"
    assert len(count_series) <= 2 * len(combos) + 2, (len(count_series), len(combos), len(devices))
    # and the same through the label API (every label name VM knows for these series)
    names_api = set(vm_get(core, "/api/v1/labels", **{"match[]": '{__name__=~"exp_st_.*"}', "start": "-3d"})["data"])
    assert names_api <= ALLOWED_LABELS, sorted(names_api - ALLOWED_LABELS)
    print(f"A6.8 VM: {len(series)} series, labels {sorted(labels)}, {len(devices)} devices, {len(combos)} label combinations")


def test_a68_dashboard_breakdowns_match_sqlite(core: M.Core):
    rows = box_rows(core)
    dash = core.dash()
    # the dashboard's list agrees on how many tests exist
    assert len(rows) >= 8
    listed = dash.get("speedtests", limit=200)["items"]
    assert {x["id"] for x in listed} == {r["id"] for r in rows}, "dashboard list != collector table"
    key = {"zone": lambda r: r["zone"], "ap": lambda r: r["ap_name"] or "unknown", "ssid": lambda r: r["ssid"] or "unknown",
           "band": lambda r: r["band"] or "unknown", "os_family": lambda r: r["os_family"] or "unknown", "cause": lambda r: r["cause"] or "unknown"}
    for group, kf in key.items():
        got = {i["key"]: i for i in dash.get("speedtests/aggregate", group_by=group, metric="count")["items"]}
        want = Counter(kf(r) for r in rows)
        assert {k: int(v["value"]) for k, v in got.items()} == dict(want), (group, got, want)
        assert all(i["count"] == int(i["value"]) for i in got.values())
    for metric, col, leg in (("down_p50", "local_down", "local"), ("up_p50", "local_up", "local"), ("down_p50", "internet_down", "internet"),
                             ("score_p50", "score", "local")):
        got = {i["key"]: i for i in dash.get("speedtests/aggregate", group_by="zone", metric=metric, leg=leg)["items"]}
        by: dict[str, list[float]] = {}
        for r in rows:
            if r[col] is not None:
                by.setdefault(r["zone"], []).append(float(r[col]))
        assert set(got) == set(by), (metric, leg, sorted(got), sorted(by))
        for z, vs in by.items():
            assert got[z]["count"] == len(vs) and got[z]["value"] == pytest.approx(statistics.median(vs), rel=1e-6, abs=1e-6), (metric, z, got[z], vs)
    hours = dash.get("speedtests/aggregate", group_by="hour", metric="count")["items"]
    assert sum(int(h["value"]) for h in hours) == len(rows)
    # the page for the breakdowns renders
    assert dash.page("/speedtests").status == 200
    # no identifier in the breakdowns either (dashboard answers are aggregates)
    blob = json.dumps(dash.get("speedtests/aggregate", group_by="ap", metric="count"))
    assert not any(r["client_ip"] and r["client_ip"] in blob or r["mac"] and r["mac"] in blob for r in rows)
