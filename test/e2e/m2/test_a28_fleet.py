"""A2.8 - fleet view: every host shows CPU / memory / disk / uptime / pps / bps and its component metrics within 2 status
intervals; filling a collector's disk past 85 % opens a `disk_high` issue; stopping a host's agent marks it `stale`, then
`offline` - and it is never shown as current.

Two hosts: A (collector + dashboard + probe on a veth LAN; /var/lib/exp is a small tmpfs so that it can be filled) and B (a
dashboard only; its agent is stopped). Time is advanced by moving `hosts.last_seen` back in D1 and running the manager's
cron through wrangler dev's scheduled-event endpoint.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import pytest
from expharness.dockerhost import wait_for

import m2lib
from m2lib import host_row, provision_full

SITE = "fleet-e2e"
STATUS_INTERVAL_S = 60
# the collector's own health gate wants >= 0.5 GB free (>= 2 GB to be `ok`): a tmpfs that is healthy before it is filled past 85 %
TMPFS_MB = 2500


@dataclass
class Fleet:
    a: m2lib.Full
    b: m2lib.Full


@pytest.fixture(scope="module")
def fleet(stack, host_image):
    a = provision_full(stack, SITE, "a28a", "e2e-fleet-a", tmpfs_mb=TMPFS_MB)
    try:
        b = provision_full(stack, SITE, "a28b", "e2e-fleet-b", shapes=("dashboard",))
    except BaseException:
        a.host.remove()
        raise
    try:
        yield Fleet(a, b)
    finally:
        for f, n in ((a, "a"), (b, "b")):
            try:
                (stack.artifacts / f"a28{n}-host-diagnostics.txt").write_text(f.host.diagnostics())
            finally:
                f.host.remove()


def row(stack, hid: str) -> dict[str, Any]:
    return next(x for x in stack.admin.get("/fleet/hosts?limit=1000")["items"] if x["host_id"] == hid)


def has_figures(r: dict[str, Any]) -> bool:
    n = r.get("net") or {}
    return all(r.get(k) is not None for k in ("cpu_pct", "mem_pct", "disk_pct_max", "uptime_s")) and all(
        n.get(k) is not None for k in ("rx_pps", "tx_pps", "rx_bps", "tx_bps")
    )


def test_every_host_shows_its_figures_within_two_status_intervals(stack, fleet):
    for f in (fleet.a, fleet.b):
        # the first report carries no rates (deltas need two samples): the figures must be complete by the second one
        first = wait_for(
            lambda f=f: (h := host_row(stack, f.host_id))["last_seen"] and h, 120, 2, "first status", f.host.diagnostics
        )
        t0 = time.time()
        r = wait_for(
            lambda f=f: (x := row(stack, f.host_id)) and has_figures(x) and x,
            2 * STATUS_INTERVAL_S + 30,
            3,
            f"cpu/mem/disk/uptime/pps/bps for {f.host_id}",
            f.host.diagnostics,
        )
        took = time.time() - t0
        assert took <= 2 * STATUS_INTERVAL_S + 30, took
        assert first["state"] == "enrolled" and r["state"] == "enrolled" and r["stale"] is False and r["health"] in ("ok", "degraded")
        assert 0 <= r["cpu_pct"] <= 100 and 0 < r["mem_pct"] <= 100 and 0 < r["disk_pct_max"] <= 100 and r["uptime_s"] > 0
        assert r["net"]["rx_pps"] >= 0 and r["net"]["rx_bps"] >= 0 and r["net"]["tx_bps"] >= 0
        assert r["site"] == SITE and r["mgmt_ip"] == f.host.ip and r["agent_version"] == stack.version
    a = row(stack, fleet.a.host_id)
    assert sorted(a["shapes"]) == ["collector", "dashboard", "probe"]
    assert sorted(row(stack, fleet.b.host_id)["shapes"]) == ["dashboard"]


def test_host_metric_series_and_component_metrics(stack, fleet):
    keys = ["cpu_pct", "mem_pct", "disk_pct", "net_rx_pps", "net_tx_pps", "net_rx_bps", "net_tx_bps", "load1"]

    def series():
        m = stack.admin.get(f"/fleet/hosts/{fleet.a.host_id}/metrics?range=1h&keys={','.join(keys)}")
        s = m["series"]
        return m if all(s.get(k) for k in keys) else None

    m = wait_for(series, 3 * STATUS_INTERVAL_S, 5, "host metric series", fleet.a.host.diagnostics)
    assert m["host_id"] == fleet.a.host_id and m["range"] == "1h"
    for k in keys:
        pt = m["series"][k][-1]
        assert isinstance(pt["t"], int) and isinstance(pt["avg"], (int, float)), (k, pt)
    # component metrics: each of the three types reports its own figures
    want = {"collector": "probes_total", "probe": "measurements_per_min", "dashboard": "collectors_total"}

    def comp_ok():
        for typ, key in want.items():
            s = stack.admin.get(f"/fleet/components/{fleet.a.cids[typ]}/metrics?range=1h&keys={key}")["series"]
            if not s.get(key):
                return False
        return True

    wait_for(comp_ok, 4 * STATUS_INTERVAL_S, 5, "component metric series", fleet.a.host.diagnostics)
    wait_for(
        lambda: row(stack, fleet.a.host_id)["work"]["measurements_per_min"] is not None,
        3 * STATUS_INTERVAL_S,
        5,
        "probe work metric",
    )
    comps = stack.admin.get(f"/hosts/{fleet.a.host_id}/components")["items"]
    by = {c["type"]: c for c in comps}
    assert by["probe"]["facts"]["metrics"], by["probe"]
    assert by["collector"]["facts"]["metrics"], by["collector"]
    top = stack.admin.get("/fleet/top?metric=cpu&limit=10")["items"]
    assert {t["host_id"] for t in top} >= {fleet.a.host_id, fleet.b.host_id}


def test_filling_the_collector_disk_opens_disk_high(stack, fleet):
    h = fleet.a.host
    r = h.run("df -P /var/lib/exp | tail -1 | awk '{print $2, $3}'")
    total_k, used_k = (int(x) for x in r.out.split())
    assert total_k < 3 * 1024 * 1024, "/var/lib/exp must be the small tmpfs"
    fill_k = int(total_k * 0.90) - used_k
    r = h.run(f"fallocate -l {fill_k}K /var/lib/exp/e2e-filler && df -P /var/lib/exp | tail -1 | awk '{{print $5}}'")
    assert r.rc == 0, r
    pct = int(r.out.strip().rstrip("%"))
    assert 86 <= pct <= 94, pct
    hid = fleet.a.host_id

    def opened():
        items = stack.admin.get("/issues?kind=disk_high&state=open")["items"]
        return next((i for i in items if i["host_id"] == hid), None)

    issue = wait_for(opened, 2 * STATUS_INTERVAL_S + 60, 5, "a disk_high issue", h.diagnostics)
    assert issue["severity"] == "warn" and issue["resolved_at"] is None
    assert issue["last_value"] >= 85 and issue["site"] == SITE, issue
    assert row(stack, hid)["disk_pct_max"] >= 85 and row(stack, hid)["open_issues"] >= 1
    # crit at 95 %
    total_k, used_k = (int(x) for x in h.run("df -P /var/lib/exp | tail -1 | awk '{print $2, $3}'").out.split())
    assert h.run(f"fallocate -l {int(total_k * 0.965) - used_k + fill_k}K /var/lib/exp/e2e-filler").rc == 0
    crit = wait_for(
        lambda: next(
            (
                i
                for i in stack.admin.get("/issues?kind=disk_high&state=open")["items"]
                if i["host_id"] == hid and i["severity"] == "crit"
            ),
            None,
        ),
        2 * STATUS_INTERVAL_S + 60,
        5,
        "disk_high escalating to crit",
        h.diagnostics,
    )
    assert crit["last_value"] >= 95
    # free the space: the issue resolves after two clean reports (hysteresis), not before
    assert h.run("rm -f /var/lib/exp/e2e-filler").rc == 0
    wait_for(
        lambda: not any(i["host_id"] == hid for i in stack.admin.get("/issues?kind=disk_high&state=open")["items"]),
        4 * STATUS_INTERVAL_S + 60,
        5,
        "disk_high resolving",
        h.diagnostics,
    )


def iso_ago(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - seconds))


def issues_of(stack, hid: str, kind: str, state: str = "open") -> list[dict[str, Any]]:
    return [i for i in stack.admin.get(f"/issues?kind={kind}&state={state}")["items"] if i["host_id"] == hid]


def test_stopped_agent_goes_stale_then_offline_never_current(stack, fleet):
    b, hid = fleet.b.host, fleet.b.host_id
    before = row(stack, hid)
    assert before["state"] == "enrolled" and not before["stale"] and before["health"] == "ok"
    online_before = stack.admin.get("/fleet/summary")["hosts_online"]
    assert b.run("systemctl stop exp-agent").rc == 0
    last = host_row(stack, hid)["last_seen"]

    # 4 minutes of silence (> 3 x 60 s): the 5-minute cron marks the host stale
    stack.mgr.sql(f"UPDATE hosts SET last_seen = '{iso_ago(240)}' WHERE host_id = '{hid}'")
    assert stack.mgr.run_cron("*/5 * * * *").status == 200
    r = wait_for(lambda: (x := row(stack, hid)) and x["state"] == "stale" and x, 30, 1, "state stale")
    assert r["stale"] is True and r["health"] == "unknown", r
    assert [i["severity"] for i in issues_of(stack, hid, "host_stale")] == ["warn"]
    # never shown as current: it is not ranked, not counted online, its components are `unknown`
    assert hid not in {t["host_id"] for t in stack.admin.get("/fleet/top?metric=cpu&limit=100")["items"]}
    s = stack.admin.get("/fleet/summary")
    assert s["hosts_by_state"]["stale"] >= 1 and s["hosts_online"] == online_before - 1
    assert host_row(stack, hid)["state"] == "stale"
    # the units keep running on the host: "stale" says "no report", not "down"
    assert b.run("systemctl is-active exp-dashboard").out.strip() == "active"

    # 11 minutes of silence: offline (crit), the stale issue is replaced
    stack.mgr.sql(f"UPDATE hosts SET last_seen = '{iso_ago(11 * 60)}' WHERE host_id = '{hid}'")
    assert stack.mgr.run_cron("*/5 * * * *").status == 200
    r = wait_for(lambda: (x := row(stack, hid)) and x["state"] == "offline" and x, 30, 1, "state offline")
    assert r["stale"] is True and r["health"] == "unknown"
    off = issues_of(stack, hid, "host_offline")
    assert [i["severity"] for i in off] == ["crit"], off
    assert issues_of(stack, hid, "host_stale") == []
    assert hid not in {t["host_id"] for t in stack.admin.get("/fleet/top?metric=mem&limit=100")["items"]}
    assert stack.admin.get("/fleet/summary")["hosts_by_state"]["offline"] >= 1
    # the other host is untouched
    assert row(stack, fleet.a.host_id)["state"] == "enrolled"
    assert last  # (the report timestamp the agent last sent)


def test_agent_returns_and_the_host_is_current_again(stack, fleet):
    b, hid = fleet.b.host, fleet.b.host_id
    assert b.run("systemctl start exp-agent").rc == 0
    r = wait_for(
        lambda: (x := row(stack, hid)) and x["state"] == "enrolled" and not x["stale"] and x,
        150,
        3,
        "enrolled again",
        b.diagnostics,
    )
    assert r["health"] == "ok"
    # offline resolves after two clean reports
    wait_for(lambda: not issues_of(stack, hid, "host_offline"), 4 * STATUS_INTERVAL_S, 5, "host_offline resolving", b.diagnostics)
