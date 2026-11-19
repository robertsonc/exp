"""A3.3 (SPEC.md section 9, M3): the manager is unreachable for 30 minutes - no data loss, alerts still fire, dashboards work
(SPEC principle 2: the data plane never depends on the cloud; 06-agent.md section 2: the agent never stops components).

The M2 stack: the manager Worker under `wrangler dev`, and ONE Ubuntu 24.04 systemd host enrolled through the real
one-liner running collector + dashboard + probe (the probe on a veth LAN with dnsmasq), with the site's webhook alerts
pointing at a local https receiver. The outage is an iptables DROP of every packet from the host to the manager's
address and port (the manager keeps running and keeps its state). Length: EXP_M3_MANAGER_OUTAGE_S (default 1800, the
spec's 30 minutes; the per-PR variant sets e.g. 180). The assertions are identical for every length.

During the outage: nothing on the host restarts, the agent keeps the last applied state and backs off, the probe's
heartbeat records keep arriving at the collector without a gap longer than 2 beats, a DNS fault injected on the probe's
LAN pages `down` and (after the fault is cleared) `back` at the receiver, and the dashboard (local operator) shows the live
state. After the outage: the agent reconnects within its backoff bound, the manager shows the host online with fresh
metrics, no record is duplicated or missing, and the probe tweak made on the manager DURING the outage is applied.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import outagelib as O
import pytest

pytestmark = pytest.mark.e2e
m2lib = O.m2lib

HOLD_DOWN_S = 20
HOLD_BACK_S = 60
BACKOFF_MAX_S = 300
CONNECT_TIMEOUT_S = 10
STATUS_S = 60
DNS_TWEAK_S = 120                    # the desired-state change made on the manager during the outage


SYN_TIMELINE: list[tuple[int, int]] = []   # (epoch, SYNs to the manager so far), for the failure message and the artifact


@dataclass
class Run:
    notes: dict[str, Any] = field(default_factory=dict)


@pytest.fixture(scope="module")
def run() -> Run:
    return Run()


def probe_row(st: O.ManagerStack, site: O.Site, dash: Any) -> dict[str, Any] | None:
    items = dash.get("states", voice="plain")["items"]
    return next((i for i in items if i["probe"] == site.ids["probe"]), None)


def lines_of(item: dict[str, Any]) -> dict[str, str]:
    return {ln["key"]: ln["state"] for ln in item["lines"]}


MEASURED = ("network", "dhcp", "dns", "internet")   # the lines this probe's intent measures (no app tests: `apps` stays unknown)


def measured_ok(it: dict[str, Any] | None) -> bool:
    return bool(it) and all(lines_of(it).get(k) == "ok" for k in MEASURED)


def fleet_row(st: O.ManagerStack, site: O.Site) -> dict[str, Any]:
    return next(x for x in st.admin.get("/fleet/hosts?limit=1000")["items"] if x["host_id"] == site.host_id)


def has_figures(r: dict[str, Any]) -> bool:
    n = r.get("net") or {}
    return all(r.get(k) is not None for k in ("cpu_pct", "mem_pct", "disk_pct_max", "uptime_s")) and all(
        n.get(k) is not None for k in ("rx_pps", "tx_pps", "rx_bps", "tx_bps"))


# ============================================================================================ 1. baseline
def test_a3_3_0_baseline_probe_data_flows_and_the_dashboard_is_green(outage_site, run: Run) -> None:
    st, site, hooks = outage_site
    coll = site.collector(st)
    O.wait_until(lambda: len(O.beats(site, coll, time.time() - 60, time.time() + 5)) >= 4, 180, 5,
                 "heartbeat records from the probe", site.host.diagnostics)
    dash = site.dash(st, fresh=True)

    def green() -> bool:
        return measured_ok(probe_row(st, site, dash))

    O.wait_until(green, 240, 3, "the probe's board is green", site.host.diagnostics)
    opened = [i for i in dash.get("incidents", probe=site.ids["probe"])["items"] if i["end"] is None]
    assert not opened, opened
    run.notes["t_start"] = time.time()
    assert hooks.pages() == [], "the receiver already got pages before any fault"
    # the receiver is reachable from the host and the collector trusts it (a real webhook test through the manager is not
    # used: it would leave the manager)
    health = f"https://{O.HOOK_NAME}:{hooks.port}/_health"
    assert site.host.run(f"curl -sS -m 10 -o /dev/null -w '%{{http_code}}' {health}").out == "200"


# ============================================================================================ 2. the outage
def test_a3_3_1_during_the_outage_the_site_runs_alone(outage_site, run: Run) -> None:
    if "t_start" not in run.notes:
        pytest.skip("the baseline test did not pass")
    st, site, hooks = outage_site
    coll = site.collector(st)
    host = site.host
    probe = site.ids["probe"]
    port = st.mgr.port
    T = O.OUTAGE_S
    assert T >= 150, "EXP_M3_MANAGER_OUTAGE_S must leave room for the fault, the down page and the back page (>= 150)"

    units0 = site.unit_snapshot()
    assert {"exp-agent.service", "exp-collector.service", "exp-dashboard.service", "exp-probe.service"} <= set(units0), units0
    desired0, cfg0 = site.desired_hash(), site.probe_config()
    seen0 = m2lib.host_row(st, site.host_id)["last_seen"]
    dash = site.dash(st, fresh=True)
    pages_since = time.time()

    t0 = time.time()
    run.notes["t_block"] = t0
    site.block_manager(port)
    try:
        # the block works: the host cannot reach the manager (a timeout, not a refusal)
        r = host.run(f"curl -sS -m 8 -o /dev/null https://{O.MANAGER_NAME}:{port}/healthz", timeout=30)
        assert r.rc == 28, f"the manager is still reachable from the host (curl rc={r.rc}): {r}"
        syns0 = site.manager_syns()                       # (our own curl is not the agent's attempt)
        t_syn0 = time.time()

        # a desired-state change made on the manager DURING the outage: it must not reach the host until the manager is back
        # (the config is replaced as a whole: keep the stored one, ports included, and change only the DNS test's period)
        cfg = json.loads(json.dumps(m2lib.comp_row(st, site.host_id, "probe")["config"]))
        assert cfg.get("ports"), cfg
        cfg["tests"]["dns"]["interval_s"] = DNS_TWEAK_S
        st.admin.call("PATCH", f"/components/{site.cids['probe']}", {"config": cfg}, ok=(200,))
        run.notes["t_tweak"] = time.time()

        # a fault on the probe's LAN, injected mid-outage
        fault_at = t0 + min(max(T * 0.15, 20), 600)
        _sleep_until(fault_at, site, dash, st)
        assert lines_of(probe_row(st, site, dash)).get("dns") == "ok", "the dns line was not green before the fault"
        site.block_dns()
        t_fault = time.time()
        live: list[str] = []

        def down_page() -> dict[str, Any] | None:
            it = probe_row(st, site, dash)
            live.append(lines_of(it).get("dns", "?") if it else "?")
            return next((p for p in hooks.pages(pages_since) if O.page_kind(p) == "down"), None)

        page = O.wait_until(down_page, 150, 3, "the 'down' page at the webhook receiver", host.diagnostics)
        t_down = page["ts"]
        assert page["doc"]["line"] == "dns" and page["doc"]["board"] == probe, page["doc"]
        assert t_down >= t_fault + HOLD_DOWN_S - 3, "paged before the failure had lasted hold_down_s"
        # the dashboard shows the live state: its dns line left `ok` while the manager was unreachable
        assert any(s != "ok" for s in live), f"the dashboard never showed the dns fault (dns line states: {live})"
        inc = next(i for i in dash.get("incidents", probe=probe)["items"] if i["id"] == page["doc"]["incident"])
        assert inc["line"] == "dns" and inc["end"] is None
        time.sleep(15)                                     # still failing: still exactly one page
        assert [O.page_kind(p) for p in hooks.pages(pages_since)] == ["down"]

        site.restore_dns()
        t_clear = time.time()
        back = O.wait_until(lambda: next((p for p in hooks.pages(pages_since) if O.page_kind(p) == "back"), None),
                            HOLD_BACK_S + 120, 3, "the 'back' page at the webhook receiver", host.diagnostics)
        # (the recovery is its own row in the incidents list: same line, same start as the failure it closes)
        assert back["doc"]["line"] == "dns" and back["doc"]["start"] == page["doc"]["start"] and back["doc"]["end"], back["doc"]
        assert back["ts"] >= t_clear + HOLD_BACK_S - 5
        assert back["doc"]["incident"] in {i["id"] for i in dash.get("incidents", probe=probe)["items"]}
        assert [O.page_kind(p) for p in hooks.pages(pages_since)] == ["down", "back"]
        assert time.time() < t0 + T, f"the down/back pages did not fit in the outage ({T:.0f}s): raise EXP_M3_MANAGER_OUTAGE_S"
        O.wait_until(lambda: lines_of(probe_row(st, site, dash)).get("dns") == "ok", 60, 3, "the dns line green again")

        # the rest of the outage: keep watching the dashboard and the units
        _sleep_until(t0 + T, site, dash, st)
        t_end = time.time()

        # ---- assertions at the end of the outage (the manager is still unreachable)
        syns = site.manager_syns() - syns0
        window = time.time() - t_syn0
        assert host.run("curl -sS -m 8 -o /dev/null https://%s:%d/healthz" % (O.MANAGER_NAME, port)).rc == 28
        units1 = site.unit_snapshot()
        for u, was in units0.items():
            now = units1.get(u)
            assert now == was, f"{u} changed during the outage: {was} -> {now}"
        assert site.desired_hash() == desired0, "the agent's cached desired state changed while the manager was unreachable"
        assert site.probe_config() == cfg0, "the probe's config changed while the manager was unreachable"
        assert m2lib.host_row(st, site.host_id)["last_seen"] == seen0, "the manager heard from the host during the outage"
        log = host.agent_log(400)
        assert "manager unreachable" in log, log[-800:]
        # an attempt sends at most 1 + tcp_syn_retries SYNs (the connect timeout is shorter than the kernel's give-up time)
        retries = int(host.run("sysctl -n net.ipv4.tcp_syn_retries").out.strip() or "6")
        bound = (O.expected_attempts(window) + 2) * (1 + retries) + (1 + retries)
        assert 1 <= syns <= bound, (
            f"{syns} SYNs to the manager in {window:.0f}s (bound {bound}): the agent is not backing off; timeline {SYN_TIMELINE}")
        assert host.run("systemctl is-active exp-agent").out.strip() == "active"
        if T >= 300:                                       # the manager never shows a silent host as current (3 status intervals)
            assert fleet_row(st, site)["stale"] is True, fleet_row(st, site)

        rows = O.beats(site, coll, t0, t_end + 5)
        gap = O.max_gap(rows, t0, t_end)
        run.notes.update(t_end=t_end, gap=gap, syns=syns, bound=bound, units=len(units0))
        assert gap <= 2 * O.BEAT_S + 2, f"heartbeat gap of {gap:.1f}s ({gap / O.BEAT_S:.1f} beats) during the outage"
        assert len(rows) >= (t_end - t0) / O.BEAT_S - 3, (len(rows), t_end - t0)
        # dashboard: still serving, live (a fresh login with the local user works with the manager gone)
        d2 = site.dash(st, fresh=True)
        it = probe_row(st, site, d2)
        assert measured_ok(it), it
    finally:
        site.restore_dns()
        site.unblock_manager(port)
        run.notes["t_restore"] = time.time()


# ============================================================================================ 3. recovery
def test_a3_3_2_after_the_outage_the_agent_reconnects_and_the_manager_catches_up(outage_site, run: Run) -> None:
    if "t_end" not in run.notes:
        pytest.skip("the outage test did not pass")
    st, site, hooks = outage_site
    host = site.host
    coll = site.collector(st)
    t_restore = run.notes["t_restore"]
    probe = site.ids["probe"]

    # reconnect: within the backoff bound (5 min + the connect timeout + a status interval of slack)
    bound = BACKOFF_MAX_S * 1.2 + CONNECT_TIMEOUT_S + 30
    row = O.wait_until(lambda: (h := m2lib.host_row(st, site.host_id))["last_seen"] and O.epoch(h["last_seen"]) > t_restore and h,
                       bound, 3, "the agent reporting to the manager again", host.diagnostics)
    reconnect_s = O.epoch(row["last_seen"]) - t_restore
    assert row["state"] == "enrolled", row

    # components still healthy and the manager shows them (status report) and the host's fresh figures (fleet API)
    O.wait_until(lambda: m2lib.components_ok(st, site.host_id, ("collector", "dashboard", "probe")), 180, 3,
                 "all components healthy in the manager", host.diagnostics)
    fr = O.wait_until(lambda: (r := fleet_row(st, site)) and has_figures(r) and r["stale"] is False and r, 3 * STATUS_S, 3,
                      "fresh fleet figures", host.diagnostics)
    assert fr["state"] == "enrolled" and fr["health"] in ("ok", "degraded"), fr
    assert O.epoch(fr["last_seen"]) > t_restore
    keys = "cpu_pct,mem_pct,net_rx_bps"

    def fresh_series() -> bool:
        m = st.admin.get(f"/fleet/hosts/{site.host_id}/metrics?range=1h&keys={keys}")
        # buckets are `step_s` wide and `t` is the bucket start: the newest bucket is the one of the newest report
        newest = int(O.epoch(fleet_row(st, site)["last_seen"]) // m["step_s"] * m["step_s"])
        return all(m["series"].get(k) and m["series"][k][-1]["t"] >= newest for k in keys.split(","))

    O.wait_until(fresh_series, 3 * STATUS_S, 5, "host metrics up to the newest report", host.diagnostics)

    # the change made on the manager during the outage is applied now
    def tweaked() -> bool:
        return f'"interval_s": {DNS_TWEAK_S}' in json.dumps(site.probe_config())

    O.wait_until(tweaked, 180, 3, "the probe's config tweak (made during the outage) applied", host.diagnostics)
    O.wait_until(lambda: m2lib.components_ok(st, site.host_id, ("probe",)), 120, 3, "the probe healthy after its reload",
                 host.diagnostics)
    t_after = time.time()
    O.wait_until(lambda: len(O.beats(site, coll, t_after, time.time() + 5)) >= 3, 120, 5, "heartbeats after the reload",
                 host.diagnostics)

    # no duplicate and no missing record: the collector's SQLite holds what the API serves, once; the probe's spool is empty
    t_lo, t_hi = run.notes["t_start"], time.time() - 5       # a closed window in the past: nothing is still in flight in it
    rows = O.beats(site, coll, t_lo, t_hi)
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate record ids"
    query = (
        "import sqlite3, sys\n"
        "c = sqlite3.connect('file:/var/lib/exp/collector/records.db?mode=ro', uri=True)\n"
        "q = 'select id from records where probe=? and test=? and ts_ms>=? and ts_ms<=?'\n"
        "print('\\n'.join(r[0] for r in c.execute(q, (sys.argv[1], 'gateway', int(sys.argv[2]), int(sys.argv[3])))))\n")
    host.write("/tmp/a33-ids.py", query)
    out = host.run(f"python3 /tmp/a33-ids.py {probe} {int(t_lo * 1000)} {int(t_hi * 1000)}").out.split()
    assert len(out) == len(set(out)), "duplicate ids in the collector's SQLite"
    assert set(out) == set(ids), f"SQLite and the records API disagree: only in SQLite {sorted(set(out) - set(ids))[:5]}, " \
        f"only in the API {sorted(set(ids) - set(out))[:5]}"
    outage_rows = [r for r in rows if run.notes["t_block"] <= O.epoch(r["ts"]) <= run.notes["t_end"]]
    window_s = run.notes["t_end"] - run.notes["t_block"]
    assert len(outage_rows) >= window_s / O.BEAT_S - 3, "records are missing from the outage window"
    exe = "exp-probe"
    spool = host.run(f"{exe} spool stat --json 2>&1 || /opt/exp/probe/current/bin/{exe} spool stat --json 2>&1").out.strip()
    stat = json.loads(spool.splitlines()[-1])
    assert stat["depth"] <= 5 and stat["dropped_total"] == 0, stat
    assert m2lib.components_ok(st, site.host_id, ("collector", "dashboard", "probe")) is not None

    # the dashboard is still live with the manager back
    d3 = site.dash(st, fresh=True)       # (the probe's restart for the tweak leaves a short DHCP blip in the window: wait it out)
    O.wait_until(lambda: measured_ok(probe_row(st, site, d3)), 240, 5, "the board green again after the probe's reload",
                 host.diagnostics)
    (st.artifacts / "a33-manager-outage.txt").write_text(
        f"outage {O.OUTAGE_S:.0f}s; units unchanged {run.notes['units']}; max heartbeat gap {run.notes['gap']:.1f}s; "
        f"agent SYNs {run.notes['syns']} (bound {run.notes['bound']}); reconnected {reconnect_s:.0f}s after the restore "
        f"(bound {bound:.0f}s); records {len(rows)} (outage window {len(outage_rows)}), duplicates 0; spool {stat}\n")


# ============================================================================================ helpers
def _sleep_until(t: float, site: O.Site, dash: Any, st: O.ManagerStack, step: float = 15.0) -> None:
    """Wait until wall-clock `t`, keeping watch: every component still active and the dashboard still answering."""
    while time.time() < t:
        time.sleep(min(step, max(0.0, t - time.time())))
        act = site.host.run("systemctl is-active exp-agent exp-collector exp-dashboard exp-probe").out.split()
        assert act == ["active"] * 4, f"a component stopped during the outage: {act}"
        SYN_TIMELINE.append((round(time.time()), site.manager_syns()))
        assert probe_row(st, site, dash) is not None, "the dashboard lost the probe"
