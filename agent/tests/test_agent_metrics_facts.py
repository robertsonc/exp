"""Host metrics from /proc and /sys (deltas, null on first report / counter reset), process metrics, facts."""

from __future__ import annotations

import json
import os

import pytest
from agent_helpers import Env
from exp_common import config as exp_config

from exp_agent.facts import collect_facts, default_route_iface, in_use_by, interface_facts
from exp_agent.metrics import HostMetrics


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def put(env: Env, logical: str, text: str) -> None:
    p = env.path(logical)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def proc_stat(user=100, nice=0, system=50, idle=800, iowait=40, irq=0, softirq=10, steal=0) -> str:
    return (
        f"cpu  {user} {nice} {system} {idle} {iowait} {irq} {softirq} {steal} 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\n"
    )


def net(env, iface, rx_p, tx_p, rx_b, tx_b, rx_e=0, tx_e=0, rx_d=0, tx_d=0, oper="up", speed="1000"):
    base = f"/sys/class/net/{iface}"
    put(env, f"{base}/operstate", oper + "\n")
    put(env, f"{base}/speed", speed + "\n")
    for k, v in (
        ("rx_packets", rx_p),
        ("tx_packets", tx_p),
        ("rx_bytes", rx_b),
        ("tx_bytes", tx_b),
        ("rx_errors", rx_e),
        ("tx_errors", tx_e),
        ("rx_dropped", rx_d),
        ("tx_dropped", tx_d),
    ):
        put(env, f"{base}/statistics/{k}", f"{v}\n")


def seed(env, cpu=None, **netkw):
    put(env, "/proc/stat", cpu or proc_stat())
    put(env, "/proc/loadavg", "0.80 0.60 0.50 1/100 1234\n")
    put(env, "/proc/uptime", "1234567.89 5000.00\n")
    put(
        env,
        "/proc/meminfo",
        "MemTotal:       32768000 kB\nMemAvailable:   24576000 kB\n"
        "SwapTotal: 1048576 kB\nSwapFree: 1048576 kB\n",
    )
    put(
        env,
        "/proc/diskstats",
        "   8       0 sda 100 0 4096 0 100 0 2048 0 0 0 0\n"
        "   8       1 sda1 5 0 99999 0 5 0 99999 0 0 0 0\n"
        " 259 0 nvme0n1 1 0 0 0 1 0 4096 0 0 0 0\n"
        "   7 0 loop0 1 0 77777 0 1 0 77777 0 0 0 0\n",
    )
    put(env, "/sys/class/thermal/thermal_zone0/temp", "54000\n")
    put(env, "/sys/class/thermal/thermal_zone1/temp", "41500\n")
    net(env, "eno1", 1000, 500, 100000, 50000, **netkw)
    net(env, "lo", 9, 9, 9, 9)


def test_first_report_has_null_rates_but_absolute_values(env):
    seed(env)
    m = HostMetrics(env.ctx).collect(60, {"eno1": "mgmt"})
    assert m["cpu"]["pct"] is None and m["cpu"]["iowait_pct"] is None and m["cpu"]["steal_pct"] is None
    assert m["cpu"]["load1"] == 0.8 and m["cpu"]["load15"] == 0.5
    assert m["disk_io"] == {"read_kbps": None, "write_kbps": None}
    n = m["net"][0]
    assert n["iface"] == "eno1" and n["role"] == "mgmt" and n["link"] == "up" and n["speed_mbps"] == 1000
    assert n["rx_pps"] is None and n["tx_bps"] is None and n["rx_errors"] is None
    assert [x["iface"] for x in m["net"]] == ["eno1"]  # lo skipped
    assert m["mem"]["total_mb"] == 32000 and m["mem"]["used_mb"] == 8000 and m["mem"]["pct"] == 25.0
    assert m["mem"]["swap_used_mb"] == 0
    assert m["uptime_s"] == 1234567.89 and m["temp_c_max"] == 54.0 and m["interval_s"] == 60
    assert m["disk"][0]["mount"] == "/" and m["disk"][0]["total_gb"] > 0
    exp_config.validate(
        {
            "schema": "exp.status/1",
            "agent": {"version": "0.1.0", "uptime_s": 1},
            "facts": {"hostname": "h", "arch": "amd64"},
            "metrics": m,
            "components": [],
        },
        "status.schema.json",
    )


def test_second_report_computes_deltas(env):
    seed(env)
    hm = HostMetrics(env.ctx)
    hm.collect(60)
    env.clock.sleep(10)
    seed(env, cpu=proc_stat(user=300, system=150, idle=1300, iowait=140, steal=10), rx_e=7, tx_d=3)
    put(env, "/sys/class/net/eno1/statistics/rx_packets", "2000\n")
    put(env, "/sys/class/net/eno1/statistics/tx_packets", "1500\n")
    put(env, "/sys/class/net/eno1/statistics/rx_bytes", "600000\n")
    put(env, "/sys/class/net/eno1/statistics/tx_bytes", "250000\n")
    put(
        env,
        "/proc/diskstats",
        "   8       0 sda 100 0 24576 0 100 0 4096 0 0 0 0\n 259 0 nvme0n1 1 0 0 0 1 0 8192 0 0 0 0\n",
    )
    m = hm.collect(60)
    cpu = m["cpu"]
    # deltas: user+200 system+100 idle+500 iowait+100 steal+10 softirq 0 -> total 910
    assert cpu["pct"] == round(100 * (910 - 500 - 100) / 910, 1)
    assert cpu["iowait_pct"] == round(100 * 100 / 910, 1) and cpu["steal_pct"] == round(100 * 10 / 910, 1)
    n = m["net"][0]
    assert (
        n["rx_pps"] == 100.0 and n["tx_pps"] == 100.0 and n["rx_bps"] == 400000.0 and n["tx_bps"] == 160000.0
    )
    assert n["rx_errors"] == 7 and n["tx_errors"] == 0 and n["tx_drops"] == 3 and n["rx_drops"] == 0
    assert m["disk_io"] == {"read_kbps": 1024.0, "write_kbps": 307.2}  # whole disks only, no partitions/loop


def test_counter_resets_yield_null_never_negative(env):
    seed(env, cpu=proc_stat(user=5000, idle=90000))
    hm = HostMetrics(env.ctx)
    hm.collect(60)
    env.clock.sleep(10)
    # "reboot": every counter restarts from small numbers
    seed(env, cpu=proc_stat(user=10, system=1, idle=20, iowait=0, softirq=0))
    put(env, "/proc/diskstats", "   8       0 sda 1 0 8 0 1 0 8 0 0 0 0\n")
    for k in ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes"):
        put(env, f"/sys/class/net/eno1/statistics/{k}", "3\n")
    m = hm.collect(60)
    assert m["cpu"]["pct"] is None and m["cpu"]["iowait_pct"] is None
    assert m["disk_io"] == {"read_kbps": None, "write_kbps": None}
    n = m["net"][0]
    assert n["rx_pps"] is None and n["tx_pps"] is None and n["rx_bps"] is None and n["tx_bps"] is None
    # the next interval after the reset is computed normally again
    env.clock.sleep(10)
    put(env, "/sys/class/net/eno1/statistics/rx_packets", "103\n")
    m2 = hm.collect(60)
    assert m2["net"][0]["rx_pps"] == 10.0
    for k, v in m2["net"][0].items():
        assert not (isinstance(v, (int, float)) and not isinstance(v, bool) and v < 0), k


def test_absent_sources_are_null_not_crashes(env):
    m = HostMetrics(env.ctx).collect(60)
    assert m["cpu"]["load1"] is None and m["temp_c_max"] is None and m["net"] == [] and m["uptime_s"] is None
    assert m["mem"]["pct"] == 0.0


def test_process_metrics_from_systemctl_show(env):
    hm = HostMetrics(env.ctx)
    put(env, "/proc/uptime", "5000.0 1.0\n")
    env.runner.show["exp-probe.service"] = {
        "CPUUsageNSec": "2000000000",
        "MemoryCurrent": "104857600",
        "NRestarts": "2",
        "ActiveEnterTimestampMonotonic": "1000000000",
    }
    env.runner.show["exp-probe-lease@c01.service"] = {
        "CPUUsageNSec": "1000000000",
        "MemoryCurrent": "1048576",
        "NRestarts": "1",
        "ActiveEnterTimestampMonotonic": "4000000000",
    }
    units = ["exp-probe.service", "exp-probe-lease@c01.service"]
    p1 = hm.process(units)
    assert (
        p1["cpu_pct"] is None and p1["rss_mb"] == 101.0 and p1["restarts"] == 3 and p1["uptime_s"] == 1000.0
    )
    env.clock.sleep(10)
    env.runner.show["exp-probe.service"]["CPUUsageNSec"] = "3000000000"  # +1 s over 10 s -> 10 %
    env.runner.show["exp-probe-lease@c01.service"]["CPUUsageNSec"] = "1500000000"  # +0.5 s -> 5 %
    assert hm.process(units)["cpu_pct"] == 15.0
    env.clock.sleep(10)
    env.runner.show["exp-probe.service"]["CPUUsageNSec"] = "100"  # unit restarted: counter reset
    p3 = hm.process(units)
    assert p3["cpu_pct"] is None
    env.runner.show["exp-probe.service"] = {
        "CPUUsageNSec": "[not set]",
        "MemoryCurrent": "[not set]",
        "NRestarts": "18446744073709551615",
        "ActiveState": "inactive",
    }
    p4 = hm.process(["exp-probe.service"])
    assert (
        p4["cpu_pct"] is None and p4["rss_mb"] is None and p4["restarts"] is None and p4["uptime_s"] is None
    )


# ---------------------------------------------------------------------------------------------- facts
IP_LINK = [
    {"ifname": "lo", "operstate": "UNKNOWN", "address": "00:00:00:00:00:00"},
    {"ifname": "eno1", "operstate": "UP", "address": "18:66:DA:00:11:22"},
    {"ifname": "enp10s0f0", "operstate": "DOWN", "address": "aa:bb:cc:dd:ee:01"},
    {"ifname": "enp130s1f0", "operstate": "UP", "address": "aa:bb:cc:dd:ee:02"},
    {"ifname": "bad;name", "operstate": "UP"},
]
IP_ADDR = [
    {
        "ifname": "eno1",
        "addr_info": [
            {"local": "10.32.98.25", "prefixlen": 23, "scope": "global"},
            {"local": "fe80::1", "prefixlen": 64, "scope": "link"},
        ],
    }
]
IP_ROUTE = [
    {"dst": "default", "gateway": "10.32.98.1", "dev": "eno1", "metric": 100},
    {"dst": "10.32.98.0/23", "dev": "eno1"},
]


def test_interfaces_facts_and_in_use_by_from_the_current_config(env):
    env.runner.ip = {"link": IP_LINK, "addr": IP_ADDR, "route": IP_ROUTE}
    put(env, "/sys/class/net/eno1/speed", "1000\n")
    os.makedirs(env.path("/sys/class/net/eno1/device"))
    os.symlink("tg3", env.path("/sys/class/net/eno1/device/driver"))
    put(
        env,
        "/etc/exp/probe/config.json",
        json.dumps(
            {
                "mgmt_iface": "eno1",
                "ports": [
                    {"id": "c01", "iface": "enp10s0f0", "role": "client"},
                    {"id": "s01", "iface": "enp130s1f0", "role": "target"},
                ],
            }
        ),
    )
    ifaces, default_if, roles = interface_facts(env.ctx)
    by = {i["name"]: i for i in ifaces}
    assert sorted(by) == ["eno1", "enp10s0f0", "enp130s1f0"] and default_if == "eno1"
    e = by["eno1"]
    assert (
        e["state"] == "up"
        and e["mac"] == "18:66:da:00:11:22"
        and e["speed_mbps"] == 1000
        and e["driver"] == "tg3"
    )
    assert e["addrs"] == ["10.32.98.25/23"] and e["default_route"] is True and e["in_use_by"] == "mgmt"
    assert by["enp10s0f0"]["in_use_by"] == "probe:c01" and by["enp10s0f0"]["state"] == "down"
    assert by["enp130s1f0"]["in_use_by"] == "probe:s01" and by["enp130s1f0"]["default_route"] is False
    assert roles == {"eno1": "mgmt", "enp10s0f0": "probe:c01", "enp130s1f0": "probe:s01"}
    assert [c for c in env.runner.calls if c[0] == "ip"] == [
        ["ip", "-j", "link", "show"],
        ["ip", "-j", "addr", "show"],
        ["ip", "-j", "route", "show"],
    ]


def test_a_probe_port_inside_its_netns_is_still_reported_as_an_interface_in_use(env):
    """Regression (found by the A3.3 e2e): once the probe runs, its test port lives in netns exp-<id> and vanished from the
    facts, so the manager refused every edit of the running probe's config with `unknown_interface`."""
    env.runner.ip = {"link": IP_LINK[:2], "addr": IP_ADDR, "route": IP_ROUTE}
    env.runner.netns = {
        "exp-c01": {
            "link": [
                {"ifname": "vp0", "operstate": "UP", "address": "aa:bb:cc:dd:ee:09"},
                {"ifname": "other", "operstate": "UP"},
            ],
            "addr": [
                {"ifname": "vp0", "addr_info": [{"local": "10.99.0.50", "prefixlen": 24, "scope": "global"}]}
            ],
        }
    }
    put(
        env,
        "/etc/exp/probe/config.json",
        json.dumps(
            {
                "mgmt_iface": "eno1",
                "ports": [
                    {"id": "c01", "iface": "vp0", "role": "client"},
                    {"id": "c02", "iface": "vp1", "role": "client"},
                ],
            }
        ),
    )
    ifaces, _default_if, roles = interface_facts(env.ctx)
    by = {i["name"]: i for i in ifaces}
    assert sorted(by) == ["eno1", "vp0"], (
        "vp0 (in exp-c01) is reported; vp1 (no such namespace) is not invented"
    )
    assert (
        by["vp0"]["in_use_by"] == "probe:c01"
        and by["vp0"]["state"] == "up"
        and by["vp0"]["default_route"] is False
    )
    assert by["vp0"]["mac"] == "aa:bb:cc:dd:ee:09" and by["vp0"]["addrs"] == ["10.99.0.50/24"]
    assert roles["vp0"] == "probe:c01"
    assert ["ip", "-n", "exp-c01", "-j", "link", "show"] in env.runner.calls
    # an interface that IS in the host namespace is never looked up in a namespace
    env.runner.calls.clear()
    env.runner.ip = {
        "link": IP_LINK[:2] + [{"ifname": "vp0", "operstate": "UP"}],
        "addr": [],
        "route": IP_ROUTE,
    }
    interface_facts(env.ctx)
    assert not [c for c in env.runner.calls if c[:3] == ["ip", "-n", "exp-c01"]]


def test_in_use_by_rules():
    assert in_use_by("eth0", None, {}, "eth0") == "mgmt"
    assert in_use_by("eth1", "eth0", {"eth1": "c01"}, "eth0") == "probe:c01"
    assert in_use_by("eth2", "eth0", {}, "eth0") == "none"
    assert (
        default_route_iface(
            [{"dst": "default", "dev": "b", "metric": 200}, {"dst": "default", "dev": "a", "metric": 5}]
        )
        == "a"
    )
    assert default_route_iface([]) is None


def test_collect_facts_validates_against_the_status_schema(env):
    env.runner.ip = {"link": IP_LINK, "addr": IP_ADDR, "route": IP_ROUTE}
    put(env, "/etc/os-release", 'ID=ubuntu\nVERSION_ID="24.04"\nNAME="Ubuntu"\n')
    put(env, "/etc/machine-id", "0123456789abcdef0123456789abcdef\n")
    put(env, "/proc/meminfo", "MemTotal:       32768000 kB\n")
    f = collect_facts(env.ctx)
    assert (
        f["os"] == {"id": "ubuntu", "version": "24.04"}
        and f["machine_id"].startswith("0123")
        and f["mem_mb"] == 32000
    )
    assert f["arch"] == "amd64" and f["time"]["synced"] is True and f["cpus"] >= 1 and f["disk_free_mb"] > 0
    exp_config.validate(
        {
            "schema": "exp.status/1",
            "agent": {"version": "0.1.0", "uptime_s": 1},
            "facts": f,
            "metrics": {},
            "components": [],
        },
        "status.schema.json",
    )
    env.runner.synced = "no"
    assert collect_facts(env.ctx)["time"]["synced"] is False
