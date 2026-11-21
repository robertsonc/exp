"""A6.2: the INSTALLED exp-speedtest serves >= 2 Gb/s aggregate download on this 4-core host with <= 1 core per Gb/s, and its
byte counters agree with what the clients received within 5 % (12-speedtest-analytics.md section 11).

The load generator (bench_client.py) runs inside the core box against the box's own listen address; the server's CPU comes
from /proc/<MainPID>/stat of the systemd unit. A second, routed measurement from an attendee namespace (veth + bridge + the
gateway, no NAT) is reported for reference (its figure is bounded by the harness' virtual links and the client, not asserted
against the 2 Gb/s line). Numbers go to <artifacts>/a62-bench.json."""
from __future__ import annotations

import json
import time

import pytest

import m6lib as M

pytestmark = pytest.mark.e2e
TICKS = 100
STREAMS, SECONDS, CHUNK = 4, 6.0, 25_000_000


def _cpu_s(core: M.Core, pid: int) -> float:
    f = core.col.ok(f"cat /proc/{pid}/stat").rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / TICKS


def _counter(core: M.Core) -> int:
    time.sleep(2.3)                                 # status.json refreshes every 2 s
    return int(core.st_status()["counters"]["local_bytes_total"])


def test_a62_installed_box_sustains_2gbps(core: M.Core, artifacts):
    def relax(cfg):
        cfg["limits"].update({"tests_per_10min_per_ip": 1000, "max_concurrent_per_ip": 100, "max_concurrent_tests": 100,
                              "bytes_local": 10_000_000_000, "leg_token_ttl_s": 300})
    core.reconfigure("speedtest", relax)
    try:
        core.col.put(M.BENCH_PY, "/root/bench_client.py")
        pid = int(core.col.ok("systemctl show -p MainPID --value exp-speedtest.service").strip())
        assert pid > 1
        cores = int(core.col.ok("nproc").strip())
        # warm-up (page cache, connections), then the measured run
        core.col.ok(f"python3 /root/bench_client.py {M.CORE_IP} 80 {STREAMS} 1.5 {CHUNK}", timeout=60)
        c0, cpu0 = _counter(core), _cpu_s(core, pid)
        t0 = time.monotonic()
        out = json.loads(core.col.ok(f"python3 /root/bench_client.py {M.CORE_IP} 80 {STREAMS} {SECONDS} {CHUNK}", timeout=120).strip().splitlines()[-1])
        wall = time.monotonic() - t0
        cpu1 = _cpu_s(core, pid)
        c1 = _counter(core)
        server_bytes, cpu_s = c1 - c0, cpu1 - cpu0
        gbps = out["bytes"] * 8 / out["seconds"] / 1e9
        cores_used = cpu_s / out["seconds"]
        agree = abs(server_bytes - out["bytes"]) / max(1, out["bytes"])
        # reference: the same download from an attendee device through the routed path (one stream per core, python client)
        phone = core.new_client("bench")
        routed = phone.run("python3", "-I", "-c", (M.BENCH_PY.read_text()), M.CORE_IP, "80", "2", "4", str(CHUNK // 2), timeout=60)
        routed_gbps = json.loads(routed.stdout.strip().splitlines()[-1])["gbps"] if routed.returncode == 0 and routed.stdout.strip() else None
        report = {"streams": STREAMS, "seconds": out["seconds"], "client_bytes": out["bytes"], "server_counter_bytes": server_bytes,
                  "aggregate_gbps": round(gbps, 2), "server_cpu_s": round(cpu_s, 2), "server_cores_used": round(cores_used, 2),
                  "cores_per_gbps": round(cores_used / gbps, 2), "counter_disagreement_pct": round(agree * 100, 2),
                  "host_cores": cores, "errors": out["errors"], "wall_s": round(wall, 1), "routed_client_gbps": routed_gbps}
        (artifacts / "a62-bench.json").write_text(json.dumps(report, indent=1))
        print("A6.2 bench:", json.dumps(report))
        assert out["errors"] == 0, report
        assert gbps >= 2.0, report
        assert cores_used / gbps <= 1.0, report
        assert agree <= 0.05, report
        if routed_gbps is not None:
            assert routed_gbps > 0.2, report
    finally:
        core.reset_config("speedtest")
