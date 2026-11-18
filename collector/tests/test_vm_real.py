"""Optional: the writer against a REAL VictoriaMetrics (docker image pinned in the build). Skipped when
docker or the image is unavailable. Proves acceptance 3 end to end: VM stopped -> ingest still accepted ->
VM started -> every sample present in VM (export), none missing, none duplicated."""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
import urllib.request

import pytest
from colhelpers import ingest, iso, rec, wait_for
from exp_common import schema

IMAGE = "victoriametrics/victoria-metrics:v1.106.1"
pytestmark = pytest.mark.harness


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


needs_docker = pytest.mark.skipif(not _docker_ok(), reason="docker / VictoriaMetrics image not available")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def export(port: int) -> list[dict]:
    url = f"http://127.0.0.1:{port}/api/v1/export?match[]=%7B__name__%3D~%22exp_.*%22%7D"
    with urllib.request.urlopen(url, timeout=10) as r:  # noqa: S310 - loopback
        return [json.loads(ln) for ln in r.read().decode().splitlines() if ln]


@needs_docker
def test_real_victoriametrics_outage_and_recovery(env):
    port = free_port()
    name = f"exp-vm-test-{port}"
    subprocess.run(["docker", "run", "-d", "--name", name, "-p", f"127.0.0.1:{port}:8428", IMAGE,
                    "-retentionPeriod=1d", "-search.latencyOffset=1s"], check=True, capture_output=True, timeout=120)
    try:
        assert wait_for(lambda: _http_ok(port), 30)
        env.vm_url = f"http://127.0.0.1:{port}"
        app = env.start()
        now = time.time()
        sent: list[tuple[float, int]] = []

        def push(n: int, base: int) -> None:
            batch = []
            for i in range(n):
                ts = iso(now - 600 + (base + i))
                r = rec(test="dns", ts=ts, metrics={"rtt_ms": float(base + i)}, labels={"port": f"c{i % 3}"})
                batch.append(r)
                sent.append((float(base + i), schema.iso_to_ms(ts)))
            resp = ingest(app.address[1], env.ingest_token, batch)
            assert resp.status == 200 and resp.json()["accepted"] == n

        push(40, 0)
        assert wait_for(lambda: sum(len(s["values"]) for s in export(port)) == 40, 30)
        subprocess.run(["docker", "stop", name], check=True, capture_output=True, timeout=60)
        push(30, 100)                                      # VM is DOWN: still accepted
        time.sleep(2.5)
        assert app.store.count_records() == 70 and app.vm.backlog_points > 0 and not app.vm.up
        subprocess.run(["docker", "start", name], check=True, capture_output=True, timeout=60)
        assert wait_for(lambda: app.vm.up and app.vm.backlog_points == 0, 60)

        def all_there() -> bool:
            try:
                pts = {(v, t) for s in export(port) for v, t in zip(s["values"], s["timestamps"], strict=True)}
            except OSError:
                return False
            return pts == set(sent)
        assert wait_for(all_there, 60)
        total = sum(len(s["values"]) for s in export(port))
        assert total == 70                                  # no gaps, no duplicates
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=60)


def _http_ok(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as r:  # noqa: S310
            return r.status == 200
    except OSError:
        return False
