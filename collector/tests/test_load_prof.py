"""Acceptance 8 (03-collector.md section 13): 50 probes x 20 records/s; p95 ingest < 100 ms, no backlog, CPU < 60%.

Opt-in (needs a quiet 4 vCPU box and, for the official run, 30 minutes):
    EXP_LOAD=1 EXP_LOAD_SECONDS=1800 pytest collector/tests/test_load.py -s
Without EXP_LOAD the test is skipped; EXP_LOAD_SECONDS defaults to 60 for a smoke run. The load generator is a
Python client in the same process tree, so its own CPU is excluded: only the collector's process CPU time
(time.process_time delta) is counted, as a fraction of wall time x online cores."""
from __future__ import annotations

import http.client
import json
import os
import threading
import time

import pytest
import synth
from colhelpers import Env, FakeVM, client_ctx, wait_for
from exp_common import ids

pytestmark = pytest.mark.skipif(os.environ.get("EXP_LOAD") != "1", reason="load test is opt-in (EXP_LOAD=1)")

PROBES, RATE = 50, 20


def test_50_probes_x_20_per_s(tmp_path):
    seconds = int(os.environ.get("EXP_LOAD_SECONDS", "60"))
    vm = FakeVM()
    env = Env(tmp_path, vm.url)
    tokens = {f"probe-l{i:02d}": ids.new_token("expi") for i in range(PROBES)}
    env.cfg_doc["probes"] = [{"probe_id": p, "site": "hall-b", "label": p} for p in tokens]
    env.write_creds({p: ids.token_hash(t) for p, t in tokens.items()}, {}, [])
    env.cfg_doc["alerts"]["enabled"] = False
    app = env.start()
    port = app.address[1]
    lat: list[float] = []
    series: list[tuple[float, float]] = []
    errors: list[str] = []
    lock = threading.Lock()
    stop_at = time.monotonic() + seconds

    def probe(pid: str, token: str) -> None:
        conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=client_ctx())
        nxt = time.monotonic() + (hash(pid) % 1000) / 1000
        while time.monotonic() < stop_at:
            now = int(time.time() * 1000)
            lines = [synth.mk("ping", now - k * 40, port=f"c{k % 4 + 1:02d}", metrics={"rtt_ms": 10.0},
                              probe=pid) for k in range(RATE)]
            body = ("\n".join(json.dumps(x) for x in lines) + "\n").encode()
            t0 = time.monotonic()
            try:
                conn.request("POST", "/ingest/v1/measurements", body=body, headers={
                    "Authorization": f"Bearer {token}", "Content-Type": "application/x-ndjson",
                    "User-Agent": "exp-probe/0.1.0"})
                r = conn.getresponse()
                r.read()
                ms = (time.monotonic() - t0) * 1000
                with lock:
                    lat.append(ms)
                    series.append((time.monotonic(), ms))
                    if r.status != 200:
                        errors.append(f"{pid}: {r.status}")
            except (OSError, http.client.HTTPException) as e:
                errors.append(f"{pid}: {e!r}")
                conn.close()
                conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=client_ctx())
            nxt += 1.0
            time.sleep(max(0.0, nxt - time.monotonic()))
        conn.close()

    import sys; sys.path.insert(0,'/tmp/claude-0'); import sample; top=[]; sample.start(time.monotonic()+150, top)
    cpu0, wall0 = time.process_time(), time.monotonic()
    ths = [threading.Thread(target=probe, args=a, daemon=True) for a in tokens.items()]
    for t in ths:
        t.start()
    for t in ths:
        t.join(seconds + 30)
    wall = time.monotonic() - wall0
    cpu_frac = (time.process_time() - cpu0) / wall / (os.cpu_count() or 1)   # includes the generator: an upper bound
    sent = len(lat) * RATE
    drained = bool(wait_for(lambda: vm.count() >= sent, timeout=60))
    for m in range(0, int(wall) // 60 + 1):                       # p95 per minute: shows drift, not just the total
        w = sorted(x for t, x in series if wall0 + m * 60 <= t < wall0 + (m + 1) * 60)
        if w:
            print(f"  minute {m:2d}: n={len(w)} p95={w[int(len(w) * 0.95) - 1]:.1f} ms")
    lat.sort()
    p95 = lat[int(len(lat) * 0.95) - 1]
    backlog = app.vm.backlog_points + app.vm.queue_points
    print(f"\nLOAD: {len(lat)} posts, {sent} records, p95={p95:.1f} ms, cpu={cpu_frac:.1%}, "
          f"backlog={backlog}, vm_lines={vm.count()}, errors={len(errors)}")
    print('TOP', *top, sep='\n')
    env.stop_all()
    vm.stop()
    assert not errors, errors[:5]
    assert p95 < 100
    assert drained and backlog == 0
    assert cpu_frac < 0.6
