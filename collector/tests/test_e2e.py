"""End to end, in process and as a real daemon: a probe posts measurements over the pinned TLS channel, the
state flips and an SSE `state` event arrives in < 2 s, an incident appears after the hold, records are
queryable; restart tests (A1.4): killing the collector mid-stream and replaying the spool stores nothing twice
and loses nothing."""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import synth
from colhelpers import Env, FakeVM, check_openapi, check_schema_file, https, ingest, wait_for
from exp_common import ids, tlspin
from test_engine_live import to_lines
from test_sse import Sse

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "collector" / "bin" / "exp-collector"


def iso(ms):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000)) + ".000Z"


def post(app, env, records):
    """POST as a real probe does: TLS verified by the pinned SHA-256 fingerprint of the collector's certificate
    (exp_common.tlspin), not by a CA. A wrong pin would raise before anything is sent."""
    fp = tlspin.fingerprint_of_pem_file(app.paths.tls_cert)
    host, port = app.address
    body = b"\n".join(json.dumps(r).encode() for r in records) + b"\n"
    resp = tlspin.request("POST", f"https://{host}:{port}/ingest/v1/measurements", fp, body=body, read_timeout=10,
                          headers={"Authorization": f"Bearer {env.ingest_token}",
                                   "Content-Type": "application/x-ndjson", "User-Agent": "exp-probe/0.1.0"})
    assert resp.status == 200, (resp.status, resp.body[:200])
    return resp.json()


def test_probe_to_dashboard_end_to_end(env, vm):
    env.cfg_doc["alerts"].update(hold_down_s=2, hold_back_s=2, enabled=False)       # short holds; nobody gets paged
    app = env.start(rules_wake=True)
    port = app.address[1]
    dash = {"Authorization": f"Bearer {env.dash_token}"}
    sse = Sse(port, env.dash_token, query="probes=probe-a1")
    assert sse.block() == "retry: 3000"
    assert wait_for(lambda: app.hub.client_count() == 1)

    # 1. a healthy probe: the state becomes ok
    now = int(time.time() * 1000)
    healthy = to_lines(synth.healthy(now - 120_000, now - 2_000, ports=2))
    assert post(app, env, healthy)["accepted"] == len(healthy)
    deadline = time.monotonic() + 5
    sev = None
    while time.monotonic() < deadline and sev != "ok":
        ev = sse.event()
        if ev["event"] == "state":
            sev = ev["json"]["severity"]
    assert sev == "ok"
    assert https(port, "GET", "/api/v1/state?probe=probe-a1", headers=dash).json()["verdict"]["severity"] == "ok"

    # 2. the gateway stops answering: the state flips to fail and the dashboard hears within 2 s
    t_post = time.monotonic()
    tn = int(time.time() * 1000)
    bad = to_lines([r for k in (24_000, 16_000, 8_000, 500) for r in synth.gateway(tn - k, ports=2, bad=2)])
    assert post(app, env, bad)["accepted"] == 8                  # four failing beats: half of the 30 s window
    fail_event = None
    sse.s.settimeout(0.5)
    while time.monotonic() - t_post < 4:
        try:
            ev = sse.event()
        except (TimeoutError, OSError):
            continue
        if ev["event"] == "state" and ev["json"]["severity"] == "fail":
            fail_event = ev
            break
    assert fail_event is not None, "no SSE state event within 4 s"
    latency = time.monotonic() - t_post
    assert latency < 2.0, f"state flip took {latency:.2f}s to reach the dashboard"
    st = fail_event["json"]
    assert st["probe"] == "probe-a1" and {ln["key"]: ln["state"] for ln in st["lines"]}["network"] == "fail"
    assert https(port, "GET", "/api/v1/state?probe=probe-a1", headers=dash).json()["verdict"]["severity"] == "fail"
    probes = {p["probe"]: p["state"] for p in https(port, "GET", "/api/v1/probes", headers=dash).json()["items"]}
    assert probes["probe-a1"] == "fail"

    # 3. keep failing: beats stream, and after the 2 s hold an incident opens (and is announced)
    deadline = time.monotonic() + 12
    incident = None
    kinds = set()
    while time.monotonic() < deadline and incident is None:
        post(app, env, to_lines(synth.gateway(int(time.time() * 1000) - 300, ports=2, bad=2)))
        sse.s.settimeout(1.2)
        try:
            while True:
                ev = sse.event()
                kinds.add(ev["event"])
                if ev["event"] == "incident":
                    incident = ev["json"]
                    break
        except (TimeoutError, OSError):
            continue
    assert incident is not None, f"no incident event; saw {kinds}"
    assert "beat" in kinds
    check_schema_file("incident.schema.json", incident)
    assert incident["line"] == "network" and incident["kind"] == "down" and incident["probe"] == "probe-a1"
    listed = https(port, "GET", "/api/v1/incidents?open=true&probe=probe-a1", headers=dash).json()
    check_openapi("collector", "/incidents", "get", 200, listed)
    assert any(i["id"] == incident["id"] for i in listed["items"])
    assert app.store.count_open_incidents() >= 1
    app.monitor.collect()
    assert app.monitor.metrics["open_incidents"] >= 1

    # 4. the records are queryable (API) and the series reached VM
    t0, t1 = iso(now - 130_000), iso(int(time.time() * 1000) + 5000)
    recs = https(port, "GET", f"/api/v1/records?probe=probe-a1&test=gateway&outcome=fail&from={t0}&to={t1}&limit=1000",
                 headers=dash).json()
    check_openapi("collector", "/records", "get", 200, recs)
    assert len(recs["items"]) >= 4 and all(r["outcome"] == "fail" for r in recs["items"])
    assert wait_for(lambda: vm.count("exp_gateway_rtt_ms") + vm.count("exp_gateway_loss_pct") > 0, 8)
    # 5. self telemetry (03 section 9) lands in VM too, and the health snapshot has every metric
    app.telemetry.emit_once()
    app.vm.flush_now()
    names = {"exp_collector_ingest_records_total", "exp_collector_ingest_bytes_total",
             "exp_collector_vm_backlog_points", "exp_collector_sse_clients", "exp_collector_rules_eval_ms"}
    assert wait_for(lambda: names <= set(vm.names()), 8), names - set(vm.names())
    sse.close()


# ---------------------------------------------------------------------- restart: the spool replayed (A1.4)
def spool(n, start_ms):
    """n distinct measurement records with their ids fixed, as a probe's spool would hold them."""
    return to_lines([synth.mk("ping", start_ms + i * 100, "ok", metrics={"rtt_ms": float(i % 50)}) for i in range(n)])


def stored_ids(port, env, t0, t1):
    out, cursor = [], None
    while True:
        q = f"probe=probe-a1&from={t0}&to={t1}&limit=1000" + (f"&cursor={cursor}" if cursor else "")
        d = https(port, "GET", "/api/v1/records?" + q, headers={"Authorization": f"Bearer {env.dash_token}"}).json()
        out += [r["id"] for r in d["items"]]
        cursor = d["next_cursor"]
        if not cursor:
            return out


def test_restart_in_process_replaying_the_spool_stores_nothing_twice(env, vm):
    now = int(time.time() * 1000)
    records = spool(300, now - 60_000)
    app1 = env.start()
    for i in range(0, 150, 50):
        assert ingest(app1.address[1], env.ingest_token, records[i:i + 50]).json()["accepted"] == 50
    env.stop_all()                                                   # the collector goes away mid-stream
    app2 = env.start()                                               # ... and comes back on the same state dir
    port = app2.address[1]
    totals = {"accepted": 0, "duplicates": 0}
    for i in range(100, 300, 50):                                    # the probe replays from the last batch it
        r = ingest(port, env.ingest_token, records[i:i + 50]).json()   # was sure about (100): at-least-once
        totals["accepted"] += r["accepted"]
        totals["duplicates"] += r["duplicates"]
    assert totals == {"accepted": 150, "duplicates": 50}             # 100..149 were already stored
    t0, t1 = iso(now - 120_000), iso(now + 60_000)
    got = stored_ids(port, env, t0, t1)
    assert sorted(got) == sorted(r["id"] for r in records) and len(got) == len(set(got)) == 300
    assert app2.store.count_records() == 300


# --------------------------------------------------------------------------------- the real daemon
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Daemon:
    def __init__(self, env: Env, vm: FakeVM, port: int):
        env.cfg_doc["listen"] = f"127.0.0.1:{port}"
        env.cfg_doc["vm"] = {"listen": f"127.0.0.1:{vm.port}", "memory_allowed_pct": 40}
        env.cfg_doc["alerts"]["enabled"] = False
        self.cfg = env.tmp / "collector.json"
        self.cfg.write_text(json.dumps(env.cfg_doc))
        self.env, self.port = env, port
        self.argv = [sys.executable, str(BIN), "run", "--config", str(self.cfg), "--state-dir", str(env.state),
                     "--run-dir", str(env.run), "--creds-dir", str(env.creds)]
        self.proc: subprocess.Popen | None = None

    def start(self):
        self.proc = subprocess.Popen(self.argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        up = wait_for(lambda: self._up(), 20)
        assert up, f"daemon did not come up: {self.proc.poll()} {self._err()}"

    def _err(self):
        if self.proc and self.proc.poll() is not None:
            return self.proc.stderr.read()[-2000:]
        return ""

    def _up(self):
        if self.proc.poll() is not None:
            return False
        try:
            return https(self.port, "GET", "/healthz", timeout=2).status == 200
        except OSError:
            return False

    def kill(self):
        self.proc.send_signal(signal.SIGKILL)
        self.proc.wait(10)

    def term(self):
        self.proc.send_signal(signal.SIGTERM)
        return self.proc.wait(20)


def test_kill_9_and_restart_the_daemon_mid_stream_loses_nothing_and_stores_nothing_twice(env, vm):
    now = int(time.time() * 1000)
    records = spool(400, now - 60_000)
    d = Daemon(env, vm, free_port())
    d.start()
    try:
        sent = 0
        for i in range(0, 400, 50):
            r = ingest(d.port, env.ingest_token, records[i:i + 50])
            assert r.status == 200 and r.json()["accepted"] == 50
            sent = i + 50
            if sent == 200:
                break
        d.kill()                                                    # SIGKILL: no shutdown handling at all
        d.start()
        replay_from = 150                                           # the probe never saw the ack of the last batches
        acc = dup = 0
        for i in range(replay_from, 400, 50):
            r = ingest(d.port, env.ingest_token, records[i:i + 50]).json()
            acc, dup = acc + r["accepted"], dup + r["duplicates"]
        assert (acc, dup) == (200, 50)                              # 150..199 were durable before the kill
        t0, t1 = iso(now - 120_000), iso(now + 60_000)
        got = stored_ids(d.port, env, t0, t1)
        assert sorted(got) == sorted(r["id"] for r in records) and len(set(got)) == 400
        h = subprocess.run([sys.executable, str(BIN), "health", "--json", "--config", str(d.cfg), "--state-dir",
                            str(env.state), "--run-dir", str(env.run), "--creds-dir", str(env.creds)],
                           capture_output=True, text=True, timeout=30)
        assert json.loads(h.stdout)["schema"] == "exp.health/1"
    finally:
        if d.proc and d.proc.poll() is None:
            d.proc.kill()


def test_sigterm_drains_and_exits_zero_and_sighup_reloads_credentials(env, vm):
    d = Daemon(env, vm, free_port())
    d.start()
    try:
        auth = {"Authorization": f"Bearer {env.dash_token}"}
        assert https(d.port, "GET", "/api/v1/health", headers=auth).status == 200
        new_dash = ids.new_token("expd")
        env.write_creds({"probe-a1": ids.token_hash(env.ingest_token)}, {"dash-main": ids.token_hash(new_dash)}, [])
        d.proc.send_signal(signal.SIGHUP)                           # reload now, not within the 5 s poll
        assert wait_for(lambda: https(d.port, "GET", "/api/v1/health",
                                      headers={"Authorization": f"Bearer {new_dash}"}).status == 200, 4)
        assert https(d.port, "GET", "/api/v1/health", headers=auth).status == 401
        recs = to_lines([synth.mk("ping", int(time.time() * 1000) - i, "ok", metrics={"rtt_ms": 1.0}) for i in range(20)])
        assert ingest(d.port, env.ingest_token, recs).json()["accepted"] == 20
        sse = Sse(d.port, new_dash)
        sse.block()
        assert d.term() == 0                                        # graceful: queues drained, exit 0
        assert not (env.run / "health.json").exists()
    finally:
        if d.proc and d.proc.poll() is None:
            d.proc.kill()
    # everything accepted before SIGTERM is in SQLite, and the VM points either reached VM or sit in the backlog
    from exp_collector.store import Store
    st = Store(env.state / "records.db").open()
    try:
        assert st.count_records() == 20
        assert vm.count() + st.backlog_points() >= 20
    finally:
        st.close()


def test_a_second_collector_answers_the_same_with_state_surviving_a_restart(env, vm):
    """Open incidents survive a restart: no second page, the same incident id is still the open one."""
    env.cfg_doc["alerts"].update(hold_down_s=0, enabled=False)
    app = env.start(rules_wake=True)
    port = app.address[1]
    for _ in range(40):
        ingest(port, env.ingest_token, to_lines(synth.gateway(int(time.time() * 1000) - 200, ports=2, bad=2)))
        if app.store.count_open_incidents():
            break
        time.sleep(0.3)
    first = app.store.list_incidents(open_only=True)
    assert first
    env.stop_all()
    app2 = env.start(rules_wake=True)
    ingest(app2.address[1], env.ingest_token, to_lines(synth.gateway(int(time.time() * 1000) - 200, ports=2, bad=2)))
    time.sleep(1.5)
    again = app2.store.list_incidents(open_only=True)
    assert sorted(i["id"] for i in again) == sorted(i["id"] for i in first)
    assert os.path.exists(env.state / "records.db")
