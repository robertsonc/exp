"""The live engine: ingest observer -> ring buffers -> 2 s ticks -> cached State; time travel from SQLite;
incident persistence across a restart; CLI `rules eval` and `replay`; performance of one tick."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import synth
from colhelpers import check_schema_file, https, ingest, rec, wait_for
from exp_common import schema as exp_schema

from exp_collector.engine import RulesEngine, evaluate_from_store, state_doc
from exp_collector.rules import HISTORY_MS, Rec

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "collector" / "bin" / "exp-collector"
NOW = int(time.time() * 1000)


def to_lines(dicts, probe="probe-a1", site="hall-b"):
    """Re-stamp synthetic dicts for the ingest API (valid ULID ids, identity, current timestamps)."""
    out = []
    for d in dicts:
        d = dict(d)
        d["probe"], d["site"] = probe, site
        out.append(d)
    return out


def scenario_records(now_ms: int, probe="probe-a1", site="hall-b"):
    """Healthy for 3 minutes, then the gateway fails for the last 60 s (ends at now)."""
    t0 = now_ms - 240_000
    recs = synth.healthy(t0, now_ms - 60_000, ports=2)
    for t in range(now_ms - 60_000, now_ms - 1_000, 10_000):
        recs += synth.gateway(t, ports=2, bad=2)
        recs.append(synth.wifi(t + 600, gw=False, ok=False))
    return to_lines(recs, probe, site)


def test_ingested_records_reach_the_live_state_within_one_tick(env, app, port):
    lines = scenario_records(int(time.time() * 1000))
    r = ingest(port, env.ingest_token, lines)
    assert r.status == 200 and r.json()["accepted"] == len(lines), r.json()["rejected"][:3]
    app.rules.tick()                                   # the 2 s loop, on demand
    doc = app.rules.state("probe-a1")
    check_schema_file("state.schema.json", doc)
    assert doc["live"] is True and doc["probe"] == "probe-a1" and doc["site"] == "hall-b"
    assert doc["verdict"]["severity"] == "fail" and doc["verdict"]["where"]["seg"] in ("lan", "gateway", "switch")
    assert doc["newest_s"] is not None and doc["newest_s"] < 10
    net = doc["lines"][0]
    assert net["key"] == "network" and net["state"] == "fail" and net["detail"].startswith("10.1.0.1 not answering")
    # the probe list shows the real state
    probes = https(port, "GET", "/api/v1/probes", headers={"Authorization": f"Bearer {env.dash_token}"}).json()
    states = {p["probe"]: p["state"] for p in probes["items"]}
    assert states["probe-a1"] == "fail" and states["probe-a2"] == "unknown"
    assert app.rules.severity("probe-c1") == "unknown" and app.rules.state("nobody") is None


def test_live_state_equals_time_travel_for_the_same_moment(env, app, port):
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    app.rules.tick(now)
    live = app.rules.state("probe-a1", None, "plain")
    travel = app.rules.state("probe-a1", now, "plain")                  # same instant, evaluated from SQLite
    live = json.loads(json.dumps(live))
    travel = json.loads(json.dumps(travel))
    assert travel["live"] is False and live["live"] is True
    live.pop("live"), travel.pop("live")
    assert live == travel                                                # same records -> same output


def test_time_travel_is_independent_of_what_arrived_later(env, app, port):
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    before = app.rules.state("probe-a1", now - 120_000, "sysadmin")      # all green back then
    assert before["verdict"]["severity"] in ("ok", "unknown") and before["verdict"]["where"] is None
    again = app.rules.state("probe-a1", now - 120_000, "sysadmin")
    assert before == again
    later = to_lines([synth.gateway(now + 1000, ports=2, bad=2)[0]])
    ingest(port, env.ingest_token, later)
    assert app.rules.state("probe-a1", now - 120_000, "sysadmin") == before
    assert app.rules.states(site="hall-b", at_ms=now - 120_000)[0]["probe"] == "probe-a1"
    assert [s["probe"] for s in app.rules.states(site="hall-c")] == ["probe-c1"]


def test_beats_document_and_markers_from_sqlite(env, app, port):
    now = int(time.time() * 1000)
    extra = [synth.mk("drill", now - 100_000, labels={"run": "run_01", "phase": "start", "type": "port_down"},
                      metrics={"ok": 1}),
             synth.mk("ext_mist", now - 90_000, labels={"kind": "ap_offline", "severity": "major"}, metrics={"count": 1})]
    ingest(port, env.ingest_token, scenario_records(now) + to_lines(extra))
    app.rules.tick(now)
    doc = app.rules.beats("probe-a1", now - 200_000, now)
    check_schema_file("beats.schema.json", doc)
    assert doc["lines"]["network"] and doc["lines"]["network"][-1][1] == 2
    kinds = {m["kind"] for m in doc["markers"]}
    assert {"drill", "ext"} <= kinds
    assert any("port_down" in m["text"] for m in doc["markers"] if m["kind"] == "drill")
    assert app.rules.beats("nobody", 0, 1) is None


def test_incident_is_recorded_and_survives_a_restart(env, vm):
    from colhelpers import Env  # noqa: F401
    app1 = env.start()
    port = app1.address[1]
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    for dt in (-40_000, -30_000, -20_000, -10_000):                     # failing since -50 s: 20 s hold passed at -20 s
        app1.rules.tick(now + dt)
    rows = app1.store.list_incidents(probe="probe-a1", open_only=True)
    by = {r["line"]: r for r in rows}
    assert set(by) == {"network", "wifi"} and by["network"]["kind"] == "down" and by["network"]["site"] == "hall-b"
    assert by["network"]["folded_into"] is None and by["wifi"]["folded_into"] == by["network"]["id"]   # wifi: a consequence
    saved = app1.store.get_meta("incidents:probe-a1")
    assert saved and json.loads(saved)["inc"]["network"]["phase"] == "open"
    env.stop_all()
    app2 = env.start()                                                  # same state dir: same SQLite file
    app2.rules.tick(now - 5_000)
    assert sorted((r["line"], r["kind"]) for r in app2.store.list_incidents(probe="probe-a1")) == \
        [("network", "down"), ("wifi", "down")]                                              # nothing new recorded
    assert "network" in app2.rules._incidents["probe-a1"].inc and \
        app2.rules._incidents["probe-a1"].inc["network"]["phase"] == "open"


def test_listeners_get_state_changes_and_beats(env, app, port):
    events: list[tuple[str, dict]] = []
    app.rules.subscribe(lambda k, p: events.append((k, p)))
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    app.rules.tick(now)
    kinds = {k for k, _ in events}
    assert {"state", "beat"} <= kinds
    state = next(p for k, p in events if k == "state" and p["probe"] == "probe-a1")
    assert state["severity"] == "fail" and {"key", "state"} <= set(state["lines"][0])
    n = len(events)
    app.rules.tick(now + 1)                                             # nothing changed: nothing re-announced
    assert [k for k, _ in events[n:]] == []
    app.rules.subscribe(lambda k, p: 1 / 0)                             # a failing listener never breaks the engine
    app.rules.tick(now + 2)


def test_the_loop_runs_by_itself_and_reports_eval_time(env, vm):
    app = env.start()
    assert wait_for(lambda: app.rules.last_tick is not None, 8)
    assert app.rules.eval_ms >= 0 and app.rules_eval_ms() == app.rules.eval_ms


def test_engine_warms_its_buffers_from_sqlite_after_a_restart(env, vm):
    app = env.start()
    now = int(time.time() * 1000)
    ingest(app.address[1], env.ingest_token, scenario_records(now))
    env.stop_all()
    app2 = env.start()
    doc = app2.rules.state("probe-a1")                                  # before any new record arrived
    assert doc["verdict"]["severity"] == "fail"


def test_a_tick_for_many_probes_is_fast(tmp_path):
    """50 probes, one hour of history each: one evaluation pass must be far below the 2 s tick."""
    from exp_collector.config import CollectorConfig, ProbeEntry
    from exp_collector.rules import BeatStore
    from exp_collector.store import Store
    store = Store(tmp_path / "r.db").open()
    try:
        probes = {f"p{i:02d}": ProbeEntry(f"p{i:02d}", "hall-b", "") for i in range(50)}
        cfg = CollectorConfig.from_dict({
            "schema": "exp.collector.config/1", "collector_id": "col-x", "site": "hall-b", "listen": "127.0.0.1:8443",
            "probes": [{"probe_id": p, "site": "hall-b"} for p in probes], "dashboards": []})
        eng = RulesEngine(cfg, store)
        now = NOW
        base = [Rec.from_dict(d) for d in synth.healthy(now - 3_600_000, now, ports=12)]
        for pid in probes:
            b = BeatStore()
            b.extend(base)
            eng._buffers[pid] = b
        eng.tick(now)                                                    # warm-up (builds the merged lines)
        t0 = time.perf_counter()
        eng.tick(now + 2_000)
        dt = time.perf_counter() - t0
        assert dt < 1.5, f"one tick over 50 probes took {dt:.2f}s"
        assert eng.eval_ms > 0
        assert len(eng.states()) == 50
    finally:
        store.close()


# --------------------------------------------------------------------------------------------- the CLI
def cli(*args, cwd=None):
    return subprocess.run([sys.executable, str(BIN), *args], capture_output=True, text=True, timeout=120, cwd=cwd)


def test_cli_rules_eval_prints_the_state(env, vm):
    app = env.start()
    now = int(time.time() * 1000)
    ingest(app.address[1], env.ingest_token, scenario_records(now))
    cfg_path = env.tmp / "collector.json"
    cfg_path.write_text(json.dumps(env.cfg_doc))
    env.stop_all()
    at = exp_schema_iso(now)
    common = ["--config", str(cfg_path), "--state-dir", str(env.state), "--run-dir", str(env.run),
              "--creds-dir", str(env.creds)]
    r = cli("rules", "eval", "--probe", "probe-a1", "--at", at, "--voice", "plain", *common)
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    check_schema_file("state.schema.json", doc)
    assert doc["verdict"]["voice"] == "plain" and doc["verdict"]["severity"] == "fail" and doc["live"] is False
    r2 = cli("rules", "eval", "--probe", "probe-a1", "--at", at, *common)
    assert json.loads(r2.stdout)["verdict"]["voice"] == "sysadmin"
    # same records, same output
    assert cli("rules", "eval", "--probe", "probe-a1", "--at", at, "--voice", "plain", *common).stdout == r.stdout
    bad = cli("rules", "eval", "--probe", "nobody", "--at", at, *common)
    assert bad.returncode == 2 and "not in the config" in bad.stderr and bad.stdout == ""
    bad = cli("rules", "eval", "--probe", "probe-a1", "--at", "yesterday", *common)
    assert bad.returncode == 2 and "ISO-8601" in bad.stderr
    bad = cli("rules", "eval", "--probe", "probe-a1", "--config", str(env.tmp / "nope.json"))
    assert bad.returncode != 0


def exp_schema_iso(ms: int) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ms / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def test_cli_replay_prints_states_and_the_messages_it_would_post():
    fx = ROOT / "test" / "fixtures" / "exm" / "outage-2026-10-27.ndjson.gz"
    r = cli("replay", str(fx), "--at", "2026-10-27T03:10:00Z", "--at", "2026-10-27T03:57:30Z", "--voice", "plain")
    assert r.returncode == 0, r.stderr
    docs = [json.loads(x) for x in _split_json(r.stdout)]
    assert [d["verdict"]["where"]["seg"] for d in docs] == ["gateway", "ssid"]
    assert docs[0]["probe"] == "t430-srv-02" and docs[0]["site"] == "lab"
    r = cli("replay", str(fx), "--alerts", "--from", "2026-10-27T02:55:00Z", "--to", "2026-10-27T04:28:00Z",
            "--tz", "America/Chicago", "--board-url", "https://10.32.98.25")
    assert r.returncode == 0, r.stderr
    heads = [ln for ln in r.stdout.splitlines() if ln.startswith("[2026")]
    assert [h.split("] ")[1].split(":")[0] for h in heads] == [
        "down Network", "resolved Network", "down DNS", "resolved DNS", "down Wi-Fi", "down DNS", "resolved DNS",
        "down DNS", "resolved DNS"]
    assert "9 messages" in r.stderr
    slack = cli("replay", str(fx), "--alerts", "--from", "2026-10-27T02:55:00Z", "--to", "2026-10-27T03:05:00Z",
                "--format", "slack", "--board-url", "https://10.32.98.25")
    assert json.loads(_split_json(slack.stdout)[0])["text"].startswith(":red_circle: *The network is down*")
    assert cli("replay", "/nonexistent.ndjson").returncode == 1
    assert cli("replay", str(fx), "--at", "tomorrow").returncode == 2


def _split_json(text: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in text:
        cur.append(ch)
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                out.append("".join(cur).strip())
                cur = []
    return out


def test_evaluate_from_store_reads_only_the_history_window(env, app, port):
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    ev = evaluate_from_store(app.store, "probe-a1", "hall-b", now)
    assert ev.newest is not None and ev.states["network"] == "fail"
    ev_old = evaluate_from_store(app.store, "probe-a1", "hall-b", now - HISTORY_MS - 600_000)
    assert ev_old.newest is None and set(ev_old.states.values()) == {"unknown"}
    assert state_doc(ev_old, tz="UTC")["verdict"]["severity"] == "unknown"
    assert exp_schema.iso_to_ms(state_doc(ev, tz="UTC")["at"]) == now
    assert rec  # (imported helper kept for symmetry with other tests)


def test_health_metrics_report_open_incidents_webhook_failures_and_eval_time(env, app, port):
    now = int(time.time() * 1000)
    ingest(port, env.ingest_token, scenario_records(now))
    for dt in (-40_000, -30_000, -20_000, -10_000):
        app.rules.tick(now + dt)
    m = app.monitor.collect()
    assert m["open_incidents"] == 1 and m["webhook_failures_1h"] == 0 and m["rules_eval_ms_p95"] > 0
    app.webhooks._note_failure()
    assert app.monitor.collect()["webhook_failures_1h"] == 1


def test_concurrent_ingest_ticks_and_reads_do_not_corrupt_the_buffers(env, app):
    import threading
    now = int(time.time() * 1000)
    errors: list[BaseException] = []
    stop = threading.Event()

    def feeder():
        try:
            for i in range(120):
                t = now - 120_000 + i * 1000
                batch = synth.gateway(t, ports=2, bad=2 if i % 7 == 0 else 0) + [synth.wifi(t + 5)]
                app.rules.observe([exp_schema.Measurement.from_dict(d, require_id=True) for d in batch])
                if i % 20 == 0:                                      # out-of-order backfill
                    app.rules.observe([exp_schema.Measurement.from_dict(d, require_id=True)
                                       for d in synth.gateway(t - 500, ports=2)])
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def reader():
        try:
            while not stop.is_set():
                app.rules.tick(now)
                for v in ("plain", "sysadmin"):
                    assert app.rules.state("probe-a1", None, v)["schema"] == "exp.state/1"
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=feeder), threading.Thread(target=reader), threading.Thread(target=reader)]
    for th in threads:
        th.start()
    threads[0].join(30)
    stop.set()
    for th in threads[1:]:
        th.join(30)
    assert errors == []
    doc = app.rules.state("probe-a1")
    assert doc["lines"][0]["key"] == "network" and doc["newest_s"] is not None
