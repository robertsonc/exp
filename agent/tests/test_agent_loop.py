"""The main loop: 304 hot path, heartbeat, manager down, 401 pause, retry, fast polling, status contents."""

from __future__ import annotations

import json

import pytest
from agent_helpers import Env, tokens_in
from exp_common import config as exp_config
from exp_common import ids as exp_ids

from exp_agent import loop as loop_mod
from exp_agent.client import ManagerClient
from exp_agent.errors import ManagerUnreachable
from exp_agent.loop import Agent
from exp_agent.runner import Result


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.standard_release(comps=("collector", "probe"), creds={"probe": ("ingest_token",)})
    yield e
    e.close()


def reports(env: Env) -> list[dict]:
    return env.app.hosts[env.host_id].reports


def publish(env: Env, comps=None) -> None:
    env.push(env.desired(comps if comps is not None else [env.comp("collector"), env.comp("probe")]))


def test_first_tick_converges_reports_and_enters_fast_mode(env):
    publish(env)
    agent = Agent(env.ctx)
    agent.startup()
    delay = agent.tick()
    st = env.ctx.state.data
    assert st["applied_version"] == 1 and st["etag"] == f'"{env.host_id}:1"'
    assert len(reports(env)) == 1
    rep = reports(env)[0]
    exp_config.validate(rep, "status.schema.json")
    assert rep["reconcile"]["result"] == "ok" and rep["agent"]["applied_version"] == 1
    assert sorted(c["type"] for c in rep["components"]) == ["collector", "probe"]
    col = next(c for c in rep["components"] if c["type"] == "collector")
    assert col["health"] == "ok" and col["state"] == "running" and col["process"]["rss_mb"] == 50.0
    assert any("installed exp-collector" in e["msg"] for e in rep["events"])
    assert 5 * 0.8 <= delay <= 5 * 1.2  # fast poll for 2 minutes after applying a change
    assert agent.poll_s == 30


def test_304_is_the_hot_path_and_heartbeat_follows_status_interval(env):
    publish(env)
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    n_calls, n_reports = len(env.runner.calls), len(reports(env))
    reconciles = []
    real = agent.reconciler.run
    agent.reconciler.run = lambda doc: reconciles.append(1) or real(doc)
    env.clock.sleep(5)
    d = agent.tick()
    assert reconciles == [] and len(reports(env)) == n_reports  # 304, no heartbeat yet
    assert not [c for c in env.runner.calls[n_calls:] if c[0] == "systemctl" and c[1] != "show"]
    assert 4 <= d <= 6  # still inside the 2-minute fast window
    env.clock.sleep(125)
    d = agent.tick()
    assert 24 <= d <= 36  # back to 30 s +/- 20 %
    assert len(reports(env)) == n_reports + 1  # heartbeat after >= 60 s
    assert reports(env)[-1]["reconcile"]["result"] == "ok"
    env.clock.sleep(30)
    agent.tick()
    assert len(reports(env)) == n_reports + 1  # 30 s < status_interval_s
    assert reconciles == []


def test_new_desired_version_reconciles_again_and_reports_immediately(env):
    publish(env, [env.comp("collector")])
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    publish(env, [env.comp("collector"), env.comp("probe")])
    env.clock.sleep(5)
    agent.tick()
    assert env.ctx.state.data["applied_version"] == 2 and len(reports(env)) == 2
    assert "probe" in {c["type"] for c in reports(env)[-1]["components"]}


def test_manager_down_keeps_the_applied_state_and_backs_off(env):
    publish(env)
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    before = {c: dict(r) for c, r in env.ctx.state.data["components"].items()}
    n = len(env.runner.calls)
    env.app.set_force(unreachable=True)
    delays = []
    for _ in range(7):
        delays.append(agent.tick())
        env.clock.sleep(delays[-1])
    assert delays == [30, 60, 120, 240, 300, 300, 300]
    assert env.ctx.state.data["components"] == before and env.ctx.state.data["applied_version"] == 1
    assert not [
        c for c in env.runner.calls[n:] if c[0] == "systemctl" and c[1] in ("stop", "disable", "restart")
    ]
    assert sum(1 for e in env.ctx.state.pending_events() if "unreachable" in e["msg"]) == 1  # logged once
    env.app.set_force()  # manager comes back
    publish(env, [env.comp("collector")])
    d = agent.tick()
    assert env.ctx.state.data["applied_version"] == 2 and 4 <= d <= 6
    assert agent.backoff.next() == 30  # reset


def test_503_from_the_manager_counts_as_unreachable_and_honours_retry_after(env):
    publish(env)
    agent = Agent(env.ctx)
    env.app.set_force(503, count=1, retry_after=90)
    assert agent.tick() == 90


def test_401_pauses_five_minutes_logs_once_and_never_uninstalls(env):
    publish(env)
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    n_calls = len(env.runner.calls)
    env.client.set_secret(exp_ids.new_token("expa"))
    requests0 = env.app.requests
    assert agent.tick() == 300
    assert env.app.requests == requests0 + 1
    env.clock.sleep(100)
    assert agent.tick() == pytest.approx(200)  # paused: no request at all
    assert env.app.requests == requests0 + 1
    env.clock.sleep(200)
    assert agent.tick() == 300  # pause over: one more try, 401 again
    assert env.app.requests == requests0 + 2
    assert sum(1 for e in env.ctx.state.pending_events() if "401" in e["msg"]) == 1
    assert not [c for c in env.runner.calls[n_calls:] if c[0] == "systemctl" and c[1] != "show"]
    assert set(env.ctx.state.data["components"]) == {"collector", "probe"}
    env.client.set_secret(env.secret)
    env.clock.sleep(300)
    assert agent.tick() < 40 and agent._warned_401 is False


def test_transient_failure_is_retried_but_a_permanent_one_is_not(env):
    publish(env, [env.comp("collector")])
    agent = Agent(env.ctx)
    agent.startup()
    real = ManagerClient.download_artifact
    calls = {"n": 0}

    def flaky(self, *a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ManagerUnreachable("artifact download failed: ConnectionResetError")
        return real(self, *a, **k)

    ManagerClient.download_artifact = flaky
    try:
        agent.tick()
        st = env.ctx.state.data
        assert st["applied_version"] is None and st["etag"] == f'"{env.host_id}:1"'
        assert st["last_reconcile"]["result"] == "error" and not st["failed"]
        assert agent.retry_at is not None
        env.clock.sleep(10)
        agent.tick()  # 304, but the retry is not due yet (30 s backoff)
        assert env.ctx.state.data["applied_version"] is None and calls["n"] == 1
        env.clock.sleep(30)
        agent.tick()  # 304 -> retry from the cached document
    finally:
        ManagerClient.download_artifact = real
    assert env.ctx.state.data["applied_version"] == 1 and agent.retry_at is None
    # a refused (permanent) desired version is remembered and its etag stored: no hammering
    env.sign_release("0.1.0", tamper=True)
    env.ctx.manifests._mem.clear()
    import shutil

    shutil.rmtree(env.ctx.paths.agent_state / "manifests")
    publish(env, [env.comp("collector")])
    env.clock.sleep(10)
    agent.tick()
    assert env.ctx.state.data["last_reconcile"]["result"] == "error" and "2" in env.ctx.state.data["failed"]
    assert env.ctx.state.data["etag"] == f'"{env.host_id}:2"'


def test_startup_converges_from_the_cached_desired_state_with_the_manager_down(env):
    publish(env, [env.comp("collector")])
    a1 = Agent(env.ctx)
    a1.startup()
    a1.tick()
    n = len(env.runner.calls)
    env.app.set_force(unreachable=True)
    a2 = Agent(env.ctx)  # "reboot": fresh process, same disk
    env.ctx.state.data = {}
    a2.startup()
    assert env.ctx.state.data["applied_version"] == 1 and "collector" in env.ctx.state.data["components"]
    assert not [
        c for c in env.runner.calls[n:] if c[0] == "systemctl" and c[1] in ("restart", "stop", "enable")
    ]


def test_status_report_has_no_secrets_and_is_schema_valid(env):
    secret = "expi_" + "Q" * 43
    env.standard_release("0.1.0", comps=("collector", "probe"), creds={"probe": ("ingest_token",)})
    env.push(env.desired([env.comp("collector"), env.comp("probe", creds={"ingest_token": secret})]))
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    blob = json.dumps(reports(env))
    assert secret not in blob and not tokens_in(blob)
    for r in reports(env):
        exp_config.validate(r, "status.schema.json")


def test_poll_interval_comes_from_desired_state(env):
    doc = env.desired([env.comp("collector")])
    doc["agent"]["poll_interval_s"] = 60
    doc["agent"]["status_interval_s"] = 120
    env.push(doc)
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    assert agent.poll_s == 60 and agent.status_s == 120
    assert loop_mod.FAST_POLL_S == 5.0


def test_malformed_component_facts_are_dropped_not_sent(env):
    """CR-wp4-status-component-facts: one bad wiring fact would make the manager reject the whole report."""
    bad = {
        "schema": "exp.health/1",
        "status": "ok",
        "detail": "",
        "version": "0.1.0",
        "uptime_s": 1,
        "metrics": {"vm_up": 1},
        "facts": {
            "tls_fingerprint_sha256": "not-a-fingerprint",
            "listen": "10.0.0.1:8443",
            "url": "http://x",
            "extra": 1,
        },
    }
    env.runner.health["collector"] = Result(0, json.dumps(bad), "")
    publish(env, [env.comp("collector")])
    agent = Agent(env.ctx)
    agent.startup()
    agent.tick()
    rep = reports(env)[-1]  # accepted by the (strict) fake manager
    col = next(c for c in rep["components"] if c["type"] == "collector")
    assert col["health"] == "ok" and col["facts"] == {"listen": "10.0.0.1:8443", "extra": 1}
    assert col["metrics"] == {"vm_up": 1}
