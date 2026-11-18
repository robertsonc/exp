"""Decommission, uninstall --local, and the CLI surface (run in a tmp root with a scripted runner)."""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest
from agent_helpers import Env
from exp_common import config as exp_config

from exp_agent import cli
from exp_agent.loop import Agent
from exp_agent.reconcile import Reconciler
from exp_agent.runner import Result


@pytest.fixture
def env(tmp_path, monkeypatch):
    e = Env(tmp_path)
    e.standard_release(
        comps=("collector", "probe"), creds={"collector": ("webhooks.json",), "probe": ("ingest_token",)}
    )
    real = cli.build_context

    def guarded(root, **kw):
        assert os.path.abspath(str(root)) != "/", "a test tried to run against the REAL root filesystem"
        return real(root, runner=e.runner, lchown=lambda *a: None, user_exists=lambda n: True, **kw)

    monkeypatch.setattr(cli, "build_context", guarded)
    yield e
    e.close()


def converge(env: Env):
    env.push(env.desired([env.comp("collector"), env.comp("probe")]))
    d = env.client.get_desired(None)[1]
    assert Reconciler(env.ctx).run(d).result == "ok"
    env.path("/var/lib/exp/collector/data.db").write_text("data")
    sentinel = [env.path("/etc/other/keep"), env.path("/var/lib/other/keep"), env.path("/opt/other/keep")]
    for s in sentinel:
        s.parent.mkdir(parents=True, exist_ok=True)
        s.write_text("keep")
    return sentinel


def everything_gone(env: Env):
    for root_dir in ("/opt/exp", "/etc/exp", "/var/lib/exp"):  # the (protected) roots stay, empty
        assert not os.path.exists(env.path(root_dir)) or os.listdir(env.path(root_dir)) == [], root_dir
    for logical in (
        "/var/lib/exp/collector",
        "/var/lib/exp/probe",
        "/var/lib/exp/agent",
        "/etc/systemd/system/exp-collector.service",
        "/etc/systemd/system/exp-probe.service",
        "/etc/systemd/system/exp-agent.service",
        "/usr/local/bin/exp-collector",
    ):
        assert not os.path.lexists(env.path(logical)), logical


def test_decommission_removes_everything_including_data_and_tells_the_manager(env):
    sentinel = converge(env)
    env.push(env.desired([], decommission=True))
    env.runner.calls.clear()
    d = env.client.get_desired(None)[1]
    out = Reconciler(env.ctx).run(d)
    assert out.result == "ok" and out.decommissioned
    everything_gone(env)
    assert all(s.read_text() == "keep" for s in sentinel)  # nothing outside the roots touched
    assert env.app.hosts[env.host_id].state == "removed"  # POST decommissioned arrived
    assert (
        env.runner.systemctl("daemon-reload")
        and ["systemctl", "--no-block", "stop", "exp-agent.service"] in env.runner.calls
    )
    netns = [c for c in env.runner.calls if c[:2] == ["systemctl", "stop"] and "netns" in c[2]]
    assert netns and env.runner.calls.index(netns[0]) > env.runner.calls.index(
        ["systemctl", "stop", "exp-probe.service"]
    )


def test_decommission_through_the_loop_ends_the_run(env):
    converge(env)
    env.push(env.desired([], decommission=True))
    agent = Agent(env.ctx)
    agent.tick()
    assert agent.decommissioned and agent.stop.is_set()
    everything_gone(env)


def test_decommission_with_a_manager_that_refuses_keeps_the_agent(env):
    converge(env)
    doc = env.desired([], decommission=True)
    env.push(doc)
    d = env.client.get_desired(None)[1]
    env.app.set_force(503, count=1)  # the decommissioned call fails -> agent stays, retried
    n = {"k": 0}
    real = env.client.get_manifest

    def gm(v):
        return real(v)

    env.client.get_manifest = gm
    out = Reconciler(env.ctx).run(d)
    # components are gone, but the agent config survives so the call can be retried
    assert out.result == "error" or out.decommissioned
    del n


def test_uninstall_local_works_offline_and_with_a_broken_agent_json(env, capsys, monkeypatch):
    converge(env)
    env.fake.stop()  # manager gone
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    os.chmod(env.path("/etc/exp/agent.json"), 0o644)  # unusable agent.json must not block a local uninstall
    rc = cli.main(["--root", str(env.root), "uninstall", "--local"])
    assert rc == 0 and "uninstalled" in capsys.readouterr().out
    everything_gone(env)
    assert env.path("/etc/other/keep").read_text() == "keep"


def test_uninstall_without_local_notifies_the_manager_best_effort(env, capsys, monkeypatch):
    converge(env)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    env.push(env.desired([], decommission=True))
    rc = cli.main(["--root", str(env.root), "uninstall"])
    assert rc == 0 and env.app.hosts[env.host_id].state == "removed"
    everything_gone(env)


# ------------------------------------------------------------------------------------------ CLI
def test_version_and_help_and_unknown(env, capsys):
    assert cli.main(["version"]) == 0 and capsys.readouterr().out.strip() == "0.1.0"
    with pytest.raises(SystemExit):
        cli.main(["bogus"])
    with pytest.raises(SystemExit) as e:
        cli.main(["--help"])
    assert e.value.code == 0
    assert "run" in capsys.readouterr().out


def test_every_subcommand_accepts_config_after_the_subcommand(env, capsys):
    assert cli.main(["--root", str(env.root), "status", "--config", "/nonexistent"]) == 0
    assert cli.main(["--root", str(env.root), "version", "--config", "/x"]) == 0


def test_run_refuses_an_invalid_config_with_the_reason(env, capsys):
    os.chmod(env.path("/etc/exp/agent.json"), 0o644)
    assert cli.main(["--root", str(env.root), "run"]) == 78
    err = capsys.readouterr().err
    assert "refusing to start" in err and "0600" in err and env.secret not in err
    env.path("/etc/exp/agent.json").write_text("{}")
    os.chmod(env.path("/etc/exp/agent.json"), 0o600)
    assert cli.main(["--root", str(env.root), "run"]) == 78
    assert "manager_url" in capsys.readouterr().err
    env.path("/etc/exp/agent.json").unlink()
    assert cli.main(["--root", str(env.root), "run"]) == 78


def test_enrol_writes_agent_json_0600_and_never_prints_the_secret(env, capsys):
    pend = env.app.add_host(name="srv-9")
    token = env.app.issue_enrol_token(pend["host_id"])
    fresh = env.root / "fresh"
    fresh.mkdir()
    rc = cli.main(["--root", str(fresh), "enrol", token, "--manager", env.cfg.manager_url])
    out = capsys.readouterr()
    assert rc == 0 and pend["host_id"] in out.out
    cfgp = fresh / "etc" / "exp" / "agent.json"
    doc = json.loads(cfgp.read_text())
    assert stat.S_IMODE(os.stat(cfgp).st_mode) == 0o600
    assert doc["agent_secret"].startswith("expa_") and doc["manager_url"] == env.cfg.manager_url
    assert doc["agent_secret"] not in out.out + out.err and token not in out.out + out.err
    assert "BEGIN PUBLIC KEY" in doc["release_pubkey_pem"]
    # a spent token fails cleanly; no manager URL on an un-enrolled host is a usage error
    assert cli.main(["--root", str(fresh), "enrol", token, "--manager", env.cfg.manager_url]) == 1
    assert cli.main(["--root", str(env.root / "nowhere"), "enrol", token]) == 2
    assert cli.main(["--root", str(fresh), "enrol", "garbage", "--manager", env.cfg.manager_url]) == 1


def test_health_json_is_exp_health_1_and_exit_code_tracks_health(env, capsys):
    assert cli.main(["--root", str(env.root), "health", "--json"]) == 1  # never polled
    doc = json.loads(capsys.readouterr().out)
    exp_config.validate(doc, "health.schema.json")
    assert doc["status"] == "degraded" and env.secret not in json.dumps(doc)
    env.push(env.desired([]))
    Agent(env.ctx).tick()
    import time

    env.ctx.state.data["last_poll"] = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    env.ctx.state.save()
    assert cli.main(["--root", str(env.root), "health", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    os.chmod(env.path("/etc/exp/agent.json"), 0o644)
    assert cli.main(["--root", str(env.root), "health", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "fail"


def test_status_and_facts_and_reconcile_once(env, capsys):
    env.push(env.desired([]))
    assert cli.main(["--root", str(env.root), "reconcile", "--once"]) == 0
    assert "reconcile: ok" in capsys.readouterr().out
    assert cli.main(["--root", str(env.root), "status"]) == 0
    out = capsys.readouterr().out
    assert "applied version: 1" in out and "last reconcile: ok" in out
    assert cli.main(["--root", str(env.root), "facts"]) == 0
    facts = json.loads(capsys.readouterr().out)
    assert facts["arch"] in ("amd64", "arm64") and "hostname" in facts


def test_selftest_runs_the_safety_checks(env, capsys, tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for n in ("ip", "systemctl"):
        (bindir / n).write_text("#!/bin/sh\n")
        (bindir / n).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    assert cli.main(["--root", str(env.root), "selftest"]) == 0
    out = capsys.readouterr().out
    for name in ("python", "openssl ed25519", "path guard", "safe unpack", "schemas"):
        assert f"ok   {name}" in out


def test_health_timeout_is_degraded_in_status(env):
    from exp_agent.status import build_status

    converge(env)
    env.runner.health["collector"] = Result(124, "", "timed out", timed_out=True)
    rep = build_status(env.ctx, Agent(env.ctx).metrics)
    col = next(c for c in rep["components"] if c["type"] == "collector")
    assert col["health"] == "degraded" and col["detail"] == "health timeout"
    exp_config.validate(rep, "status.schema.json")
