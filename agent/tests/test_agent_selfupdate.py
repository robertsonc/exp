"""Self-update with the pending marker and the rollback timer path; min_agent_version; refusals."""

from __future__ import annotations

import json
import os

import pytest
from agent_helpers import Env, build_tar

from exp_agent import selfupdate
from exp_agent.loop import Agent
from exp_agent.reconcile import Reconciler


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.install_running_agent("0.1.0")
    e.add_agent_release("0.2.0")
    e.sign_release("0.2.0")
    e.release_version = "0.2.0"
    yield e
    e.close()


def desired_with_agent(env, version="0.2.0", comps=()):
    env.push(env.desired(list(comps), agent_version=version))
    return env.client.get_desired(None)[1]


def test_update_flips_current_writes_marker_and_restarts_without_blocking(env):
    d = desired_with_agent(env)
    out = Reconciler(env.ctx).run(d)
    assert out.restarting and out.result == "ok"
    p = env.ctx.paths
    assert (
        os.readlink(p.current("agent")) == "0.2.0"
        and os.readlink(p.comp_opt("agent") / "previous") == "0.1.0"
    )
    pend = json.loads((p.agent_state / "pending.json").read_text())
    assert pend["from"] == "0.1.0" and pend["to"] == "0.2.0" and pend["deadline_s"] == 300
    assert ["systemctl", "--no-block", "restart", "exp-agent.service"] in env.runner.calls
    assert (
        (p.unit("exp-agent.service")).read_text().startswith("[Unit]")
    )  # unit files refreshed from the artifact
    assert (p.unit("exp-agent-rollback.timer")).exists()
    assert os.path.realpath(p.bin_link("agent")).endswith("/opt/exp/agent/0.2.0/bin/exp-agent")
    assert (p.version_dir("agent", "0.1.0") / "bin" / "exp-agent").exists()  # the old tree stays for rollback


def test_the_loop_stops_for_the_restart_and_the_new_agent_confirms_after_its_first_report(env):
    d = desired_with_agent(env)
    env.ctx.state.cache_desired(d)
    agent = Agent(env.ctx)
    agent.tick()
    assert agent.restarting and agent.stop.is_set()
    assert (env.ctx.paths.agent_state / "pending.json").exists()
    # --- the new agent process starts (same disk, version 0.2.0)
    env.ctx.agent_version = "0.2.0"
    env.ctx.state.data["etag"] = None
    new = Agent(env.ctx)
    new.startup()
    assert (env.ctx.paths.agent_state / "pending.json").exists()  # not confirmed by merely starting
    new.tick()
    assert not (env.ctx.paths.agent_state / "pending.json").exists()  # poll + report succeeded: cleared
    assert selfupdate.rollback_check(env.ctx) == "idle"


def test_rollback_timer_restores_the_old_agent_only_after_the_window(env):
    Reconciler(env.ctx).run(desired_with_agent(env))
    env.ctx.agent_version = "0.2.0"
    env.runner.calls.clear()
    assert selfupdate.rollback_check(env.ctx) == "waiting"
    assert os.readlink(env.ctx.paths.current("agent")) == "0.2.0" and not env.runner.systemctl("restart")
    env.clock.sleep(301)
    assert selfupdate.rollback_check(env.ctx) == "rolled-back"
    p = env.ctx.paths
    assert os.readlink(p.current("agent")) == "0.1.0"
    assert not (p.agent_state / "pending.json").exists() and (p.agent_state / "rolled_back.json").exists()
    assert ["systemctl", "--no-block", "restart", "exp-agent.service"] in env.runner.calls
    # --- the old agent is back: it reports agent_rollback and refuses to retry that version
    env.ctx.agent_version = "0.1.0"
    env.ctx.state.data["etag"] = None
    old = Agent(env.ctx)
    old.startup()
    assert any(
        e["msg"].startswith("agent_rollback") and "0.2.0" in e["msg"] for e in env.ctx.state.pending_events()
    )
    assert env.ctx.state.data["bad_agent_versions"] == ["0.2.0"]
    env.runner.calls.clear()
    old.tick()
    assert os.readlink(p.current("agent")) == "0.1.0" and not env.runner.systemctl("restart")
    assert (
        "refused" in env.ctx.state.data["last_reconcile"]["error"]
        or "not retrying" in env.ctx.state.data["last_reconcile"]["error"]
    )
    rep = env.app.hosts[env.host_id].reports[-1]
    assert any(e["msg"].startswith("agent_rollback") for e in rep["events"])  # reported to the manager


def test_rollback_check_is_idle_without_a_marker(env):
    assert selfupdate.rollback_check(env.ctx) == "idle"


def test_min_agent_version_blocks_downgrade_below_the_manifest_floor(env):
    env.add_agent_release("0.0.5")
    env.sign_release("0.0.5", min_agent="0.1.0")
    env.release_version = "0.0.5"
    out = Reconciler(env.ctx).run(desired_with_agent(env, "0.0.5"))
    assert out.result == "error" and "min_agent_version" in out.error
    assert os.readlink(env.ctx.paths.current("agent")) == "0.1.0"
    assert not (env.ctx.paths.agent_state / "pending.json").exists()


def test_old_agent_below_min_version_without_an_offered_update_refuses_everything(env):
    env.ctx.agent_version = "0.0.9"
    env.sign_release("0.2.0", min_agent="0.1.0")
    env.push(env.desired([], agent_version="0.0.9"))
    out = Reconciler(env.ctx).run(env.client.get_desired(None)[1])
    assert out.result == "error" and "older than the release's min_agent_version" in out.error


def test_tampered_agent_artifact_is_refused_and_nothing_changes(env):
    aid = env.artifacts["exp-agent-0.2.0-noarch.tar.gz"]["id"]
    blob = bytearray(env.app.artifacts[aid])
    blob[len(blob) // 2] ^= 0xFF
    env.app.artifacts[aid] = bytes(blob)
    out = Reconciler(env.ctx).run(desired_with_agent(env))
    assert out.result == "error" and out.permanent and "sha256" in out.error and not out.restarting
    p = env.ctx.paths
    assert os.readlink(p.current("agent")) == "0.1.0" and not (p.agent_state / "pending.json").exists()
    assert not (p.comp_opt("agent") / "0.2.0").exists() and not env.runner.systemctl("restart")


def test_agent_artifact_with_a_hostile_unit_name_or_missing_binary_is_refused(env):
    files = {"VERSION": b"0.3.0\n", "bin/exp-agent": (b"#!", 0o755), "systemd/evil.service": b"[Service]\n"}
    env.add_agent_release("0.3.0", files)
    env.sign_release("0.3.0")
    env.release_version = "0.3.0"
    out = Reconciler(env.ctx).run(desired_with_agent(env, "0.3.0"))
    assert out.result == "error" and "exp-*" in out.error
    env.add_agent_release("0.4.0", {"VERSION": b"0.4.0\n"})
    env.sign_release("0.4.0")
    env.release_version = "0.4.0"
    out = Reconciler(env.ctx).run(desired_with_agent(env, "0.4.0"))
    assert out.result == "error" and "bin/exp-agent" in out.error
    assert os.readlink(env.ctx.paths.current("agent")) == "0.1.0"


def test_update_refused_when_it_could_not_be_rolled_back(env):
    import shutil

    shutil.rmtree(env.ctx.paths.version_dir("agent", "0.1.0"))
    os.unlink(env.ctx.paths.current("agent"))
    out = Reconciler(env.ctx).run(desired_with_agent(env))
    assert out.result == "error" and "rolled back" in out.error
    assert not env.runner.systemctl("restart")


def test_real_agent_unit_templates_are_accepted_by_the_unit_loader():
    from pathlib import Path

    from exp_agent import units

    repo = Path(__file__).resolve().parents[1]
    tpl = units.load_templates(repo.parent / "agent")
    assert sorted(tpl) == ["exp-agent-rollback.service", "exp-agent-rollback.timer", "exp-agent.service"]
    for n, t in tpl.items():
        assert units.render(n, t, {}) == t
    assert (
        "ReadWritePaths=/opt/exp /etc/exp /var/lib/exp /run/exp /etc/systemd/system"
        in tpl["exp-agent.service"]
    )
    assert "Restart=always" in tpl["exp-agent.service"] and "RestartSec=5" in tpl["exp-agent.service"]
    assert "ProtectHome=yes" in tpl["exp-agent.service"] and "PrivateTmp=yes" in tpl["exp-agent.service"]
    assert (
        "Type=oneshot" in tpl["exp-agent-rollback.service"]
        and "OnUnitActiveSec=5min" in tpl["exp-agent-rollback.timer"]
    )
    assert build_tar  # helper import kept for symmetry
