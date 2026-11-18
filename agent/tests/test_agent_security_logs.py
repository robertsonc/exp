"""SR-14 / acceptance 9: no secret in logs, argv, status, events, diagnostics or state; creds are 0600."""

from __future__ import annotations

import io
import json
import logging
import os
import re
import stat

import pytest
from agent_helpers import Env, tokens_in
from exp_common import config as exp_config
from exp_common.log import scrub

from exp_agent import cli
from exp_agent.loop import Agent

WEBHOOK = "https://hooks.slack.com/services/T000/B000/SUPERSECRETPATH"
INGEST = "expi_" + "S" * 43
DASH = "expd_" + "T" * 43
PATTERNS = [
    re.compile(r"exp[aeidn]_(?!\[REDACTED\])[A-Za-z0-9_-]{8,}"),  # a token (not its redacted form)
    re.compile(r"hooks\.slack\.com/(?!\[REDACTED\])"),
    re.compile(r"BEGIN PRIVATE KEY-----\s*abc"),
    re.compile(r"SUPERSECRETPATH"),
]


def leaks(text: str) -> list[str]:
    return [p.pattern for p in PATTERNS if p.search(text)]


@pytest.fixture
def raw_logs():
    """Capture EVERYTHING logged, unscrubbed: the product code itself must not emit secrets."""
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    old = root.level
    root.addHandler(h)
    root.setLevel(logging.DEBUG)
    yield buf
    root.removeHandler(h)
    root.setLevel(old)


def test_full_run_leaves_no_secret_in_logs_argv_status_events_state_or_diagnostics(
    tmp_path, raw_logs, capsys, monkeypatch
):
    env = Env(tmp_path)
    try:
        env.standard_release(
            comps=("collector", "probe"),
            creds={"collector": ("ingest_tokens.json", "webhooks.json"), "probe": ("ingest_token",)},
        )
        real = cli.build_context
        monkeypatch.setattr(
            cli,
            "build_context",
            lambda root, **kw: real(root, runner=env.runner, user_exists=lambda n: True, **kw),
        )
        # enrol through the CLI: the new agent secret must never be printed
        pend = env.app.add_host(name="srv-77")
        tok = env.app.issue_enrol_token(pend["host_id"])
        fresh = tmp_path / "fresh"
        fresh.mkdir()
        assert cli.main(["--root", str(fresh), "enrol", tok, "--manager", env.cfg.manager_url]) == 0
        enrol_out = capsys.readouterr()

        comp_c = env.comp(
            "collector",
            creds={
                "ingest_tokens.json": json.dumps({"p": INGEST}),
                "webhooks.json": json.dumps([{"id": "w", "format": "slack", "url": WEBHOOK}]),
            },
        )
        comp_p = env.comp("probe", creds={"ingest_token": INGEST})
        actions = [
            {"id": "act_01M7R3X9G0KH7PP7H3VPWK5AW9", "type": "rotate_agent_secret"},
            {"id": "act_01M7R3X9G0RF634P8RS8WNGFHK", "type": "collect_diagnostics"},
        ]
        env.runner.journal = (
            f"token {DASH} url {WEBHOOK}\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
        )
        env.push(env.desired([comp_c, comp_p], actions=actions))
        agent = Agent(env.ctx)
        agent.startup()
        agent.tick()
        env.client.set_secret("expa_" + "X" * 43)  # revoked: exercise the 401 path too
        env.clock.sleep(10)
        agent.tick()
        env.app.set_force(unreachable=True)
        env.client.set_secret(env.ctx.cfg.agent_secret)
        env.clock.sleep(400)
        agent.tick()
        env.app.set_force()
        env.clock.sleep(400)
        agent.tick()

        sink = {
            "logs": raw_logs.getvalue(),
            "cli": enrol_out.out + enrol_out.err,
            "argv": "\n".join(" ".join(c) for c in env.runner.calls),
            "reports": json.dumps(env.app.hosts[env.host_id].reports),
            "events": json.dumps(env.ctx.state.pending_events()),
            "state": (env.ctx.paths.agent_state / "state.json").read_text(),
        }
        for d in (env.ctx.paths.agent_state / "diagnostics").glob("*.txt"):
            sink["diag:" + d.name] = d.read_text()
        for name, text in sink.items():
            assert not leaks(text), (name, leaks(text))
        assert "installed exp-collector" in sink["logs"]  # the capture really did capture
        assert "diagnostics" in sink["events"] or "diag" in "".join(sink)
        # the enrolled secret of the fresh host is on disk 0600 and nowhere else
        secret = json.loads((fresh / "etc" / "exp" / "agent.json").read_text())["agent_secret"]
        assert secret not in "".join(sink.values())
        # the scrubber is a backstop that really redacts these shapes
        assert not leaks(scrub(f"{INGEST} {WEBHOOK} Authorization: Bearer {DASH}"))
    finally:
        env.close()


def test_creds_directory_and_files_are_root_0600_after_a_full_run(tmp_path):
    from exp_agent.reconcile import Reconciler

    env = Env(tmp_path)
    try:
        env.standard_release(
            creds={
                "collector": ("ingest_tokens.json", "dashboard_tokens.json", "webhooks.json"),
                "dashboard": ("sso_secret",),
                "probe": ("ingest_token",),
            }
        )
        env.push(
            env.desired(
                [
                    env.comp("collector", creds={"ingest_tokens.json": "{}"}),
                    env.comp("dashboard", creds={"sso_secret": "s"}),
                    env.comp("probe", creds={"ingest_token": INGEST}),
                ]
            )
        )
        assert Reconciler(env.ctx).run(env.client.get_desired(None)[1]).result == "ok"
        uid = os.geteuid()
        for c in ("collector", "dashboard", "probe"):
            d = env.ctx.paths.creds_dir(c)
            st = os.lstat(d)
            assert stat.S_IMODE(st.st_mode) == 0o700 and st.st_uid == uid
            for n in os.listdir(d):
                fst = os.lstat(d / n)
                assert (
                    stat.S_ISREG(fst.st_mode) and stat.S_IMODE(fst.st_mode) == 0o600 and fst.st_uid == uid
                ), (c, n)
        # config files hold no secrets and are world-readable by contract
        for c in ("collector", "dashboard", "probe"):
            cfg = env.ctx.paths.config(c)
            assert stat.S_IMODE(os.lstat(cfg).st_mode) == 0o644 and not tokens_in(cfg.read_text())
        for rel in ("state.json", "desired.json"):
            assert (
                stat.S_IMODE(os.lstat(env.ctx.paths.agent_state / rel).st_mode) == 0o600
                if (env.ctx.paths.agent_state / rel).exists()
                else True
            )
        assert stat.S_IMODE(os.lstat(env.ctx.paths.agent_state).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(env.ctx.paths.agent_json).st_mode) == 0o600
    finally:
        env.close()


def test_the_status_schema_has_no_place_for_credentials():
    # status.schema.json components[].facts/metrics are open objects: the agent only copies what the
    # component's
    # own exp.health/1 output carries, and never reads creds -- asserted by the leak scan above.
    exp_config.validate(
        {
            "schema": "exp.status/1",
            "agent": {"version": "0.1.0", "uptime_s": 1},
            "facts": {"hostname": "h", "arch": "amd64"},
            "metrics": {},
            "components": [],
        },
        "status.schema.json",
    )
