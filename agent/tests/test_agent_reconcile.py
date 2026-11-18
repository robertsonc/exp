"""Reconcile end to end against the fake manager: install, idempotence, refusal, rollback, removal."""

from __future__ import annotations

import json
import os
import stat

import pytest
from agent_helpers import SVC_UID, Env, component_files, tokens_in
from exp_common import config as exp_config

from exp_agent.errors import Refused  # noqa: F401
from exp_agent.reconcile import Reconciler
from exp_agent.runner import Result


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def fetch(env: Env, doc=None):
    """Push `doc` and fetch it like the agent does."""
    if doc is not None:
        env.push(doc)
    code, d, _etag = env.client.get_desired(None)
    assert code == 200
    return d


def mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_full_install_all_components(env):
    env.standard_release(
        creds={
            "collector": ("ingest_tokens.json", "dashboard_tokens.json", "webhooks.json"),
            "probe": ("ingest_token",),
        }
    )
    doc = env.desired([env.comp("probe"), env.comp("dashboard"), env.comp("collector")])
    d = fetch(env, doc)
    out = Reconciler(env.ctx).run(d)
    assert out.result == "ok", out.error
    p = env.ctx.paths
    for c in ("collector", "dashboard", "probe"):
        assert (p.version_dir(c, "0.1.0") / "bin" / f"exp-{c}").is_file()
        assert os.readlink(p.current(c)) == "0.1.0"
        assert p.config(c).is_file() and mode(p.config(c)) == 0o644
        assert os.path.islink(p.bin_link(c))
    # order collector -> runner -> dashboard -> probe: the restarts happen in that order
    restarts = [c[2] for c in env.runner.argvs("systemctl", "restart")]
    first = {u.split(".")[0].split("-")[1]: i for i, u in reversed(list(enumerate(restarts)))}
    assert first["collector"] < first["dashboard"] < first["probe"]
    # service users created through argv, with the contracted flags
    assert [
        "useradd",
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "exp-collector",
    ] in env.runner.calls
    assert env.runner.users >= {"exp-collector", "exp-vm", "exp-dashboard"}
    # units rendered with fixed placeholders only
    unit = (p.unit("exp-collector.service")).read_text()
    assert (
        "ExecStart=/opt/exp/collector/0.1.0/bin/exp-collector run --config /etc/exp/collector/config.json"
        in unit
    )
    assert "@" not in unit
    # creds: dir 0700, files 0600, content verbatim
    cd = p.creds_dir("collector")
    assert mode(cd) == 0o700
    assert sorted(os.listdir(cd)) == ["dashboard_tokens.json", "ingest_tokens.json", "webhooks.json"]
    assert all(mode(cd / n) == 0o600 for n in os.listdir(cd))
    assert (cd / "ingest_tokens.json").read_text() == doc["components"][2]["creds"]["ingest_tokens.json"]
    # TLS generated, key chowned to the service user via lchown, mode 0600
    key = p.state_dir("collector") / "tls" / "key.pem"
    assert mode(key) == 0o600 and any(
        c[0].endswith("key.pem") and c[1:] == (SVC_UID, SVC_UID) for c in env.chowns
    )
    # probe: port instances from its config
    assert [
        "systemctl",
        "enable",
        "exp-probe-lease@c01.service",
        "exp-probe-target@s01.service",
    ] in env.runner.calls or any("exp-probe-lease@c01.service" in c for c in env.runner.systemctl("enable"))
    st = env.ctx.state.data
    assert st["applied_version"] == doc["version"] and st["last_reconcile"]["result"] == "ok"
    assert sorted(st["components"]) == ["collector", "dashboard", "probe"]


def snapshot_tree(root) -> dict[str, tuple]:
    out = {}
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            st = os.lstat(p)
            out[os.path.relpath(p, root)] = (
                stat.S_IFMT(st.st_mode),
                st.st_size,
                st.st_mtime_ns,
                os.readlink(p) if stat.S_ISLNK(st.st_mode) else None,
            )
    return out


def host_trees(env: Env) -> dict:
    """Everything the agent manages EXCEPT its own bookkeeping dir (/var/lib/exp/agent)."""
    out = {
        k: snapshot_tree(env.path(k))
        for k in ("/opt/exp", "/etc/exp", "/etc/systemd/system", "/var/lib/exp")
        if env.path(k).exists()
    }
    out["/var/lib/exp"] = {
        k: v for k, v in out.get("/var/lib/exp", {}).items() if k != "agent" and not k.startswith("agent/")
    }
    return {k: v for k, v in out.items() if v}  # an empty root dir is "nothing"


def one_collector(env: Env, version="0.1.0", **kw):
    return env.desired([env.comp("collector", version, **kw)])


def test_reconcile_is_idempotent(env):
    env.standard_release(creds={"collector": ("webhooks.json",)})
    d = fetch(env, one_collector(env))
    assert Reconciler(env.ctx).run(d).result == "ok"
    before = host_trees(env)
    n_calls = len(env.runner.calls)
    out = Reconciler(env.ctx).run(d)
    assert out.result == "ok" and out.changed is False
    new_calls = env.runner.calls[n_calls:]
    assert not [c for c in new_calls if c[0] in ("apt-get", "useradd")]
    assert not [c for c in new_calls if c[0] == "systemctl" and c[1] not in ("show",)]
    assert host_trees(env) == before  # same bytes, same mtimes: nothing was rewritten


@pytest.mark.parametrize(
    "how", ["tampered_manifest", "bad_signature", "wrong_sha_in_desired", "artifact_bytes_swapped"]
)
def test_verification_failures_refuse_and_change_nothing(env, tmp_path, how):
    env.standard_release(comps=("collector",))
    comp = env.comp("collector")
    if how == "tampered_manifest":
        env.sign_release("0.1.0", tamper=True)
    elif how == "bad_signature":
        # signed by a throwaway key that is not the pinned release key
        import subprocess

        k = tmp_path / "evil.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(k)], check=True, capture_output=True
        )
        raw, _ = env.app.releases["0.1.0"]
        (tmp_path / "m").write_bytes(raw)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(k),
                "-in",
                str(tmp_path / "m"),
                "-out",
                str(tmp_path / "s"),
            ],
            check=True,
            capture_output=True,
        )
        import base64

        env.app.releases["0.1.0"] = (raw, base64.b64encode((tmp_path / "s").read_bytes()).decode())
    elif how == "wrong_sha_in_desired":
        comp["artifact"]["sha256"] = "0" * 64
    else:  # the manager serves different bytes than the signed manifest promises
        aid = comp["artifact"]["id"]
        blob = bytearray(env.app.artifacts[aid])
        blob[len(blob) // 2] ^= 0xFF
        env.app.artifacts[aid] = bytes(blob)
    d = fetch(env, env.desired([comp]))
    before = host_trees(env)
    out = Reconciler(env.ctx).run(d)
    assert out.result == "error" and out.permanent
    assert env.runner.mutating() == []
    assert host_trees(env) == before
    assert not env.path("/opt/exp/collector").exists() or os.listdir(env.path("/opt/exp/collector")) == []
    assert env.ctx.state.data["applied_version"] is None


def v2_release(env, creds=("webhooks.json",)):
    env.standard_release("0.2.0", comps=("collector",), creds={"collector": creds})


def test_health_failure_rolls_back_and_is_not_retried(env):
    env.standard_release(comps=("collector",), creds={"collector": ("webhooks.json",)})
    v2_release(env)
    d1 = fetch(env, env.desired([env.comp("collector", "0.1.0", creds={"webhooks.json": "[]"})]))
    assert Reconciler(env.ctx).run(d1).result == "ok"
    old_cfg = env.path("/etc/exp/collector/config.json").read_bytes()
    old_cred = env.path("/etc/exp/collector/creds/webhooks.json").read_bytes()

    cfg2 = json.loads(old_cfg)
    cfg2["retention"]["metrics_days"] = 31
    env.runner.health["collector"] = lambda ver: (
        Result(1, "", "boom")
        if ver == "0.2.0"
        else Result(
            0,
            json.dumps(
                {
                    "schema": "exp.health/1",
                    "status": "ok",
                    "detail": "",
                    "version": ver,
                    "uptime_s": 1,
                    "metrics": {},
                    "facts": {},
                }
            ),
        )
    )
    d2 = fetch(
        env,
        env.desired(
            [env.comp("collector", "0.2.0", config=cfg2, creds={"webhooks.json": "[1]"})], release="0.2.0"
        ),
    )
    out = Reconciler(env.ctx).run(d2)
    assert out.result == "rolled_back" and "rolled back to 0.1.0" in out.error
    p = env.ctx.paths
    assert os.readlink(p.current("collector")) == "0.1.0"
    assert p.config("collector").read_bytes() == old_cfg
    assert (p.creds_dir("collector") / "webhooks.json").read_bytes() == old_cred
    assert "0.1.0" in env.path("/etc/systemd/system/exp-collector.service").read_text()
    st = env.ctx.state.data
    assert st["components"]["collector"]["version"] == "0.1.0" and st["applied_version"] == d1["version"]
    assert st["last_reconcile"]["result"] == "rolled_back" and str(d2["version"]) in st["failed"]
    # the same desired version is never retried
    n = len(env.runner.calls)
    out2 = Reconciler(env.ctx).run(d2)
    assert out2.result == "rolled_back"
    assert not [c for c in env.runner.calls[n:] if c[0] == "systemctl" and c[1] != "show"]
    # a NEW desired version (same content, higher number) is tried again
    env.runner.health["collector"] = None
    del env.runner.health["collector"]
    d3 = fetch(
        env,
        env.desired(
            [env.comp("collector", "0.2.0", config=cfg2, creds={"webhooks.json": "[1]"})], release="0.2.0"
        ),
    )
    assert Reconciler(env.ctx).run(d3).result == "ok"
    assert os.readlink(p.current("collector")) == "0.2.0"


def test_health_failure_on_first_install_stops_the_component(env):
    env.standard_release(comps=("collector",))
    env.runner.health["collector"] = Result(1, "", "never comes up")
    d = fetch(env, one_collector(env))
    out = Reconciler(env.ctx).run(d)
    assert out.result == "rolled_back" and "no previous version" in out.error
    assert "collector" not in env.ctx.state.data["components"]
    assert env.runner.systemctl("stop")
    assert env.ctx.state.data["applied_version"] is None


def test_activation_failure_also_rolls_back(env):
    env.standard_release(comps=("collector",))
    v2_release(env, creds=())
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env))).result == "ok"
    env.runner.fail[("systemctl", "restart", "exp-collector.service")] = Result(1, "", "unit failed")
    cfg2 = json.loads(env.path("/etc/exp/collector/config.json").read_text())
    cfg2["retention"]["records_days"] = 8
    n_fail = {"n": 0}
    real_run = env.runner.run

    def run(argv, **kw):  # fail only the FIRST restart (the new version); the rollback restart works
        if list(argv)[:3] == ["systemctl", "restart", "exp-collector.service"]:
            n_fail["n"] += 1
            if n_fail["n"] > 1:
                env.runner.fail.clear()
        return real_run(argv, **kw)

    env.runner.run = run
    out = Reconciler(env.ctx).run(
        fetch(env, env.desired([env.comp("collector", "0.2.0", config=cfg2)], release="0.2.0"))
    )
    assert out.result == "rolled_back"
    assert os.readlink(env.ctx.paths.current("collector")) == "0.1.0"


def test_unknown_component_type_is_ignored_and_reported(env):
    env.standard_release(comps=("collector",))
    doc = one_collector(env)
    doc["components"].append({"type": "widget", "id": "w1"})
    d = fetch(env, doc)
    out = Reconciler(env.ctx).run(d)
    assert out.result == "ok" and out.ignored[0]["type"] == "widget"
    assert any("widget" in e["msg"] for e in env.ctx.state.pending_events())
    assert not env.path("/opt/exp/widget").exists()
    from exp_agent.loop import Agent
    from exp_agent.status import build_status

    rep = build_status(env.ctx, Agent(env.ctx).metrics)
    assert any(c["type"] == "widget" and c["state"] == "unsupported" for c in rep["components"])
    exp_config.validate(rep, "status.schema.json")


def refused_release(env, files, expect: str):
    env.add_artifact("collector", "0.1.0", files, "amd64")
    env.sign_release("0.1.0")
    d = fetch(env, one_collector(env))
    before = host_trees(env)
    out = Reconciler(env.ctx).run(d)
    assert out.result == "error" and out.permanent, out
    assert expect in out.error
    assert env.runner.mutating() == [], env.runner.mutating()
    assert host_trees(env) == before
    base = env.path("/opt/exp/collector")
    assert not base.exists() or not [n for n in os.listdir(base)]  # no version dir, no staging leftovers
    assert env.ctx.state.data["applied_version"] is None


def test_apt_package_off_allowlist_refuses_the_component(env):
    files = component_files("collector", "0.1.0", requirements=("curl", "nmap"))
    refused_release(env, files, "allowlist")


def test_apt_allowlisted_packages_are_installed_with_argv(env):
    env.standard_release(comps=("collector",), requirements=("iperf3", "curl"))
    out = Reconciler(env.ctx).run(fetch(env, one_collector(env)))
    assert out.result == "ok"
    apt = env.runner.argvs("apt-get")
    assert apt == [
        ["apt-get", "update", "-q"],
        ["apt-get", "install", "-y", "--no-install-recommends", "iperf3", "curl"],
    ]


@pytest.mark.parametrize(
    "name,text,expect",
    [
        ("evil.service", "[Service]\nExecStart=/bin/true\n", "does not match exp-"),
        ("exp-ok.conf", "x", "does not match exp-"),
        ("exp-x.service", "[Service]\nExecStart=@HOME@/x\n", "unknown placeholder"),
        ("exp-x.service", "[Service]\nLoadCredential=a:/etc/passwd\n", "not inside"),
    ],
)
def test_bad_unit_templates_refused(env, name, text, expect):
    files = component_files("collector", "0.1.0")
    files[f"systemd/{name}"] = text.encode()
    refused_release(env, files, expect)


def test_creds_pruned_and_referenced_files_created_empty(env):
    env.standard_release(comps=("collector",), creds={"collector": ("webhooks.json", "other")})
    d1 = fetch(env, one_collector(env, creds={"a.json": "1", "b.json": "2"}))
    assert Reconciler(env.ctx).run(d1).result == "ok"
    cd = env.ctx.paths.creds_dir("collector")
    assert sorted(os.listdir(cd)) == ["a.json", "b.json", "other", "webhooks.json"]  # referenced ones empty
    assert (cd / "webhooks.json").read_bytes() == b"" and mode(cd / "webhooks.json") == 0o600
    d2 = fetch(env, one_collector(env, creds={"a.json": "1"}))
    assert Reconciler(env.ctx).run(d2).result == "ok"
    assert sorted(os.listdir(cd)) == ["a.json", "other", "webhooks.json"]  # b.json removed
    assert all(mode(cd / n) == 0o600 for n in os.listdir(cd)) and mode(cd) == 0o700


def test_creds_only_change_restarts_even_when_reload_is_declared(env):
    """systemd re-reads LoadCredential= only at unit start: a credential change never uses reload/SIGHUP."""
    env.standard_release(comps=("collector",), reload_=True)
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env, creds={"t": "1"}))).result == "ok"
    n = len(env.runner.calls)
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env, creds={"t": "2"}))).result == "ok"
    new = env.runner.calls[n:]
    assert ["systemctl", "restart", "exp-collector.service"] in new
    assert not [c for c in new if c[:2] == ["systemctl", "reload"]]


def test_config_only_change_reloads_when_declared(env):
    env.standard_release(comps=("collector",), reload_=True)
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env, creds={"t": "1"}))).result == "ok"
    n = len(env.runner.calls)
    doc = one_collector(env, creds={"t": "1"})
    doc["components"][0]["config"] = {**doc["components"][0]["config"], "extra_setting": 7}
    assert Reconciler(env.ctx).run(fetch(env, doc)).result == "ok"
    new = env.runner.calls[n:]
    assert ["systemctl", "reload", "exp-collector.service"] in new
    assert not [c for c in new if c[:2] == ["systemctl", "restart"]]


def test_apt_failure_reported_once_per_desired_version_and_others_converge(env):
    env.standard_release(comps=("collector", "dashboard"), requirements=("iperf3",))
    env.runner.fail[("apt-get", "install")] = Result(100, "", "E: Unable to locate package iperf3")
    rec = Reconciler(env.ctx)
    doc = fetch(env, env.desired([env.comp("collector"), env.comp("dashboard")]))
    out = rec.run(doc)
    assert out.result == "error" and "iperf3" in out.error
    assert len([c for c in env.runner.argvs("apt-get") if c[1] == "update"]) == 1  # once per reconcile
    out = rec.run(doc)
    assert out.result == "error"
    events = [e for e in env.ctx.state.pending_events() if "apt-get install failed" in e["msg"]]
    assert len(events) == 1  # reported once for this desired version, not again on the second poll
    env.runner.fail.clear()
    assert rec.run(doc).result == "ok"


def test_creds_only_change_restarts_without_reload_support(env):
    env.standard_release(comps=("collector",))
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env, creds={"t": "1"}))).result == "ok"
    n = len(env.runner.calls)
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env, creds={"t": "2"}))).result == "ok"
    assert ["systemctl", "restart", "exp-collector.service"] in env.runner.calls[n:]


def test_only_changed_components_restart(env):
    env.standard_release(comps=("collector", "dashboard"))
    assert (
        Reconciler(env.ctx)
        .run(fetch(env, env.desired([env.comp("collector"), env.comp("dashboard")])))
        .result
        == "ok"
    )
    n = len(env.runner.calls)
    cfg = json.loads(env.path("/etc/exp/dashboard/config.json").read_text())
    cfg["title"] = "changed"
    out = Reconciler(env.ctx).run(
        fetch(env, env.desired([env.comp("collector"), env.comp("dashboard", config=cfg)]))
    )
    assert out.result == "ok"
    restarted = [c[2] for c in env.runner.calls[n:] if c[:2] == ["systemctl", "restart"]]
    assert restarted == ["exp-dashboard.service"]


def probe_cfg(env, extra_port=False):
    cfg = json.loads(json.dumps(env.comp("probe")["config"]))
    if extra_port:
        cfg["ports"].append(
            {
                "id": "c02",
                "iface": "enp10s0f1",
                "role": "client",
                "vlan": None,
                "dhcp": {"hostname": "exp-hallb-c02", "vendor_class": "exp-probe", "client_id": "mac"},
            }
        )
    return cfg


def test_probe_preflight_refuses_port_change_and_keeps_previous_config(env):
    env.standard_release(comps=("probe",))
    assert Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("probe")]))).result == "ok"
    cfgp = env.path("/etc/exp/probe/config.json")
    old = cfgp.read_bytes()
    env.runner.preflight_rc, env.runner.preflight_msg = 2, "interface enp10s0f1 carries the management route"
    n = len(env.runner.calls)
    out = Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("probe", config=probe_cfg(env, True))])))
    assert out.result == "error" and "management route" in out.error and "preflight" in out.error
    assert cfgp.read_bytes() == old
    assert not os.path.exists(str(cfgp) + ".new")
    assert not [c for c in env.runner.calls[n:] if c[0] == "systemctl" and c[1] != "show"]
    pre = env.runner.argvs(env.path("/opt/exp/probe/0.1.0/bin/exp-probe").as_posix(), "preflight")
    assert pre and pre[-1][2] == "--config" and pre[-1][3].endswith("config.json.new")
    # once preflight passes the new ports are applied, with their lease instance started
    env.runner.preflight_rc = 0
    out = Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("probe", config=probe_cfg(env, True))])))
    assert out.result == "ok"
    assert json.loads(cfgp.read_text())["ports"][-1]["id"] == "c02"
    assert ["systemctl", "restart", "exp-probe-lease@c02.service"] in env.runner.calls


def test_probe_instances_for_ports(env):
    env.standard_release(comps=("probe",))
    assert Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("probe")]))).result == "ok"
    rec = env.ctx.state.data["components"]["probe"]
    assert rec["instances"] == ["exp-probe-lease@c01.service", "exp-probe-target@s01.service"]
    assert rec["units"][0].endswith("netns.service")  # netns first
    restarts = [c[2] for c in env.runner.argvs("systemctl", "restart")]
    assert restarts.index("exp-probe-netns.service") < restarts.index("exp-probe-lease@c01.service")


def test_component_no_longer_desired_is_removed_but_data_kept(env):
    env.standard_release(comps=("collector", "probe"), creds={"collector": ("webhooks.json",)})
    assert (
        Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("collector"), env.comp("probe")]))).result
        == "ok"
    )
    data = env.path("/var/lib/exp/collector/spool.db")
    data.write_text("precious")
    out = Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("collector")])))
    assert out.result == "ok"
    assert (
        not env.path("/opt/exp/probe").exists()
        and not env.path("/etc/systemd/system/exp-probe.service").exists()
    )
    assert not os.path.lexists(env.path("/usr/local/bin/exp-probe"))
    assert not env.path("/etc/exp/probe/creds").exists()
    assert ["systemctl", "stop", "exp-probe-netns.service"] in env.runner.calls
    stops = [c[2] for c in env.runner.argvs("systemctl", "stop")]
    assert stops.index("exp-probe-lease@c01.service") < stops.index("exp-probe-netns.service")
    assert "probe" not in env.ctx.state.data["components"]
    # now remove the collector: its data stays too
    assert Reconciler(env.ctx).run(fetch(env, env.desired([]))).result == "ok"
    assert data.read_text() == "precious"


def test_min_agent_version_is_enforced(env):
    env.standard_release(comps=("collector",))
    env.sign_release("0.1.0", min_agent="9.0.0")
    out = Reconciler(env.ctx).run(fetch(env, one_collector(env)))
    assert out.result == "error" and "min_agent_version" in out.error
    assert env.runner.mutating() == []


def test_architecture_mismatch_refused(env):
    env.standard_release(comps=("collector",))
    env.ctx.arch = "arm64"
    out = Reconciler(env.ctx).run(fetch(env, one_collector(env)))
    assert out.result == "error" and "amd64" in out.error
    assert env.runner.mutating() == []


def test_actions_run_once_per_id(env):
    env.standard_release(comps=("probe",), creds={"probe": ("ingest_token",)})
    comp = env.comp("probe")
    actions = [
        {"id": "act_01M7R3X9G0KH7PP7H3VPWK5AW9", "type": "rotate_agent_secret"},
        {
            "id": "act_01M7R3X9G0M5M65F05ER1ZFZV5",
            "type": "restart_component",
            "component_id": comp["component_id"],
        },
        {"id": "act_01M7R3X9G0RF634P8RS8WNGFHK", "type": "collect_diagnostics"},
    ]
    env.runner.journal = (
        "started ok\nAuthorization: Bearer expa_" + "A" * 43 + "\n"
        "posting to https://hooks.slack.com/services/T000/B000/XXXXSECRET\n"
    )
    d = fetch(env, env.desired([comp], actions=actions))
    old_secret = env.ctx.cfg.agent_secret
    out = Reconciler(env.ctx).run(d)
    assert out.result == "ok", out.error
    # rotate: new secret persisted 0600, used by the client, never put in argv
    new = json.loads(env.path("/etc/exp/agent.json").read_text())["agent_secret"]
    assert (
        new != old_secret
        and env.ctx.cfg.agent_secret == new
        and mode(env.path("/etc/exp/agent.json")) == 0o600
    )
    # restart_component
    assert ["systemctl", "restart", "exp-probe.service"] in env.runner.calls[-30:]
    # diagnostics: sanitized, 0600
    f = env.path("/var/lib/exp/agent/diagnostics/act_01M7R3X9G0RF634P8RS8WNGFHK.txt")
    text = f.read_text()
    assert "started ok" in text and "XXXXSECRET" not in text and "expa_" + "A" * 10 not in text
    assert mode(f) == 0o600
    assert env.ctx.state.actions_done() == {a["id"] for a in actions}
    n = len(env.runner.calls)
    Reconciler(env.ctx).run(d)  # same doc again: actions are remembered
    assert not [c for c in env.runner.calls[n:] if c[0] == "journalctl" or c[:2] == ["systemctl", "restart"]]


def test_no_token_ever_in_argv_or_events(env):
    env.standard_release(comps=("collector",), creds={"collector": ("ingest_tokens.json",)})
    secret = "expi_" + "Z" * 43
    d = fetch(env, one_collector(env, creds={"ingest_tokens.json": secret}))
    assert Reconciler(env.ctx).run(d).result == "ok"
    assert not [a for c in env.runner.calls for a in c if tokens_in(a)]
    assert not tokens_in(json.dumps(env.ctx.state.pending_events()))
    assert not tokens_in(env.path("/var/lib/exp/agent/state.json").read_text())


def test_degraded_health_passes_the_gate_but_fail_does_not(env):
    """`degraded` = serving with something imperfect (e.g. a collector is down): not a reason to roll back."""
    env.standard_release(comps=("collector",))
    degraded = {
        "schema": "exp.health/1",
        "status": "degraded",
        "detail": "a collector is unreachable",
        "version": "0.1.0",
        "uptime_s": 3,
        "metrics": {},
        "facts": {},
    }
    env.runner.health["collector"] = Result(1, json.dumps(degraded), "")
    out = Reconciler(env.ctx).run(fetch(env, one_collector(env)))
    assert out.result == "ok", out.error
    comp = env.ctx.state.data["components"]["collector"]
    assert comp["version"] == "0.1.0"
    failing = {**degraded, "status": "fail", "detail": "database locked"}
    env.runner.health["collector"] = Result(
        0, json.dumps(failing), ""
    )  # exit 0 but status fail: contradiction
    env.standard_release("0.2.0", comps=("collector",))
    out = Reconciler(env.ctx).run(fetch(env, env.desired([env.comp("collector", "0.2.0")], release="0.2.0")))
    assert out.result == "rolled_back" and "database locked" in out.error


def test_rotate_honours_grace_and_restores_the_old_secret_when_the_new_one_is_refused(env):
    env.standard_release(comps=("probe",), creds={"probe": ("ingest_token",)})
    comp = env.comp("probe")
    act = {"id": "act_01M7R3X9G0KH7PP7H3VPWK5AW9", "type": "rotate_agent_secret"}
    d = fetch(env, env.desired([comp], actions=[act]))
    old = env.ctx.cfg.agent_secret
    seen: list[int] = []
    real = env.client.rotate

    def rotate():
        secret, grace = real()
        seen.append(grace)
        return secret, grace

    env.client.rotate = rotate
    env.client.check_auth = lambda: False  # the manager refuses the new secret inside the grace window
    out = Reconciler(env.ctx).run(d)
    assert seen and seen[0] > 0  # the grace_s returned by POST rotate is read ...
    assert env.ctx.cfg.agent_secret == old  # ... and the still-valid old secret is put back
    assert json.loads(env.path("/etc/exp/agent.json").read_text())["agent_secret"] == old
    assert any(
        "not accepted" in e["msg"] and str(seen[0]) in e["msg"] for e in env.ctx.state.pending_events()
    )
    assert out.result in ("ok", "error")


def test_rotate_success_reports_the_grace(env):
    env.standard_release(comps=("probe",), creds={"probe": ("ingest_token",)})
    act = {"id": "act_01M7R3X9G0KH7PP7H3VPWK5AW9", "type": "rotate_agent_secret"}
    d = fetch(env, env.desired([env.comp("probe")], actions=[act]))
    Reconciler(env.ctx).run(d)
    assert any("previous secret stays valid for" in e["msg"] for e in env.ctx.state.pending_events())


def test_health_gate_decides_on_status_not_exit_code_and_unparsable_fails(env):
    from exp_agent.health import run_health

    env.standard_release(comps=("collector",))
    assert Reconciler(env.ctx).run(fetch(env, one_collector(env))).result == "ok"
    base = {
        "schema": "exp.health/1",
        "detail": "",
        "version": "0.1.0",
        "uptime_s": 1,
        "metrics": {},
        "facts": {},
    }
    cases = [
        ("ok", 0, True),
        ("degraded", 0, True),  # probe: collector down, spool accepting
        ("degraded", 1, True),  # dashboard: a collector is unreachable
        ("fail", 0, False),
        ("fail", 1, False),
    ]
    for status, rc, passes in cases:
        env.runner.health["collector"] = Result(rc, json.dumps({**base, "status": status}), "")
        assert run_health(env.ctx, "collector", "0.1.0").passed is passes, (status, rc)
    env.runner.health["collector"] = Result(0, "not json", "")
    assert run_health(env.ctx, "collector", "0.1.0").passed is False
    env.runner.health["collector"] = Result(1, "", "boom")
    assert run_health(env.ctx, "collector", "0.1.0").passed is False
