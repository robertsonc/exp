"""06-agent.md section 9 items 1, 5, 6, 7 (decommission) and 9 on a real systemd host.

One host per OS in the matrix (Ubuntu 22.04, 24.04, Debian 12), tests run in order (the host's state carries over):
install.sh -> repair -> re-enrol -> a component converges -> manager down -> self-update ->
rollback timer -> decommission -> journal scan.
"""

from __future__ import annotations

import json
import warnings

import pytest
from harness import (
    ARCH,
    TOKEN_RE,
    World,
    agent_cfg,
    assert_no_tokens,
    fake_manager,
    main_pid,
    run_install,
    sha,
    token_used,
    wait_for,
)

COLLECTOR_CREDS = ["dashboard_tokens.json", "ingest_tokens.json", "webhooks.json"]


class State:
    """Values the ordered tests hand to each other."""

    hid = ""
    token = ""
    secret = ""


@pytest.fixture(scope="module")
def st(host) -> State:  # depends on `host`: a fresh State for every OS in the matrix
    return State()


def reports_grow(world: World, hid: str, secs: float = 150) -> None:
    n = len(world.reports(hid))
    wait_for(lambda: len(world.reports(hid)) > n, secs, 2, "new status reports from the agent")


# ---------------------------------------------------------------------------------------------
# item 1: install.sh enrols and starts the agent; secret never printed; re-run idempotent
# ---------------------------------------------------------------------------------------------
def test_01_install_enrols_and_starts_the_agent(world, host, st):
    world.standard_release("0.1.0", components=("collector",))
    st.hid, st.token = world.add_host("srv-life", "hall-b")
    world.set_desired(st.hid, "0.1.0")
    # sample every process's argv while the installer runs: the agent secret must never be in one
    host.write(
        "/tmp/sample.sh",
        "while [ ! -e /tmp/stop-sampling ]; do for f in /proc/[0-9]*/cmdline; do "
        "tr '\\0' ' ' <\"$f\" 2>/dev/null; echo; done; done >> /tmp/cmdlines.txt\n",
    )
    host.run("rm -f /tmp/stop-sampling /tmp/cmdlines.txt; (nohup bash /tmp/sample.sh >/dev/null 2>&1 &)")
    r = run_install(host, world, st.token)
    host.run("touch /tmp/stop-sampling")
    assert r.rc == 0, r
    assert "Components will be installed by the agent; watch progress in the manager" in r.text
    assert "Hall B" in r.text and "exp-host-01" in r.text
    cfg = agent_cfg(host)
    st.secret = cfg["agent_secret"]
    # the secret and the token are never printed ...
    assert st.secret not in r.text and st.token not in r.text
    assert_no_tokens(r.text.replace(st.token, ""), "install.sh output")
    # ... and the secret was never in any process's argv, the token only in the documented bash -s -- argv
    wait_for(lambda: host.run("pgrep -f sample.sh").rc != 0, 30, 1, "the argv sampler to stop")
    cmdlines = host.read("/tmp/cmdlines.txt")
    assert len(cmdlines) > 1000, "argv sampler captured nothing"
    assert st.secret not in cmdlines
    offenders = [
        ln
        for ln in cmdlines.splitlines()
        if st.token in ln and not ln.startswith(("sudo", "bash -s", "bash"))
    ]
    assert not offenders, offenders[:2]
    # end state
    assert host.run("stat -c '%U:%G %a' /etc/exp/agent.json").out.strip() == "root:root 600"
    assert cfg["manager_url"] == world.url and cfg["agent_id"] == st.hid
    assert cfg["release_pubkey_pem"].strip() == world.app.key.public_pem.strip()
    assert host.run("readlink /opt/exp/agent/current").out.strip() == "0.1.0"
    assert host.run("/usr/local/bin/exp-agent version").out.strip() == "0.1.0"
    # the version-independent rollback checker exists from the first install (no previous agent yet)
    assert host.run("stat -c '%U:%G %a' /opt/exp/agent/rollback-check").out.strip() == "root:root 755"
    assert (
        "ExecStart=/opt/exp/agent/rollback-check" in host.run("systemctl cat exp-agent-rollback.service").out
    )
    for unit in ("exp-agent.service", "exp-agent-rollback.service", "exp-agent-rollback.timer"):
        assert host.run(f"systemd-analyze verify /etc/systemd/system/{unit}").rc == 0, unit
    assert host.run("/opt/exp/agent/rollback-check").rc == 0  # nothing pending: a no-op
    for unit in ("exp-agent.service", "exp-agent-rollback.timer"):
        assert host.run(f"systemctl is-enabled {unit}").out.strip() == "enabled", unit
        assert host.active(unit), unit
    show = host.run(
        "systemctl show exp-agent.service -p Restart -p ProtectHome -p PrivateTmp -p User -p RestartUSec"
    ).out
    assert "Restart=always" in show and "ProtectHome=yes" in show and "PrivateTmp=yes" in show
    assert token_used(world, st.token)
    assert world.host(st.hid).state == "enrolled"
    assert world.host(st.hid).facts["hostname"] == "exp-host-01" and world.host(st.hid).facts["arch"] == ARCH
    # the agent really talks to the manager over verified TLS
    wait_for(lambda: world.reports(st.hid), 120, 2, "the first status report")
    assert world.last_report(st.hid)["agent"]["version"] == "0.1.0"


def test_02_selftest_health_status(host, st):
    r = host.run("exp-agent selftest")
    assert r.rc == 0, r
    h = json.loads(host.run("exp-agent health --json").out)
    assert h["schema"] == "exp.health/1"
    assert host.run("exp-agent status").out.startswith("agent 0.1.0")


def test_03_rerun_without_token_repairs_idempotently(world, host, st):
    before = sha(host, "/etc/exp/agent.json")
    units_before = sha(host, "/etc/systemd/system/exp-agent.service")
    # damage the installation: the tree loses its entry point and the service is stopped
    host.run("systemctl stop exp-agent.service; rm -f /opt/exp/agent/0.1.0/bin/exp-agent")
    r = run_install(host, world)
    assert r.rc == 0, r
    assert "repairing" in r.text and st.secret not in r.text
    assert sha(host, "/etc/exp/agent.json") == before, "a repair must not touch the credentials"
    assert sha(host, "/etc/systemd/system/exp-agent.service") == units_before
    assert host.active("exp-agent.service")
    assert host.run("/opt/exp/agent/0.1.0/bin/exp-agent version").out.strip() == "0.1.0"
    # again: idempotent end state
    r = run_install(host, world)
    assert r.rc == 0, r
    listing = host.run("ls -A /opt/exp/agent").out.split()
    assert sorted(listing) == ["0.1.0", "current", "rollback-check"], listing
    assert not host.exists("/opt/exp/agent/.staging-*")
    assert sha(host, "/etc/exp/agent.json") == before
    reports_grow(world, st.hid)


def test_04_used_token_is_refused_and_changes_nothing(world, host, st):
    before = sha(host, "/etc/exp/agent.json")
    pid = main_pid(host, "exp-agent.service")
    r = run_install(host, world, st.token)
    assert r.rc != 0 and "already used or has expired" in r.err
    assert sha(host, "/etc/exp/agent.json") == before
    assert main_pid(host, "exp-agent.service") == pid and host.active("exp-agent.service")


def test_05_rerun_with_a_new_token_reenrols(world, host, st):
    new_token = world.app.issue_enrol_token(st.hid)
    old = agent_cfg(host)["agent_secret"]
    pid = main_pid(host, "exp-agent.service")
    # under bash -x: the installer switches tracing off before it touches a secret
    r = run_install(host, world, new_token, bash_flags="-x")
    assert r.rc == 0, r
    new = agent_cfg(host)["agent_secret"]
    assert new != old
    for s in (old, new, new_token):
        assert s not in r.text, "a secret or token leaked into the (xtrace) output"
    assert host.run("stat -c '%a' /etc/exp/agent.json").out.strip() == "600"
    assert main_pid(host, "exp-agent.service") != pid, "the agent must restart onto the new credentials"
    with pytest.raises(fake_manager.ApiError):
        world.app.authenticate(old)
    st.secret = new
    reports_grow(world, st.hid)


def test_06_cli_enrol_replaces_credentials_and_restarts_the_agent(world, host, st):
    token = world.app.issue_enrol_token(st.hid)
    old = agent_cfg(host)["agent_secret"]
    pid = main_pid(host, "exp-agent.service")
    r = host.run(
        f"printf %s {token} | exp-agent enrol --manager {world.url}"
    )  # token via stdin, never argv (CR-wp6-enrol-token-not-argv)
    assert r.rc == 0, r
    assert "enrolled as " + st.hid in r.out and token not in r.text
    new = agent_cfg(host)["agent_secret"]
    assert new != old and host.run("stat -c '%a' /etc/exp/agent.json").out.strip() == "600"
    wait_for(
        lambda: main_pid(host, "exp-agent.service") != pid and host.active("exp-agent.service"),
        60,
        1,
        "the agent to restart onto the new credentials",
    )
    st.secret = new
    reports_grow(world, st.hid)


# ---------------------------------------------------------------------------------------------
# a component converges (needed by the next tests)
# ---------------------------------------------------------------------------------------------
def test_07_component_converges_with_creds_and_tls(world, host, st):
    comp = world.collector_component("0.1.0")
    world.set_desired(st.hid, "0.1.0", components=[comp])
    wait_for(
        lambda: host.active("exp-collector.service"), 150, 2, "exp-collector to be active", host.agent_log
    )
    # §9 item 9: creds are root 0600 in a 0700 directory, exposed to the service by systemd
    assert host.run("stat -c '%U:%G %a' /etc/exp/collector/creds").out.strip() == "root:root 700"
    modes = host.run("stat -c '%n %U:%G %a' /etc/exp/collector/creds/*").out.strip().splitlines()
    assert sorted(m.split()[0].rsplit("/", 1)[1] for m in modes) == COLLECTOR_CREDS
    assert all(m.split()[1:] == ["root:root", "600"] for m in modes), modes
    assert host.run("stat -c '%U:%G %a' /etc/exp/collector/config.json").out.strip() == "root:root 644"
    assert host.run("stat -c '%a' /var/lib/exp/collector/tls/key.pem").out.strip() == "600"
    assert host.run("stat -c '%U' /var/lib/exp/collector/tls/key.pem").out.strip() == "exp-collector"
    logs = host.run("journalctl -u exp-collector --no-pager -o cat").out
    if host.credentials_supported():
        assert "credentials delivered: " + ",".join(COLLECTOR_CREDS) in logs
    else:  # this docker host's systemd cannot create /run/credentials/<unit>: the unit is still up without them
        assert "credentials directory unavailable" in logs
        warnings.warn(
            "LoadCredential= is not supported by this container environment; delivery not asserted",
            stacklevel=1,
        )
    assert host.run("readlink /opt/exp/collector/current").out.strip() == "0.1.0"
    assert host.run("/usr/local/bin/exp-collector health --json").rc == 0

    def healthy() -> bool:
        rep = world.last_report(st.hid)
        return bool(rep) and any(c["type"] == "collector" and c["health"] == "ok" for c in rep["components"])

    wait_for(healthy, 120, 3, "a status report with a healthy collector")


# ---------------------------------------------------------------------------------------------
# item 6: manager down -> components unaffected, the agent recovers and reports
# ---------------------------------------------------------------------------------------------
def test_08_manager_down_components_unaffected_and_agent_recovers(world, host, st):
    cpid = main_pid(host, "exp-collector.service")
    assert cpid not in ("", "0")
    n_before = len(world.reports(st.hid))
    world.app.set_force(unreachable=True)  # the manager answers nothing at all
    try:
        # (the spec's 30 minutes are simulated by 60 s: backoff 30 s -> 60 s is the same code path)
        wait_for(
            lambda: "manager unreachable" in host.run("journalctl -u exp-agent --no-pager -o cat -n 50").out,
            90,
            3,
            "the agent to notice the outage",
        )
        assert host.active("exp-agent.service") and host.active("exp-collector.service")
        assert main_pid(host, "exp-collector.service") == cpid
        # a restart of the agent during the outage converges from its cache and leaves the component alone
        host.run("systemctl restart exp-agent.service")
        host.run("sleep 20")
        assert host.active("exp-agent.service") and main_pid(host, "exp-collector.service") == cpid
        assert host.run("exp-agent status").rc == 0
    finally:
        world.app.set_force()
    wait_for(lambda: len(world.reports(st.hid)) > n_before, 180, 3, "the agent to recover and report")
    assert main_pid(host, "exp-collector.service") == cpid, "the component was restarted by a manager outage"
    assert world.last_report(st.hid)["agent"]["version"] == "0.1.0"


# ---------------------------------------------------------------------------------------------
# item 5: self-update, then a new agent that cannot report -> the rollback timer restores the old one
# ---------------------------------------------------------------------------------------------
def test_09_self_update_succeeds_and_confirms(world, host, st):
    world.standard_release("0.1.1", components=("collector",))
    comp = world.collector_component("0.1.1")
    world.set_desired(st.hid, "0.1.1", components=[comp])
    wait_for(
        lambda: host.run("readlink /opt/exp/agent/current").out.strip() == "0.1.1",
        180,
        3,
        "agent 0.1.1 to be current",
    )
    wait_for(
        lambda: host.run("exp-agent version").out.strip() == "0.1.1" and host.active("exp-agent.service"),
        60,
        2,
        "agent 0.1.1 to run",
    )
    assert host.run("readlink /opt/exp/agent/previous").out.strip() == "0.1.0"
    # self-update refreshed the standalone checker from the new tree (same bytes, root 0755)
    assert (
        host.run("cmp /opt/exp/agent/rollback-check /opt/exp/agent/0.1.1/lib/exp_agent/rollback_check.py").rc
        == 0
    )
    assert host.run("stat -c '%U:%G %a' /opt/exp/agent/rollback-check").out.strip() == "root:root 755"
    # the new agent reported, so the pending marker is gone
    wait_for(
        lambda: not host.exists("/var/lib/exp/agent/pending.json"), 120, 3, "the pending marker to be cleared"
    )
    wait_for(
        lambda: world.last_report(st.hid)["agent"]["version"] == "0.1.1", 90, 3, "a report from agent 0.1.1"
    )
    wait_for(
        lambda: host.run("readlink /opt/exp/collector/current").out.strip() == "0.1.1",
        150,
        3,
        "the component to follow to 0.1.1",
    )


def test_10_rollback_timer_restores_an_agent_that_cannot_report(world, host, st):
    assert "OnUnitActiveSec=5min" in host.run("systemctl cat exp-agent-rollback.timer").out
    assert host.active("exp-agent-rollback.timer")
    assert (
        "ExecStart=/opt/exp/agent/rollback-check" in host.run("systemctl cat exp-agent-rollback.service").out
    )
    world.standard_release(
        "0.1.2", components=("collector",), stub_agent=True
    )  # starts, never polls or reports
    world.set_desired(st.hid, "0.1.2", components=[world.collector_component("0.1.2")])
    wait_for(
        lambda: host.run("readlink /opt/exp/agent/current").out.strip() == "0.1.2",
        180,
        3,
        "agent 0.1.2 to be current",
    )
    assert host.exists("/var/lib/exp/agent/pending.json")
    assert host.run("readlink /opt/exp/agent/previous").out.strip() == "0.1.1"
    # simulate the 5 minutes passing and shorten the timer (the unit under test is otherwise unchanged)
    host.write(
        "/tmp/backdate.py",
        "import json\np='/var/lib/exp/agent/pending.json'\nd=json.load(open(p))\n"
        "d['started']-=1000\njson.dump(d,open(p,'w'))\n",
    )
    assert host.run("python3 /tmp/backdate.py").rc == 0
    host.run("mkdir -p /etc/systemd/system/exp-agent-rollback.timer.d")
    host.write(
        "/etc/systemd/system/exp-agent-rollback.timer.d/test.conf",
        "[Timer]\nOnBootSec=\nOnUnitActiveSec=\nOnActiveSec=3\nOnUnitActiveSec=5\n",
    )
    host.run("systemctl daemon-reload && systemctl restart exp-agent-rollback.timer")
    wait_for(
        lambda: host.run("readlink /opt/exp/agent/current").out.strip() == "0.1.1",
        90,
        2,
        "the rollback to 0.1.1",
    )
    wait_for(
        lambda: host.active("exp-agent.service") and host.run("exp-agent version").out.strip() == "0.1.1",
        60,
        2,
        "the old agent to be running again",
    )
    assert not host.exists("/var/lib/exp/agent/pending.json")
    # reported, and the bad version is not retried even though the desired state still asks for it
    wait_for(lambda: "agent_rollback" in world.all_text(st.hid), 150, 3, "the agent_rollback report")
    host.run("sleep 15")
    assert host.run("readlink /opt/exp/agent/current").out.strip() == "0.1.1"
    assert host.run("exp-agent status").rc == 0
    # the admin goes back to a good version: the host is healthy again
    world.set_desired(st.hid, "0.1.1", components=[world.collector_component("0.1.1")])
    reports_grow(world, st.hid)
    host.run(
        "rm -rf /etc/systemd/system/exp-agent-rollback.timer.d; systemctl daemon-reload; "
        "systemctl restart exp-agent-rollback.timer"
    )


# ---------------------------------------------------------------------------------------------
# item 7: decommission removes everything
# ---------------------------------------------------------------------------------------------
def test_11_decommission_removes_everything(world, host, st):
    cpid_unit = "exp-collector.service"
    assert host.active(cpid_unit)
    world.set_desired(st.hid, "0.1.1", components=[world.collector_component("0.1.1")], decommission=True)
    wait_for(lambda: world.host(st.hid).state == "removed", 180, 3, "POST decommissioned")
    wait_for(lambda: not host.active("exp-agent.service"), 60, 2, "the agent service to stop")
    assert not host.active(cpid_unit)
    left = host.files_under("/opt/exp", "/etc/exp", "/var/lib/exp", "/run/exp", "/usr/local/bin/exp-*")
    left += host.run(
        "ls -d /etc/systemd/system/exp-* /etc/systemd/system/*.wants/exp-* 2>/dev/null"
    ).out.split()
    assert left == [], left
    assert not host.exists("/etc/exp/agent.json")
    with pytest.raises(fake_manager.ApiError):
        world.app.authenticate(st.secret)


# ---------------------------------------------------------------------------------------------
# item 9: no token patterns anywhere in the journal after a full run
# ---------------------------------------------------------------------------------------------
def test_12_journal_scan_finds_no_token_patterns(world, host, st):
    j = host.journal()
    assert len(j) > 2000, "journal suspiciously empty"
    assert "exp-agent" in j
    # sudo itself logs the command line of the documented one-liner (`sudo bash -s -- expe_...`) to the
    # journal; that is outside the agent's control. Everything else must be clean, and the enrol tokens
    # sudo recorded must by now be spent (single use), so they are harmless to anyone reading the journal.
    sudo_lines = [ln for ln in j.splitlines() if "COMMAND=" in ln and TOKEN_RE.search(ln)]
    rest = "\n".join(ln for ln in j.splitlines() if ln not in sudo_lines)
    assert_no_tokens(rest, "the journal (apart from sudo's own command log)")
    for ln in sudo_lines:
        for tok in TOKEN_RE.findall(ln):
            assert tok.startswith("expe_") and token_used(world, tok), (
                "sudo logged a token that is still usable"
            )
    # what the manager received is clean too
    assert_no_tokens(world.all_text(st.hid), "status reports")
