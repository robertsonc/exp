"""CLI surface, entry script in both layouts, M4 stubs."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest
from conftest import FIXTURES, ROOT, make_config
from fakes import FakeIp

from exp_probe import cli, scheduler
from exp_probe.spool import Spool

BIN = ROOT / "probe" / "bin" / "exp-probe"


def run_bin(path, *args, cwd=None):
    return subprocess.run([sys.executable, str(path), *args], capture_output=True, text=True, timeout=60, cwd=cwd)


@pytest.fixture
def cfgfile(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(make_config().raw))
    return p


def args(cfgfile, paths):
    return ["--config", str(cfgfile), "--state-dir", str(paths.state_dir), "--run-dir", str(paths.run_dir),
            "--etc-netns", str(paths.etc_netns)]


def test_entry_script_in_the_dev_tree():
    assert BIN.stat().st_mode & 0o111
    assert BIN.read_text().startswith("#!/usr/bin/python3")
    r = run_bin(BIN, "version")
    assert r.returncode == 0 and r.stdout.startswith("exp-probe ")
    r = run_bin(BIN, "selftest")
    assert r.returncode == 0 and "FAIL" not in r.stdout and "PASS spool" in r.stdout


def test_entry_script_in_the_tarball_layout(tmp_path):
    top = tmp_path / "exp-probe-0.0.1"
    (top / "bin").mkdir(parents=True)
    (top / "vendor").mkdir()
    shutil.copy(BIN, top / "bin" / "exp-probe")
    shutil.copytree(ROOT / "probe" / "exp_probe", top / "lib" / "exp_probe", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "shared" / "python" / "exp_common", top / "lib" / "exp_common",
                    ignore=shutil.ignore_patterns("__pycache__", "tests"))
    shutil.copytree(ROOT / "shared" / "schemas", top / "lib" / "exp_common" / "schemas")
    (top / "VERSION").write_text("0.0.1\n")
    # run from a directory where the repo is NOT importable, so only lib/ can satisfy the imports
    r = run_bin(top / "bin" / "exp-probe", "version", cwd=tmp_path)
    assert r.returncode == 0 and r.stdout.strip() == "exp-probe 0.0.1", r.stderr
    r = run_bin(top / "bin" / "exp-probe", "health", "--json", "--config", str(FIXTURES / "probe.collector-null.json"),
                "--run-dir", str(tmp_path / "run"), "--state-dir", str(tmp_path / "st"), cwd=tmp_path)
    doc = json.loads(r.stdout)                                  # config validated against the packaged schemas
    assert r.returncode == 1 and doc["schema"] == "exp.health/1" and "daemon is not running" in doc["detail"]


def test_version_and_health_need_no_valid_config(capsys):
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.startswith("exp-probe ")


def test_target_commands_are_m4_stubs(cfgfile, paths, capsys):
    for action in (["set", "s01", "--http-status", "500", "--for", "5m"], ["clear", "s01"], ["serve", "s01"]):
        assert cli.main(["target", *action, *args(cfgfile, paths)]) == 69
        assert "M4" in capsys.readouterr().err


def test_test_command_with_unavailable_test(cfgfile, paths, capsys):
    saved = dict(scheduler.REGISTRY)
    scheduler.REGISTRY.clear()
    try:
        assert cli.main(["test", "wifi_hb", "--port", "c01", "--once", *args(cfgfile, paths)]) == 2
        assert "not available in this build" in capsys.readouterr().err
    finally:
        scheduler.REGISTRY.update(saved)


def test_test_command_runs_a_registered_test_without_spooling(cfgfile, paths, capsys):
    from exp_probe.checks import register_all
    register_all()                                  # load the real modules first, then override one
    saved = dict(scheduler.REGISTRY)
    scheduler.register_test("gateway", lambda ctx: [ctx.measure("gateway", "ok", metrics={"rtt_ms": 2.0},
                                                                labels={"iface": ctx.port.iface})])
    try:
        assert cli.main(["test", "gateway", "--port", "c01", "--once", *args(cfgfile, paths)]) == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["test"] == "gateway" and doc["labels"] == {"port": "c01", "iface": "t0"} and doc["probe"] == "probe-t1"
        assert not paths.spool_db.exists()                                       # not spooled
        assert cli.main(["test", "gateway", "--port", "nope", *args(cfgfile, paths)]) == 2
    finally:
        scheduler.REGISTRY.clear()
        scheduler.REGISTRY.update(saved)


def test_spool_stat(cfgfile, paths, capsys):
    assert cli.main(["spool", "stat", *args(cfgfile, paths)]) == 1
    Spool(paths.spool_db).close()
    assert cli.main(["spool", "stat", "--json", *args(cfgfile, paths)]) == 0
    assert json.loads(capsys.readouterr().out)["depth"] == 0


def test_netns_up_down_via_cli(cfgfile, paths, capsys):
    ip = FakeIp()
    ip.add_host_link("t0", up=True, virtual=True)
    ip.add_host_link("t1", up=True, virtual=True)
    assert cli.main(["netns", "up", "--wait-s", "0", *args(cfgfile, paths)], runner=ip) == 0
    assert set(ip.ns) == {"", "exp-c01", "exp-c02"}
    assert cli.main(["netns", "down", *args(cfgfile, paths)], runner=ip) == 0
    assert ip.host_names() == {"t0", "t1"} and set(ip.ns) == {""}
    ip.mutations.clear()
    ip.ns[""]["t0"].addrs = ["10.0.0.9/24"]                                      # now a port has an address
    assert cli.main(["netns", "up", "--wait-s", "0", *args(cfgfile, paths)], runner=ip) == 1
    err = capsys.readouterr().err
    assert "carries address" in err and "nothing was changed" in err and ip.mutations == []


def test_netns_down_reports_a_stuck_port(cfgfile, paths, capsys):
    ip = FakeIp()
    ip.add_host_link("t0", up=True, virtual=True)
    ip.add_host_link("t1", up=True, virtual=True)
    cli.main(["netns", "up", "--wait-s", "0", *args(cfgfile, paths)], runner=ip)
    ip.fail_move_back = {"t1"}
    assert cli.main(["netns", "down", *args(cfgfile, paths)], runner=ip) == 1
    assert "exp-c02" in capsys.readouterr().err and "exp-c02" in ip.ns


def test_lease_command_refuses_without_namespace(cfgfile, paths, capsys):
    assert cli.main(["lease", "c01", *args(cfgfile, paths)], runner=FakeIp()) == 3
    assert "does not exist" in capsys.readouterr().err


def test_udhcpc_hook_command(cfgfile, paths, monkeypatch):
    for k, v in {"interface": "t0", "ip": "10.1.0.5", "mask": "24", "router": "10.1.0.1", "dns": "10.1.0.1"}.items():
        monkeypatch.setenv(k, v)
    assert cli.main(["udhcpc-hook", "bound", *args(cfgfile, paths)], runner=FakeIp()) == 0
    assert json.loads(paths.lease_file("c01").read_text())["ip"] == "10.1.0.5"


def test_every_unit_command_accepts_config():
    for sub in ("run", "health", "version", "selftest", "preflight", "test", "spool", "netns", "lease"):
        ns = cli.build_parser().parse_args([sub, *({"test": ["gateway", "--port", "c01"], "spool": ["stat"],
                                                    "netns": ["up"], "lease": ["c01"]}.get(sub, [])),
                                            "--config", "/x/y.json"])
        assert ns.config == "/x/y.json"
