"""exp.probe.config/1 loading: schema + cross-field rules; the probe refuses an invalid config."""
from __future__ import annotations

import json
import shutil

import pytest
from conftest import FIXTURES, make_config
from exp_common.config import ConfigError

from exp_probe import cli
from exp_probe.config import load_probe_config, parse_config


@pytest.mark.parametrize("name", ["probe.json", "probe.collector-null.json", "probe.host-mode.json", "probe.wifi.json"])
def test_fixture_configs_load(name):
    cfg = load_probe_config(FIXTURES / name)
    assert cfg.probe_id and cfg.ports


def test_collector_null_means_measure_and_spool():
    cfg = load_probe_config(FIXTURES / "probe.collector-null.json")
    assert cfg.collector is None
    assert cfg.heartbeat["interval_s"] == 10 and cfg.heartbeat["trace"]["pace_ms"] == 20


def test_defaults_applied():
    cfg = make_config()
    assert (cfg.spool_max_mb, cfg.spool_max_days) == (500, 7)
    assert cfg.heartbeat["dns_names"] and cfg.heartbeat["gateway"] is True
    assert cfg.control_path is True


def test_dhcp_identity_has_no_personal_data():
    cfg = make_config(ports=[{"id": "c01", "iface": "t0", "role": "client"}])
    d = cfg.dhcp_params(cfg.ports[0])
    assert d == {"hostname": "exp-probe-t1-c01", "vendor_class": "exp-probe", "client_id": "mac"}


def _bad(**over):
    doc = json.loads((FIXTURES / "probe.json").read_text())
    doc.update(over)
    return doc


def test_duplicate_port_ids_and_ifaces_refused():
    doc = _bad(ports=[{"id": "c01", "iface": "a0", "role": "client"}, {"id": "c01", "iface": "a1", "role": "client"}])
    with pytest.raises(ConfigError, match="duplicate port id"):
        parse_config(doc)
    doc = _bad(ports=[{"id": "c01", "iface": "a0", "role": "client"}, {"id": "c02", "iface": "a0", "role": "client"}])
    with pytest.raises(ConfigError, match="more than one port"):
        parse_config(doc)


def test_port_on_mgmt_iface_refused():
    doc = _bad(mgmt_iface="enp10s0f0")
    with pytest.raises(ConfigError, match="management interface"):
        parse_config(doc)


def test_host_mode_rules():
    base = json.loads((FIXTURES / "probe.host-mode.json").read_text())
    two = {**base, "ports": base["ports"] + [{"id": "c02", "iface": "ens224", "role": "client"}]}
    with pytest.raises(ConfigError, match="exactly one port"):
        parse_config(two)
    shared = {**base, "ports": [{"id": "c01", "iface": base["mgmt_iface"], "role": "client"}]}
    with pytest.raises(ConfigError, match="management interface"):
        parse_config(shared)
    cfg = parse_config({**shared, "allow_shared": True})       # explicit opt-in, host mode only
    assert cfg.allow_shared and cfg.control_path is False        # control-path traceroute disabled
    with pytest.raises(ConfigError):                              # allow_shared means nothing in netns mode
        parse_config(_bad(mgmt_iface="enp10s0f0", allow_shared=True))


def test_schema_violations_listed():
    with pytest.raises(ConfigError) as ei:
        parse_config(_bad(probe_id="Bad ID", mode="bridge"))
    assert len(ei.value.errors) >= 2


def test_unknown_port_lookup():
    with pytest.raises(ConfigError, match="unknown port"):
        make_config().port("nope")


def test_cli_refuses_to_start_on_invalid_config(tmp_path, capsys):
    bad = tmp_path / "config.json"
    bad.write_text(json.dumps(_bad(mgmt_iface="enp10s0f0")))
    for cmd in (["run"], ["preflight"], ["netns", "up"], ["netns", "down"], ["lease", "c01"], ["spool", "stat"]):
        with pytest.raises(SystemExit) as ei:
            cli.main([*cmd, "--config", str(bad), "--state-dir", str(tmp_path), "--run-dir", str(tmp_path)])
        assert ei.value.code == 78, cmd
    assert "refusing to start" in capsys.readouterr().err


def test_cli_missing_config_refused(tmp_path, capsys):
    with pytest.raises(SystemExit) as ei:
        cli.main(["preflight", "--config", str(tmp_path / "nope.json")])
    assert ei.value.code == 78


def test_cli_trailing_garbage_config_refused(tmp_path):
    p = tmp_path / "c.json"
    shutil.copy(FIXTURES / "probe.json", p)
    p.write_text(p.read_text() + "garbage")
    with pytest.raises(SystemExit):
        cli.main(["preflight", "--config", str(p)])
