"""Config and credentials loading."""
from __future__ import annotations

import json
import os

import pytest
from exp_common import config as exp_config
from exp_common import ids as exp_ids
from rthelpers import FIX, base_config, load_fixture, secret

from exp_runner.config import CredStore, Paths, RunnerConfigError, load_config, parse_config


def write(tmp_path, doc, name="config.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def test_correlation_fixture_loads_with_defaults(tmp_path):
    cfg = load_config(FIX / "configs" / "runner.correlation.json")
    assert cfg.correlation_enabled and cfg.runner_id == "run-core" and cfg.site == "hall-b"
    assert (cfg.window_before_s, cfg.window_after_s, cfg.poll_interval_s) == (300, 120, 5)
    assert cfg.syslog.listen == (("udp", 5514), ("tcp", 5514), ("tls", 6514))
    assert cfg.syslog.ring_minutes == 60 and cfg.syslog.max_line_bytes == 4096
    assert cfg.channel_url == "http://127.0.0.1:8480/local/v1"
    assert cfg.mist and cfg.mist["max_calls_per_test"] == 6 and cfg.ec and cfg.ec["max_flows"] == 50


def test_plain_m5_runner_config_means_no_correlation():
    cfg = load_config(FIX / "configs" / "runner.json")
    assert cfg.correlation_enabled is False


def test_drill_fields_are_ignored_with_one_log_line(caplog):
    caplog.set_level("WARNING")
    cfg = load_config(FIX / "configs" / "runner.json")
    assert cfg.drills_enabled in (True, False)
    msgs = [r.getMessage() for r in caplog.records if "drill" in r.getMessage()]
    assert len(msgs) <= 1


@pytest.mark.parametrize("name", sorted(p.name for p in (FIX / "invalid" / "configs").glob("runner-*.json")))
def test_invalid_runner_configs_are_refused(name):
    with pytest.raises((exp_config.ConfigError, RunnerConfigError)):
        load_config(FIX / "invalid" / "configs" / name)


def test_privileged_syslog_port_is_refused(tmp_path):
    doc = base_config()
    doc["correlation"]["sources"]["syslog"]["listen"] = ["udp:514"]
    with pytest.raises(RunnerConfigError, match="privileged"):
        parse_config(doc)
    p = write(tmp_path, doc)
    with pytest.raises(RunnerConfigError):
        load_config(p)


def test_network_block_is_validated_and_parsed():
    cfg = parse_config(base_config())
    assert cfg.network.require_real_client_ip is True
    assert "10.0.0.2" in cfg.network.translated_addresses and len(cfg.network.zone_subnets) == 2

def test_bad_network_cidr_is_refused(tmp_path):
    bad = base_config()
    bad["correlation"]["network"]["client_subnets"] = ["not-a-cidr"]
    with pytest.raises(exp_config.ConfigError):
        load_config(write(tmp_path, bad))


def test_empty_allowlist_is_kept_empty():
    doc = base_config()
    doc["correlation"]["sources"]["syslog"]["allow"] = []
    assert parse_config(doc).syslog.allow == ()


def test_paths_resolve_and_syslog_db_override(tmp_path, monkeypatch):
    monkeypatch.delenv("STATE_DIRECTORY", raising=False)
    monkeypatch.delenv("RUNTIME_DIRECTORY", raising=False)
    p = Paths.resolve(None, None, None, None)
    assert str(p.syslog_db) == "/var/lib/exp/runner/syslog.db" and str(p.run_dir) == "/run/exp/runner"
    q = Paths.resolve(str(tmp_path / "s"), str(tmp_path / "r"), str(tmp_path / "c"), str(tmp_path / "x.db"))
    assert q.syslog_db == tmp_path / "x.db" and q.state_dir == tmp_path / "s"
    monkeypatch.setenv("STATE_DIRECTORY", str(tmp_path / "env-state"))
    assert Paths.resolve().state_dir == tmp_path / "env-state"


def make_creds(tmp_path, **files):
    d = tmp_path / "creds"
    d.mkdir(exist_ok=True)
    for name, content in files.items():
        (d / name.replace("__", ".")).write_text(content)
    return d


def test_creds_load_and_validate_formats(tmp_path):
    d = make_creds(tmp_path, collector_token=exp_ids.new_token("expr"), speedtest_channel_token=exp_ids.new_token("expl") + "\n",
                   device_key_secret=secret(),
                   integrations__json=json.dumps({"mist": {"api_base": "https://api.example.invalid", "token": "t"},
                                                  "ec": {"url": "https://orch.example.invalid", "api_key": "k"},
                                                  "sse": {"url": "https://sse.example.invalid", "token": "nope"}}))
    c = CredStore(d)
    assert c.collector_token().startswith("expr_") and c.channel_token().startswith("expl_") and c.device_key_secret().startswith("expk_")
    ints = c.integrations()
    assert set(ints) == {"mist", "ec"}            # never an SSE entry
    assert ints["mist"] == {"api_base": "https://api.example.invalid", "token": "t"}


def test_wrong_prefix_tokens_are_rejected(tmp_path):
    d = make_creds(tmp_path, collector_token=exp_ids.new_token("expi"), speedtest_channel_token="expl_short", device_key_secret="expr_x")
    c = CredStore(d)
    assert c.collector_token() is None and c.channel_token() is None and c.device_key_secret() is None


def test_missing_for_lists_every_gap(tmp_path):
    cfg = parse_config(load_fixture("configs/runner.correlation.json"))
    c = CredStore(make_creds(tmp_path))
    miss = " ".join(c.missing_for(cfg))
    for want in ("collector_token", "device_key_secret", "speedtest_channel_token", "mist", "ec"):
        assert want in miss
    # correlation disabled -> nothing is required
    doc = base_config()
    doc["correlation"]["enabled"] = False
    assert CredStore(make_creds(tmp_path)).missing_for(parse_config(doc)) == []


def test_symlinked_credential_is_refused(tmp_path):
    d = make_creds(tmp_path)
    target = tmp_path / "elsewhere"
    target.write_text(exp_ids.new_token("expr"))
    os.symlink(target, d / "collector_token")
    assert CredStore(d).collector_token() is None


def test_bad_integrations_json_is_ignored(tmp_path):
    d = make_creds(tmp_path, integrations__json="{not json")
    assert CredStore(d).integrations() == {}
    assert CredStore(None).collector_token() is None
