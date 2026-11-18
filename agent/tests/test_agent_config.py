"""/etc/exp/agent.json: safe reading, validation, no secret leakage."""

from __future__ import annotations

import json
import os

import pytest
from exp_common import ids as exp_ids

from exp_agent.config import (
    AgentConfig,
    AgentConfigError,
    load_agent_config,
    normalise_manager_url,
    save_agent_config,
)
from exp_agent.pathguard import Paths, SafeFS

GOOD = {
    "manager_url": "https://exp.example.com",
    "agent_id": "h_01M7R3X9G0F9XWWWZD2QJPV03C",
    "agent_secret": "expa_" + "A" * 43,
    "release_pubkey_pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
}


@pytest.fixture
def paths(tmp_path):
    p = Paths(tmp_path / "root", uid=os.geteuid(), gid=os.getegid())
    p.etc.mkdir(parents=True)
    return p


def write(paths, doc, mode=0o600):
    paths.agent_json.write_text(json.dumps(doc))
    os.chmod(paths.agent_json, mode)


def test_loads_a_good_config(paths):
    write(paths, GOOD)
    cfg = load_agent_config(paths)
    assert cfg.agent_id == GOOD["agent_id"] and cfg.manager_url == "https://exp.example.com"
    assert GOOD["agent_secret"] not in repr(cfg) and "hidden" in repr(cfg)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
def test_too_open_mode_refused(paths, mode):
    write(paths, GOOD, mode)
    with pytest.raises(AgentConfigError) as e:
        load_agent_config(paths)
    assert "0600" in str(e.value) and GOOD["agent_secret"] not in str(e.value)


def test_symlink_refused(paths, tmp_path):
    real = tmp_path / "real.json"
    real.write_text(json.dumps(GOOD))
    os.chmod(real, 0o600)
    os.symlink(real, paths.agent_json)
    with pytest.raises(AgentConfigError, match="symlink"):
        load_agent_config(paths)


def test_wrong_owner_refused(paths):
    write(paths, GOOD)
    other = Paths(paths.root, uid=os.geteuid() + 1)
    with pytest.raises(AgentConfigError, match="owned by"):
        load_agent_config(other)


def test_missing_and_invalid_documents(paths):
    with pytest.raises(AgentConfigError, match="not found"):
        load_agent_config(paths)
    for bad in (
        {**GOOD, "agent_secret": "nope"},
        {**GOOD, "agent_id": "x"},
        {k: v for k, v in GOOD.items() if k != "manager_url"},
        {**GOOD, "extra": 1},
        {**GOOD, "release_pubkey_pem": "x"},
    ):
        write(paths, bad)
        with pytest.raises(AgentConfigError):
            load_agent_config(paths)
    paths.agent_json.write_text("{not json")
    os.chmod(paths.agent_json, 0o600)
    with pytest.raises(AgentConfigError):
        load_agent_config(paths)


@pytest.mark.parametrize(
    "url",
    [
        "http://exp.example.com",
        "ftp://x",
        "https://u:p@exp.example.com",
        "https://x/y",
        "https://x?q=1",
        "https://",
        "exp.example.com",
        "https://bad host",
    ],
)
def test_manager_url_must_be_a_plain_https_origin(url):
    with pytest.raises(AgentConfigError):
        normalise_manager_url(url)


def test_manager_url_normalised():
    assert normalise_manager_url("https://Exp.Example.com:8443/") == "https://exp.example.com:8443"
    assert normalise_manager_url("http://127.0.0.1:5", allow_http=True) == "http://127.0.0.1:5"


def test_save_is_atomic_0600_and_roundtrips(paths):
    fs = SafeFS(paths)
    cfg = AgentConfig(
        GOOD["manager_url"], GOOD["agent_id"], exp_ids.new_token("expa"), GOOD["release_pubkey_pem"]
    )
    save_agent_config(fs, cfg)
    assert os.stat(paths.agent_json).st_mode & 0o777 == 0o600
    assert load_agent_config(paths).agent_secret == cfg.agent_secret
    with pytest.raises(AgentConfigError):
        save_agent_config(
            fs, AgentConfig(GOOD["manager_url"], GOOD["agent_id"], "bad", GOOD["release_pubkey_pem"])
        )
