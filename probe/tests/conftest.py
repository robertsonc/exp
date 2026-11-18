"""Test plumbing: import paths, the fake command runner, a fake clock."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for p in (str(ROOT / "probe"), str(ROOT / "shared" / "python"), str(ROOT / "test" / "fakes"),
          str(Path(__file__).resolve().parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from fakes import FakeClock, FakeIp  # noqa: E402

from exp_probe.config import Paths, parse_config  # noqa: E402

FIXTURES = ROOT / "test" / "fixtures" / "configs"


def make_config(ports=None, mode="netns", mgmt="mgmt0", collector=None, **extra):
    doc = {"schema": "exp.probe.config/1", "probe_id": "probe-t1", "site": "hall-b", "collector": collector,
           "mode": mode, "mgmt_iface": mgmt,
           "ports": ports or [{"id": "c01", "iface": "t0", "role": "client"},
                              {"id": "c02", "iface": "t1", "role": "client"}]}
    doc.update(extra)
    return parse_config(doc)


@pytest.fixture
def paths(tmp_path):
    p = Paths(state_dir=tmp_path / "state", run_dir=tmp_path / "run", etc_netns=tmp_path / "etc-netns",
              sys_class_net=tmp_path / "sys-net", proc=tmp_path / "proc")
    p.state_dir.mkdir()
    p.run_dir.mkdir()
    return p


@pytest.fixture
def ip():
    return FakeIp()


@pytest.fixture
def clock():
    return FakeClock()
