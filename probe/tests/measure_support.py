"""Builders shared by the measurement-test unit tests."""
from __future__ import annotations

from typing import Any

from conftest import make_config
from fakes import FakeClock
from netfakes import FakeEnv, ScriptRunner, link_rules, net_factory

from exp_probe.config import Paths
from exp_probe.lease import write_lease
from exp_probe.scheduler import TestContext

PORTS2 = [{"id": "c01", "iface": "t0", "role": "client"}, {"id": "c02", "iface": "t1", "role": "client"}]
BOUND = {"state": "bound", "ip": "10.1.0.31", "prefix": 24, "router": ["10.1.0.1"], "dns": ["10.1.0.2"],
         "serverid": "10.1.0.2", "lease_s": 598}


def make_ctx(tmp_path: Any, *, ports: list[dict[str, Any]] | None = None, leased: tuple[str, ...] = ("c01", "c02"),
             lease_doc: dict[str, Any] | None = None, env: FakeEnv | None = None, control: FakeEnv | None = None,
             runner: ScriptRunner | None = None, port_id: str = "c01", path: str = "", explicit: bool = False,
             beat_ts: float = 1_000_000.0, mode: str = "netns", **cfg_extra: Any) -> TestContext:
    cfg = make_config(ports=ports or PORTS2, mode=mode, **cfg_extra)
    paths = Paths(state_dir=tmp_path / "state", run_dir=tmp_path / "run", etc_netns=tmp_path / "etc",
                  sys_class_net=tmp_path / "sys", proc=tmp_path / "proc")
    paths.state_dir.mkdir(exist_ok=True)
    paths.run_dir.mkdir(exist_ok=True)
    for p in cfg.ports:
        if p.id in leased:
            write_lease(paths, p, dict(lease_doc or BOUND))
    r = runner or ScriptRunner()
    if runner is None:
        for p in cfg.ports:
            link_rules(r, p.iface)
    env = env or FakeEnv()
    return TestContext(cfg, paths, r, FakeClock(beat_ts), cfg.port(port_id), path, beat_ts, explicit,
                       net_factory(env, control))
