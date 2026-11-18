"""Fixtures/helpers for the real-namespace tests (imported by test_real_namespaces.py).

They create veth pairs and namespaces, so they only run inside the privileged container started by run.sh
(EXP_HARNESS=1) -- never on a developer's host. (Not a conftest.py: a second conftest module would shadow
probe/tests/conftest.py.)"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
for p in (str(ROOT / "probe"), str(ROOT / "shared" / "python")):
    if p not in sys.path:
        sys.path.insert(0, p)

from exp_probe.config import Paths, parse_config  # noqa: E402
from exp_probe.runner import CommandRunner  # noqa: E402

BIN = ROOT / "probe" / "bin" / "exp-probe"


@pytest.fixture(autouse=True)
def _real_environment():
    if os.environ.get("EXP_HARNESS") != "1":
        pytest.skip("real-namespace tests run only via probe/tests/harness/run.sh (EXP_HARNESS=1)")
    if os.geteuid() != 0 or not shutil.which("ip"):
        pytest.skip("needs root and iproute2")


@pytest.fixture
def run():
    runner = CommandRunner()

    def sh(*argv, check=True, timeout=20):
        r = runner.run(list(argv), timeout)
        if check and not r.ok:
            raise AssertionError(f"{argv} failed rc={r.rc}: {r.stderr}")
        return r
    return sh


@pytest.fixture
def net(run):
    """Factory for veth ports: net.veth('c01') -> host interface 'hv-c01' (the port) with peer 'hv-c01p'."""
    made: list[str] = []

    class Net:
        def veth(self, name, peer_addr=None):
            run("ip", "link", "add", f"hv-{name}", "type", "veth", "peer", "name", f"hv-{name}p")
            made.append(f"hv-{name}")
            run("ip", "link", "set", f"hv-{name}", "up")
            run("ip", "link", "set", f"hv-{name}p", "up")
            if peer_addr:
                run("ip", "addr", "add", peer_addr, "dev", f"hv-{name}p")
            return f"hv-{name}"

        def host_has(self, iface):
            return run("ip", "link", "show", "dev", iface, check=False).ok

        def ns_names(self):
            return {ln.split()[0] for ln in run("ip", "netns", "list").stdout.splitlines() if ln.strip()}

        def snapshot(self):
            """Host-visible link/address state that a refusal must leave untouched."""
            links = json.loads(run("ip", "-j", "-d", "link", "show").stdout)
            addrs = json.loads(run("ip", "-j", "addr", "show").stdout)
            return (sorted((x["ifname"], tuple(x.get("flags", [])), x.get("master"), x.get("operstate")) for x in links),
                    sorted((x["ifname"], tuple((a["local"], a["prefixlen"]) for a in x.get("addr_info", [])))
                           for x in addrs), self.ns_names())
    n = Net()
    yield n
    for ns in [x for x in n.ns_names() if x.startswith("exp-")]:
        run("ip", "netns", "del", ns, check=False)
    for name in made + ["hv-br0", "hv-bond0"]:
        run("ip", "link", "del", name, check=False)
    run("ip", "link", "del", "hv-def", check=False)


@pytest.fixture
def paths(tmp_path):
    p = Paths(state_dir=tmp_path / "state", run_dir=tmp_path / "run", etc_netns=Path("/etc/netns"))
    p.state_dir.mkdir()
    p.run_dir.mkdir()
    return p


def make_cfg(ports, mgmt="eth0", mode="netns"):
    return parse_config({"schema": "exp.probe.config/1", "probe_id": "probe-h1", "site": "lab", "collector": None,
                         "mode": mode, "mgmt_iface": mgmt,
                         "ports": [{"id": pid, "iface": iface, "role": "client"} for pid, iface in ports]})


def wait_for(fn, timeout=15.0, step=0.2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(step)
    return None


def cli(*args, **kw):
    return subprocess.run([sys.executable, str(BIN), *args], capture_output=True, text=True, timeout=60, **kw)
