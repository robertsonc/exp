"""Fixtures for the M6 "core" acceptance suite (A6.1 A6.2 A6.3 A6.7 A6.9 A6.11). See m6lib.py.

Env: EXP_E2E_DIST + EXP_E2E_PUBKEY (an existing signed release; else 0.2.0 is built with a throwaway key),
EXP_E2E_ARTIFACTS (screenshots and logs, under <dir>/m6), EXP_E2E_KEEP=1 (leave the containers up).
The stack is session-scoped: the tests run in file order against one installed all-in-one box."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import m6lib


def _problem() -> str | None:
    if not shutil.which("docker"):
        return "docker is not installed"
    r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30)  # noqa: S603,S607
    if r.returncode != 0:
        return "docker daemon unavailable: " + (r.stderr.strip()[-200:] or "docker info failed")
    if not shutil.which("node") or subprocess.run(["node", "-e", "require('playwright')"], capture_output=True, timeout=60, env=m6lib.node_env()).returncode != 0:  # noqa: S603,S607
        return "node + playwright are not available"
    if not shutil.which("nsenter") or not shutil.which("unshare"):
        return "nsenter/unshare are not available"
    return None


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e: end-to-end acceptance test (privileged Docker harness)")


@pytest.fixture(scope="session")
def release(tmp_path_factory: pytest.TempPathFactory):
    why = _problem()
    if why:
        pytest.skip(why)
    return m6lib.find_release(tmp_path_factory.mktemp("release"))


@pytest.fixture(scope="session")
def artifacts() -> Path:
    m6lib.ARTIFACTS.mkdir(parents=True, exist_ok=True)
    return m6lib.ARTIFACTS


@pytest.fixture(scope="session")
def core(release, artifacts: Path, tmp_path_factory: pytest.TempPathFactory):
    st = None
    try:
        work = tmp_path_factory.mktemp("work-core")
        st = m6lib.attach(release, work, artifacts) if os.environ.get("EXP_E2E_REUSE") == "1" else None
        if st is None:
            st = m6lib.bring_up(release, work, artifacts)
        yield st
    finally:
        if st is not None:
            try:
                st.stop_clients()
                st.save_logs("final")
            except Exception as exc:  # noqa: BLE001  logs are best effort; never mask the test result
                print(f"could not save logs: {exc}")
        if os.environ.get("EXP_E2E_KEEP") != "1":
            m6lib.tear_down()


@pytest.fixture()
def phone(core: m6lib.Core):
    """A fresh attendee device (DHCP lease from the LAN) known to the fake Mist and the fake Orchestrator."""
    c = core.new_client(f"p{len(core.clients) + 1}")
    core.fake("mist", "POST", "/_fake/reset")
    core.fake("mist", "POST", "/_fake/scenario", {"name": "healthy", "ip": c.ip, "mac": c.mac})
    core.fake("orch", "POST", "/_fake/scenario", {"name": "healthy", "client_ip": c.ip})
    yield c
