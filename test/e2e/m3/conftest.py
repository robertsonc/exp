"""Fixtures for the M3 multi-site acceptance suite (A3.1 federation, A3.2 webhooks). See m3lib.py.

Env: EXP_E2E_DIST + EXP_E2E_PUBKEY (an existing signed release; else one is built with a throwaway key),
EXP_E2E_ARTIFACTS (screenshots and logs, under <dir>/m3), EXP_E2E_KEEP=1 (leave the containers up).
The multisite stack is session-scoped: the tests run in file order and share one running installation (A3.1
starts the probes and times the green board, A3.2 then drives faults on it)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import m3lib


def _docker_problem() -> str | None:
    if not shutil.which("docker"):
        return "docker is not installed"
    r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30)  # noqa: S603,S607
    return None if r.returncode == 0 else "docker daemon unavailable: " + (r.stderr.strip()[-200:] or "docker info failed")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e: end-to-end acceptance test (privileged Docker harness)")


@pytest.fixture(scope="session")
def release(tmp_path_factory: pytest.TempPathFactory) -> m3lib.L.Release:
    why = _docker_problem()
    if why:
        pytest.skip(why)
    return m3lib.L.find_release(tmp_path_factory.mktemp("release"))


@pytest.fixture(scope="session")
def artifacts() -> Path:
    m3lib.ARTIFACTS.mkdir(parents=True, exist_ok=True)
    return m3lib.ARTIFACTS


@pytest.fixture(scope="session")
def stack(release: m3lib.L.Release, artifacts: Path, tmp_path_factory: pytest.TempPathFactory):
    st = None
    try:
        st = m3lib.bring_up(release, tmp_path_factory.mktemp("work-multisite"), artifacts)
        yield st
    finally:
        if st is not None:
            try:
                st.save_logs("final")
            except Exception as exc:  # noqa: BLE001  logs are best effort; never mask the test result
                print(f"could not save logs: {exc}")
        if os.environ.get("EXP_E2E_KEEP") != "1":
            m3lib.tear_down()
