"""Fixtures for the M1 acceptance suite. See m1lib.py for what a "stack" is.

Env: EXP_E2E_LAYOUTS (default "all,split"), EXP_E2E_DIST + EXP_E2E_PUBKEY (an existing signed release; else one is
built with a throwaway key), EXP_E2E_ARTIFACTS (screenshots and logs), EXP_E2E_KEEP=1 (leave the containers up)."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

import m1lib


def _docker_problem() -> str | None:
    if not shutil.which("docker"):
        return "docker is not installed"
    r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True, timeout=30)  # noqa: S603,S607
    return None if r.returncode == 0 else "docker daemon unavailable: " + (r.stderr.strip()[-200:] or "docker info failed")


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "e2e: end-to-end acceptance test (privileged Docker harness)")


@pytest.fixture(scope="session")
def release(tmp_path_factory: pytest.TempPathFactory) -> m1lib.Release:
    why = _docker_problem()
    if why:
        pytest.skip(why)
    return m1lib.find_release(tmp_path_factory.mktemp("release"))


@pytest.fixture(scope="session")
def artifacts() -> Path:
    m1lib.ARTIFACTS.mkdir(parents=True, exist_ok=True)
    return m1lib.ARTIFACTS


@pytest.fixture(
    scope="module",
    params=[x for x in os.environ.get("EXP_E2E_LAYOUTS", "all,split").split(",") if x],
    ids=lambda p: f"layout-{p}",
)
def stack(request: pytest.FixtureRequest, release: m1lib.Release, artifacts: Path,
          tmp_path_factory: pytest.TempPathFactory):
    layout = request.param
    st = None
    try:
        st = m1lib.bring_up(layout, release, tmp_path_factory.mktemp(f"work-{layout}"))
        st.log_dir = artifacts / layout
        st.log_dir.mkdir(parents=True, exist_ok=True)
        yield st
    finally:
        if st is not None:
            try:
                st.log_dir.mkdir(parents=True, exist_ok=True)
                st.save_logs("final")
            except Exception as exc:  # noqa: BLE001  logs are best effort; never mask the test result
                print(f"could not save logs: {exc}")
        if os.environ.get("EXP_E2E_KEEP") != "1":
            m1lib.tear_down()
