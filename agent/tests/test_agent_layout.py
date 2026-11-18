"""bin/exp-agent works in the dev tree AND in the tarball layout (<prefix>/{bin,lib,vendor,VERSION})."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}  # no PYTHONPATH: the script must find its libs
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True, env=env, timeout=60
    )


def test_dev_tree_layout():
    r = run(REPO / "agent" / "bin" / "exp-agent", "version")
    assert r.returncode == 0 and r.stdout.strip() == (REPO / "VERSION").read_text().strip()
    assert (REPO / "agent" / "bin" / "exp-agent").stat().st_mode & 0o111
    assert (REPO / "agent" / "bin" / "exp-agent").read_text().startswith("#!/usr/bin/python3")


def test_tarball_layout(tmp_path):
    prefix = tmp_path / "exp-agent-9.9.9"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "lib").mkdir()
    (prefix / "vendor").mkdir()
    (prefix / "VERSION").write_text("9.9.9\n")
    shutil.copy(REPO / "agent" / "bin" / "exp-agent", prefix / "bin" / "exp-agent")
    shutil.copytree(
        REPO / "agent" / "exp_agent",
        prefix / "lib" / "exp_agent",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(
        REPO / "shared" / "python" / "exp_common",
        prefix / "lib" / "exp_common",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(REPO / "shared" / "schemas", prefix / "lib" / "exp_common" / "schemas")
    r = run(prefix / "bin" / "exp-agent", "version")
    assert r.returncode == 0 and r.stdout.strip() == "9.9.9", r.stderr
    # selftest finds the packaged schemas and works from the tarball tree
    r = run(prefix / "bin" / "exp-agent", "--root", str(tmp_path / "root"), "selftest")
    assert "ok   schemas" in r.stdout and "ok   safe unpack" in r.stdout, r.stdout + r.stderr


def test_health_json_cli_contract_from_the_entry_script(tmp_path):
    r = run(REPO / "agent" / "bin" / "exp-agent", "--root", str(tmp_path / "root"), "health", "--json")
    assert r.returncode == 1 and '"schema": "exp.health/1"' in r.stdout
