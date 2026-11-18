"""Unit regression tests for the container harness itself (no docker needed).

Defect covered: docker's `/` is a private mount, so systemd's per-unit credentials mount
(LoadCredential=) silently vanished from service namespaces; the harness must make `/` rshared
right after boot and must be able to probe whether credentials are deliverable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "container"))
harness = pytest.importorskip("harness")


def _cp(argv: list[str], rc: int = 0, out: str = "running\n") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, rc, out, "")


def test_systemd_container_makes_root_mount_shared_after_boot(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_sh(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return _cp(argv)

    monkeypatch.setattr(harness, "sh", fake_sh)
    harness.Container("24.04", systemd=True)
    execs = [a[-1] for a in calls if a[:2] == ["docker", "exec"]]
    boot = next(i for i, c in enumerate(execs) if "is-system-running" in c)
    shared = next(i for i, c in enumerate(execs) if "mount --make-rshared /" in c)
    assert shared > boot


def test_credentials_supported_follows_systemd_run_result(monkeypatch: pytest.MonkeyPatch) -> None:
    rcs = iter([0, 0, 0, 1])

    def fake_sh(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        return _cp(argv, rc=next(rcs, 0))

    monkeypatch.setattr(harness, "sh", fake_sh)
    c = harness.Container.__new__(harness.Container)
    c.name = "x"
    seen: list[str] = []
    orig = c.run

    def run(cmd: str, **kw: Any) -> Any:
        seen.append(cmd)
        return orig(cmd, **kw)

    c.run = run  # type: ignore[method-assign]
    c.write = lambda p, t: None  # type: ignore[method-assign]
    assert c.credentials_supported() is True  # write(stub), chmod rc 0, systemd-run rc 0
    assert any("LoadCredential=x:/root/credprobe" in s and "CREDENTIALS_DIRECTORY" in s for s in seen)
