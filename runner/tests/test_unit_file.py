"""The systemd unit and the packaging convention for the runner."""
from __future__ import annotations

from pathlib import Path

RUNNER = Path(__file__).resolve().parents[1]
UNIT = (RUNNER / "systemd" / "exp-runner.service").read_text()


def test_convention_files_exist():
    assert (RUNNER / "bin" / "exp-runner").is_file() and (RUNNER / "exp_runner" / "__init__.py").is_file()
    assert (RUNNER / "requirements.apt").read_text().split() == ["openssl"]


def test_unit_runs_unprivileged_with_loadcredential_and_no_capabilities():
    assert "User=exp-runner" in UNIT and "CapabilityBoundingSet=\n" in UNIT and "AmbientCapabilities=\n" in UNIT
    assert "NoNewPrivileges=yes" in UNIT and "ProtectSystem=strict" in UNIT
    for cred in ("collector_token", "speedtest_channel_token", "device_key_secret", "integrations.json", "syslog_tls.crt", "syslog_tls.key"):
        assert f"LoadCredential={cred}:@CREDS@/{cred}" in UNIT
    assert "StateDirectory=exp/runner" in UNIT and "RuntimeDirectory=exp/runner" in UNIT
    assert "ExecStart=@PREFIX@/bin/exp-runner run --config @CONFIG@" in UNIT


def test_unit_has_no_shell_and_no_secret_in_environment():
    assert "/bin/sh" not in UNIT and "Environment=" not in UNIT and "token=" not in UNIT.lower()
