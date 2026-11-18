"""systemd unit templates and the packaging convention (collector/ layout)."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

COLLECTOR = Path(__file__).resolve().parents[1]
UNITS = sorted((COLLECTOR / "systemd").glob("*"))
PLACEHOLDERS = {"@VERSION@", "@PREFIX@", "@CONFIG@", "@CREDS@", "@STATE@", "@RUN@"}
APT_ALLOW = {"busybox", "busybox-static", "iproute2", "iputils-ping", "iperf3", "curl", "openssl",
             "ca-certificates", "ethtool", "iw", "wpasupplicant", "tcpdump"}


def read(name: str) -> str:
    return (COLLECTOR / "systemd" / name).read_text()


def test_expected_units_exist_and_are_named_exp_star():
    assert [u.name for u in UNITS] == ["exp-collector.service", "exp-iperf3.service", "exp-reflector.service",
                                       "exp-victoriametrics.service"]


@pytest.mark.parametrize("unit", UNITS, ids=lambda u: u.name)
def test_only_known_placeholders_and_no_config_interpolation(unit):
    text = unit.read_text()
    used = set(re.findall(r"@[A-Z]+@", text))
    assert used <= PLACEHOLDERS, used - PLACEHOLDERS
    for line in text.splitlines():
        if line.startswith("ExecStart="):
            assert "$" not in line and ";" not in line and "|" not in line and "&&" not in line
            assert line.startswith("ExecStart=@PREFIX@/bin/exp-collector ") and "--config @CONFIG@" in line
    assert "sh -c" not in text and "bash" not in text


@pytest.mark.parametrize("unit", UNITS, ids=lambda u: u.name)
def test_hardening_baseline(unit):
    text = unit.read_text()
    for directive in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                      "PrivateDevices=yes", "RestrictSUIDSGID=yes", "ProtectKernelModules=yes", "LockPersonality=yes",
                      "CapabilityBoundingSet=", "SystemCallFilter=@system-service", "UMask=0077",
                      "RestrictNamespaces=yes", "ProtectControlGroups=yes"):
        assert directive in text, f"{unit.name} lacks {directive}"
    assert re.search(r"^User=exp-(collector|vm)$", text, re.M)


def test_collector_unit_credentials_state_and_ordering():
    t = read("exp-collector.service")
    for name in ("ingest_tokens.json", "dashboard_tokens.json", "webhooks.json"):
        assert f"LoadCredential={name}:@CREDS@/{name}" in t
    assert "User=exp-collector" in t and "StateDirectory=exp/collector" in t and "RuntimeDirectory=exp/collector" in t
    assert "ExecStart=@PREFIX@/bin/exp-collector run --config @CONFIG@" in t
    assert "exp-victoriametrics.service" in t
    assert "AmbientCapabilities=\n" in t          # port 8443: no CAP_NET_BIND_SERVICE
    assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" in t


def test_vm_unit_runs_as_exp_vm_loopback_only_with_config_derived_args():
    t = read("exp-victoriametrics.service")
    assert "User=exp-vm" in t
    assert "ExecStart=@PREFIX@/bin/exp-collector vm-exec --config @CONFIG@ --state-dir @STATE@" in t
    assert "IPAddressDeny=any" in t and "IPAddressAllow=localhost" in t
    for flag in ("-httpListenAddr=127.0.0.1:8428", "-storageDataPath=@STATE@/vm", "-search.maxQueryDuration=10s",
                 "-search.maxSeries=500", "-retentionPeriod=", "-memory.allowedPercent="):
        assert flag in t                              # documented in the unit comments
    assert "ReadWritePaths=@STATE@/vm" in t


def test_reflector_and_iperf3_units():
    r = read("exp-reflector.service")
    assert "ExecStart=@PREFIX@/bin/exp-collector reflector --config @CONFIG@" in r
    i = read("exp-iperf3.service")
    assert "User=exp-collector" in i and "iperf3-exec" in i and "5201" in i


def test_requirements_apt_follows_the_agent_allowlist():
    lines = [ln.strip() for ln in (COLLECTOR / "requirements.apt").read_text().splitlines() if ln.strip()]
    assert lines == ["iperf3"] and set(lines) <= APT_ALLOW


def test_entry_script_is_executable_with_the_conventional_shebang():
    exe = COLLECTOR / "bin" / "exp-collector"
    assert os.access(exe, os.X_OK)
    assert exe.read_text().splitlines()[0] == "#!/usr/bin/python3"


def test_entry_script_supports_the_tarball_layout(tmp_path):
    """bin/ + lib/ + vendor/ beside each other -> sys.path uses ../lib and ../vendor."""
    root = tmp_path / "exp-collector-0.1.0"
    (root / "bin").mkdir(parents=True)
    shutil.copy(COLLECTOR / "bin" / "exp-collector", root / "bin" / "exp-collector")
    shutil.copytree(COLLECTOR / "exp_collector", root / "lib" / "exp_collector", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(COLLECTOR.parent / "shared" / "python" / "exp_common", root / "lib" / "exp_common",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(COLLECTOR.parent / "shared" / "schemas", root / "lib" / "exp_common" / "schemas")
    (root / "vendor").mkdir()
    (root / "VERSION").write_text("9.9.9\n")
    (root / "lib" / "exp_collector" / "VERSION").write_text("9.9.9\n")
    import sys
    r = subprocess.run([sys.executable, str(root / "bin" / "exp-collector"), "version"], capture_output=True,
                       text=True, timeout=20, env={"PATH": os.environ["PATH"]})
    assert r.returncode == 0 and r.stdout.strip() == "exp-collector 9.9.9", r.stderr


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze not installed")
@pytest.mark.parametrize("unit", UNITS, ids=lambda u: u.name)
def test_systemd_analyze_accepts_rendered_units(unit, tmp_path):
    text = unit.read_text()
    for k, v in {"@VERSION@": "0.1.0", "@PREFIX@": "/opt/exp/collector/0.1.0", "@CONFIG@": "/etc/exp/collector/config.json",
                 "@CREDS@": "/etc/exp/collector/creds", "@STATE@": "/var/lib/exp/collector",
                 "@RUN@": "/run/exp/collector"}.items():
        text = text.replace(k, v)
    out = tmp_path / unit.name
    out.write_text(text)
    r = subprocess.run(["systemd-analyze", "verify", "--man=no", str(out)], capture_output=True, text=True, timeout=30)
    problems = [ln for ln in (r.stdout + r.stderr).splitlines()
                if ln.strip() and "is not executable" not in ln and "Failed to create" not in ln
                and "No such file" not in ln and "not found" not in ln.lower()]
    assert not problems, problems
