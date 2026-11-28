"""systemd unit templates and packaging conventions (agreed between WP-1, WP-6, WP-7)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import ROOT

UNITS = ROOT / "probe" / "systemd"
AGENT_ALLOWLIST = {"busybox", "busybox-static", "iproute2", "iputils-ping", "iperf3", "curl", "openssl",
                   "ca-certificates", "ethtool", "iw", "wpasupplicant", "tcpdump"}
PLACEHOLDERS = {"@VERSION@", "@PREFIX@", "@CONFIG@", "@CREDS@", "@STATE@", "@RUN@"}


def parse(path: Path) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ln in path.read_text().splitlines():
        if ln.strip() and not ln.startswith(("#", "[")) and "=" in ln:
            k, v = ln.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def test_expected_units_exist():
    assert {p.name for p in UNITS.iterdir()} == {"exp-probe-netns.service", "exp-probe-lease@.service",
                                                  "exp-probe-target@.service", "exp-probe-wifi@.service",
                                                  "exp-probe.service"}
    assert all(re.fullmatch(r"exp-[a-z-]+(@)?\.(service|timer)", p.name) for p in UNITS.iterdir())


@pytest.mark.parametrize("unit", sorted(p.name for p in UNITS.iterdir()))
def test_only_known_placeholders_and_no_config_interpolation(unit):
    text = (UNITS / unit).read_text()
    assert set(re.findall(r"@[A-Z]+@", text)) <= PLACEHOLDERS
    u = parse(UNITS / unit)
    assert u["ExecStart"][0].startswith("@PREFIX@/bin/exp-probe ")
    assert "--config @CONFIG@" in u["ExecStart"][0]
    assert not re.search(r"\$\{|\$\(|`|;|\|", "\n".join(u["ExecStart"]))        # nothing from the config is interpolated
    rendered = text
    for ph, val in {"@VERSION@": "1.2.3", "@PREFIX@": "/opt/exp/probe/1.2.3", "@CONFIG@": "/etc/exp/probe/config.json",
                    "@CREDS@": "/etc/exp/probe/creds", "@STATE@": "/var/lib/exp/probe", "@RUN@": "/run/exp/probe"}.items():
        rendered = rendered.replace(ph, val)
    assert "@" not in re.sub(r"%i|@\.service", "", rendered.replace("exp-probe-lease@", "").replace("exp-probe-target@", ""))


def test_netns_unit_is_oneshot_and_returns_ports_on_stop():
    u = parse(UNITS / "exp-probe-netns.service")
    assert u["Type"] == ["oneshot"] and u["RemainAfterExit"] == ["yes"]
    assert " netns up " in u["ExecStart"][0] and " netns down " in u["ExecStop"][0]


def test_lease_unit_is_per_port_and_releases_on_stop():
    u = parse(UNITS / "exp-probe-lease@.service")
    assert "lease %i" in u["ExecStart"][0] and u["Restart"] == ["always"]
    assert u["Requires"] == ["exp-probe-netns.service"] and u["PartOf"] == ["exp-probe-netns.service"]


def test_target_unit_is_an_m4_stub_that_does_not_restart():
    u = parse(UNITS / "exp-probe-target@.service")
    assert "target serve %i" in u["ExecStart"][0] and u["Restart"] == ["no"]


def test_wifi_unit_is_per_port_and_runs_before_its_lease():
    u = parse(UNITS / "exp-probe-wifi@.service")
    assert "wifi %i" in u["ExecStart"][0] and u["Restart"] == ["always"] and u["NoNewPrivileges"] == ["yes"]
    assert u["Requires"] == ["exp-probe-netns.service"] and u["PartOf"] == ["exp-probe-netns.service"]
    assert u["Before"] == ["exp-probe-lease@%i.service"]


def test_daemon_unit_hardening_exactly_as_the_spec():
    u = parse(UNITS / "exp-probe.service")
    assert u["ProtectSystem"] == ["strict"] and u["NoNewPrivileges"] == ["yes"] and u["PrivateTmp"] == ["yes"]
    assert u["ReadWritePaths"] == ["@STATE@ @RUN@"]
    assert u["LoadCredential"] == ["ingest_token:@CREDS@/ingest_token"]
    assert "ProtectHome" in u and u["Restart"] == ["always"] and "exp-probe-netns.service" in u["Requires"][0]


def test_requirements_apt_uses_only_allowlisted_packages():
    pkgs = [ln.strip() for ln in (ROOT / "probe" / "requirements.apt").read_text().splitlines() if ln.strip()]
    assert set(pkgs) == {"busybox", "iproute2", "iputils-ping", "curl", "openssl", "iperf3", "iw", "wpasupplicant"}
    assert set(pkgs) <= AGENT_ALLOWLIST
