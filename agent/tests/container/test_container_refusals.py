"""install.sh preflight: refuses with a clear reason and changes nothing (06-agent.md section 1).

Plain (non-systemd) containers and one systemd host; the manager must never see an enrolment attempt
(the token stays unused) and nothing may be created under /etc/exp, /opt/exp or /var/lib/exp.
"""

from __future__ import annotations

import pytest
from harness import REPO, Container, World, ensure_image, run_install, token_used


@pytest.fixture(scope="module")
def plain(world: World):
    reason = ensure_image("24.04")
    if reason:
        pytest.skip(reason)
    c = Container("24.04", systemd=False, ca_pem=world.ca_pem)
    c.run(f"curl -fsSL {world.url}/install.sh -o /tmp/install.sh && chmod 644 /tmp/install.sh")
    yield c
    c.remove()


def untouched(c: Container) -> None:
    assert (
        c.run("ls /etc/exp /opt/exp /var/lib/exp /etc/systemd/system/exp-* 2>&1 | grep -v 'No such file'").out
        == ""
    )


def test_refuses_without_systemd_as_pid1_and_leaves_the_token_unused(world, plain):
    hid, token = world.add_host("srv-nosd")
    r = plain.run(f"bash /tmp/install.sh {token}")
    assert r.rc != 0 and "systemd is not PID 1" in r.err
    assert not token_used(world, token)
    untouched(plain)


def test_refuses_to_run_as_non_root(world, plain):
    hid, token = world.add_host("srv-nonroot")
    r = plain.run(f"runuser -u nobody -- bash /tmp/install.sh {token}")
    assert r.rc != 0 and "must run as root" in r.err
    assert not token_used(world, token)
    untouched(plain)


@pytest.mark.parametrize(
    "os_id,version",
    [("ubuntu", "20.04"), ("debian", "11"), ("raspbian", "12")],
    ids=["ubuntu20.04", "debian11", "raspbian12-32bit"],
)
def test_refuses_an_unsupported_os(world, plain, os_id, version):
    hid, token = world.add_host(f"srv-os-{os_id}{version.replace('.', '')}")
    plain.run(
        "cp /etc/os-release /tmp/os-release.bak; "
        f"sed -i -e 's/^ID=.*/ID={os_id}/' -e 's/^VERSION_ID=.*/VERSION_ID=\"{version}\"/' /etc/os-release"
    )
    try:
        r = plain.run(f"bash /tmp/install.sh {token}")
    finally:
        plain.run("cp /tmp/os-release.bak /etc/os-release")
    assert r.rc != 0 and f"unsupported OS '{os_id} {version}'" in r.err, r
    assert "Ubuntu 22.04/24.04 or Debian 12 (incl. Raspberry Pi OS 64-bit)" in r.err, r
    assert not token_used(world, token)
    untouched(plain)


@pytest.mark.parametrize(
    "bad", ["not-a-token", "expe_short", "expa_" + "A" * 43, "expe_" + "A" * 43 + "x;rm -rf /"]
)
def test_refuses_a_malformed_token_before_doing_anything(plain, bad):
    r = plain.run(f"bash /tmp/install.sh '{bad}'")
    assert r.rc != 0 and "does not look like an enrol token" in r.err
    untouched(plain)


def test_refuses_to_run_with_unsubstituted_placeholders(plain):
    raw = (REPO / "agent/install/install.sh").read_text()
    plain.write("/tmp/raw-install.sh", raw)
    r = plain.run("bash /tmp/raw-install.sh expe_" + "A" * 43)
    assert r.rc != 0 and "unsubstituted placeholders" in r.err
    # a single leftover placeholder is enough
    half = raw.replace("@@MANAGER_URL@@", "https://exp-manager.test").replace("@@AGENT_VERSION@@", "0.1.0")
    plain.write("/tmp/half-install.sh", half)
    r = plain.run("bash /tmp/half-install.sh expe_" + "A" * 43)
    assert r.rc != 0 and "unsubstituted placeholders" in r.err
    untouched(plain)


def test_no_token_and_no_terminal_is_refused(world, plain):
    r = plain.run("bash /tmp/install.sh </dev/null")
    assert r.rc != 0 and "no enrol token given" in r.err
    untouched(plain)


def test_unreachable_manager_and_untrusted_certificate_are_refused(world, host24):
    hid, token = world.add_host("srv-net")
    host24.reset_host()
    # a manager that does not answer
    dead = world.serve_install_sh(manager_url="https://exp-manager.test:9")
    host24.write("/tmp/dead.sh", dead.read_text())
    r = host24.run(f"bash /tmp/dead.sh {token}")
    assert r.rc != 0 and "cannot reach https://exp-manager.test:9" in r.err
    # a manager whose certificate the system does not trust (the test CA is removed from the trust store)
    good = world.serve_install_sh()
    host24.write("/tmp/good.sh", good.read_text())
    host24.run(
        "rm /usr/local/share/ca-certificates/exp-test-ca.crt && update-ca-certificates --fresh >/dev/null 2>&1"
    )
    try:
        r = host24.run(f"bash /tmp/good.sh {token}")
    finally:
        host24.install_ca(world.ca_pem)
    assert r.rc != 0 and "cannot reach" in r.err and "certificate" in r.err.lower()
    assert not token_used(world, token)
    untouched(host24)


def test_a_wrong_token_is_reported_without_changing_the_host(world, host24):
    host24.reset_host()
    world.standard_release("0.1.0")
    hid, _ = world.add_host("srv-badtok")
    fake = "expe_" + "A" * 43
    r = run_install(host24, world, fake)
    assert r.rc != 0 and "does not know this enrol token" in r.err
    untouched(host24)
