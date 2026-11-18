"""06-agent.md section 9 item 3 (and the install-time half of item 8): a release the agent cannot verify
is refused end to end by install.sh and nothing is installed or started."""

from __future__ import annotations

import io
import tarfile

import pytest
from harness import agent_files, build_tar, pubkey_of, run_install


def slip(tar: tarfile.TarFile) -> None:
    ti = tarfile.TarInfo("exp-agent-0.1.0/../../../../tmp/exp-evil")
    ti.size = 4
    tar.addfile(ti, io.BytesIO(b"evil"))


def symlink_out(tar: tarfile.TarFile) -> None:
    ti = tarfile.TarInfo("exp-agent-0.1.0/lib/escape")
    ti.type, ti.linkname = tarfile.SYMTYPE, "/etc"
    tar.addfile(ti)


def setuid(tar: tarfile.TarFile) -> None:
    ti = tarfile.TarInfo("exp-agent-0.1.0/bin/suid-helper")
    ti.size, ti.mode = 3, 0o4755
    tar.addfile(ti, io.BytesIO(b"x\n\n"))


def device(tar: tarfile.TarFile) -> None:
    ti = tarfile.TarInfo("exp-agent-0.1.0/lib/null")
    ti.type, ti.devmajor, ti.devminor = tarfile.CHRTYPE, 1, 3
    tar.addfile(ti)


# name -> (publish kwargs, extra tar member writer, expected message fragment)
VARIANTS = {
    "tampered-manifest": ({"tamper_manifest": True}, None, "signature verification FAILED"),
    "wrong-signing-key": ({"wrong_key": True}, None, "signature verification FAILED"),
    "wrong-sha256": ({"corrupt": True}, None, "sha256 does not match"),
    "tar-slip": ({}, slip, "unsafe path"),
    "symlink-member": ({}, symlink_out, "link or special file"),
    "device-member": ({}, device, "link or special file"),
    "setuid-member": ({}, setuid, "setuid/setgid/sticky"),
}


@pytest.mark.parametrize("variant", sorted(VARIANTS))
def test_unverifiable_release_is_refused_and_nothing_is_installed(world, host24, tmp_path, variant):
    opts, extra, message = VARIANTS[variant]
    host24.reset_host()
    files = agent_files("0.1.0")
    artifact = build_tar("exp-agent-0.1.0", files, extra=extra)
    kw = {}
    if opts.get("tamper_manifest"):
        kw["tamper_manifest"] = True
    if opts.get("wrong_key"):
        kw["signing_key"], _ = pubkey_of(tmp_path / "other-key")
    if opts.get("corrupt"):
        kw["corrupt_artifact"] = "exp-agent-0.1.0-noarch.tar.gz"
    world.publish_release("0.1.0", [("agent", "0.1.0", "noarch", artifact)], **kw)
    hid, token = world.add_host(f"srv-{variant}")
    world.set_desired(hid, "0.1.0")
    r = run_install(host24, world, token)
    assert r.rc != 0, r
    assert message in r.err, r
    assert "installed and running" not in r.text
    # nothing was installed or started: no files below the roots, no units, no agent process
    assert host24.files_under("/opt/exp", "/var/lib/exp", "/usr/local/bin/exp-agent") == []
    assert host24.run("ls -d /opt/exp/agent/.staging-* /opt/exp/agent/current 2>/dev/null").out == ""
    assert host24.run("ls /etc/systemd/system/exp-* 2>/dev/null").out == ""
    assert not host24.active("exp-agent.service") and host24.run("pgrep -f exp-agent").rc != 0
    assert not host24.exists("/tmp/exp-evil") and not host24.exists("/etc/exp-evil")
    assert host24.run("ls /tmp | grep -c exp-install").out.strip() == "0", (
        "installer temp dir was not cleaned up"
    )


def test_after_the_release_is_fixed_a_rerun_without_a_token_repairs(world, host24):
    host24.reset_host()
    world.standard_release("0.1.0", tamper_manifest=True)
    hid, token = world.add_host("srv-fixit")
    world.set_desired(hid, "0.1.0")
    r = run_install(host24, world, token)
    assert r.rc != 0 and "signature verification FAILED" in r.err
    # the token was consumed by the enrolment; the credentials are kept so that a re-run can repair
    assert host24.run("stat -c '%U:%G %a' /etc/exp/agent.json").out.strip() == "root:root 600"
    world.standard_release("0.1.0")  # the release is re-published correctly
    r = run_install(host24, world)  # no token
    assert r.rc == 0, r
    assert host24.active("exp-agent.service")
    assert host24.run("readlink /opt/exp/agent/current").out.strip() == "0.1.0"


def test_a_desired_state_below_min_agent_version_is_refused(world, host24):
    host24.reset_host()
    world.standard_release("0.1.0", min_agent="0.9.0")
    hid, token = world.add_host("srv-minagent")
    world.set_desired(hid, "0.1.0")
    r = run_install(host24, world, token)
    assert r.rc != 0 and "min_agent_version" in r.err
    assert host24.files_under("/opt/exp", "/var/lib/exp") == []
