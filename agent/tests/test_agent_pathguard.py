"""One path guard: allowed roots only; every mutation attempt outside them is refused."""

from __future__ import annotations

import os
import stat

import pytest

from exp_agent.errors import PathRefused
from exp_agent.pathguard import Paths, SafeFS


@pytest.fixture
def fs(tmp_path):
    root = tmp_path / "root"
    (root / "etc" / "systemd" / "system").mkdir(parents=True)
    return SafeFS(Paths(root, uid=os.geteuid(), gid=os.getegid()), lambda p, u, g: None)


@pytest.mark.parametrize(
    "logical",
    [
        "/opt/exp",
        "/opt/exp/probe/0.1.0/bin/exp-probe",
        "/etc/exp/agent.json",
        "/etc/exp/collector/creds/x",
        "/var/lib/exp/agent/state.json",
        "/run/exp/probe",
        "/etc/systemd/system/exp-probe.service",
        "/etc/systemd/system/exp-probe-lease@c01.service",
        "/etc/systemd/system/exp-agent-rollback.timer",
        "/usr/local/bin/exp-probe",
    ],
)
def test_allowed(fs, logical):
    assert fs.g(fs.paths.host(logical))


@pytest.mark.parametrize(
    "logical",
    [
        "/",
        "/etc",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/cron.d/x",
        "/etc/systemd/system/evil.service",
        "/etc/systemd/system/exp-x.conf",
        "/etc/systemd/system/exp-x.service.d/override.conf",
        "/etc/systemd/system/sub/exp-x.service",
        "/usr/local/bin/other",
        "/usr/bin/exp-probe",
        "/opt",
        "/opt/other",
        "/opt/expx/y",
        "/var/lib/other",
        "/var/lib/expx",
        "/root/.ssh/authorized_keys",
        "/etc/expx/config",
    ],
)
def test_outside_roots_refused(fs, logical):
    with pytest.raises(PathRefused):
        fs.g(fs.paths.host(logical))


def test_dotdot_relative_and_nul_refused(fs):
    root = fs.paths.root
    for bad in (
        f"{root}/opt/exp/../../etc/passwd",
        f"{root}/opt/exp/probe/../../../x",
        "opt/exp/x",
        "relative",
        f"{root}/opt/exp/a\x00b",
        f"{root}/etc/exp/../passwd",
    ):
        with pytest.raises(PathRefused):
            fs.g(bad)


def test_outside_the_agent_root_refused(fs, tmp_path):
    with pytest.raises(PathRefused):
        fs.g(tmp_path / "elsewhere" / "opt" / "exp" / "x")


def test_symlink_escaping_the_roots_is_refused_for_every_operation(fs, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "victim").write_text("keep")
    fs.mkdir(fs.paths.opt)
    os.symlink(outside, fs.paths.opt / "evil")  # /opt/exp/evil -> outside the roots
    os.symlink("/etc/passwd", fs.paths.opt / "pw")
    with pytest.raises(PathRefused):
        fs.write(fs.paths.opt / "evil" / "x", b"pwn")
    with pytest.raises(PathRefused):
        fs.mkdir(fs.paths.opt / "evil" / "sub")
    with pytest.raises(PathRefused):
        fs.rmtree(fs.paths.opt / "evil")
    with pytest.raises(PathRefused):
        fs.read_bytes(fs.paths.opt / "pw")
    with pytest.raises(PathRefused):
        fs.listdir(fs.paths.opt / "evil")
    assert (outside / "victim").read_text() == "keep" and not (outside / "x").exists()


def test_protected_roots_cannot_be_removed(fs):
    fs.mkdir(fs.paths.opt)
    for p in (fs.paths.opt, fs.paths.etc, fs.paths.var, fs.paths.run, fs.paths.systemd, fs.paths.usr_bin):
        with pytest.raises(PathRefused):
            fs.rmtree(p)


def test_symlink_targets_must_be_relative_and_inside(fs):
    fs.mkdir(fs.paths.opt / "probe")
    with pytest.raises(PathRefused):
        fs.symlink("/etc/passwd", fs.paths.opt / "probe" / "current")
    with pytest.raises(PathRefused):
        fs.symlink("../../../../etc", fs.paths.opt / "probe" / "current")
    fs.mkdir(fs.paths.opt / "probe" / "1.0.0")
    fs.symlink("1.0.0", fs.paths.opt / "probe" / "current")
    assert os.readlink(fs.paths.opt / "probe" / "current") == "1.0.0"


def test_lchown_only_in_root_owned_non_writable_parent_and_never_a_symlink(fs, tmp_path):
    calls: list = []
    fs2 = SafeFS(fs.paths, lambda p, u, g: calls.append((p, u, g)))
    d = fs2.mkdir(fs.paths.var / "collector" / "tls", 0o755)
    f = d / "key.pem"
    f.write_text("k")
    fs2.lchown(f, 1234, 1234)
    assert calls and calls[0][1:] == (1234, 1234)
    os.symlink("/etc/passwd", d / "ln")
    with pytest.raises(PathRefused):
        fs2.lchown(d / "ln", 1, 1)
    os.chmod(d, 0o777)  # a service-writable parent: refused
    with pytest.raises(PathRefused):
        fs2.lchown(f, 1234, 1234)
    assert len(calls) == 1
    os.chmod(d, 0o755)


def test_unit_and_component_names_are_validated(fs):
    with pytest.raises(PathRefused):
        fs.paths.unit("evil.service")
    with pytest.raises(PathRefused):
        fs.paths.comp_opt("../etc")
    with pytest.raises(PathRefused):
        fs.paths.version_dir("probe", "../../x")
    assert stat.S_ISDIR(os.lstat(fs.mkdir(fs.paths.etc_dir("probe"))).st_mode)
