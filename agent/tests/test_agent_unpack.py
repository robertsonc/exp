"""Safe unpack: every classic archive attack is refused and leaves nothing behind."""

from __future__ import annotations

import gzip
import io
import os
import stat
import tarfile

import pytest
from agent_helpers import Env, build_tar

from exp_agent.artifacts import safe_unpack, stage_and_unpack
from exp_agent.errors import UnsafeArchive, VerifyError

TOP = "exp-probe-0.1.0"


def tgz(members, top=TOP) -> bytes:
    """members: list of (name, kind, kwargs); kind in file|dir|sym|hard|chr|blk|fifo."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        if top:
            d = tarfile.TarInfo(top)
            d.type, d.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(d)
        for name, kind, kw in members:
            ti = tarfile.TarInfo(name)
            ti.mode = kw.get("mode", 0o644)
            data = kw.get("data", b"x")
            if kind == "file":
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
            else:
                ti.type = {
                    "dir": tarfile.DIRTYPE,
                    "sym": tarfile.SYMTYPE,
                    "hard": tarfile.LNKTYPE,
                    "chr": tarfile.CHRTYPE,
                    "blk": tarfile.BLKTYPE,
                    "fifo": tarfile.FIFOTYPE,
                }[kind]
                ti.linkname = kw.get("link", "")
                tar.addfile(ti)
    return buf.getvalue()


def unpack(tmp_path, data: bytes, prefix="exp-probe-"):
    a = tmp_path / "a.tgz"
    a.write_bytes(data)
    dest = tmp_path / "dest"
    dest.mkdir(exist_ok=True)
    safe_unpack(a, dest, prefix)
    return dest


def listing(root):
    return sorted(os.path.relpath(os.path.join(d, n), root) for d, ds, fs in os.walk(root) for n in ds + fs)


def test_good_archive_unpacks_with_safe_modes(tmp_path):
    data = tgz(
        [
            (f"{TOP}/bin", "dir", {"mode": 0o755}),
            (f"{TOP}/bin/exp-probe", "file", {"mode": 0o755, "data": b"#!"}),
            (f"{TOP}/lib/exp_probe/x.py", "file", {"mode": 0o666}),
            (f"{TOP}/bin/alias", "sym", {"link": "exp-probe"}),
            (f"{TOP}/lib/up", "sym", {"link": "../bin/exp-probe"}),
            (f"{TOP}/bin/hard", "hard", {"link": f"{TOP}/bin/exp-probe"}),
        ]
    )
    d = unpack(tmp_path, data)
    assert stat.S_IMODE(os.stat(d / "bin/exp-probe").st_mode) == 0o755
    assert stat.S_IMODE(os.stat(d / "lib/exp_probe/x.py").st_mode) & 0o022 == 0  # group/other write stripped
    assert os.readlink(d / "bin/alias") == "exp-probe" and (d / "bin/hard").read_bytes() == b"#!"
    assert os.path.exists(d / "lib" / "up")


@pytest.mark.parametrize(
    "name,members,expect",
    [
        ("absolute", [("/etc/evil", "file", {})], "absolute"),
        ("dotdot", [(f"{TOP}/../../evil", "file", {})], "'..'"),
        ("dotdot_mid", [(f"{TOP}/a/../../evil", "file", {})], "'..'"),
        ("backslash", [(f"{TOP}\\evil", "file", {})], "unsafe"),
        ("symlink_abs", [(f"{TOP}/l", "sym", {"link": "/etc"})], "absolute"),
        ("symlink_up", [(f"{TOP}/l", "sym", {"link": "../../../etc"})], "escapes"),
        ("symlink_up_from_sub", [(f"{TOP}/a/b/l", "sym", {"link": "../../../x"})], "escapes"),
        (
            "symlink_dotdot_after_name",
            [(f"{TOP}/a", "sym", {"link": "."}), (f"{TOP}/b", "sym", {"link": "a/../.."})],
            "'..' after",
        ),
        (
            "write_through_symlink",
            [(f"{TOP}/l", "sym", {"link": "."}), (f"{TOP}/l/evil", "file", {})],
            "below a symlink",
        ),
        ("hardlink_outside", [(f"{TOP}/h", "hard", {"link": "etc/passwd"})], "outside"),
        ("hardlink_abs", [(f"{TOP}/h", "hard", {"link": "/etc/passwd"})], "absolute"),
        ("hardlink_dotdot", [(f"{TOP}/h", "hard", {"link": f"{TOP}/../../etc/passwd"})], "'..'"),
        ("hardlink_to_nothing", [(f"{TOP}/h", "hard", {"link": f"{TOP}/missing"})], "earlier regular"),
        (
            "hardlink_to_symlink",
            [(f"{TOP}/s", "sym", {"link": "x"}), (f"{TOP}/h", "hard", {"link": f"{TOP}/s"})],
            "earlier regular",
        ),
        ("char_device", [(f"{TOP}/dev", "chr", {})], "special"),
        ("block_device", [(f"{TOP}/dev", "blk", {})], "special"),
        ("fifo", [(f"{TOP}/p", "fifo", {})], "special"),
        ("setuid", [(f"{TOP}/su", "file", {"mode": 0o4755})], "setuid"),
        ("setgid", [(f"{TOP}/sg", "file", {"mode": 0o2755})], "setuid"),
        ("sticky_dir", [(f"{TOP}/d", "dir", {"mode": 0o1777})], "setuid"),
        ("duplicate", [(f"{TOP}/f", "file", {}), (f"{TOP}/f", "file", {})], "duplicate"),
        ("second_top_level", [("other/f", "file", {})], "more than one"),
    ],
)
def test_attacks_refused(tmp_path, name, members, expect):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    with pytest.raises(UnsafeArchive, match=expect):
        unpack(tmp_path, tgz(members))
    assert victim.read_text() == "keep"
    assert not (tmp_path / "evil").exists() and not (tmp_path / "etc").exists()
    assert not any("evil" in p for p in listing(tmp_path / "dest"))


def test_wrong_top_directory_and_garbage_refused(tmp_path):
    with pytest.raises(UnsafeArchive, match="top directory"):
        unpack(tmp_path, tgz([("exp-dashboard-0.1.0/f", "file", {})], top="exp-dashboard-0.1.0"))
    with pytest.raises(UnsafeArchive):
        unpack(tmp_path, b"this is not a tarball")
    with pytest.raises(UnsafeArchive):
        unpack(tmp_path, tgz([], top=None))


def test_non_empty_staging_refused(tmp_path):
    (tmp_path / "dest").mkdir()
    (tmp_path / "dest" / "stale").write_text("x")
    with pytest.raises(UnsafeArchive, match="not empty"):
        unpack(tmp_path, tgz([(f"{TOP}/f", "file", {})]))


def test_unpack_limits_member_count(tmp_path, monkeypatch):
    import exp_agent.artifacts as art

    monkeypatch.setattr(art, "MAX_MEMBERS", 3)
    with pytest.raises(UnsafeArchive, match="too many"):
        unpack(tmp_path, tgz([(f"{TOP}/f{i}", "file", {}) for i in range(5)]))


def test_stage_and_unpack_cleans_up_on_violation_and_verifies_digest_first(tmp_path):
    e = Env(tmp_path)
    try:
        bad = tgz([(f"{TOP}/ok", "file", {}), (f"{TOP}/../../evil", "file", {})])
        e.add_raw_artifact("exp-probe-0.1.0-noarch.tar.gz", "probe", "noarch", bad)
        e.sign_release("0.1.0")
        e.push(e.desired([{**e.comp("probe"), "creds": {}}]))
        a = e.artifacts["exp-probe-0.1.0-noarch.tar.gz"]
        art = {
            "id": a["id"],
            "name": "exp-probe-0.1.0-noarch.tar.gz",
            "url": f"/api/agent/v1/artifacts/{a['id']}",
            "sha256": a["sha256"],
            "size": a["size"],
        }
        entry = {"sha256": a["sha256"], "size": a["size"]}
        parent = e.ctx.paths.comp_opt("probe")
        with pytest.raises(UnsafeArchive):
            stage_and_unpack(e.client, e.ctx.fs, art, entry, "probe", parent)
        assert not parent.exists() or os.listdir(parent) == []
        assert os.listdir(e.ctx.paths.agent_state / "downloads") == []  # download deleted too
        with pytest.raises(VerifyError, match="sha256"):  # digest checked BEFORE unpacking
            stage_and_unpack(e.client, e.ctx.fs, art, {**entry, "sha256": "1" * 64}, "probe", parent)
        assert not parent.exists() or os.listdir(parent) == []
    finally:
        e.close()


@pytest.mark.parametrize(
    "variant", ["tar_slip", "symlink_escape", "hardlink_escape", "device", "setuid", "unknown_symlink_chain"]
)
def test_reconcile_refuses_hostile_artifacts_end_to_end(tmp_path, variant):
    from exp_agent.reconcile import Reconciler

    e = Env(tmp_path)
    try:
        members = {
            "tar_slip": [(f"{TOP}/../../../../pwned", "file", {})],
            "symlink_escape": [
                (f"{TOP}/bin", "sym", {"link": "../../../../../etc"}),
                (f"{TOP}/bin/x", "file", {}),
            ],
            "hardlink_escape": [(f"{TOP}/h", "hard", {"link": "etc/shadow"})],
            "device": [(f"{TOP}/null", "chr", {})],
            "setuid": [(f"{TOP}/bin/exp-probe", "file", {"mode": 0o4755})],
            "unknown_symlink_chain": [(f"{TOP}/a", "sym", {"link": "."}), (f"{TOP}/a/b", "file", {})],
        }[variant]
        e.add_raw_artifact("exp-probe-0.1.0-noarch.tar.gz", "probe", "noarch", tgz(members))
        e.sign_release("0.1.0")
        e.push(e.desired([e.comp("probe")]))
        code, d, _ = e.client.get_desired(None)
        out = Reconciler(e.ctx).run(d)
        assert out.result == "error" and out.permanent
        assert not e.ctx.paths.comp_opt("probe").exists() or os.listdir(e.ctx.paths.comp_opt("probe")) == []
        assert e.runner.mutating() == []
        assert not (tmp_path / "pwned").exists() and not (tmp_path / "root" / "pwned").exists()
    finally:
        e.close()


def test_build_tar_helper_makes_a_valid_artifact(tmp_path):
    d = unpack(tmp_path, build_tar(TOP, {"VERSION": b"1\n", "bin/exp-probe": (b"#!", 0o755)}))
    assert (d / "VERSION").read_bytes() == b"1\n"
