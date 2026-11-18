import json
import os
import stat

import pytest
from exp_common.atomic import AtomicWriteError, atomic_write, atomic_write_json, atomic_write_text


def test_creates_and_replaces_with_mode(tmp_path):
    p = tmp_path / "f"
    atomic_write(p, b"one", 0o600)
    assert p.read_bytes() == b"one" and stat.S_IMODE(p.stat().st_mode) == 0o600
    atomic_write(p, "two", 0o644)
    assert p.read_text() == "two" and stat.S_IMODE(p.stat().st_mode) == 0o644
    assert [x.name for x in tmp_path.iterdir()] == ["f"]        # no temp leftovers


def test_mode_independent_of_umask(tmp_path):
    old = os.umask(0o077)
    try:
        atomic_write(tmp_path / "f", b"x", 0o644)
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "f").stat().st_mode) == 0o644


def test_unicode_text_and_json(tmp_path):
    atomic_write_text(tmp_path / "t", "é€")
    assert (tmp_path / "t").read_text(encoding="utf-8") == "é€"
    atomic_write_json(tmp_path / "j", {"b": 1, "a": [1.5, "é"]})
    txt = (tmp_path / "j").read_text(encoding="utf-8")
    assert txt.endswith("\n") and json.loads(txt) == {"a": [1.5, "é"], "b": 1}
    with pytest.raises(ValueError):
        atomic_write_json(tmp_path / "bad", {"x": float("nan")})
    assert not (tmp_path / "bad").exists()


def test_refuses_symlink_target_and_leaves_victim_untouched(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("precious")
    d = tmp_path / "d"
    d.mkdir()
    os.symlink(victim, d / "target")
    with pytest.raises(AtomicWriteError, match="symlink"):
        atomic_write(d / "target", b"pwned")
    assert victim.read_text() == "precious" and os.path.islink(d / "target")
    assert [x.name for x in d.iterdir()] == ["target"]            # no temp file left behind


def test_refuses_dangling_symlink_target(tmp_path):
    os.symlink(tmp_path / "does-not-exist", tmp_path / "t")
    with pytest.raises(AtomicWriteError):
        atomic_write(tmp_path / "t", b"x")
    assert not (tmp_path / "does-not-exist").exists()


def test_refuses_symlinked_parent_directory(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    os.symlink(real, tmp_path / "linkdir")
    with pytest.raises(AtomicWriteError, match="parent directory"):
        atomic_write(tmp_path / "linkdir" / "f", b"x")
    assert list(real.iterdir()) == []


def test_refuses_directory_or_special_target(tmp_path):
    (tmp_path / "dir").mkdir()
    with pytest.raises(AtomicWriteError, match="not a regular file"):
        atomic_write(tmp_path / "dir", b"x")
    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(AtomicWriteError):
        atomic_write(tmp_path / "fifo", b"x")


def test_missing_parent_and_bad_names(tmp_path):
    with pytest.raises(AtomicWriteError):
        atomic_write(tmp_path / "nodir" / "f", b"x")
    for bad in ("/", str(tmp_path) + "/.."):
        with pytest.raises(AtomicWriteError):
            atomic_write(bad, b"x")
    with pytest.raises(TypeError):
        atomic_write(tmp_path / "f", 5)


def test_pre_planted_temp_names_cannot_hijack(tmp_path, monkeypatch):
    # attacker pre-creates a symlink where our temp file would go: O_EXCL|O_NOFOLLOW must refuse it
    victim = tmp_path / "victim"
    victim.write_text("precious")
    import secrets
    monkeypatch.setattr(secrets, "token_hex", lambda n=None: "deadbeef0000")
    os.symlink(victim, tmp_path / ".f.deadbeef0000.tmp")
    with pytest.raises(AtomicWriteError):
        atomic_write(tmp_path / "f", b"pwned")
    assert victim.read_text() == "precious"


def test_failure_keeps_old_content_and_cleans_temp(tmp_path, monkeypatch):
    p = tmp_path / "f"
    atomic_write(p, b"old")
    def boom(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(AtomicWriteError):
        atomic_write(p, b"new")
    monkeypatch.undo()
    assert p.read_bytes() == b"old" and [x.name for x in tmp_path.iterdir()] == ["f"]


def test_large_payload_roundtrip(tmp_path):
    data = os.urandom(3_000_000)
    atomic_write(tmp_path / "big", data)
    assert (tmp_path / "big").read_bytes() == data
