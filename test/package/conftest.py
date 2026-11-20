"""Fixtures for the packaging tests: STUB component trees in tmp dirs (never the real components),
a throwaway Ed25519 key, and a pre-seeded vendor cache (no network)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from pkg_common import COMPONENTS, EPOCH, PKG, REPO, VERIFY, VERSION, make_wheel, sha  # noqa: F401,E402

BUILD = PKG / "build.sh"


@pytest.fixture()
def stub(tmp_path: Path) -> dict:
    """Returns dict(repo, lock, cache, key, pub, run) for a stub source tree."""
    repo = tmp_path / "repo"
    (repo / "shared" / "schemas").mkdir(parents=True)
    (repo / "shared" / "schemas" / "common.schema.json").write_text('{"$defs": {}}\n')
    (repo / "shared" / "schemas" / "manifest.schema.json").write_text('{"type": "object"}\n')
    ec = repo / "shared" / "python" / "exp_common"
    (ec / "__pycache__").mkdir(parents=True)
    (ec / "__pycache__" / "x.cpython-310.pyc").write_bytes(b"junk")
    (ec / "__init__.py").write_text('"""stub exp_common"""\n')
    (ec / "config.py").write_text("X = 1\n")
    (repo / "VERSION").write_text(VERSION + "\n")
    for c in COMPONENTS:
        d = repo / c
        (d / ("exp_" + c) / "tests").mkdir(parents=True)
        (d / ("exp_" + c) / "static").mkdir()
        (d / ("exp_" + c) / "__pycache__").mkdir()
        (d / ("exp_" + c) / "__init__.py").write_text("")
        # the real speedtest imports dnspython (DNS-leg authority): the stub does too, so the build must vendor it
        (d / ("exp_" + c) / "cli.py").write_text(("import dns\n" if c == "speedtest" else "") + "def main():\n    return 0\n")
        (d / ("exp_" + c) / "static" / "app.js").write_text("// asset\n")
        (d / ("exp_" + c) / "tests" / "test_x.py").write_text("def test_x():\n    pass\n")
        (d / ("exp_" + c) / "__pycache__" / "cli.cpython-310.pyc").write_bytes(b"junk")
        (d / "tests").mkdir()
        (d / "tests" / "test_y.py").write_text("")
        (d / "bin").mkdir()
        b = d / "bin" / ("exp-" + c)
        b.write_text("#!/usr/bin/python3\nimport sys\nsys.exit(0)\n")
        b.chmod(0o700)  # deliberately odd mode: must be normalized
        (d / "systemd").mkdir()
        (d / "systemd" / ("exp-%s.service" % c)).write_text(
            "[Service]\nExecStart=@PREFIX@/bin/exp-%s run --config @CONFIG@\n" % c)
        (d / "systemd" / ("exp-%s.service" % c)).chmod(0o600)
        (d / "requirements.apt").write_text("# none needed\ncurl\n" if c == "agent" else "")
        (d / "README.md").write_text("# " + c + "\n")

    cache = tmp_path / "cache"
    wheel = tmp_path / "stubdns-1.0-py3-none-any.whl"
    make_wheel(wheel)
    items = []
    wb = wheel.read_bytes()
    wd = cache / "stubdns-1.0-noarch" / sha(wb)
    wd.mkdir(parents=True)
    (wd / wheel.name).write_bytes(wb)
    items.append({"name": "stubdns", "version": "1.0", "kind": "wheel", "component": "probe",
                  "arch": "noarch", "file": wheel.name, "sha256": sha(wb), "license": "ISC",
                  "sources": [{"type": "url", "url": "https://invalid.example/stubdns.whl"}]})
    items.append({**items[0], "component": "speedtest"})  # the same pinned wheel serves two components
    for arch in ("amd64", "arm64"):
        vb = ("stub victoria-metrics " + arch).encode() * 100
        vd = cache / ("vmstub-v1-" + arch) / sha(vb)
        vd.mkdir(parents=True)
        (vd / "victoria-metrics-prod").write_bytes(vb)
        items.append({"name": "vmstub", "version": "v1", "kind": "binary", "component": "collector",
                      "arch": arch, "file": "victoria-metrics-prod", "install_as": "victoria-metrics",
                      "sha256": sha(vb), "license": "Apache-2.0",
                      "sources": [{"type": "url", "url": "https://invalid.example/vm-%s.tgz" % arch}]})
    lock = tmp_path / "vendor.lock"
    lock.write_text(json.dumps({"schema": "exp.vendor.lock/1", "items": items}))

    keydir = tmp_path / "keys"
    keydir.mkdir()
    key, pub = keydir / "release.pem", keydir / "release-pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
                   check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                   check=True, capture_output=True)
    key.chmod(0o600)

    def run(out: Path, *args: str, env: dict | None = None, key_path: Path | None = key,
            repo_dir: Path = repo, signed: bool = True) -> subprocess.CompletedProcess:
        e = {k: v for k, v in os.environ.items() if not k.startswith("EXP_")}
        e.update(SOURCE_DATE_EPOCH=EPOCH, EXP_RELEASE_PUBKEY=str(pub))
        if key_path is not None:
            e["EXP_RELEASE_KEY"] = str(key_path)
        e.update(env or {})
        cmd = [str(BUILD), "--repo", str(repo_dir), "--lock", str(lock), "--cache", str(cache),
               "--no-fetch", "--out", str(out)]
        cmd += ["--release", VERSION] if signed else ["--version", VERSION]
        return subprocess.run(cmd + list(args), capture_output=True, text=True, env=e, timeout=300)

    return dict(repo=repo, lock=lock, cache=cache, key=key, pub=pub, run=run, tmp=tmp_path, items=items)


@pytest.fixture()
def built(stub, tmp_path):
    out = tmp_path / "dist"
    r = stub["run"](out)
    assert r.returncode == 0, r.stderr
    return out


def rm_tree(p: Path) -> None:
    shutil.rmtree(p, ignore_errors=True)
