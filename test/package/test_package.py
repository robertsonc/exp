"""WP-7 packaging tests: reproducibility, signing, verification, layout, vendoring."""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
import vendor
from exp_common import config as expconfig

from conftest import COMPONENTS, EPOCH, PKG, REPO, VERIFY, VERSION, sha


def members(tar: Path) -> dict:
    with tarfile.open(tar, "r:gz") as tf:
        return {m.name: m for m in tf.getmembers()}


def verify(dist: Path, pub: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(VERIFY), str(dist), str(pub), *extra], capture_output=True, text=True, timeout=60)


# --- reproducibility ---------------------------------------------------------------------

def test_two_builds_are_byte_identical(stub, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert stub["run"](a).returncode == 0
    # perturb everything that must not matter: mtimes of sources, build directory, cwd
    future = time.time() + 86400
    for p in stub["repo"].rglob("*"):
        os.utime(p, (future, future))
    assert stub["run"](b).returncode == 0
    names = sorted(p.name for p in a.iterdir())
    assert names == sorted(p.name for p in b.iterdir())
    assert any(n.endswith(".tar.gz") for n in names) and any(n.endswith("-manifest.json") for n in names)
    for n in names:
        assert (a / n).read_bytes() == (b / n).read_bytes(), n  # tarballs, manifest and (deterministic) sig


def test_epoch_defaults_to_head_commit_time(stub, tmp_path):
    repo = stub["repo"]
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_COMMITTER_DATE": "@1600000123 +0000",
           "GIT_AUTHOR_DATE": "@1600000123 +0000"}
    full = {**os.environ, **env}
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=full)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True, env=full)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "x"], check=True, env=full)
    e = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
    del e  # run() always sets SOURCE_DATE_EPOCH, so exercise the git fallback via the helper directly
    p = subprocess.run(["python3", "-I", str(PKG / "pack.py"), "epoch", "--repo", str(repo)],
                       capture_output=True, text=True, env={"PATH": os.environ["PATH"]})
    assert p.stdout.strip() == "1600000123"


# --- signing / verification --------------------------------------------------------------

def test_signature_verifies_with_openssl_and_script(stub, built, tmp_path):
    manifest = built / ("exp-%s-manifest.json" % VERSION)
    sig = base64.b64decode((built / ("exp-%s-manifest.json.sig" % VERSION)).read_text())
    assert len(sig) == 64
    (tmp_path / "s.bin").write_bytes(sig)
    r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(stub["pub"]), "-rawin",
                        "-in", str(manifest), "-sigfile", str(tmp_path / "s.bin")], capture_output=True)
    assert r.returncode == 0
    r = verify(built, stub["pub"])
    assert r.returncode == 0, r.stderr


def test_manifest_content_and_schema(stub, built):
    raw = (built / ("exp-%s-manifest.json" % VERSION)).read_bytes()
    doc = json.loads(raw)
    assert raw.endswith(b"\n") and b" " not in raw.replace(b"\n", b"").split(b'"created"')[0][:20]
    assert doc["schema"] == "exp.manifest/1" and doc["version"] == VERSION
    assert doc["created"] == time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(EPOCH)))
    expconfig.validate(doc, "manifest.schema.json")  # the real frozen schema
    got = {(a["component"], a["arch"]) for a in doc["artifacts"]}
    want = {(c, "noarch") for c in COMPONENTS if c != "collector"} | {("collector", "amd64"), ("collector", "arm64")}
    assert got == want
    for a in doc["artifacts"]:
        f = built / a["name"]
        assert a["name"] == "exp-%s-%s-%s.tar.gz" % (a["component"], VERSION, a["arch"])
        assert a["size"] == f.stat().st_size and a["sha256"] == sha(f.read_bytes())


def test_tampered_manifest_fails_verification(stub, built):
    m = built / ("exp-%s-manifest.json" % VERSION)
    m.write_bytes(m.read_bytes().replace(b'"min_agent_version":"0.1.0"', b'"min_agent_version":"0.0.1"', 1))
    r = verify(built, stub["pub"])
    assert r.returncode != 0 and "signature" in r.stderr


def test_tampered_artifact_fails_verification(stub, built):
    t = built / ("exp-probe-%s-noarch.tar.gz" % VERSION)
    raw = bytearray(t.read_bytes())
    raw[len(raw) // 2] ^= 0xFF  # same size, different content: only the sha256 can catch it
    t.write_bytes(bytes(raw))
    r = verify(built, stub["pub"])
    assert r.returncode != 0 and "probe" in r.stderr and "MISMATCH" in r.stderr


def test_wrong_key_and_missing_signature_fail(stub, built, tmp_path):
    other = tmp_path / "other-pub.pem"
    k = tmp_path / "other.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(k)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(k), "-pubout", "-out", str(other)], check=True, capture_output=True)
    assert verify(built, other).returncode != 0
    (built / ("exp-%s-manifest.json.sig" % VERSION)).unlink()
    r = verify(built, stub["pub"])
    assert r.returncode != 0 and "no signature" in r.stderr


def test_build_verifies_against_pubkey_and_removes_bad_signature(stub, tmp_path):
    other = tmp_path / "x-pub.pem"
    k = tmp_path / "x.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(k)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(k), "-pubout", "-out", str(other)], check=True, capture_output=True)
    out = tmp_path / "dist"
    r = stub["run"](out, env={"EXP_RELEASE_PUBKEY": str(other)})
    assert r.returncode != 0 and "does NOT verify" in r.stderr
    assert not (out / ("exp-%s-manifest.json.sig" % VERSION)).exists()


def test_unsigned_dev_build_is_labelled_and_unverifiable(stub, tmp_path):
    out = tmp_path / "dev"
    r = stub["run"](out, "--unsigned", signed=False, key_path=None)
    assert r.returncode == 0 and "UNSIGNED" in r.stderr
    assert (out / "UNSIGNED-DEV-BUILD.txt").exists()
    assert not list(out.glob("*.sig"))
    assert verify(out, stub["pub"], "--version", VERSION).returncode != 0


# --- key hygiene (SR-10) -----------------------------------------------------------------

def test_refuses_key_inside_repo(stub, tmp_path):
    inside = stub["repo"] / "secrets-oops" / "release.pem"
    inside.parent.mkdir()
    inside.write_bytes(stub["key"].read_bytes())
    inside.chmod(0o600)
    out = tmp_path / "dist"
    r = stub["run"](out, key_path=inside)
    assert r.returncode != 0 and "inside the repository" in r.stderr
    assert not out.exists() or not list(out.iterdir())
    assert "PRIVATE KEY" not in r.stdout + r.stderr


def test_refuses_symlink_into_repo(stub, tmp_path):
    inside = stub["repo"] / "k.pem"
    inside.write_bytes(stub["key"].read_bytes())
    inside.chmod(0o600)
    link = tmp_path / "link.pem"
    link.symlink_to(inside)
    r = stub["run"](tmp_path / "dist", key_path=link)
    assert r.returncode != 0 and "inside the repository" in r.stderr


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_refuses_group_or_world_accessible_key(stub, tmp_path, mode):
    stub["key"].chmod(mode)
    r = stub["run"](tmp_path / "dist")
    assert r.returncode != 0 and "accessible by group/others" in r.stderr


def test_refuses_missing_key_and_never_prints_key(stub, tmp_path):
    r = stub["run"](tmp_path / "d1", key_path=None)
    assert r.returncode != 0 and "EXP_RELEASE_KEY" in r.stderr
    ok = stub["run"](tmp_path / "d2")
    assert ok.returncode == 0
    body = stub["key"].read_text().splitlines()[1]
    assert body not in ok.stdout + ok.stderr and "PRIVATE KEY" not in ok.stdout + ok.stderr


def test_gen_release_key_script(tmp_path):
    priv = tmp_path / "k" / "release.pem"
    priv.parent.mkdir()
    r = subprocess.run([str(PKG / "gen-release-key.sh"), str(priv)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    pub = Path(r.stdout.strip())
    assert r.stdout.strip().count("\n") == 0 and pub.exists() and pub != priv
    assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    assert "PRIVATE" not in r.stdout + r.stderr
    assert "PUBLIC KEY" in pub.read_text()
    again = subprocess.run([str(PKG / "gen-release-key.sh"), str(priv)], capture_output=True, text=True)
    assert again.returncode != 0 and "overwrite" in again.stderr
    inside = REPO / "packaging" / "should-not-exist.pem"
    bad = subprocess.run([str(PKG / "gen-release-key.sh"), str(inside)], capture_output=True, text=True)
    assert bad.returncode != 0 and not inside.exists()


# --- layout / normalization --------------------------------------------------------------

def test_probe_layout_exact(stub, built):
    top = "exp-probe-%s" % VERSION
    names = set(members(built / ("exp-probe-%s-noarch.tar.gz" % VERSION)))
    want = {
        top, top + "/VERSION", top + "/bin", top + "/bin/exp-probe",
        top + "/lib", top + "/lib/exp_probe", top + "/lib/exp_probe/__init__.py",
        top + "/lib/exp_probe/cli.py", top + "/lib/exp_probe/static", top + "/lib/exp_probe/static/app.js",
        top + "/lib/exp_common", top + "/lib/exp_common/__init__.py", top + "/lib/exp_common/config.py",
        top + "/lib/exp_common/schemas", top + "/lib/exp_common/schemas/common.schema.json",
        top + "/lib/exp_common/schemas/manifest.schema.json",
        top + "/vendor", top + "/vendor/dns", top + "/vendor/dns/__init__.py",
        top + "/vendor/stubdns-1.0.dist-info", top + "/vendor/stubdns-1.0.dist-info/METADATA",
        top + "/vendor/stubdns-1.0.dist-info/licenses", top + "/vendor/stubdns-1.0.dist-info/licenses/LICENSE",
        top + "/systemd", top + "/systemd/exp-probe.service",
        top + "/requirements.apt",
        top + "/LICENSES", top + "/LICENSES/THIRD-PARTY.txt", top + "/LICENSES/stubdns-LICENSE",
    }
    assert names == want, sorted(names ^ want)
    ver = tarfile.open(built / ("exp-probe-%s-noarch.tar.gz" % VERSION), "r:gz").extractfile(top + "/VERSION")
    assert ver.read() == (VERSION + "\n").encode()


def test_collector_per_arch_bundles_vm(stub, built):
    for arch in ("amd64", "arm64"):
        m = members(built / ("exp-collector-%s-%s.tar.gz" % (VERSION, arch)))
        vm = m["exp-collector-%s/vendor/victoria-metrics" % VERSION]
        assert vm.mode == 0o755 and vm.size > 0
        assert not any(n.startswith("exp-collector-%s/vendor/dns" % VERSION) for n in m)
    a = tarfile.open(built / ("exp-collector-%s-amd64.tar.gz" % VERSION)).extractfile(
        "exp-collector-%s/vendor/victoria-metrics" % VERSION).read()
    b = tarfile.open(built / ("exp-collector-%s-arm64.tar.gz" % VERSION)).extractfile(
        "exp-collector-%s/vendor/victoria-metrics" % VERSION).read()
    assert a != b
    assert not (built / ("exp-collector-%s-noarch.tar.gz" % VERSION)).exists()


def test_no_pycache_tests_or_pyc(stub, built):
    for tar in built.glob("*.tar.gz"):
        for n in members(tar):
            parts = n.split("/")
            assert "__pycache__" not in parts and "tests" not in parts, (tar.name, n)
            assert not n.endswith((".pyc", ".pyo")), (tar.name, n)


def test_modes_owners_mtime_normalized(stub, built):
    for tar in built.glob("*.tar.gz"):
        ms = list(members(tar).values())
        names = [m.name for m in ms]
        assert names == sorted(names)
        for m in ms:
            assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "root", "root"), m.name
            assert m.mtime == int(EPOCH), m.name
            if m.isdir():
                assert m.mode == 0o755, m.name
            else:
                assert m.isreg() and m.mode in (0o644, 0o755), m.name
                is_exec = "/bin/exp-" in m.name or m.name.endswith("/vendor/victoria-metrics")
                assert (m.mode == 0o755) == is_exec, (tar.name, m.name)
        raw = tar.read_bytes()
        assert raw[:4] == b"\x1f\x8b\x08\x00" and raw[4:8] == b"\0\0\0\0"  # no FNAME flag, mtime 0


def test_bin_entry_is_executable_and_units_not(stub, built):
    m = members(built / ("exp-agent-%s-noarch.tar.gz" % VERSION))
    assert m["exp-agent-%s/bin/exp-agent" % VERSION].mode == 0o755
    assert m["exp-agent-%s/systemd/exp-agent.service" % VERSION].mode == 0o644


def test_exp_common_is_identical_in_every_tarball(stub, built):
    seen = set()
    for tar in sorted(built.glob("*.tar.gz")):
        with tarfile.open(tar) as tf:
            blob = b"".join(
                tf.extractfile(m).read() + m.name.split("/lib/")[1].encode()
                for m in tf.getmembers() if m.isreg() and "/lib/exp_common/" in m.name)
        seen.add(sha(blob))
    assert len(seen) == 1


# --- malformed components ----------------------------------------------------------------

@pytest.mark.parametrize("breakage,needle", [
    ("nobin", "bin/exp-agent missing"),
    ("noexec", "not executable"),
    ("shebang", "#!/usr/bin/python3"),
    ("nopkginit", "__init__.py missing"),
    ("nounits", "no unit templates"),
    ("badunit", "not a regular exp-*"),
    ("noapt", "requirements.apt missing"),
    ("badapt", "allowlist"),
    ("syntax", "byte-compile"),
    ("symlink", "symlink"),
    ("tests_package", "named like an excluded directory"),
])
def test_malformed_component_fails_clearly(stub, tmp_path, breakage, needle):
    d = stub["repo"] / "agent"
    if breakage == "nobin":
        (d / "bin" / "exp-agent").unlink()
    elif breakage == "noexec":
        (d / "bin" / "exp-agent").chmod(0o600)
    elif breakage == "shebang":
        (d / "bin" / "exp-agent").write_text("#!/bin/sh\n")
        (d / "bin" / "exp-agent").chmod(0o755)
    elif breakage == "nopkginit":
        (d / "exp_agent" / "__init__.py").unlink()
    elif breakage == "nounits":
        (d / "systemd" / "exp-agent.service").unlink()
    elif breakage == "badunit":
        (d / "systemd" / "other.service").write_text("")
    elif breakage == "noapt":
        (d / "requirements.apt").unlink()
    elif breakage == "badapt":
        (d / "requirements.apt").write_text("curl\nnetcat-openbsd\n")
    elif breakage == "syntax":
        (d / "exp_agent" / "bad.py").write_text("def (:\n")
    elif breakage == "symlink":
        (d / "exp_agent" / "ln.py").symlink_to("cli.py")
    elif breakage == "tests_package":
        # regression (M1 e2e): exp_probe/tests/ held the probe's MEASUREMENT code and was silently dropped from
        # the tarball by the "never package tests/" rule, so the released probe measured nothing
        (d / "exp_agent" / "tests" / "test_x.py").unlink()
        (d / "exp_agent" / "tests" / "__init__.py").write_text("")
        (d / "exp_agent" / "tests" / "gateway.py").write_text("X = 1\n")
    out = tmp_path / "dist"
    r = stub["run"](out)
    assert r.returncode != 0, r.stderr
    assert needle in r.stderr, r.stderr
    assert not (out / ("exp-%s-manifest.json" % VERSION)).exists()


def test_component_without_code_is_skipped_not_fatal(stub, tmp_path):
    import shutil
    for c in ("dashboard", "runner"):
        shutil.rmtree(stub["repo"] / c / "bin")
        shutil.rmtree(stub["repo"] / c / ("exp_" + c))
    out = tmp_path / "dist"
    r = stub["run"](out)
    assert r.returncode == 0, r.stderr
    assert "skipping dashboard" in r.stderr
    assert not list(out.glob("exp-dashboard-*"))
    assert verify(out, stub["pub"]).returncode == 0


# --- vendoring (SR-11) --------------------------------------------------------------------

def test_cache_hash_mismatch_aborts_build(stub, tmp_path):
    vm = next(i for i in stub["items"] if i["arch"] == "amd64" and i["kind"] == "binary")
    f = stub["cache"] / "vmstub-v1-amd64" / vm["sha256"] / "victoria-metrics-prod"
    f.write_bytes(f.read_bytes() + b"tampered")
    out = tmp_path / "dist"
    r = stub["run"](out)
    assert r.returncode != 0 and "SHA-256 MISMATCH" in r.stderr
    assert not (out / ("exp-%s-manifest.json" % VERSION)).exists()
    assert not list(out.glob("exp-collector-*"))


def test_wheel_hash_mismatch_aborts_build(stub, tmp_path):
    w = stub["items"][0]
    f = stub["cache"] / "stubdns-1.0-noarch" / w["sha256"] / w["file"]
    f.write_bytes(b"not the wheel")
    r = stub["run"](tmp_path / "dist")
    assert r.returncode != 0 and "SHA-256 MISMATCH" in r.stderr


def test_missing_cache_without_sources_aborts(stub, tmp_path, monkeypatch):
    import shutil
    shutil.rmtree(stub["cache"])
    r = stub["run"](tmp_path / "dist")
    assert r.returncode != 0 and "not in the cache" in r.stderr


def test_download_with_wrong_hash_aborts_and_caches_nothing(stub, tmp_path, monkeypatch):
    item = dict(stub["items"][0])
    cache = tmp_path / "fresh-cache"

    def evil(src, dest):
        dest.write_bytes(b"attacker bytes")
    monkeypatch.setitem(vendor._FETCHERS, "url", evil)
    with pytest.raises(vendor.VendorError, match="SHA-256 MISMATCH"):
        vendor.fetch_item(item, cache)
    assert not [p for p in cache.rglob("*") if p.is_file()]


def test_unreachable_source_falls_through_but_mismatch_does_not(stub, tmp_path, monkeypatch):
    good = b"the real bytes"
    item = {"name": "x", "version": "1", "kind": "binary", "component": "probe", "arch": "noarch",
            "file": "x.bin", "sha256": sha(good),
            "sources": [{"type": "url", "url": "https://a.invalid/x"},
                        {"type": "docker", "image": "r/i:1@sha256:" + "0" * 64, "path": "/x"}]}

    def down(src, dest):
        raise vendor.SourceUnavailable("offline")

    def ok(src, dest):
        dest.write_bytes(good)
    monkeypatch.setitem(vendor._FETCHERS, "url", down)
    monkeypatch.setitem(vendor._FETCHERS, "docker", ok)
    p = vendor.fetch_item(item, tmp_path / "c")
    assert p.read_bytes() == good
    item2 = dict(item, sha256=sha(b"other"))
    monkeypatch.setitem(vendor._FETCHERS, "docker", lambda s, d: d.write_bytes(good))
    with pytest.raises(vendor.VendorError, match="MISMATCH"):
        vendor.fetch_item(item2, tmp_path / "c2")


def test_noncanonical_fallback_needs_explicit_opt_in(tmp_path, monkeypatch):
    canon, fb = b"upstream", b"docker build"
    item = {"name": "x", "version": "1", "kind": "binary", "component": "c", "arch": "amd64",
            "file": "x.bin", "sha256": sha(canon),
            "sources": [{"type": "url", "url": "https://a.invalid/x"},
                        {"type": "docker", "image": "r/i:1@sha256:" + "0" * 64, "path": "/x", "sha256": sha(fb)}]}
    monkeypatch.setitem(vendor._FETCHERS, "url", lambda s, d: (_ for _ in ()).throw(vendor.SourceUnavailable("x")))
    monkeypatch.setitem(vendor._FETCHERS, "docker", lambda s, d: d.write_bytes(fb))
    p = vendor.fetch_item(item, tmp_path / "c")
    monkeypatch.delenv("EXP_ALLOW_FALLBACK_VENDOR", raising=False)
    with pytest.raises(vendor.VendorError, match="NON-CANONICAL"):
        vendor.verified_path(tmp_path / "c", item)
    monkeypatch.setenv("EXP_ALLOW_FALLBACK_VENDOR", "1")
    assert vendor.verified_path(tmp_path / "c", item) == p


def test_release_build_refuses_fallback_opt_in(stub, tmp_path):
    """SR-11 / T8: --release must never package a non-upstream vendored binary."""
    out = tmp_path / "rel"
    r = stub["run"](out, env={"EXP_ALLOW_FALLBACK_VENDOR": "1"})
    assert r.returncode != 0
    assert "fallback" in r.stderr.lower()
    assert not out.exists() or not any(out.glob("*.tar.gz"))


def test_release_flag_overrides_fallback_in_vendor(monkeypatch):
    monkeypatch.setenv("EXP_ALLOW_FALLBACK_VENDOR", "1")
    monkeypatch.delenv("EXP_RELEASE_BUILD", raising=False)
    assert vendor.fallback_allowed() is True
    monkeypatch.setenv("EXP_RELEASE_BUILD", "1")
    assert vendor.fallback_allowed() is False


def test_real_vendor_lock_is_well_formed():
    lock = vendor.load_lock(PKG / "vendor.lock")
    by = {(i["name"], i["arch"]): i for i in lock["items"]}
    dns = by[("dnspython", "noarch")]
    assert dns["version"] == "2.7.0" and dns["component"] == "probe" and dns["kind"] == "wheel"
    assert dns["sha256"] == "b4c34b7d10b51bcc3a5071e7b8dee77939f1e878477eeecc965e9835f63c6c86"
    for arch in ("amd64", "arm64"):
        vm = by[("victoria-metrics", arch)]
        assert vm["version"] == "v1.106.1" and vm["component"] == "collector"
        types = [s["type"] for s in vm["sources"]]
        assert types == ["url", "docker"]
        assert re.search(r"@sha256:[0-9a-f]{64}$", vm["sources"][1]["image"])
        assert vm["sources"][0]["url"].startswith("https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.106.1/")
        assert vm["sources"][0]["archive_sha256"]
    from pack import component_arches
    assert component_arches(lock, "collector") == ["amd64", "arm64"]
    assert component_arches(lock, "probe") == ["noarch"]


def test_vendor_lock_rejects_unpinned_docker_and_http(tmp_path):
    base = {"schema": "exp.vendor.lock/1", "items": [{
        "name": "x", "version": "1", "kind": "binary", "component": "probe", "arch": "noarch",
        "file": "x", "sha256": "0" * 64, "sources": [{"type": "docker", "image": "r/i:latest", "path": "/x"}]}]}
    p = tmp_path / "l.json"
    p.write_text(json.dumps(base))
    with pytest.raises(vendor.VendorError, match="digest"):
        vendor.load_lock(p)
    base["items"][0]["sources"] = [{"type": "url", "url": "http://insecure.example/x"}]
    p.write_text(json.dumps(base))
    with pytest.raises(vendor.VendorError, match="https"):
        vendor.load_lock(p)


def test_wheel_unpack_rejects_traversal(tmp_path):
    import zipfile

    from pack import PackError, _safe_unzip
    z = tmp_path / "evil.whl"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape.py", "x")
    with pytest.raises(PackError, match="unsafe"):
        _safe_unzip(z, tmp_path / "out")
    assert not (tmp_path / "escape.py").exists()


@pytest.mark.internet
def test_real_lock_fetch_and_build_with_stub_components(stub, tmp_path):
    """Fetch the REAL pinned dnspython wheel + VictoriaMetrics binaries (GitHub, falling back to the
    docker image) and package them into stub probe/collector tarballs."""
    import tarfile as tf
    cache = tmp_path / "real-cache"
    env = {**os.environ, "EXP_VENDOR_CACHE": str(cache)}
    r = subprocess.run([str(PKG / "fetch-vendor.sh")], capture_output=True, text=True, env=env, timeout=900)
    assert r.returncode == 0, r.stderr
    real = {**os.environ, "SOURCE_DATE_EPOCH": EPOCH, "EXP_VENDOR_CACHE": str(cache),
            "EXP_ALLOW_FALLBACK_VENDOR": "1"}
    out = tmp_path / "dist"
    r = subprocess.run([str(PKG / "build.sh"), "--version", VERSION, "--repo", str(stub["repo"]), "--out", str(out),
                        "--lock", str(PKG / "vendor.lock"), "--no-fetch", "--components", "probe,collector"],
                       capture_output=True, text=True, env=real, timeout=900)
    assert r.returncode == 0, r.stderr
    names = tf.open(out / ("exp-probe-%s-noarch.tar.gz" % VERSION)).getnames()
    assert "exp-probe-%s/vendor/dns/resolver.py" % VERSION in names
    assert any(n.endswith("LICENSES/dnspython-LICENSE") for n in names)
    for arch in ("amd64", "arm64"):
        m = tf.open(out / ("exp-collector-%s-%s.tar.gz" % (VERSION, arch))).getmember(
            "exp-collector-%s/vendor/victoria-metrics" % VERSION)
        assert m.mode == 0o755 and m.size > 10_000_000


def test_real_components_have_no_package_named_like_an_excluded_directory():
    """Static guard on the real tree (no build needed): a product package called tests/ (or any other name in
    pack.EXCLUDE_DIRS) is dropped from the tarball, so the component would ship without it."""
    import pack
    bad = []
    for c in COMPONENTS:
        pkg = REPO / c / ("exp_" + c)
        if not pkg.is_dir():
            continue
        for init in pkg.rglob("__init__.py"):
            d = init.parent
            if d != pkg and d.name in pack.EXCLUDE_DIRS and not any(f.name.startswith("test_") for f in d.iterdir()):
                bad.append(str(d.relative_to(REPO)))
    assert not bad, "product packages that packaging would drop: %s" % bad
