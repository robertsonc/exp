"""Manifest signature (openssl pkeyutl -rawin), artifact cross-checks, manifest cache, semver."""

from __future__ import annotations

import base64
import json
import subprocess

import pytest
from agent_helpers import Env, ScriptedRunner

from exp_agent import verify
from exp_agent.errors import VerifyError
from exp_agent.runner import Runner


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    e.standard_release(comps=("collector",))
    yield e
    e.close()


def sig_of(env: Env) -> tuple[bytes, str]:
    return env.app.releases["0.1.0"]


def test_valid_signature_passes_and_uses_the_documented_openssl_argv(env):
    raw, sig = sig_of(env)
    verify.verify_signature(env.runner, env.ctx.fs, env.cfg.release_pubkey_pem, raw, sig)
    argv = env.runner.argvs("openssl", "pkeyutl")[-1]
    assert argv[:5] == ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey"] and "-rawin" in argv
    assert "-in" in argv and "-sigfile" in argv
    # temp files were in a private dir that is gone again
    import os

    assert os.listdir(env.ctx.paths.agent_state / "tmp") == []


def test_tampered_manifest_wrong_key_garbage_signature(env, tmp_path):
    raw, sig = sig_of(env)
    with pytest.raises(VerifyError, match="FAILED"):
        verify.verify_signature(env.runner, env.ctx.fs, env.cfg.release_pubkey_pem, raw + b" ", sig)
    k = tmp_path / "k.pem"
    p = tmp_path / "p.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(k)], check=True, capture_output=True
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(k), "-pubout", "-out", str(p)], check=True, capture_output=True
    )
    with pytest.raises(VerifyError, match="FAILED"):  # right signature, other pinned key
        verify.verify_signature(env.runner, env.ctx.fs, p.read_text(), raw, sig)
    for bad in (
        "not base64!!",
        base64.b64encode(b"short").decode(),
        "",
        base64.b64encode(b"\0" * 64).decode(),
    ):
        with pytest.raises(VerifyError):
            verify.verify_signature(env.runner, env.ctx.fs, env.cfg.release_pubkey_pem, raw, bad)
    with pytest.raises(VerifyError, match="PEM"):
        verify.verify_signature(env.runner, env.ctx.fs, "not a pem", raw, sig)


def test_manifest_parse_checks_schema_and_version(env):
    raw, _ = sig_of(env)
    assert verify.parse_manifest(raw, "0.1.0").entry("exp-collector-0.1.0-amd64.tar.gz")
    with pytest.raises(VerifyError, match="expected"):
        verify.parse_manifest(raw, "0.2.0")
    with pytest.raises(VerifyError, match="invalid"):
        verify.parse_manifest(json.dumps({"schema": "exp.manifest/1"}).encode(), "0.1.0")
    with pytest.raises(VerifyError):
        verify.parse_manifest(b"{", "0.1.0")


def test_cache_verifies_once_per_version_and_drops_a_tampered_cache(env):
    cache = env.ctx.manifests
    fetched = []

    def fetch(v):
        fetched.append(v)
        return env.client.get_manifest(v)

    m1 = cache.get("0.1.0", fetch)
    m2 = cache.get("0.1.0", fetch)
    assert m1 is m2 and fetched == ["0.1.0"]
    # fresh process, intact disk cache: no network, still verified (an openssl call happens)
    c2 = verify.ManifestCache(env.ctx.fs, env.runner, env.cfg.release_pubkey_pem)
    n = len(env.runner.argvs("openssl", "pkeyutl"))
    c2.get("0.1.0", lambda v: pytest.fail("must not refetch"))
    assert len(env.runner.argvs("openssl", "pkeyutl")) == n + 1
    # tamper with the cached manifest: discarded, refetched, and verified again
    f = env.ctx.paths.agent_state / "manifests" / "0.1.0" / "manifest.json"
    f.write_bytes(f.read_bytes().replace(b"0.1.0", b"0.1.9"))
    c3 = verify.ManifestCache(env.ctx.fs, env.runner, env.cfg.release_pubkey_pem)
    fetched.clear()
    c3.get("0.1.0", fetch)
    assert fetched == ["0.1.0"]


def test_unverifiable_manifest_is_never_cached(env, tmp_path):
    env.sign_release("0.1.0", tamper=True)
    cache = verify.ManifestCache(env.ctx.fs, Runner(), env.cfg.release_pubkey_pem)
    with pytest.raises(VerifyError):
        cache.get("0.1.0", env.client.get_manifest)
    assert not (env.ctx.paths.agent_state / "manifests" / "0.1.0").exists()


def test_check_artifact_cross_checks(env):
    raw, _ = sig_of(env)
    man = verify.parse_manifest(raw, "0.1.0")
    a = env.artifacts["exp-collector-0.1.0-amd64.tar.gz"]
    art = {"name": "exp-collector-0.1.0-amd64.tar.gz", "sha256": a["sha256"], "size": a["size"]}
    assert verify.check_artifact(man, art, "collector", "amd64")["sha256"] == a["sha256"]
    for bad, why in (
        ({**art, "sha256": "0" * 64}, "disagrees"),
        ({**art, "size": 1}, "disagrees"),
        ({**art, "name": "exp-collector-0.1.0-arm64.tar.gz"}, "not in the signed"),
    ):
        with pytest.raises(VerifyError, match=why):
            verify.check_artifact(man, bad, "collector", "amd64")
    with pytest.raises(VerifyError, match="not a probe"):
        verify.check_artifact(man, art, "probe", "amd64")
    with pytest.raises(VerifyError, match="this host"):
        verify.check_artifact(man, art, "collector", "arm64")


def test_semver_ordering():
    lt = verify.version_lt
    assert (
        lt("0.1.0", "0.2.0")
        and lt("0.9.9", "0.10.0")
        and lt("1.0.0-rc.1", "1.0.0")
        and not lt("1.0.0", "1.0.0")
    )
    assert lt("1.0.0-rc.1", "1.0.0-rc.2") and lt("1.0.0-alpha", "1.0.0-beta") and not lt("2.0.0", "1.9.9")
    with pytest.raises(VerifyError):
        verify.parse_semver("nope")


def test_scripted_runner_is_a_runner_substitute():
    assert ScriptedRunner().run(["true"], timeout=5).rc == 0
