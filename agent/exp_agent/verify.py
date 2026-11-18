"""Release verification (SR-8): Ed25519 manifest signature via the openssl CLI, artifact digests,
min_agent_version, and a per-version cache of verified manifests.

    openssl pkeyutl -verify -pubin -inkey <pem> -rawin -in <manifest> -sigfile <sig.bin>

Temp files live in a private (0700) directory under /var/lib/exp/agent/tmp and are removed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from exp_common import config as exp_config

from .errors import VerifyError
from .pathguard import SafeFS
from .runner import Runner

log = logging.getLogger(__name__)

_SEMVER = re.compile(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.]+))?\Z")
MAX_MANIFEST_BYTES = 1024 * 1024


def parse_semver(v: str) -> tuple[int, int, int, tuple[Any, ...]]:
    m = _SEMVER.match(v or "")
    if not m:
        raise VerifyError(f"invalid version {v!r}")
    pre = m.group(4)
    # a pre-release sorts before the release: (1,) > (0, ...) ; numeric identifiers compare as numbers
    key: tuple[Any, ...] = (
        (1,) if pre is None else (0, *((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))
    )
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), key


def version_lt(a: str, b: str) -> bool:
    return parse_semver(a) < parse_semver(b)


@dataclass
class Manifest:
    version: str
    min_agent_version: str
    artifacts: list[dict[str, Any]]
    raw_sha256: str

    def entry(self, name: str) -> dict[str, Any] | None:
        for a in self.artifacts:
            if a.get("name") == name:
                return a
        return None


def sha256_file(path: str | os.PathLike[str]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def decode_signature(sig_b64: bytes | str) -> bytes:
    text = sig_b64.decode("ascii", "strict") if isinstance(sig_b64, bytes) else sig_b64
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise VerifyError("manifest signature is not valid base64") from None
    if len(raw) != 64:
        raise VerifyError("manifest signature is not a 64-byte Ed25519 signature")
    return raw


def verify_signature(
    runner: Runner, fs: SafeFS, pubkey_pem: str, manifest: bytes, sig_b64: bytes | str
) -> None:
    """Raise VerifyError unless `sig_b64` is a valid Ed25519 signature of the exact `manifest` bytes."""
    if len(manifest) > MAX_MANIFEST_BYTES:
        raise VerifyError("manifest is too large")
    sig = decode_signature(sig_b64)
    if not pubkey_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        raise VerifyError("release public key is not a PEM public key")
    tmp_root = fs.paths.agent_state / "tmp"
    fs.mkdir(tmp_root, 0o700)
    td = tempfile.mkdtemp(prefix="verify-", dir=fs.g(tmp_root))  # 0700, private to root
    try:
        d = Path(td)
        (d / "manifest").write_bytes(manifest)
        (d / "sig.bin").write_bytes(sig)
        (d / "pub.pem").write_text(pubkey_pem, encoding="ascii")
        res = runner.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(d / "pub.pem"),
                "-rawin",
                "-in",
                str(d / "manifest"),
                "-sigfile",
                str(d / "sig.bin"),
            ],
            timeout=20,
        )
    except UnicodeEncodeError:
        raise VerifyError("release public key is not ASCII") from None
    finally:
        fs.rmtree(td)
    if res.rc != 0 or "Signature Verified Successfully" not in res.stdout:
        raise VerifyError("release manifest signature verification FAILED")


def parse_manifest(raw: bytes, expect_version: str) -> Manifest:
    try:
        doc = exp_config.parse_json(raw, "manifest")
        exp_config.validate(doc, "manifest.schema.json")
    except exp_config.ConfigError as exc:
        raise VerifyError(f"manifest is invalid: {exc.summary}") from None
    if doc["version"] != expect_version:
        raise VerifyError(f"manifest is for version {doc['version']}, expected {expect_version}")
    return Manifest(
        doc["version"],
        doc.get("min_agent_version", "0.0.0"),
        list(doc["artifacts"]),
        hashlib.sha256(raw).hexdigest(),
    )


class ManifestCache:
    """Verified manifests per version: memory first, then /var/lib/exp/agent/manifests/<ver>/ (re-verified
    once per process, so a tampered cache file is dropped), else fetched through `fetch`."""

    def __init__(self, fs: SafeFS, runner: Runner, pubkey_pem: str) -> None:
        self.fs, self.runner, self.pub = fs, runner, pubkey_pem
        self._mem: dict[str, Manifest] = {}

    def _dir(self, version: str) -> Path:
        return self.fs.paths.agent_state / "manifests" / version

    def get(self, version: str, fetch: Any) -> Manifest:
        parse_semver(version)
        hit = self._mem.get(version)
        if hit is not None:
            return hit
        d = self._dir(version)
        raw, sig = (
            self.fs.read_bytes(d / "manifest.json", MAX_MANIFEST_BYTES),
            self.fs.read_bytes(d / "manifest.sig", 4096),
        )
        if raw is not None and sig is not None:
            try:
                verify_signature(self.runner, self.fs, self.pub, raw, sig)
                man = parse_manifest(raw, version)
                self._mem[version] = man
                return man
            except VerifyError:
                log.warning("cached manifest for %s failed verification; discarding it", version)
                self.fs.rmtree(d)
        raw, sig = fetch(version)
        verify_signature(self.runner, self.fs, self.pub, raw, sig)  # fail closed before caching anything
        man = parse_manifest(raw, version)
        self.fs.mkdir(d, 0o700)
        self.fs.write(d / "manifest.json", raw, 0o600)
        self.fs.write(d / "manifest.sig", sig, 0o600)
        self._mem[version] = man
        return man


def check_artifact(man: Manifest, art: dict[str, Any], component: str, host_arch: str) -> dict[str, Any]:
    """Cross-check a desired-state artifact against the signed manifest. Returns the manifest entry."""
    entry = man.entry(art["name"])
    if entry is None:
        raise VerifyError(f"artifact {art['name']} is not in the signed manifest")
    if entry.get("component") != component:
        raise VerifyError(f"artifact {art['name']} is not a {component} artifact")
    if entry["sha256"] != art["sha256"] or entry["size"] != art["size"]:
        raise VerifyError(f"artifact {art['name']}: desired state disagrees with the signed manifest")
    if entry.get("arch") not in ("noarch", host_arch):
        raise VerifyError(f"artifact {art['name']} is for {entry.get('arch')}, this host is {host_arch}")
    return entry
