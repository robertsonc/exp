#!/usr/bin/env python3
"""Vendored-dependency fetcher/verifier (WP-7, SR-11).

Reads packaging/vendor.lock. Every item is pinned by version AND sha256 of the file that is
finally used. Sources are tried in order (network errors fall through to the next source), but
a sha256 MISMATCH always aborts: nothing unverified is ever placed in the cache or used.

    vendor.py fetch --lock F --cache DIR [--component C] [--arch A]
    vendor.py verify --lock F --cache DIR [--component C] [--arch A]

Environment: EXP_VENDOR_SOURCES=url,docker restricts/reorders the source types tried.
Stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

NET_TIMEOUT = 60  # seconds, every network call
DOCKER_TIMEOUT = 600
MAX_DOWNLOAD = 1 << 30  # 1 GiB
MAX_EXTRACT = 512 << 20

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
ARCHES = ("amd64", "arm64", "noarch")


class VendorError(Exception):
    """Fatal: abort the build."""


class SourceUnavailable(Exception):
    """Non-fatal: try the next source."""


def log(msg: str) -> None:
    print("vendor: " + msg, file=sys.stderr)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        lock = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise VendorError("cannot read vendor lock %s: %s" % (path, e))
    if not isinstance(lock, dict) or lock.get("schema") != "exp.vendor.lock/1":
        raise VendorError("%s: schema must be exp.vendor.lock/1" % path)
    items = lock.get("items")
    if not isinstance(items, list):
        raise VendorError("%s: 'items' must be a list" % path)
    seen = set()
    for it in items:
        if not isinstance(it, dict):
            raise VendorError("%s: item is not an object" % path)
        for k in ("name", "version", "kind", "component", "arch", "file", "sha256", "sources"):
            if k not in it:
                raise VendorError("%s: item %r lacks %r" % (path, it.get("name"), k))
        if it["kind"] not in ("wheel", "binary"):
            raise VendorError("item %s: kind must be wheel|binary" % it["name"])
        if it["arch"] not in ARCHES:
            raise VendorError("item %s: bad arch %r" % (it["name"], it["arch"]))
        for k in ("name", "version", "file", "component"):
            if not isinstance(it[k], str) or not _SAFE_NAME.match(it[k]):
                raise VendorError("item %r: unsafe %s" % (it.get("name"), k))
        if it["kind"] == "binary":
            ia = it.get("install_as", it["file"])
            if not isinstance(ia, str) or not _SAFE_NAME.match(ia):
                raise VendorError("item %s: unsafe install_as" % it["name"])
        if not isinstance(it["sha256"], str) or not _SHA_RE.match(it["sha256"]):
            raise VendorError("item %s: sha256 must be 64 lowercase hex" % it["name"])
        if not isinstance(it["sources"], list) or not it["sources"]:
            raise VendorError("item %s: needs at least one source" % it["name"])
        for s in it["sources"]:
            t = s.get("type") if isinstance(s, dict) else None
            if t == "url":
                if not str(s.get("url", "")).startswith("https://"):
                    raise VendorError("item %s: url sources must be https" % it["name"])
            elif t == "docker":
                if not _IMAGE_RE.match(str(s.get("image", ""))):
                    raise VendorError("item %s: docker image must be pinned by digest" % it["name"])
                if not str(s.get("path", "")).startswith("/"):
                    raise VendorError("item %s: docker path must be absolute" % it["name"])
            else:
                raise VendorError("item %s: unknown source type %r" % (it["name"], t))
        # one file may be vendored for several components (dnspython: probe + speedtest): same pin, one cache entry
        key = (it["name"], it["version"], it["arch"], it["component"])
        if key in seen:
            raise VendorError("duplicate lock item %r" % (key,))
        seen.add(key)
    return lock


def select(lock: dict[str, Any], component: str | None = None,
           arch: str | None = None) -> list[dict[str, Any]]:
    """Items for a component; with arch: that arch plus noarch."""
    out = []
    for it in lock["items"]:
        if component and it["component"] != component:
            continue
        if arch and it["arch"] not in (arch, "noarch"):
            continue
        out.append(it)
    return out


def source_sha(item: dict[str, Any], src: dict[str, Any]) -> str:
    """Expected sha256 of the file a source yields. Sources that rebuild the artifact (the docker
    image) may carry their own pin; otherwise it is the item's canonical (upstream) hash."""
    return src.get("sha256", item["sha256"])


def cache_path(cache: Path, item: dict[str, Any], sha: str | None = None) -> Path:
    """<cache>/<name>-<version>-<arch>/<sha256>/<file>: distinct binaries never share a path."""
    return (Path(cache) / ("%s-%s-%s" % (item["name"], item["version"], item["arch"]))
            / (sha or item["sha256"]) / item["file"])


def _check_cached(p: Path, want: str, item: dict[str, Any]) -> None:
    if p.is_symlink() or not p.is_file():
        raise VendorError("%s: cache entry is not a regular file: %s" % (item["name"], p))
    got = sha256_file(p)
    if got != want:
        raise VendorError("SHA-256 MISMATCH for %s: expected %s, cache file has %s (%s). "
                          "Refusing to use it; delete it only after finding out why."
                          % (item["name"], want, got, p))


def fallback_allowed() -> bool:
    """Non-canonical fallback sources are never allowed in a release build (SR-11 / T8), whatever
    EXP_ALLOW_FALLBACK_VENDOR says; build.sh --release exports EXP_RELEASE_BUILD=1."""
    if os.environ.get("EXP_RELEASE_BUILD") == "1":
        return False
    return os.environ.get("EXP_ALLOW_FALLBACK_VENDOR") == "1"


def verified_path(cache: Path, item: dict[str, Any]) -> Path:
    """Path of the cached file, re-hashed NOW. The canonical (upstream) file is preferred; a
    non-canonical fallback (e.g. docker-image binary) is used only if EXP_ALLOW_FALLBACK_VENDOR=1.
    Raises VendorError on absence or mismatch."""
    p = cache_path(cache, item)
    if p.exists() or p.is_symlink():
        _check_cached(p, item["sha256"], item)
        return p
    for src in item["sources"]:
        sha = source_sha(item, src)
        if sha == item["sha256"]:
            continue
        fp = cache_path(cache, item, sha)
        if fp.exists() or fp.is_symlink():
            _check_cached(fp, sha, item)
            if not fallback_allowed():
                raise VendorError(
                    "%s %s (%s) is only available as a NON-CANONICAL fallback build (%s source); "
                    "set EXP_ALLOW_FALLBACK_VENDOR=1 to use it for a local (non-release) build. "
                    "Release builds always require the upstream file."
                    % (item["name"], item["version"], item["arch"], src["type"]))
            log("WARNING: using non-canonical fallback for %s (%s): tarball will differ from CI builds"
                % (item["name"], src["type"]))
            return fp
    raise VendorError("%s %s (%s) is not in the cache; run packaging/fetch-vendor.sh"
                      % (item["name"], item["version"], item["arch"]))


# --- sources ---------------------------------------------------------------------------

def _from_url(src: dict[str, Any], dest: Path) -> None:
    url = src["url"]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "exp-build"})
        with urllib.request.urlopen(req, timeout=NET_TIMEOUT) as resp:  # noqa: S310 (https only)
            if not resp.geturl().startswith("https://"):
                raise SourceUnavailable("redirected away from https")
            raw = dest.with_name(dest.name + ".dl")
            total = 0
            with open(raw, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD:
                        raise SourceUnavailable("download too large")
                    out.write(chunk)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SourceUnavailable("%s: %s" % (url, e))
    try:
        want_archive = src.get("archive_sha256")
        if want_archive and sha256_file(raw) != want_archive:
            raise VendorError("SHA-256 MISMATCH for downloaded archive %s (expected %s). Aborting."
                              % (url, want_archive))
        member = src.get("extract")
        if not member:
            os.replace(raw, dest)
            return
        try:
            with tarfile.open(raw, "r:gz") as tf:
                ti = tf.getmember(member)
                if not ti.isreg() or ti.size > MAX_EXTRACT:
                    raise SourceUnavailable("%s: member %s is not a sane regular file" % (url, member))
                fobj = tf.extractfile(ti)
                if fobj is None:
                    raise SourceUnavailable("%s: cannot read member %s" % (url, member))
                with fobj, open(dest, "wb") as out:
                    shutil.copyfileobj(fobj, out)
        except (tarfile.TarError, KeyError, OSError, EOFError) as e:
            raise SourceUnavailable("%s: bad archive: %s" % (url, e))
    finally:
        if raw.exists():
            raw.unlink()


def _docker(argv: list[str], timeout: int = DOCKER_TIMEOUT) -> str:
    try:
        r = subprocess.run(["docker"] + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, check=False, text=True)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SourceUnavailable("docker: %s" % e)
    if r.returncode != 0:
        raise SourceUnavailable("docker %s failed: %s" % (argv[0], r.stderr.strip()[-300:]))
    return r.stdout.strip()


def _from_docker(src: dict[str, Any], dest: Path) -> None:
    image = src["image"]  # pinned by digest: the pull itself is content-verified
    plat = src.get("platform")
    pf = ["--platform", plat] if plat else []
    cid = _docker(["create"] + pf + [image])
    try:
        _docker(["cp", "%s:%s" % (cid, src["path"]), str(dest)])
    finally:
        try:
            _docker(["rm", "-f", cid], timeout=60)
        except SourceUnavailable as e:
            log("could not remove container %s: %s" % (cid[:12], e))


_FETCHERS = {"url": _from_url, "docker": _from_docker}


def fetch_item(item: dict[str, Any], cache: Path) -> Path:
    """Ensure the pinned file is in the cache and verified; return its path."""
    dest = cache_path(cache, item)
    if dest.exists() or dest.is_symlink():
        _check_cached(dest, item["sha256"], item)  # mismatch -> VendorError (abort)
        log("%s %s %s: cached, sha256 ok" % (item["name"], item["version"], item["arch"]))
        return dest
    allowed = [t for t in os.environ.get("EXP_VENDOR_SOURCES", "").split(",") if t] or None
    srcs = item["sources"]
    if allowed:
        srcs = [s for t in allowed for s in item["sources"] if s["type"] == t]
    errors: list[str] = []
    for src in srcs:
        want = source_sha(item, src)
        target = cache_path(cache, item, want)
        if target.exists() or target.is_symlink():
            _check_cached(target, want, item)
            log("%s %s %s: cached fallback (%s), sha256 ok" % (item["name"], item["version"], item["arch"], src["type"]))
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fetch-", dir=str(target.parent)) as td:
            tmp = Path(td) / item["file"]
            try:
                _FETCHERS[src["type"]](src, tmp)
            except SourceUnavailable as e:
                errors.append("%s: %s" % (src["type"], e))
                log("source %s unavailable (%s), trying next" % (src["type"], e))
                continue
            if not tmp.is_file():
                errors.append("%s: produced no file" % src["type"])
                continue
            got = sha256_file(tmp)
            if got != want:
                raise VendorError("SHA-256 MISMATCH for %s from %s source: expected %s, got %s. "
                                  "Aborting; nothing was cached."
                                  % (item["name"], src["type"], want, got))
            os.chmod(tmp, 0o644)
            os.replace(tmp, target)
        if want != item["sha256"]:
            log("WARNING: %s obtained from the %s source is a NON-CANONICAL build (differs from the "
                "upstream release binary); do not publish releases built from it" % (item["name"], src["type"]))
        log("%s %s %s: fetched via %s, sha256 ok" % (item["name"], item["version"], item["arch"], src["type"]))
        return target
    raise VendorError("could not obtain %s %s (%s) from any source: %s"
                      % (item["name"], item["version"], item["arch"], "; ".join(errors) or "no usable source"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["fetch", "verify"])
    ap.add_argument("--lock", required=True)
    ap.add_argument("--cache", required=True)
    ap.add_argument("--component")
    ap.add_argument("--arch")
    a = ap.parse_args(argv)
    try:
        lock = load_lock(Path(a.lock))
        items = select(lock, a.component, a.arch)
        for it in items:
            if a.cmd == "fetch":
                fetch_item(it, Path(a.cache))
            else:
                verified_path(Path(a.cache), it)
                log("%s %s %s: ok" % (it["name"], it["version"], it["arch"]))
    except VendorError as e:
        print("vendor: ERROR: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
