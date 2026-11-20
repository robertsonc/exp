#!/usr/bin/env python3
"""Reproducible packaging helper for packaging/build.sh (WP-7). Stdlib only (3.9+).

Subcommands (all errors: message on stderr, exit 1):
  epoch        --repo DIR                      print SOURCE_DATE_EPOCH (env, else HEAD commit time)
  check-key    --key FILE --repo DIR [--repo DIR ...]
  detect       --repo DIR                      print components that have code (one per line)
  arches       --lock F --component C          print the tarball arches for a component
  assemble     --repo --component --version --arch --lock --cache --stage DIR --epoch N
  compilecheck --stage-top DIR                 byte-compile lib/, vendor/ and bin/ (no .pyc left behind)
  tar          --top DIR --out FILE --epoch N  byte-reproducible .tar.gz of DIR
  manifest     --version V --epoch N --min-agent V [--notes-url U] --out FILE FILE...
  check-manifest FILE --dist DIR               validate manifest structure + artifact sizes/sha256
  b64          IN OUT                          base64 (single line) of a file
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import time
import zipfile
import zlib
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vendor  # noqa: E402

COMPONENTS = ("agent", "probe", "collector", "dashboard", "runner", "speedtest")
PER_ARCH_COMPONENTS = ("collector",)  # bundle a native binary (VictoriaMetrics)
APT_ALLOWLIST = frozenset("""busybox busybox-static iproute2 iputils-ping iperf3 curl openssl
ca-certificates ethtool iw wpasupplicant tcpdump""".split())
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$")
UNIT_RE = re.compile(r"^exp-[a-z0-9][a-z0-9@._-]*\.(service|timer)$")
ARTIFACT_RE = re.compile(
    r"^exp-(agent|probe|collector|dashboard|runner|speedtest)-"
    r"([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?)-(amd64|arm64|noarch)\.tar\.gz$")
EXCLUDE_DIRS = {"tests", "__pycache__", ".pytest_cache", ".ruff_cache", ".hypothesis", ".mypy_cache"}
EXCLUDE_FILES = {".DS_Store"}
EXCLUDE_SUFFIX = (".pyc", ".pyo")
SHEBANG = b"#!/usr/bin/python3"
MIN_AGENT_DEFAULT = "0.1.0"


class PackError(Exception):
    pass


# --- helpers ---------------------------------------------------------------------------

def sha256_file(p: Path) -> str:
    return vendor.sha256_file(p)


def iso_utc(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def resolve_epoch(repo: Path) -> int:
    env = os.environ.get("SOURCE_DATE_EPOCH")
    if env:
        if not env.isdigit():
            raise PackError("SOURCE_DATE_EPOCH must be a non-negative integer")
        return int(env)
    try:
        r = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%ct", "HEAD"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PackError("cannot determine SOURCE_DATE_EPOCH (git failed: %s); set SOURCE_DATE_EPOCH" % e)
    out = r.stdout.strip()
    if r.returncode != 0 or not out.isdigit():
        raise PackError("cannot determine SOURCE_DATE_EPOCH from git HEAD of %s; set SOURCE_DATE_EPOCH" % repo)
    return int(out)


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def check_key(key: str, repos: list[str]) -> None:
    """SR-10: the signing key must be a private (0600-ish) regular file outside every repo root."""
    if not key:
        raise PackError("EXP_RELEASE_KEY is not set (path to the Ed25519 private key, outside the repo)")
    real = os.path.realpath(key)
    for r in repos:
        if _inside(real, os.path.realpath(r)):
            raise PackError("refusing to run: the release key file is inside the repository (%s). "
                            "Keep it outside any checkout." % r)
    try:
        st = os.stat(real)
    except OSError as e:
        raise PackError("cannot stat release key file: %s" % e.strerror)
    if not stat.S_ISREG(st.st_mode):
        raise PackError("release key path is not a regular file")
    if st.st_mode & 0o077:
        raise PackError("refusing to run: release key file is accessible by group/others (mode %04o); "
                        "chmod 600 it" % (st.st_mode & 0o7777))
    if not os.access(real, os.R_OK):
        raise PackError("release key file is not readable")


def detect_components(repo: Path) -> list[str]:
    return [c for c in COMPONENTS if (repo / c / "bin").is_dir() or (repo / c / ("exp_" + c)).is_dir()]


def component_arches(lock: dict[str, Any], component: str) -> list[str]:
    arches = sorted({i["arch"] for i in lock["items"]
                     if i["component"] == component and i["arch"] != "noarch"})
    if component in PER_ARCH_COMPONENTS:
        if arches != ["amd64", "arm64"]:
            raise PackError("%s must bundle a vendored binary for amd64 and arm64 in vendor.lock "
                            "(found: %s)" % (component, ",".join(arches) or "none"))
        return arches
    return arches or ["noarch"]


# --- assemble --------------------------------------------------------------------------

def _copy_tree(src: Path, dst: Path, what: str) -> int:
    n = 0
    for root, dirs, files in os.walk(src, followlinks=False):
        for d in dirs:
            # A product PACKAGE (has __init__.py) whose name collides with the exclusion list would be silently
            # dropped from the tarball (the probe's measurement tests once lived in exp_probe/tests/): refuse.
            if d in EXCLUDE_DIRS and (Path(root) / d / "__init__.py").is_file() and (Path(root) / "__init__.py").is_file() \
                    and not any(f.startswith("test_") for f in os.listdir(Path(root) / d)):
                raise PackError("%s: package %s/ is named like an excluded directory (%s) and would be dropped from "
                                "the tarball; rename it" % (what, Path(root) / d, d))
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDE_DIRS)
        rel = Path(root).relative_to(src)
        for d in dirs:
            if (Path(root) / d).is_symlink():
                raise PackError("%s: symlink not allowed: %s" % (what, Path(root) / d))
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for f in sorted(files):
            p = Path(root) / f
            if f in EXCLUDE_FILES or f.endswith(EXCLUDE_SUFFIX):
                continue
            if p.is_symlink():
                raise PackError("%s: symlink not allowed: %s" % (what, p))
            if not p.is_file():
                raise PackError("%s: not a regular file: %s" % (what, p))
            shutil.copyfile(p, dst / rel / f)
            os.chmod(dst / rel / f, 0o755 if p.stat().st_mode & 0o111 else 0o644)
            n += 1
    return n


def _need_dir(p: Path, what: str) -> None:
    if not p.is_dir() or p.is_symlink():
        raise PackError("malformed component: %s missing (%s)" % (what, p))


def _validate_apt(path: Path, comp: str) -> None:
    for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        pkg = line.split("#", 1)[0].strip()
        if pkg and pkg not in APT_ALLOWLIST:
            raise PackError("malformed component %s: %s:%d: apt package %r is not in the agent allowlist"
                            % (comp, path.name, ln, pkg))


def _safe_unzip(whl: Path, dest: Path) -> list[str]:
    """Unpack a pure-Python wheel into dest; reject traversal, absolute paths, symlinks."""
    names: list[str] = []
    with zipfile.ZipFile(whl) as z:
        total = 0
        for zi in z.infolist():
            n = zi.filename
            parts = n.split("/")
            if n.startswith("/") or ".." in parts or "\\" in n or ":" in parts[0]:
                raise PackError("%s: unsafe member name %r" % (whl.name, n))
            if (zi.external_attr >> 16) & 0o170000 == 0o120000:
                raise PackError("%s: symlink member %r" % (whl.name, n))
            total += zi.file_size
            if total > 256 << 20:
                raise PackError("%s: unpacked size too large" % whl.name)
            if n.endswith("/") or "__pycache__" in parts or n.endswith(EXCLUDE_SUFFIX):
                continue
            if any(p.endswith(".data") for p in parts[:1]):
                raise PackError("%s: wheel has a .data directory (not pure-python)" % whl.name)
            out = dest / n
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(z.read(zi))
            os.chmod(out, 0o644)
            names.append(n)
    return names


def assemble(repo: Path, comp: str, version: str, arch: str, lock_path: Path, cache: Path,
             stage: Path, epoch: int) -> Path:
    if comp not in COMPONENTS:
        raise PackError("unknown component %r" % comp)
    if not SEMVER.match(version):
        raise PackError("version %r is not semver" % version)
    src = repo / comp
    pkg = src / ("exp_" + comp)
    entry = src / "bin" / ("exp-" + comp)
    sysd = src / "systemd"
    apt = src / "requirements.apt"
    for p, what in ((pkg, "package dir exp_%s/" % comp), (src / "bin", "bin/"), (sysd, "systemd/")):
        _need_dir(p, what)
    if not (pkg / "__init__.py").is_file():
        raise PackError("malformed component %s: exp_%s/__init__.py missing" % (comp, comp))
    if not entry.is_file() or entry.is_symlink():
        raise PackError("malformed component %s: bin/exp-%s missing" % (comp, comp))
    if not entry.stat().st_mode & 0o100:
        raise PackError("malformed component %s: bin/exp-%s is not executable (chmod +x)" % (comp, comp))
    if not entry.read_bytes().startswith(SHEBANG + b"\n"):
        raise PackError("malformed component %s: bin/exp-%s must start with '#!/usr/bin/python3'" % (comp, comp))
    units = sorted(p.name for p in sysd.iterdir())
    if not units:
        raise PackError("malformed component %s: systemd/ has no unit templates" % comp)
    for u in units:
        if not UNIT_RE.match(u) or not (sysd / u).is_file() or (sysd / u).is_symlink():
            raise PackError("malformed component %s: systemd/%s is not a regular exp-*.service|timer file" % (comp, u))
    if not apt.is_file() or apt.is_symlink():
        raise PackError("malformed component %s: requirements.apt missing (may be empty)" % comp)
    _validate_apt(apt, comp)

    shared = repo / "shared"
    common = shared / "python" / "exp_common"
    schemas = shared / "schemas"
    _need_dir(common, "shared/python/exp_common")
    _need_dir(schemas, "shared/schemas")

    top = stage / ("exp-%s-%s" % (comp, version))
    if top.exists():
        shutil.rmtree(top)
    for d in ("bin", "lib", "vendor", "systemd", "LICENSES"):
        (top / d).mkdir(parents=True)
    (top / "VERSION").write_text(version + "\n", encoding="utf-8")
    shutil.copyfile(entry, top / "bin" / ("exp-" + comp))
    os.chmod(top / "bin" / ("exp-" + comp), 0o755)
    if _copy_tree(pkg, top / "lib" / ("exp_" + comp), "exp_" + comp) == 0:
        raise PackError("malformed component %s: exp_%s/ is empty" % (comp, comp))
    _copy_tree(common, top / "lib" / "exp_common", "exp_common")
    if _copy_tree(schemas, top / "lib" / "exp_common" / "schemas", "schemas") == 0:
        raise PackError("shared/schemas is empty")
    for u in units:
        shutil.copyfile(sysd / u, top / "systemd" / u)
        os.chmod(top / "systemd" / u, 0o644)
    shutil.copyfile(apt, top / "requirements.apt")
    os.chmod(top / "requirements.apt", 0o644)

    # vendored third-party, always re-verified against the lock at the moment of use
    lock = vendor.load_lock(lock_path)
    third: list[str] = []
    try:
        for it in vendor.select(lock, comp, arch):
            f = vendor.verified_path(cache, it)
            if it["kind"] == "wheel":
                _safe_unzip(f, top / "vendor")
                for lic in sorted((top / "vendor").glob("*.dist-info/licenses/*")) + \
                        sorted((top / "vendor").glob("*.dist-info/LICEN[CS]E*")):
                    if lic.is_file():
                        shutil.copyfile(lic, top / "LICENSES" / ("%s-%s" % (it["name"], lic.name)))
            else:
                dst = top / "vendor" / it.get("install_as", it["file"])
                shutil.copyfile(f, dst)
                os.chmod(dst, 0o755)
            third.append("%s %s (%s) license=%s sha256=%s" % (
                it["name"], it["version"], it["arch"], it.get("license", "see upstream"),
                vendor.sha256_file(f)))
            if it["kind"] == "binary":
                lic_note = "%s %s: license %s. Source and license text: see the upstream project release " \
                           "of the same version.\n" % (it["name"], it["version"], it.get("license", "?"))
                (top / "LICENSES" / ("%s-NOTICE.txt" % it["name"])).write_text(lic_note, encoding="utf-8")
                os.chmod(top / "LICENSES" / ("%s-NOTICE.txt" % it["name"]), 0o644)
    except vendor.VendorError as e:
        raise PackError(str(e))
    body = "Third-party components bundled in exp-%s-%s:\n" % (comp, version)
    body += "".join("  - " + t + "\n" for t in third) if third else "  (none)\n"
    (top / "LICENSES" / "THIRD-PARTY.txt").write_text(body, encoding="utf-8")
    os.chmod(top / "LICENSES" / "THIRD-PARTY.txt", 0o644)
    root_lic = repo / "LICENSE"
    if root_lic.is_file() and not root_lic.is_symlink():
        shutil.copyfile(root_lic, top / "LICENSES" / "EXP-LICENSE")
        os.chmod(top / "LICENSES" / "EXP-LICENSE", 0o644)
    return top


def compilecheck(top: Path) -> None:
    import compileall
    import tempfile
    # Never leave bytecode in the stage dir (and thus the tarball).
    with tempfile.TemporaryDirectory() as pyc:
        sys.pycache_prefix = pyc
        ok = True
        for d in ("lib", "vendor"):
            if (top / d).is_dir():
                ok = compileall.compile_dir(str(top / d), quiet=1, force=True) and ok
        for b in sorted((top / "bin").iterdir()):
            try:
                compile(b.read_bytes(), str(b), "exec")
            except SyntaxError as e:
                print("byte-compile failed: %s: %s" % (b, e), file=sys.stderr)
                ok = False
    if not ok:
        raise PackError("byte-compile check failed")
    leftovers = [p for p in top.rglob("*") if p.name == "__pycache__" or p.suffix in (".pyc", ".pyo")]
    if leftovers:
        raise PackError("bytecode left in stage: %s" % leftovers[0])


# --- reproducible tar.gz ---------------------------------------------------------------

class _GzipWriter:
    """Minimal deterministic gzip stream: fixed header (mtime 0, no name, XFL=2, OS=3 unix) so the
    bytes do not depend on the Python version's gzip module defaults."""

    def __init__(self, raw: Any) -> None:
        self._raw = raw
        self._c = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        self._crc = 0
        self._size = 0
        raw.write(b"\x1f\x8b\x08\x00" + struct.pack("<I", 0) + b"\x02\x03")

    def tell(self) -> int:
        return self._size

    def write(self, data: bytes) -> int:
        self._crc = zlib.crc32(data, self._crc)
        self._size += len(data)
        self._raw.write(self._c.compress(data))
        return len(data)

    def close(self) -> None:
        self._raw.write(self._c.flush())
        self._raw.write(struct.pack("<II", self._crc & 0xFFFFFFFF, self._size & 0xFFFFFFFF))


def make_tar(top: Path, out: Path, epoch: int) -> None:
    top = Path(top)
    base = top.name
    entries: list[str] = [base]
    for root, dirs, files in os.walk(top, followlinks=False):
        for n in dirs + files:
            p = Path(root) / n
            if p.is_symlink():
                raise PackError("symlink in package tree: %s" % p)
            entries.append(base + "/" + str(p.relative_to(top)).replace(os.sep, "/"))
    entries.sort()
    tmp = out.with_name(out.name + ".tmp")
    with open(tmp, "wb") as raw:
        gz = _GzipWriter(raw)
        tf = tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT)  # type: ignore[arg-type]
        for arc in entries:
            p = top.parent / arc
            st = p.lstat()
            ti = tarfile.TarInfo(arc)
            ti.mtime = epoch
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            if stat.S_ISDIR(st.st_mode):
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o755
                tf.addfile(ti)
            elif stat.S_ISREG(st.st_mode):
                ti.type = tarfile.REGTYPE
                ti.mode = 0o755 if st.st_mode & 0o111 else 0o644
                ti.size = st.st_size
                with open(p, "rb") as f:
                    tf.addfile(ti, f)
            else:
                raise PackError("unsupported file type in package tree: %s" % p)
        tf.close()
        gz.close()
    os.replace(tmp, out)


# --- manifest --------------------------------------------------------------------------

def canonical_manifest(version: str, epoch: int, min_agent: str, notes_url: str,
                       files: list[Path]) -> bytes:
    arts = []
    for f in files:
        m = ARTIFACT_RE.match(f.name)
        if not m or m.group(2) != version:
            raise PackError("artifact %s does not match exp-<component>-%s-<arch>.tar.gz" % (f.name, version))
        arts.append({"name": f.name, "component": m.group(1), "arch": m.group(3),
                     "sha256": sha256_file(f), "size": f.stat().st_size})
    arts.sort(key=lambda a: (a["component"], a["arch"]))
    doc: dict[str, Any] = {"schema": "exp.manifest/1", "version": version, "created": iso_utc(epoch),
                           "min_agent_version": min_agent, "artifacts": arts}
    if notes_url:
        doc["notes_url"] = notes_url
    # Canonical bytes: fixed key order, compact separators, ASCII, one trailing newline.
    return (json.dumps(doc, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def check_manifest(path: Path, dist: Path) -> None:
    try:
        doc = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise PackError("cannot parse manifest: %s" % e)
    if not isinstance(doc, dict) or doc.get("schema") != "exp.manifest/1":
        raise PackError("manifest schema must be exp.manifest/1")
    ver = doc.get("version")
    for k in ("version", "min_agent_version"):
        if not isinstance(doc.get(k), str) or not SEMVER.match(doc[k]):
            raise PackError("manifest %s is not semver" % k)
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", str(doc.get("created"))):
        raise PackError("manifest created is not UTC ISO-8601")
    if "notes_url" in doc and not str(doc["notes_url"]).startswith("https://"):
        raise PackError("manifest notes_url must be https")
    arts = doc.get("artifacts")
    if not isinstance(arts, list) or not 1 <= len(arts) <= 64:
        raise PackError("manifest artifacts must be a list of 1..64")
    seen = set()
    for a in arts:
        if not isinstance(a, dict):
            raise PackError("artifact entry is not an object")
        name = a.get("name")
        m = ARTIFACT_RE.match(name) if isinstance(name, str) else None
        if not m:
            raise PackError("bad artifact name %r" % (name,))
        if (m.group(1), m.group(2), m.group(3)) != (a.get("component"), ver, a.get("arch")):
            raise PackError("artifact %s disagrees with its component/version/arch fields" % name)
        if name in seen:
            raise PackError("duplicate artifact %s" % name)
        seen.add(name)
        if not isinstance(a.get("sha256"), str) or not re.match(r"^[0-9a-f]{64}$", a["sha256"]):
            raise PackError("artifact %s: bad sha256" % name)
        f = dist / name
        if f.is_symlink() or not f.is_file():
            raise PackError("artifact %s listed in manifest is missing from %s" % (name, dist))
        if f.stat().st_size != a.get("size"):
            raise PackError("artifact %s: size mismatch (manifest %s, file %d)" % (name, a.get("size"), f.stat().st_size))
        if sha256_file(f) != a["sha256"]:
            raise PackError("artifact %s: SHA-256 MISMATCH" % name)


# --- CLI -------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name: str, *args: str, multi: tuple = ()) -> argparse.ArgumentParser:
        sp = sub.add_parser(name)
        for a in args:
            sp.add_argument(a, action="append" if a in multi else "store", required=True)
        return sp

    add("epoch", "--repo")
    add("check-key", "--key", "--repo", multi=("--repo",))
    add("detect", "--repo")
    add("arches", "--lock", "--component")
    add("assemble", "--repo", "--component", "--version", "--arch", "--lock", "--cache", "--stage", "--epoch")
    add("compilecheck", "--stage-top")
    add("tar", "--top", "--out", "--epoch")
    mp = add("manifest", "--version", "--epoch", "--min-agent", "--out")
    mp.add_argument("--notes-url", default="")
    mp.add_argument("files", nargs="+")
    cm = sub.add_parser("check-manifest")
    cm.add_argument("file")
    cm.add_argument("--dist", required=True)
    b = sub.add_parser("b64")
    b.add_argument("src")
    b.add_argument("dst")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "epoch":
            print(resolve_epoch(Path(a.repo[0] if isinstance(a.repo, list) else a.repo)))
        elif a.cmd == "check-key":
            check_key(a.key[0] if isinstance(a.key, list) else a.key, a.repo)
        elif a.cmd == "detect":
            print("\n".join(detect_components(Path(a.repo))))
        elif a.cmd == "arches":
            print(" ".join(component_arches(vendor.load_lock(Path(a.lock)), a.component)))
        elif a.cmd == "assemble":
            top = assemble(Path(a.repo), a.component, a.version, a.arch, Path(a.lock), Path(a.cache),
                           Path(a.stage), int(a.epoch))
            print(top)
        elif a.cmd == "compilecheck":
            compilecheck(Path(a.stage_top))
        elif a.cmd == "tar":
            make_tar(Path(a.top), Path(a.out), int(a.epoch))
        elif a.cmd == "manifest":
            data = canonical_manifest(a.version, int(a.epoch), a.min_agent, a.notes_url,
                                      [Path(f) for f in a.files])
            Path(a.out).write_bytes(data)  # written ONCE; never re-serialized
        elif a.cmd == "check-manifest":
            check_manifest(Path(a.file), Path(a.dist))
        elif a.cmd == "b64":
            Path(a.dst).write_text(base64.b64encode(Path(a.src).read_bytes()).decode("ascii") + "\n")
    except (PackError, vendor.VendorError) as e:
        print("pack: ERROR: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
