"""Harness for the agent acceptance tests in systemd containers (06-agent.md section 9).

* `World`: a TLS fake manager (test/fakes/fake_manager.py) on the docker host, a throwaway CA whose
  certificate is installed into the container trust store for the test only, a throwaway Ed25519
  release key, and builders for signed releases with a REAL agent artifact built from agent/ plus tiny
  fake component artifacts. Nothing here touches the repo or a real network; keys live in tmp dirs.
* `Container`: a systemd-as-PID-1 container (docker run --privileged --cgroupns=host) with exec helpers.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]
for _p in (REPO / "shared" / "python", REPO / "test" / "fakes"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import fake_manager  # noqa: E402
import fakes_common as fc  # noqa: E402
from exp_common import config as exp_config  # noqa: E402
from exp_common import ids as exp_ids  # noqa: E402

MANAGER_NAME = "exp-manager.test"
TOKEN_RE = re.compile(r"exp[aeidn]_[A-Za-z0-9_-]{8,}")
HERE = Path(__file__).resolve().parent
ARCH = {"x86_64": "amd64", "aarch64": "arm64"}.get(os.uname().machine, "amd64")


# --------------------------------------------------------------------------------------------- docker
def sh(
    argv: list[str], *, timeout: float = 120, input_: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        argv, capture_output=True, text=True, timeout=timeout, input=input_, check=False
    )


def docker_unavailable_reason() -> str | None:
    try:
        r = sh(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker is not usable: {exc}"
    if r.returncode != 0:
        return f"docker daemon is not reachable: {(r.stderr or r.stdout).strip()[:200]}"
    return None


_image_cache: dict[str, str | None] = {}


def ensure_image(ubuntu: str) -> str | None:
    """Build exp-agent-systemd:<ubuntu>. Returns None on success, else the reason it cannot be built."""
    tag = f"exp-agent-systemd:{ubuntu}"
    if tag in _image_cache:
        return _image_cache[tag]
    reason: str | None = None
    try:
        r = sh(
            ["docker", "build", "-q", "--build-arg", f"UBUNTU={ubuntu}", "-t", tag, str(HERE)],
            timeout=900,
        )
        if r.returncode != 0:
            reason = (
                f"cannot build the ubuntu:{ubuntu} systemd image: {(r.stderr or r.stdout).strip()[-300:]}"
            )
    except subprocess.TimeoutExpired:
        reason = f"building the ubuntu:{ubuntu} systemd image timed out"
    _image_cache[tag] = reason
    return reason


class ExecResult:
    def __init__(self, rc: int, out: str, err: str) -> None:
        self.rc, self.out, self.err = rc, out, err

    @property
    def text(self) -> str:
        return self.out + self.err

    def __repr__(self) -> str:  # pytest assertion output
        return f"ExecResult(rc={self.rc}, out={self.out[-600:]!r}, err={self.err[-600:]!r})"


class Container:
    def __init__(self, ubuntu: str, *, systemd: bool = True, ca_pem: str | None = None) -> None:
        self.ubuntu = ubuntu
        self.name = f"exp-agent-test-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.systemd = systemd
        argv = [
            "docker",
            "run",
            "-d",
            "--name",
            self.name,
            "--hostname",
            "exp-host-01",
            "--add-host",
            f"{MANAGER_NAME}:host-gateway",
        ]
        if systemd:
            argv += [
                "--privileged",
                "--cgroupns=host",
                "-v",
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                "--tmpfs",
                "/run",
                "--tmpfs",
                "/run/lock",
            ]
            argv += [f"exp-agent-systemd:{ubuntu}"]
        else:
            argv += [f"exp-agent-systemd:{ubuntu}", "sleep", "infinity"]
        r = sh(argv, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"docker run failed: {(r.stderr or r.stdout).strip()[:300]}")
        self.ca_pem = ca_pem
        if systemd:
            self._wait_booted()
            # A real host's / is a shared mount; docker's is private, which makes systemd's per-unit
            # credentials mount (LoadCredential=) silently vanish from the service's namespace.
            self.run("mount --make-rshared /", timeout=20)
        if ca_pem:
            self.install_ca(ca_pem)

    # ---- lifecycle
    def _wait_booted(self, timeout: float = 90) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            r = self.run("systemctl is-system-running", timeout=15)
            last = r.text.strip()
            if last in ("running", "degraded"):
                return
            time.sleep(1)
        logs = sh(["docker", "logs", "--tail", "15", self.name], timeout=20)
        raise SystemdUnavailable(
            f"systemd did not reach running/degraded in {timeout:.0f}s in the container "
            f"(is-system-running: {last!r}); container log: {(logs.stdout + logs.stderr).strip()[-400:]}"
        )

    def install_ca(self, ca_pem: str) -> None:
        self.write("/usr/local/share/ca-certificates/exp-test-ca.crt", ca_pem)
        r = self.run("update-ca-certificates", timeout=60)
        assert r.rc == 0, r

    def remove(self) -> None:
        sh(["docker", "rm", "-f", self.name], timeout=60)

    # ---- exec
    def run(self, cmd: str, *, user: str | None = None, timeout: float = 120) -> ExecResult:
        argv = ["docker", "exec", "-i"] + (["-u", user] if user else []) + [self.name, "bash", "-c", cmd]
        try:
            r = sh(argv, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            return ExecResult(124, "", f"timed out after {timeout}s: {exc}")
        return ExecResult(r.returncode, r.stdout, r.stderr)

    def write(self, path: str, text: str) -> None:
        r = sh(["docker", "exec", "-i", self.name, "bash", "-c", f"cat > {path}"], timeout=30, input_=text)
        assert r.returncode == 0, r.stderr

    def cp_in(self, src: Path, dest: str) -> None:
        r = sh(["docker", "cp", str(src), f"{self.name}:{dest}"], timeout=60)
        assert r.returncode == 0, r.stderr

    def read(self, path: str) -> str:
        r = self.run(f"cat {path}")
        assert r.rc == 0, r
        return r.out

    def exists(self, path: str) -> bool:
        return self.run(f"test -e {path} || test -L {path}").rc == 0

    def credentials_supported(self) -> bool:
        """Can this container's systemd deliver LoadCredential= (a per-unit credentials directory)?"""
        self.write("/root/credprobe", "x")
        self.run("chmod 600 /root/credprobe")
        r = self.run(
            "systemd-run --wait -P -q -p LoadCredential=x:/root/credprobe "
            "bash -c 'test -r $CREDENTIALS_DIRECTORY/x'",
            timeout=60,
        )
        return r.rc == 0

    def agent_log(self, n: int = 40) -> str:
        return self.run(f"journalctl -u exp-agent --no-pager -o cat -n {n}", timeout=30).out

    def journal(self) -> str:
        return self.run("journalctl --no-pager -o cat", timeout=60).out

    def active(self, unit: str) -> bool:
        return self.run(f"systemctl is-active --quiet {unit}").rc == 0

    def files_under(self, *roots: str) -> list[str]:
        r = self.run("find " + " ".join(roots) + " \\( -type f -o -type l \\) 2>/dev/null | sort")
        return [ln for ln in r.out.splitlines() if ln]

    def reset_host(self) -> None:
        """Back to a never-enrolled host (between independent scenarios in one container)."""
        self.run(
            "systemctl stop exp-agent.service exp-agent-rollback.timer exp-agent-rollback.service 'exp-*' 2>/dev/null; "
            "systemctl disable exp-agent.service exp-agent-rollback.timer >/dev/null 2>&1; "
            "rm -rf /etc/exp /opt/exp /var/lib/exp /run/exp /etc/systemd/system/exp-* "
            "/etc/systemd/system/multi-user.target.wants/exp-* /etc/systemd/system/timers.target.wants/exp-* "
            "/usr/local/bin/exp-*; systemctl daemon-reload; systemctl reset-failed",
            timeout=120,
        )


class SystemdUnavailable(Exception):
    """systemd cannot run as PID 1 in this docker environment (cgroups, privileges)."""


def wait_for(
    fn: Callable[[], Any],
    timeout: float,
    interval: float = 1.0,
    what: str = "condition",
    diag: Callable[[], str] | None = None,
) -> Any:
    deadline = time.monotonic() + timeout
    last: Any = None
    while True:
        try:
            last = fn()
        except AssertionError as exc:
            last = exc
        else:
            if last:
                return last
        if time.monotonic() >= deadline:
            extra = ""
            if diag is not None:
                try:
                    extra = "\n--- diagnostics ---\n" + diag()
                except Exception as exc:  # noqa: BLE001 - diagnostics must never mask the real failure
                    extra = f"\n(diagnostics failed: {exc})"
            raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what} (last: {last!r}){extra}")
        time.sleep(interval)


# --------------------------------------------------------------------------------------------- tarballs
def build_tar(
    top: str,
    files: dict[str, bytes | tuple[bytes, int]],
    extra: Callable[[tarfile.TarFile], None] | None = None,
) -> bytes:
    """Deterministic root-owned tar.gz (<top>/...). files: relative path -> bytes | (bytes, mode)."""
    buf = io.BytesIO()
    dirs: set[str] = set()
    for rel in files:
        parts = rel.split("/")[:-1]
        for i in range(1, len(parts) + 1):
            dirs.add("/".join(parts[:i]))
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        ti = tarfile.TarInfo(top)
        ti.type, ti.mode, ti.uname, ti.gname = tarfile.DIRTYPE, 0o755, "root", "root"
        tar.addfile(ti)
        for d in sorted(dirs):
            ti = tarfile.TarInfo(f"{top}/{d}")
            ti.type, ti.mode, ti.uname, ti.gname = tarfile.DIRTYPE, 0o755, "root", "root"
            tar.addfile(ti)
        for rel in sorted(files):
            spec = files[rel]
            data, mode = spec if isinstance(spec, tuple) else (spec, 0o644)
            ti = tarfile.TarInfo(f"{top}/{rel}")
            ti.size, ti.mode, ti.uname, ti.gname = len(data), mode, "root", "root"
            tar.addfile(ti, io.BytesIO(data))
        if extra:
            extra(tar)
    return buf.getvalue()


def agent_files(version: str) -> dict[str, bytes | tuple[bytes, int]]:
    """The agent tarball layout (01-contracts.md section 10) built from this checkout."""
    files: dict[str, bytes | tuple[bytes, int]] = {
        "VERSION": f"{version}\n".encode(),
        "requirements.apt": b"",
    }
    files["bin/exp-agent"] = ((REPO / "agent/bin/exp-agent").read_bytes(), 0o755)
    for p in sorted((REPO / "agent/exp_agent").glob("*.py")):
        files[f"lib/exp_agent/{p.name}"] = p.read_bytes()
    for p in sorted((REPO / "shared/python/exp_common").glob("*.py")):
        files[f"lib/exp_common/{p.name}"] = p.read_bytes()
    for p in sorted((REPO / "shared/schemas").glob("*.json")):
        files[f"lib/exp_common/schemas/{p.name}"] = p.read_bytes()
    for p in sorted((REPO / "agent/systemd").glob("exp-*")):
        files[f"systemd/{p.name}"] = p.read_bytes()
    return files


STUB_AGENT = b"#!/bin/sh\n# a new agent that starts but never polls or reports (the rollback timer must restore the old one)\nexec sleep 3600\n"

FAKE_COMPONENT = r"""#!/usr/bin/python3
# A stand-in exp component for the agent acceptance tests: `run` stays up (and notes which credentials
# systemd delivered, never their values), `health --json` answers exp.health/1.
import json, os, sys, time
here = os.path.dirname(os.path.realpath(__file__))
ver = open(os.path.join(here, "..", "VERSION")).read().strip()
if sys.argv[1:2] == ["health"]:
    print(json.dumps({"schema": "exp.health/1", "status": "ok", "detail": "", "version": ver,
                      "uptime_s": 1.0, "metrics": {}, "facts": {}}))
elif sys.argv[1:2] == ["run"]:
    d = os.environ.get("CREDENTIALS_DIRECTORY", "")
    try:
        got = sorted(os.listdir(d)) if d else []
        print("fake component %s up; credentials delivered: %s" % (ver, ",".join(got)), flush=True)
    except OSError:  # a container whose systemd cannot mount per-unit credential directories
        print("fake component %s up; credentials directory unavailable" % ver, flush=True)
    while True:
        time.sleep(5)
else:
    sys.exit(2)
"""


def fake_component_files(
    comp: str, version: str, creds: tuple[str, ...]
) -> dict[str, bytes | tuple[bytes, int]]:
    unit = [
        "[Unit]",
        f"Description=fake exp {comp} (agent acceptance test)",
        "",
        "[Service]",
        "Type=simple",
        f"User=exp-{comp}",
        f"ExecStart=@PREFIX@/bin/exp-{comp} run --config @CONFIG@",
        *[f"LoadCredential={n}:@CREDS@/{n}" for n in creds],
        "Restart=on-failure",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return {
        "VERSION": f"{version}\n".encode(),
        f"bin/exp-{comp}": (FAKE_COMPONENT.encode(), 0o755),
        f"systemd/exp-{comp}.service": "\n".join(unit).encode(),
        "requirements.apt": b"",
    }


# --------------------------------------------------------------------------------------------- the world
def _openssl(*argv: str, cwd: Path) -> None:
    r = subprocess.run(["openssl", *argv], cwd=cwd, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603,S607
    if r.returncode != 0:
        raise RuntimeError(f"openssl {argv[0]} failed: {r.stderr[-300:]}")


def make_ca_and_server_cert(d: Path) -> tuple[str, Path, Path]:
    """Throwaway local CA + a server certificate for MANAGER_NAME. Returns (ca_pem_text, cert, key)."""
    d.mkdir(parents=True, exist_ok=True)
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
    _openssl(
        "req",
        "-x509",
        *ec,
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "2",
        "-subj",
        "/CN=exp agent test CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        cwd=d,
    )
    _openssl(
        "req", "-new", *ec, "-keyout", "srv.key", "-out", "srv.csr", "-subj", f"/CN={MANAGER_NAME}", cwd=d
    )
    (d / "ext.cnf").write_text(
        f"subjectAltName=DNS:{MANAGER_NAME},IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n"
    )
    _openssl(
        "x509",
        "-req",
        "-in",
        "srv.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-out",
        "srv.pem",
        "-days",
        "2",
        "-extfile",
        "ext.cnf",
        cwd=d,
    )
    for f in ("ca.key", "srv.key"):
        (d / f).chmod(0o600)
    return (d / "ca.pem").read_text(), d / "srv.pem", d / "srv.key"


class World:
    """TLS fake manager + signed releases. Use as a context manager (or call stop())."""

    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.ca_pem, cert, key = make_ca_and_server_cert(tmp / "ca")
        state = tmp / "manager"
        (state / "tls").mkdir(parents=True)
        (state / "tls" / "cert.pem").write_bytes(cert.read_bytes())
        (state / "tls" / "key.pem").write_bytes(key.read_bytes())
        (state / "tls" / "key.pem").chmod(0o600)
        self.fake = fake_manager.start(
            host="0.0.0.0",
            tls=True,
            state_dir=state,
            scenario="empty",  # noqa: S104
            enrol_rate=(1000, 60.0),
        )
        self.app = self.fake.app
        self.url = f"https://{MANAGER_NAME}:{self.fake.port}"
        self.releases: dict[str, dict[str, dict[str, Any]]] = {}  # version -> artifact name -> info
        self.version_n = 0

    def stop(self) -> None:
        self.fake.stop()
        self.app.close()

    def __enter__(self) -> World:
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---- installer as the manager would serve it
    def serve_install_sh(
        self, *, pubkey_pem: str | None = None, manager_url: str | None = None, agent_version: str = "0.1.0"
    ) -> Path:
        text = (REPO / "agent/install/install.sh").read_text("utf-8")
        text = (
            text.replace("@@MANAGER_URL@@", manager_url or self.url)
            .replace("@@AGENT_VERSION@@", agent_version)
            .replace("@@RELEASE_PUBKEY_PEM@@", (pubkey_pem or self.app.key.public_pem).strip())
        )
        out = self.tmp / "install.served.sh"
        out.write_text(text, "utf-8")
        self.app.install_sh = out
        return out

    # ---- hosts
    def add_host(self, name: str = "srv-test", site: str = "hall-b") -> tuple[str, str]:
        hid = self.app.add_host(name=name, site=site)["host_id"]
        return hid, self.app.issue_enrol_token(hid)

    def host(self, hid: str) -> Any:
        return self.app.hosts[hid]

    # ---- releases
    def publish_release(
        self,
        version: str,
        artifacts: list[tuple[str, str, str, bytes]],
        *,
        min_agent: str = "0.1.0",
        signing_key: Any = None,
        tamper_manifest: bool = False,
        corrupt_artifact: str | None = None,
    ) -> dict[str, dict[str, Any]]:
        """artifacts: (component, version, arch, tar.gz bytes). Registers bytes + a signed manifest."""
        entries, info = [], {}
        for comp, cver, arch, data in artifacts:
            name = f"exp-{comp}-{cver}-{arch}.tar.gz"
            aid = fc.det_id("art_", name + hashlib.sha256(data).hexdigest()[:10])
            sha = hashlib.sha256(data).hexdigest()
            entries.append({"name": name, "component": comp, "arch": arch, "sha256": sha, "size": len(data)})
            served = data
            if corrupt_artifact == name:  # same size, different bytes: the signed sha256 must catch it
                served = data[:-1] + bytes([data[-1] ^ 0xFF])
            self.app.artifacts[aid] = served
            info[name] = {"id": aid, "sha256": sha, "size": len(data), "component": comp, "version": cver}
        manifest = {
            "schema": "exp.manifest/1",
            "version": version,
            "created": fc.iso_from_epoch(time.time()),
            "min_agent_version": min_agent,
            "artifacts": entries,
        }
        exp_config.validate(manifest, "manifest.schema.json")
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        sig = (signing_key or self.app.key).sign(raw)
        if tamper_manifest:
            raw = raw.replace(b'"created"', b'"CREATED"')
        self.app.releases[version] = (raw, sig)
        self.releases[version] = info
        return info

    def standard_release(
        self, version: str, *, components: tuple[str, ...] = (), stub_agent: bool = False, **kw: Any
    ) -> dict[str, dict[str, Any]]:
        files = agent_files(version)
        if stub_agent:
            files["bin/exp-agent"] = (STUB_AGENT, 0o755)
        arts = [("agent", version, "noarch", build_tar(f"exp-agent-{version}", files))]
        for c in components:
            arts.append(
                (
                    c,
                    version,
                    ARCH if c == "collector" else "noarch",
                    build_tar(
                        f"exp-{c}-{version}-{ARCH if c == 'collector' else 'noarch'}",
                        fake_component_files(
                            c, version, ("ingest_tokens.json", "dashboard_tokens.json", "webhooks.json")
                        ),
                    ),
                )
            )
        return self.publish_release(version, arts, **kw)

    # ---- desired state
    def component(
        self, ctype: str, release_version: str, config: dict[str, Any], creds: dict[str, str], cid: str
    ) -> dict[str, Any]:
        """A desired-state component entry for the artifact of `ctype` in `release_version` (this host's arch)."""
        rel = self.releases[release_version]
        names = [
            n
            for n, i in rel.items()
            if i["component"] == ctype and (n.endswith("-noarch.tar.gz") or n.endswith(f"-{ARCH}.tar.gz"))
        ]
        assert names, f"release {release_version} has no {ctype} artifact for {ARCH}"
        name = names[0]
        info = rel[name]
        return {
            "type": ctype,
            "id": cid,
            "component_id": exp_ids.new_id("cmp_"),
            "version": info["version"],
            "artifact": {
                "id": info["id"],
                "name": name,
                "url": f"/api/agent/v1/artifacts/{info['id']}",
                "sha256": info["sha256"],
                "size": info["size"],
            },
            "config": config,
            "creds": creds,
        }

    def collector_component(
        self,
        release_version: str,
        config_edit: Callable[[dict[str, Any]], None] | None = None,
        creds: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        base = fc.load_fixture("desired/collector-host.json")["components"][0]
        base["config"]["listen"] = "127.0.0.1:8443"
        if config_edit:
            config_edit(base["config"])
        return self.component(
            "collector",
            release_version,
            base["config"],
            creds if creds is not None else base["creds"],
            base["id"],
        )

    def load_dist(self, dist: Path) -> str:
        """Serve a real built release (packaging/build.sh output) unchanged: manifest bytes, signature, tarballs."""
        mpath = sorted(dist.glob("exp-*-manifest.json"))[0]
        raw = mpath.read_bytes()
        sig = Path(str(mpath) + ".sig").read_text().strip()
        doc = json.loads(raw)
        info = {}
        for a in doc["artifacts"]:
            data = (dist / a["name"]).read_bytes()
            assert hashlib.sha256(data).hexdigest() == a["sha256"], f"{a['name']} does not match its manifest"
            aid = fc.det_id("art_", a["name"] + a["sha256"][:10])
            self.app.artifacts[aid] = data
            info[a["name"]] = {
                "id": aid,
                "sha256": a["sha256"],
                "size": a["size"],
                "component": a["component"],
                "version": doc["version"],
            }
        self.app.releases[doc["version"]] = (raw, sig)
        self.releases[doc["version"]] = info
        return doc["version"]

    def set_desired(
        self,
        hid: str,
        release_version: str,
        *,
        agent_version: str | None = None,
        components: list[dict[str, Any]] | None = None,
        decommission: bool = False,
        actions: list[dict[str, Any]] | None = None,
        poll_interval_s: int = 30,
    ) -> str:
        agent_version = agent_version or release_version
        ainfo = self.releases[release_version][f"exp-agent-{agent_version}-noarch.tar.gz"]
        self.version_n += 1
        doc = {
            "schema": "exp.desired/1",
            "host_id": hid,
            "version": self.version_n,
            "generated_at": fc.iso_from_epoch(time.time()),
            "org": {"id": "default", "name": "Test Org"},
            "site": {"id": "hall-b", "name": "Hall B", "timezone": "UTC"},
            "agent": {
                "version": agent_version,
                "artifact": ainfo["id"],
                "poll_interval_s": poll_interval_s,
                "status_interval_s": 30,
            },
            "release": {
                "version": release_version,
                "manifest_url": f"/api/agent/v1/releases/{release_version}/manifest",
                "signature_url": f"/api/agent/v1/releases/{release_version}/manifest.sig",
            },
            "components": components or [],
            "actions": actions or [],
            "decommission": decommission,
        }
        return self.app.set_desired(hid, doc, synthesize=False)

    # ---- manager-side observations
    def reports(self, hid: str) -> list[dict[str, Any]]:
        return list(self.host(hid).reports)

    def last_report(self, hid: str) -> dict[str, Any] | None:
        r = self.reports(hid)
        return r[-1] if r else None

    def all_text(self, hid: str) -> str:
        return json.dumps(self.reports(hid))


def pubkey_of(directory: Path) -> tuple[Any, str]:
    """A second throwaway Ed25519 key (to prove a release signed by the wrong key is refused)."""
    k = fake_manager.ReleaseKey(directory)
    return k, k.public_pem


# --------------------------------------------------------------------------------------------- scenario helpers
def run_install(
    c: Container, world: World, token: str | None = None, *, bash_flags: str = "", timeout: float = 300
) -> ExecResult:
    """The documented one-liner: curl -fsSL https://<manager>/install.sh | sudo bash -s -- <token>."""
    arg = f" {token}" if token else ""
    return c.run(f"curl -fsSL {world.url}/install.sh | sudo bash {bash_flags} -s --{arg}", timeout=timeout)


def agent_cfg(c: Container) -> dict[str, Any]:
    return json.loads(c.read("/etc/exp/agent.json"))


def sha(c: Container, path: str) -> str:
    return c.run(f"sha256sum {path} | cut -d' ' -f1").out.strip()


def main_pid(c: Container, unit: str) -> str:
    return c.run(f"systemctl show -p MainPID --value {unit}").out.strip()


def assert_no_tokens(text: str, what: str) -> None:
    found = TOKEN_RE.findall(text)
    assert not found, f"token-shaped strings in {what}: {[t[:10] + '...' for t in found[:3]]}"


def token_used(world: World, token: str) -> bool:
    return bool(world.app.enrol_tokens[exp_ids.token_hash(token)]["used"])
