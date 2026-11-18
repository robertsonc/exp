"""Test doubles: scripted command runner, fake clock, artifact builder, and an `Env` that wires a Context
(tmp root, unprivileged) to the WP-0 fake manager."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import fake_manager
import fakes_common as fc
from exp_common import ids as exp_ids

from exp_agent.client import ManagerClient
from exp_agent.config import AgentConfig
from exp_agent.context import Context, build_context
from exp_agent.runner import Result, Runner, check_argv

SVC_UID = 4242

HEALTH_OK = {
    "schema": "exp.health/1",
    "status": "ok",
    "detail": "",
    "version": "0.1.0",
    "uptime_s": 12.0,
    "metrics": {"probes_total": 1},
    "facts": {},
}


class FakeClock:
    def __init__(self, t: float = 1_700_000_000.0) -> None:
        self.t = t

    def time(self) -> float:
        return self.t

    def monotonic(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


class ScriptedRunner:
    """Records every argv, answers systemctl/apt/useradd/ip/... and the components' own CLIs from scripts;
    everything else (openssl) runs for real. Every call passes the production argv check."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.real = Runner()
        self.users: set[str] = set()
        self.installed_pkgs: set[str] = set()
        self.health: dict[str, Callable[[str], Result] | Result] = {}
        self.preflight_rc = 0
        self.preflight_msg = ""
        self.fail: dict[tuple[str, ...], Result] = {}  # prefix of argv -> forced result
        self.show: dict[str, dict[str, str]] = {}
        self.ip: dict[str, Any] = {"link": [], "addr": [], "route": []}
        self.journal = "line one\nline two\n"
        self.synced = "yes"

    # --- inspection helpers
    def argvs(self, *prefix: str) -> list[list[str]]:
        return [c for c in self.calls if c[: len(prefix)] == list(prefix)]

    def systemctl(self, verb: str) -> list[list[str]]:
        return [c for c in self.calls if c[0] == "systemctl" and verb in c[1:3]]

    def mutating(self) -> list[list[str]]:
        verbs = {"restart", "enable", "disable", "reload", "daemon-reload", "stop", "start"}
        out = [c for c in self.calls if c[0] == "systemctl" and verbs & set(c[1:3])]
        out += [c for c in self.calls if c[0] in ("apt-get", "useradd")]
        return out

    # --- the Runner interface
    def run(self, argv, *, timeout: float, input: str | None = None, env=None, cwd=None) -> Result:  # noqa: A002
        args = check_argv(argv)
        assert timeout > 0
        self.calls.append(args)
        for prefix, res in self.fail.items():
            if args[: len(prefix)] == list(prefix):
                return res
        exe = args[0]
        if exe == "systemctl":
            return self._systemctl(args)
        if exe == "apt-get":
            self.installed_pkgs.update(a for a in args[4:] if not a.startswith("-"))
            return Result(0)
        if exe == "dpkg-query":
            ok = args[-1] in self.installed_pkgs
            return Result(0 if ok else 1, "install ok installed" if ok else "")
        if exe == "useradd":
            self.users.add(args[-1])
            return Result(0)
        if exe == "ip":
            key = args[2]
            return Result(0, json.dumps(self.ip.get(key, [])))
        if exe == "timedatectl":
            return Result(0, f"Timezone=UTC\nNTP=yes\nNTPSynchronized={self.synced}\n")
        if exe == "journalctl":
            return Result(0, self.journal)
        if len(args) > 1 and args[1] == "health" and "/bin/exp-" in exe:
            comp = Path(exe).name[len("exp-") :]
            ver = Path(exe).parent.parent.name
            h = self.health.get(comp)
            if callable(h):
                return h(ver)
            if isinstance(h, Result):
                return h
            return Result(0, json.dumps({**HEALTH_OK, "version": ver}))
        if len(args) > 1 and args[1] == "preflight" and "/bin/exp-" in exe:
            return Result(self.preflight_rc, "", self.preflight_msg)
        return self.real.run(argv, timeout=timeout, input=input, env=env, cwd=cwd)

    def _systemctl(self, args: list[str]) -> Result:
        if args[1] == "show":
            unit = args[2]
            props = {
                "ActiveState": "active",
                "CPUUsageNSec": "1000000000",
                "MemoryCurrent": "52428800",
                "NRestarts": "0",
                "ActiveEnterTimestampMonotonic": "1000000",
            }
            props.update(self.show.get(unit, {}))
            return Result(0, "".join(f"{k}={v}\n" for k, v in props.items()))
        return Result(0)


def build_tar(
    top: str, files: dict[str, Any], extra: Callable[[tarfile.TarFile], None] | None = None
) -> bytes:
    """files: relative path -> bytes | (bytes, mode)."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        ti = tarfile.TarInfo(top)
        ti.type, ti.mode = tarfile.DIRTYPE, 0o755
        tar.addfile(ti)
        for rel, spec in files.items():
            data, mode = spec if isinstance(spec, tuple) else (spec, 0o644)
            ti = tarfile.TarInfo(f"{top}/{rel}")
            ti.size, ti.mode = len(data), mode
            tar.addfile(ti, io.BytesIO(data))
        if extra:
            extra(tar)
    return buf.getvalue()


def service_unit(c: str, creds: tuple[str, ...] = (), reload_: bool = False, name: str | None = None) -> str:
    lines = [
        "[Unit]",
        f"Description=exp {c}",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart=@PREFIX@/bin/exp-{c} run --config @CONFIG@",
    ]
    lines += [f"LoadCredential={n}:@CREDS@/{n}" for n in creds]
    if reload_:
        lines.append("ExecReload=/bin/kill -HUP $MAINPID")
    lines += ["", "[Install]", "WantedBy=multi-user.target", ""]
    return "\n".join(lines)


def component_files(
    c: str,
    version: str,
    creds: tuple[str, ...] = (),
    reload_: bool = False,
    requirements: tuple[str, ...] = (),
    extra_units: dict[str, str] | None = None,
) -> dict[str, Any]:
    files: dict[str, Any] = {
        "VERSION": version.encode() + b"\n",
        f"bin/exp-{c}": (b"#!/bin/sh\nexit 0\n", 0o755),
        f"systemd/exp-{c}.service": service_unit(c, creds, reload_).encode(),
        "requirements.apt": ("\n".join(requirements) + "\n").encode(),
    }
    if c == "probe":
        files["systemd/exp-probe-netns.service"] = (
            b"[Service]\nType=oneshot\nRemainAfterExit=yes\n"
            b"ExecStart=@PREFIX@/bin/exp-probe netns up --config @CONFIG@\n"
            b"ExecStop=@PREFIX@/bin/exp-probe netns down --config @CONFIG@\n"
            b"[Install]\nWantedBy=multi-user.target\n"
        )
        files["systemd/exp-probe-lease@.service"] = (
            b"[Service]\nExecStart=@PREFIX@/bin/exp-probe lease %i --config @CONFIG@\n[Install]\n"
            b"WantedBy=multi-user.target\n"
        )
        files["systemd/exp-probe-target@.service"] = (
            b"[Service]\nExecStart=@PREFIX@/bin/exp-probe target %i --config @CONFIG@\n[Install]\n"
            b"WantedBy=multi-user.target\n"
        )
    for n, t in (extra_units or {}).items():
        files[f"systemd/{n}"] = t.encode()
    return files


class Env:
    """A host in a tmp root + a fake manager serving a signed release."""

    def __init__(self, tmp_path: Path, tls: bool = False) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.root.mkdir()
        (self.root / "etc" / "systemd" / "system").mkdir(parents=True)  # exists on every real host
        self.fake = fake_manager.start(state_dir=tmp_path / "fm", scenario="empty", tls=tls)
        self.app = self.fake.app
        made = self.app.add_host(enrolled=True)
        self.host_id, self.secret = made["host_id"], made["agent_secret"]
        self.runner = ScriptedRunner()
        self.clock = FakeClock()
        self.chowns: list[tuple[str, int, int]] = []
        self.artifacts: dict[str, dict[str, Any]] = {}  # name -> {id, sha256, size, data}
        self.ctx: Context = build_context(
            self.root,
            uid=os.geteuid(),
            gid=os.getegid(),
            runner=self.runner,
            arch="amd64",
            lchown=lambda p, u, g: self.chowns.append((p, u, g)),
            clock=self.clock.time,
            monotonic=self.clock.monotonic,
            sleep=self.clock.sleep,
            user_exists=lambda n: n in self.runner.users,
            user_ids=lambda n: (SVC_UID, SVC_UID),
        )
        self.cfg = AgentConfig(
            f"{'https' if tls else 'http'}://127.0.0.1:{self.fake.port}",
            self.host_id,
            self.secret,
            self.app.key.public_pem,
        )
        self.client = ManagerClient(self.cfg.manager_url, self.secret, allow_http=not tls, use_proxy=False)
        self.ctx.attach_manager(self.cfg, self.client)
        self.ctx.state.ensure_dir()
        from exp_agent.config import save_agent_config

        save_agent_config(self.ctx.fs, self.cfg)
        self.version_n = 0
        self.release_version = "0.1.0"

    def close(self) -> None:
        self.fake.stop()

    # ----- releases
    def add_artifact(self, comp: str, version: str, files: dict[str, Any], arch: str = "noarch") -> str:
        name = f"exp-{comp}-{version}-{arch}.tar.gz"
        data = build_tar(f"exp-{comp}-{version}", files)
        self.add_raw_artifact(name, comp, arch, data)
        return name

    def add_raw_artifact(self, name: str, comp: str, arch: str, data: bytes, aid: str | None = None) -> None:
        aid = aid or fc.det_id("art_", name + hashlib.sha256(data).hexdigest()[:8])
        self.app.artifacts[aid] = data
        sha = hashlib.sha256(data).hexdigest()
        self.artifacts[name] = {
            "id": aid,
            "sha256": sha,
            "size": len(data),
            "data": data,
            "component": comp,
            "arch": arch,
        }

    def sign_release(self, version: str, min_agent: str = "0.1.0", tamper: bool = False) -> None:
        arts = [
            {
                "name": n,
                "component": a["component"],
                "arch": a["arch"],
                "sha256": a["sha256"],
                "size": a["size"],
            }
            for n, a in self.artifacts.items()
            if f"-{version}-" in n
        ]
        manifest = {
            "schema": "exp.manifest/1",
            "version": version,
            "created": "2026-11-18T20:00:00.000Z",
            "min_agent_version": min_agent,
            "artifacts": arts,
            "notes_url": "https://example.invalid/notes",
        }
        raw = (json.dumps(manifest, indent=2) + "\n").encode()
        sig = self.app.key.sign(raw)
        if tamper:
            raw = raw.replace(b'"created"', b'"CREATED"')
        self.app.releases[version] = (raw, sig)

    def add_agent_release(self, version: str, files: dict[str, Any] | None = None) -> None:
        """An agent artifact whose id is the one `desired(agent_version=...)` references."""
        repo = Path(__file__).resolve().parents[1]
        base = {"VERSION": version.encode() + b"\n", "bin/exp-agent": (b"#!/bin/sh\nexit 0\n", 0o755)}
        for n in ("exp-agent.service", "exp-agent-rollback.service", "exp-agent-rollback.timer"):
            base[f"systemd/{n}"] = (repo / "systemd" / n).read_bytes()
        data = build_tar(f"exp-agent-{version}", files if files is not None else base)
        self.add_raw_artifact(
            f"exp-agent-{version}-noarch.tar.gz",
            "agent",
            "noarch",
            data,
            aid=fc.det_id("art_", f"agent-{version}"),
        )

    def install_running_agent(self, version: str = "0.1.0") -> None:
        """The tree install.sh would have created: /opt/exp/agent/<version> + current."""
        d = self.root / "opt" / "exp" / "agent" / version
        (d / "bin").mkdir(parents=True)
        (d / "bin" / "exp-agent").write_text("#!/bin/sh\n")
        os.symlink(version, d.parent / "current")

    # ----- desired
    def comp(
        self,
        c: str,
        version: str = "0.1.0",
        config: dict[str, Any] | None = None,
        creds: dict[str, str] | None = None,
        arch: str | None = None,
    ) -> dict[str, Any]:
        fixture = {"collector": "collector-host", "dashboard": "dashboard-host", "probe": "probe-host"}[c]
        base = fc.load_fixture(f"desired/{fixture}.json")["components"][0]
        arch = arch or ("amd64" if c == "collector" else "noarch")
        name = f"exp-{c}-{version}-{arch}.tar.gz"
        a = self.artifacts[name]
        base["version"] = version
        base["artifact"] = {
            "id": a["id"],
            "name": name,
            "url": f"/api/agent/v1/artifacts/{a['id']}",
            "sha256": a["sha256"],
            "size": a["size"],
        }
        if config is not None:
            base["config"] = config
        if creds is not None:
            base["creds"] = creds
        return base

    def desired(
        self,
        comps: list[dict[str, Any]],
        actions: list[dict[str, Any]] | None = None,
        decommission: bool = False,
        agent_version: str | None = None,
        release: str | None = None,
    ) -> dict[str, Any]:
        self.version_n += 1
        rel = release or self.release_version
        doc = {
            "schema": "exp.desired/1",
            "host_id": self.host_id,
            "version": self.version_n,
            "generated_at": "2026-11-18T20:00:00.000Z",
            "org": {"id": "default", "name": "T"},
            "site": {"id": "hall-b", "name": "Hall B", "timezone": "UTC"},
            "agent": {"version": agent_version or "0.1.0", "poll_interval_s": 30, "status_interval_s": 60},
            "release": {
                "version": rel,
                "manifest_url": f"/api/agent/v1/releases/{rel}/manifest",
                "signature_url": f"/api/agent/v1/releases/{rel}/manifest.sig",
            },
            "components": comps,
            "actions": actions or [],
            "decommission": decommission,
        }
        if agent_version:
            doc["agent"]["artifact"] = fc.det_id("art_", f"agent-{agent_version}")
        return doc

    def push(self, doc: dict[str, Any]) -> None:
        self.app.set_desired(self.host_id, doc, synthesize=False)

    def standard_release(
        self,
        version: str = "0.1.0",
        comps: tuple[str, ...] = ("collector", "dashboard", "probe"),
        creds: dict[str, tuple[str, ...]] | None = None,
        **kw: Any,
    ) -> None:
        creds = creds or {}
        for c in comps:
            files = component_files(c, version, creds.get(c, ()), **kw)
            self.add_artifact(c, version, files, "amd64" if c == "collector" else "noarch")
        self.sign_release(version)

    # ----- helpers
    def path(self, logical: str) -> Path:
        return self.ctx.paths.host(logical)

    def all_logs_clean(self) -> None:
        pass


def tokens_in(text: str) -> list[str]:
    import re

    return re.findall(r"exp[aeidn]_[A-Za-z0-9_-]{8,}", text)


def new_expa() -> str:
    return exp_ids.new_token("expa")
