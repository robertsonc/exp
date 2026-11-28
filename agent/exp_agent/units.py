"""systemd unit templates: load from the artifact, refuse bad names/placeholders, render, write, and drive
systemctl (argv only). Config values are NEVER interpolated into units: only the six fixed placeholders,
whose values are computed from the component name and version."""

from __future__ import annotations

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from .errors import AgentError, Refused
from .pathguard import UNIT_RE, Paths, SafeFS
from .runner import Runner

log = logging.getLogger(__name__)

PLACEHOLDERS = ("@VERSION@", "@PREFIX@", "@CONFIG@", "@CREDS@", "@STATE@", "@RUN@")
_ANY_PLACEHOLDER = re.compile(r"@[A-Z][A-Z0-9_]*@")
MAX_UNIT_BYTES = 64 * 1024
MAX_UNITS = 32
_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def is_template(name: str) -> bool:
    return "@." in name


def placeholder_values(paths: Paths, component: str, version: str) -> dict[str, str]:
    """Logical (host) paths; computed from validated names only."""
    paths.version_dir(component, version)  # validates both
    return {
        "@VERSION@": version,
        "@PREFIX@": f"/opt/exp/{component}/{version}",
        "@CONFIG@": f"/etc/exp/{component}/config.json",
        "@CREDS@": f"/etc/exp/{component}/creds",
        "@STATE@": f"/var/lib/exp/{component}",
        "@RUN@": f"/run/exp/{component}",
    }


def load_templates(root: Path) -> dict[str, str]:
    """Read <root>/systemd/*: every entry must be a regular file named exp-*.service|timer (templates
    like exp-probe-lease@.service allowed). Anything else refuses the component."""
    d = root / "systemd"
    try:
        names = sorted(os.listdir(d))
    except FileNotFoundError:
        return {}
    if len(names) > MAX_UNITS:
        raise Refused("artifact ships too many unit templates")
    out: dict[str, str] = {}
    for name in names:
        if not UNIT_RE.match(name):
            raise Refused(f"unit template name {name[:64]!r} does not match exp-*.service|timer")
        try:
            fd = os.open(d / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            raise Refused(f"unit template {name} is not a plain file") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_UNIT_BYTES:
                raise Refused(f"unit template {name} is not a regular file of acceptable size")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                raw = fh.read(MAX_UNIT_BYTES + 1)
        finally:
            os.close(fd)
        try:
            out[name] = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Refused(f"unit template {name} is not UTF-8") from None
    return out


def render(name: str, text: str, values: dict[str, str]) -> str:
    out = text
    for k, v in values.items():
        out = out.replace(k, v)
    left = _ANY_PLACEHOLDER.findall(out)
    if left:
        raise Refused(f"unit {name} uses unknown placeholder {left[0]} (allowed: {' '.join(PLACEHOLDERS)})")
    if "\x00" in out:
        raise Refused(f"unit {name} contains NUL")
    return out


def render_all(templates: dict[str, str], values: dict[str, str]) -> dict[str, str]:
    return {n: render(n, t, values) for n, t in templates.items()}


@dataclass
class UnitInfo:
    name: str
    has_install: bool
    has_reload: bool
    credentials: list[tuple[str, str]] = field(default_factory=list)  # (credential name, logical path)


def inspect(name: str, text: str) -> UnitInfo:
    has_install = False
    has_reload = False
    creds: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.lower() == "[install]":
            has_install = True
        elif line.startswith("ExecReload="):
            has_reload = True
        elif line.startswith("LoadCredential="):
            val = line[len("LoadCredential=") :].strip()
            cname, sep, cpath = val.partition(":")
            if not sep or not cname or not cpath:
                raise Refused(f"unit {name}: malformed LoadCredential= line")
            creds.append((cname, cpath))
    return UnitInfo(name, has_install, has_reload, creds)


def referenced_credential_files(info: UnitInfo, creds_logical: str) -> list[str]:
    """File names under the component creds dir that the unit expects to exist. A LoadCredential= that
    points anywhere else refuses the unit (the agent only ever creates files in its own creds dir)."""
    files: list[str] = []
    for _cname, cpath in info.credentials:
        d, _, fname = cpath.rpartition("/")
        if d != creds_logical or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", fname):
            raise Refused(
                f"unit {info.name}: LoadCredential= path {cpath[:100]!r} is not inside {creds_logical}"
            )
        files.append(fname)
    return files


def instance_units(component: str, config: dict, available: set[str]) -> list[str]:
    """Probe port instances: exp-probe-lease@<port> for client ports, exp-probe-target@<port> for target
    ports, exp-probe-wifi@<port> + exp-probe-lease@<port> for Wi-Fi ports (only when the artifact ships
    the templates; an artifact without the wifi template predates Wi-Fi support: its Wi-Fi ports get
    nothing)."""
    if component != "probe":
        return []
    out: list[str] = []
    for port in config.get("ports", []) or []:
        pid, role = port.get("id"), port.get("role")
        if not isinstance(pid, str) or not _SLUG.match(pid):
            raise Refused("probe config has an invalid port id")
        kinds = {"client": ("lease",), "target": ("target",), "wifi": ("wifi", "lease")}.get(role)
        if kinds is None:
            continue
        missing = [f"exp-probe-{k}@.service" for k in kinds if f"exp-probe-{k}@.service" not in available]
        if missing:
            log.warning("artifact has no %s; port %s gets no %s unit",
                        ", ".join(missing), pid, "/".join(kinds))
            if role == "wifi":
                continue
        out += [f"exp-probe-{k}@{pid}.service" for k in kinds if f"exp-probe-{k}@.service" in available]
    return out


def write_units(
    fs: SafeFS, rendered: dict[str, str], previous_names: set[str]
) -> tuple[list[str], list[str]]:
    """Write changed unit files (atomic 0644) and delete previous ones that vanished.
    Returns (changed names, removed names)."""
    changed: list[str] = []
    for name, text in rendered.items():
        p = fs.paths.unit(name)
        if fs.read_bytes(p, MAX_UNIT_BYTES) != text.encode("utf-8"):
            fs.write(p, text, 0o644)
            changed.append(name)
    removed = []
    for name in sorted(previous_names - set(rendered)):
        if fs.remove(fs.paths.unit(name)):
            removed.append(name)
    return changed, removed


class Systemctl:
    def __init__(self, runner: Runner) -> None:
        self.r = runner

    def _do(self, args: list[str], timeout: float = 120, check: bool = True) -> str:
        for a in args[1:]:
            if a.startswith("exp-") and not UNIT_RE.match(a):
                raise Refused(f"invalid unit name {a[:64]!r}")
        res = self.r.run(["systemctl", *args], timeout=timeout)
        if check and res.rc != 0:
            raise AgentError(f"systemctl {' '.join(args[:2])} failed: {res.stderr.strip()[-200:]}")
        return res.stdout

    def daemon_reload(self) -> None:
        self._do(["daemon-reload"])

    def enable(self, units: list[str]) -> None:
        if units:
            self._do(["enable", *units])

    def disable(self, units: list[str]) -> None:
        if units:
            self._do(["disable", *units], check=False)

    def restart(self, units: list[str]) -> None:
        for u in units:
            self._do(["restart", u], timeout=120)

    def reset_failed(self, units: list[str]) -> None:
        """Forget the `failed` state of units whose files are gone (a non-zero exit leaves it)."""
        if units:
            self._do(["reset-failed", *units], check=False)

    def restart_no_block(self, unit: str) -> None:
        self._do(["--no-block", "restart", unit], timeout=30)

    def stop(self, units: list[str]) -> None:
        for u in units:
            self._do(["stop", u], timeout=120, check=False)

    def reload(self, unit: str) -> None:
        self._do(["reload", unit], timeout=60)

    def show(self, unit: str, props: list[str]) -> dict[str, str]:
        argv = ["show", unit]
        for p in props:
            argv += ["-p", p]
        out = self._do(argv, timeout=10, check=False)
        kv: dict[str, str] = {}
        for line in out.splitlines():
            k, sep, v = line.partition("=")
            if sep:
                kv[k] = v
        return kv
