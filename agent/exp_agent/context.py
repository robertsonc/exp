"""Everything the agent needs, wired once; tests construct it with a tmp root and injected fakes."""

from __future__ import annotations

import os
import platform
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from . import __version__
from .config import AgentConfig
from .errors import Refused
from .install import user_exists
from .pathguard import Paths, SafeFS
from .runner import Runner
from .state import State
from .tls import lookup_user
from .units import Systemctl
from .verify import ManifestCache

ARCH_MAP = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def host_arch() -> str:
    m = platform.machine().lower()
    if m not in ARCH_MAP:
        raise Refused(f"unsupported architecture {m!r} (amd64 and arm64 only)")
    return ARCH_MAP[m]


@dataclass
class Context:
    paths: Paths
    fs: SafeFS
    runner: Runner
    state: State
    sysctl: Systemctl
    cfg: AgentConfig | None = None
    client: Any = None  # ManagerClient (or a test double)
    manifests: ManifestCache | None = None
    agent_version: str = __version__
    arch: str = "amd64"
    clock: Callable[[], float] = time.time
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    user_exists: Callable[[str], bool] = user_exists
    user_ids: Callable[[str], tuple[int, int] | None] = lookup_user
    health_wait_s: float = 60.0
    health_poll_s: float = 2.0
    health_timeout_s: float = 5.0
    started: float = field(default_factory=time.monotonic)

    def attach_manager(self, cfg: AgentConfig, client: Any) -> None:
        self.cfg, self.client = cfg, client
        self.manifests = ManifestCache(self.fs, self.runner, cfg.release_pubkey_pem)


def build_context(
    root: str | os.PathLike[str] = "/",
    *,
    uid: int | None = None,
    gid: int | None = None,
    runner: Runner | None = None,
    arch: str | None = None,
    **overrides: Any,
) -> Context:
    paths = Paths(root, uid=0 if uid is None else uid, gid=0 if gid is None else gid)
    fs = SafeFS(paths, overrides.pop("lchown", None))
    run = runner or Runner()
    ctx = Context(
        paths=paths,
        fs=fs,
        runner=run,
        state=State(fs),
        sysctl=Systemctl(run),
        arch=arch or host_arch(),
        **overrides,
    )
    return ctx
