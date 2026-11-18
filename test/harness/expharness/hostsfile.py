"""Temporary /etc/hosts entries for the test (marked, removed on exit, flock-guarded)."""

from __future__ import annotations

import fcntl
import os
from pathlib import Path

HOSTS = Path("/etc/hosts")
MARK = "# exp-e2e"


def can_edit() -> bool:
    return os.access(HOSTS, os.W_OK)


def _rewrite(fn) -> None:  # noqa: ANN001
    with open(HOSTS, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        lines = f.read().splitlines()
        lines = fn(lines)
        f.seek(0)
        f.write("\n".join(lines) + "\n")
        f.truncate()


class HostsEntries:
    """with HostsEntries({"exp-manager.test": "127.0.0.1"}, tag="m2-1234"): ..."""

    def __init__(self, mapping: dict[str, str], tag: str) -> None:
        self.mapping, self.tag = mapping, f"{MARK}:{tag}"

    def __enter__(self) -> HostsEntries:
        add = [f"{ip} {name} {self.tag}" for name, ip in self.mapping.items()]
        _rewrite(lambda ls: [*ls, *add])
        return self

    def __exit__(self, *exc: object) -> None:
        _rewrite(lambda ls: [ln for ln in ls if not ln.endswith(self.tag)])
