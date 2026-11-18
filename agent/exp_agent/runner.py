"""The only place that starts processes: argv lists, never a shell (SR-17), no secrets in argv (SR-14).

Tests inject their own object with the same `run` signature.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .errors import Refused

log = logging.getLogger(__name__)

_SECRET_RE = re.compile(r"\bexp[aeidn]_[A-Za-z0-9_-]{8,}")
MAX_OUTPUT = 1024 * 1024
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class Result:
    rc: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0


def check_argv(argv: Sequence[str]) -> list[str]:
    """Validate an argv list: non-empty, all strings, no NUL, never a token (/proc exposure)."""
    if isinstance(argv, (str, bytes)) or not argv:
        raise Refused("argv must be a non-empty list (no shell strings)")
    out: list[str] = []
    for a in argv:
        if not isinstance(a, str) or "\x00" in a:
            raise Refused("argv elements must be strings without NUL")
        if _SECRET_RE.search(a):
            raise Refused("refusing to put a secret token on a command line")
        out.append(a)
    return out


class Runner:
    """Real process runner (shell=False, fixed minimal environment, bounded output, timeout)."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        input: str | None = None,  # noqa: A002
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
    ) -> Result:
        args = check_argv(argv)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        full_env = {
            "PATH": SAFE_PATH,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "DEBIAN_FRONTEND": "noninteractive",
        }
        if env:
            full_env.update(env)
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, shell never used
                args,
                input=input,
                capture_output=True,
                timeout=timeout,
                env=full_env,
                cwd=cwd,
                check=False,
                text=True,
                errors="replace",
                shell=False,
            )
        except subprocess.TimeoutExpired:
            log.warning("command timed out after %.0fs: %s", timeout, args[0])
            return Result(124, "", "timed out", timed_out=True)
        except FileNotFoundError:
            return Result(127, "", f"command not found: {args[0]}")
        except OSError as exc:
            return Result(126, "", f"cannot execute {args[0]}: {exc.strerror}")
        return Result(proc.returncode, proc.stdout[:MAX_OUTPUT], proc.stderr[:MAX_OUTPUT])


def default_path_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", SAFE_PATH)}
