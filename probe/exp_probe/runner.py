"""The ONE command runner every probe module uses (argv lists only, timeouts, captured output).

Unit tests replace `CommandRunner` with a fake (see probe/tests/fakes.py) that returns recorded
outputs, so nothing in the probe shells out except through this seam. Rules (SR-17):

* argv MUST be a list/tuple of str (a bare string is refused -- it would invite shell=True habits);
* never ``shell=True``; stdin is /dev/null unless `input_data` is given;
* every call has a timeout; on expiry the child is killed and ``timed_out`` is set (rc 124);
* a missing binary is rc 127 with a readable message instead of an exception.
"""
from __future__ import annotations

import logging
import subprocess  # noqa: S404 - this module is the only place that spawns processes
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

log = logging.getLogger(__name__)

NS_PREFIX = "exp-"
MAX_CAPTURE = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 10.0
RC_NOT_FOUND = 127
RC_TIMEOUT = 124


def ns_name(port_id: str) -> str:
    """Namespace of a port: ``exp-<port_id>``."""
    return f"{NS_PREFIX}{port_id}"


@dataclass
class CmdResult:
    argv: tuple[str, ...]
    rc: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out


def ns_exec_argv(port_id: str, argv: Sequence[str]) -> list[str]:
    """The netns wrapper: ``ip netns exec exp-<port> <argv...>``."""
    return ["ip", "netns", "exec", ns_name(port_id), *argv]


def _check_argv(argv: object) -> list[str]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, (list, tuple)) or not argv:
        raise TypeError("argv must be a non-empty list of strings (shell strings are refused)")
    out: list[str] = []
    for a in argv:
        if not isinstance(a, str) or "\x00" in a:
            raise TypeError("argv entries must be strings without NUL bytes")
        out.append(a)
    return out


def _decode(b: bytes | str | None) -> str:
    if b is None:
        return ""
    if isinstance(b, str):
        return b[:MAX_CAPTURE]
    return b[:MAX_CAPTURE].decode("utf-8", "replace")


class CommandRunner:
    """Real runner. Subclass/replace for tests; the interface is `run` and `run_ns`."""

    def run(self, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, *,
            input_data: bytes | None = None, env: Mapping[str, str] | None = None) -> CmdResult:
        args = _check_argv(argv)
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("a positive timeout is mandatory")
        try:
            cp = subprocess.run(  # noqa: S603 - argv list, shell=False, validated above
                args, capture_output=True, timeout=timeout, shell=False, check=False,
                input=input_data, stdin=None if input_data is not None else subprocess.DEVNULL,
                env=dict(env) if env is not None else None)
        except FileNotFoundError:
            return CmdResult(tuple(args), RC_NOT_FOUND, "", f"{args[0]}: command not found")
        except subprocess.TimeoutExpired as exc:
            return CmdResult(tuple(args), RC_TIMEOUT, _decode(exc.stdout), _decode(exc.stderr), True)
        except PermissionError as exc:
            return CmdResult(tuple(args), 126, "", f"{args[0]}: {exc.strerror}")
        except OSError as exc:
            return CmdResult(tuple(args), 126, "", f"{args[0]}: {exc.strerror or exc}")
        return CmdResult(tuple(args), cp.returncode, _decode(cp.stdout), _decode(cp.stderr))

    def run_ns(self, port_id: str, argv: Sequence[str], timeout: float = DEFAULT_TIMEOUT, *,
               input_data: bytes | None = None, env: Mapping[str, str] | None = None) -> CmdResult:
        """Run `argv` inside the port's namespace (``ip netns exec exp-<port> ...``)."""
        return self.run(ns_exec_argv(port_id, argv), timeout, input_data=input_data, env=env)
