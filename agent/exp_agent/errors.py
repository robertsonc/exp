"""Exception taxonomy.

`Refused` is permanent: the desired state asks for something the agent will never do (bad
signature, unsafe archive, off-allowlist apt package, ...). The same desired version is not
retried. `Transient` is retryable (network, a busy manager).
"""

from __future__ import annotations


class AgentError(Exception):
    """Base class; messages never contain secrets."""


def need(value, what: str):
    """Narrow Optional wiring without `assert` (stripped by -O): AgentError when `value` is None."""
    if value is None:
        raise AgentError(f"internal error: {what} is not available")
    return value


class AptError(AgentError):
    """`apt-get install` of an allowlisted package failed (reported once per desired version)."""


class Refused(AgentError):  # noqa: N818 - domain term
    """A safety rule or verification refused the operation; nothing was changed."""


class VerifyError(Refused):
    """Signature / digest / manifest verification failed."""


class UnsafeArchive(Refused):
    """The artifact archive violates the safe-unpack rules."""


class PathRefused(Refused):
    """A computed path is outside the allowed roots (or goes through a symlink out of them)."""


class Transient(AgentError):
    """Retryable failure (network, 5xx, timeout)."""


class ManagerUnreachable(Transient):
    """The manager could not be reached or answered 5xx/429. `retry_after` is a hint in seconds."""

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class Unauthorized(AgentError):  # noqa: N818
    """HTTP 401 from the manager: credentials revoked or rotated wrongly."""


class ClientError(AgentError):
    """A 4xx answer other than 401 (message carries the status and error code only)."""

    def __init__(self, status: int, code: str, message: str = "") -> None:
        super().__init__(f"HTTP {status} {code}" + (f": {message}" if message else ""))
        self.status = status
        self.code = code
