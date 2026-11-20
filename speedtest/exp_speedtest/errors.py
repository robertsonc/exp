"""The error envelope of 01-contracts.md section 1: ``{"error": {"code", "message", "details"}}``."""
from __future__ import annotations

from typing import Any


class ApiError(Exception):
    """A request the box refuses. ``code`` is machine-readable, ``message`` short and free of internal data."""

    def __init__(self, status: int, code: str, message: str, details: dict[str, Any] | None = None,
                 headers: dict[str, str] | None = None, close: bool = False) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details or {}
        self.headers = headers or {}
        self.close = close               # the connection cannot be reused (an unread request body)

    def body(self) -> dict[str, Any]:
        return {"error": {"code": self.code, "message": self.message, "details": self.details}}


def bad_request(message: str = "invalid request", code: str = "invalid_request", **details: Any) -> ApiError:
    return ApiError(400, code, message, details)


def not_found() -> ApiError:
    return ApiError(404, "not_found", "not found")


def too_many(limit: str, retry_after: float, message: str = "too many requests") -> ApiError:
    ra = max(1, int(retry_after + 0.999))
    return ApiError(429, "rate_limited", message, {"limit": limit, "retry_after_s": ra}, {"Retry-After": str(ra)})
