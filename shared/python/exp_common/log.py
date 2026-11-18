"""Logging setup and secret scrubbing.

Diagnostics go to stderr via ``logging`` (stdout is reserved for program output). Under journald
(``JOURNAL_STREAM`` set) lines carry no timestamp (journald adds its own) and use the sd-daemon
``<N>`` priority prefix. ``SecretScrubFilter`` is attached to the handler so that records from
every logger are scrubbed: message, formatted args, tracebacks and stack info.

Redacted: ``exp[aeidn]_`` tokens, ``Bearer <x>``, Authorization header values, Slack/Teams/
Discord webhook URLs, URL query secrets (apiKey=, token=, key=, ...), PEM private keys,
``password=``/``secret=``/``token=`` assignments.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import traceback
from typing import IO, Optional

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple["re.Pattern[str]", str]] = [
    # PEM private keys (also when truncated: redact to end of text)
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
                re.DOTALL), "-----BEGIN PRIVATE KEY-----" + REDACTED + "-----END PRIVATE KEY-----"),
    # webhook URLs: whole URL (path carries the secret)
    (re.compile(r"https?://hooks\.slack\.com/[^\s\"'<>)]*", re.I), "https://hooks.slack.com/" + REDACTED),
    (re.compile(r"https?://[A-Za-z0-9.-]*\.webhook\.office(?:365)?\.com/[^\s\"'<>)]*", re.I),
     "https://webhook.office.com/" + REDACTED),
    (re.compile(r"https?://(?:[A-Za-z0-9-]+\.)?discord(?:app)?\.com/api/webhooks/[^\s\"'<>)]*", re.I),
     "https://discord.com/api/webhooks/" + REDACTED),
    # Authorization header (any scheme) incl. JSON/quoted forms
    (re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?)(?:(?:Bearer|Basic|Token|Digest)\s+)?[^\s,;\"'}]+"),
     r"\1" + REDACTED),
    # Bearer tokens anywhere
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer " + REDACTED),
    # exp tokens
    (re.compile(r"\b(exp[aeidn]_)[A-Za-z0-9_-]{8,}"), r"\1" + REDACTED),
    # secrets in URL query strings
    (re.compile(r"(?i)([?&](?:api[-_]?key|key|token|access[-_]?token|secret|password|sig|signature|auth)=)[^&\s\"'<>]+"),
     r"\1" + REDACTED),
    # key=value style assignments
    (re.compile(r"(?i)\b((?:password|passwd|pwd|passphrase|secret|token|api[-_]?key)[\"']?\s*[=:]\s*)"
                r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"), r"\1" + REDACTED),
]


def scrub(text: str) -> str:
    """Return `text` with secrets replaced by [REDACTED]."""
    for rx, repl in _PATTERNS:
        text = rx.sub(repl, text)
    return text


class SecretScrubFilter(logging.Filter):
    """Scrubs msg, args, exception text and stack info. Always returns True (never drops)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a bad format string must not break logging or leak args
            message = str(record.msg)
        record.msg = scrub(message)
        record.args = None
        if record.exc_info and record.exc_info[0] is not None:
            record.exc_text = scrub("".join(traceback.format_exception(*record.exc_info)).rstrip("\n"))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = scrub(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub(record.stack_info)
        return True


_SD_PRIORITY = {logging.DEBUG: 7, logging.INFO: 6, logging.WARNING: 4, logging.ERROR: 3,
                logging.CRITICAL: 2}


class _TextFormatter(logging.Formatter):
    def __init__(self, component: str, journald: bool) -> None:
        self.component = component
        self.journald = journald
        fmt = "%(levelname)s %(name)s: %(message)s" if journald else \
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        super().__init__(fmt)

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if self.journald:
            prio = _SD_PRIORITY.get(record.levelno, 6 if record.levelno < logging.WARNING else 3)
            text = "\n".join(f"<{prio}>{ln}" for ln in text.splitlines()) or f"<{prio}>"
        return text


class _JsonFormatter(logging.Formatter):
    def __init__(self, component: str, journald: bool) -> None:
        super().__init__()
        self.component = component
        self.journald = journald

    def format(self, record: logging.LogRecord) -> str:
        obj = {"level": record.levelname.lower(), "component": self.component,
               "logger": record.name, "msg": record.getMessage()}
        if not self.journald:
            obj["ts"] = self.formatTime(record, "%Y-%m-%dT%H:%M:%S") + f".{int(record.msecs):03d}Z"
        if record.exc_text:
            obj["exc"] = record.exc_text
        elif record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def setup_logging(component: str, level: str = "INFO", json: bool = False,  # noqa: A002
                  stream: Optional[IO[str]] = None) -> logging.Logger:
    """Configure the root logger with one scrubbing stderr handler; returns the component logger.
    Idempotent: re-calling replaces the handler installed by a previous call."""
    journald = bool(os.environ.get("JOURNAL_STREAM"))
    lvl = logging.getLevelName(str(level).upper())
    if not isinstance(lvl, int):
        raise ValueError(f"unknown log level {level!r}")
    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.set_name("exp-log")
    handler.addFilter(SecretScrubFilter())
    handler.setFormatter((_JsonFormatter if json else _TextFormatter)(component, journald))
    root = logging.getLogger()
    for h in list(root.handlers):
        if h.get_name() == "exp-log":
            root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(lvl)
    return logging.getLogger(component)
