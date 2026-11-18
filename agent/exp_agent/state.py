"""Persistent agent state under /var/lib/exp/agent (root 0700): state.json, desired.json (cached last
desired document), actions.json, manifests/, previous/<c>/, pending.json (self-update marker)."""

from __future__ import annotations

import copy
import json
import logging
import time
from typing import Any

from exp_common import config as exp_config
from exp_common.log import scrub

from .pathguard import SafeFS

log = logging.getLogger(__name__)

STATE_SCHEMA = "exp.agent.state/1"
MAX_EVENTS = 100


def iso_now(epoch: float | None = None) -> str:
    t = time.time() if epoch is None else epoch
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int((t % 1) * 1000):03d}Z"


def default_state() -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "etag": None,
        "desired_version": None,
        "applied_version": None,
        "last_poll": None,
        "components": {},
        "failed": {},
        "last_reconcile": None,
        "agent_events": [],
    }


class State:
    def __init__(self, fs: SafeFS) -> None:
        self.fs = fs
        self.dir = fs.paths.agent_state
        self.data: dict[str, Any] = default_state()
        self._events: list[dict[str, str]] = []

    # --- files ---
    def ensure_dir(self) -> None:
        self.fs.mkdir(self.fs.paths.var, 0o755)
        self.fs.mkdir(self.dir, 0o700)
        self.fs.chmod(self.dir, 0o700)

    def load(self) -> None:
        raw = self.fs.read_bytes(self.dir / "state.json", 4 * 1024 * 1024)
        if raw is None:
            return
        try:
            doc = exp_config.parse_json(raw, "state.json")
        except exp_config.ConfigError:
            log.warning("state.json is unreadable; starting from an empty state")
            return
        if isinstance(doc, dict) and doc.get("schema") == STATE_SCHEMA:
            merged = default_state()
            merged.update(doc)
            self.data = merged

    def save(self) -> None:
        self.ensure_dir()
        self.fs.write(self.dir / "state.json", json.dumps(self.data, indent=1, sort_keys=True) + "\n", 0o600)

    def read_json(self, name: str, default: Any = None) -> Any:
        raw = self.fs.read_bytes(self.dir / name, 16 * 1024 * 1024)
        if raw is None:
            return default
        try:
            return exp_config.parse_json(raw, name)
        except exp_config.ConfigError:
            return default

    def write_json(self, name: str, doc: Any) -> None:
        self.ensure_dir()
        self.fs.write(self.dir / name, json.dumps(doc, indent=1, sort_keys=True) + "\n", 0o600)

    # --- desired cache ---
    def cached_desired(self) -> dict[str, Any] | None:
        doc = self.read_json("desired.json")
        return doc if isinstance(doc, dict) else None

    def cache_desired(self, doc: dict[str, Any]) -> None:
        self.write_json("desired.json", doc)

    # --- actions ---
    def actions_done(self) -> set[str]:
        doc = self.read_json("actions.json", [])
        return {str(x) for x in doc} if isinstance(doc, list) else set()

    def mark_action(self, action_id: str) -> None:
        done = sorted(self.actions_done() | {action_id})[-500:]
        self.write_json("actions.json", done)

    # --- failed desired versions (never retried) ---
    def failed_version(self, version: Any) -> dict[str, Any] | None:
        return self.data["failed"].get(str(version))

    def mark_failed(self, version: Any, result: str, error: str) -> None:
        failed = self.data["failed"]
        failed[str(version)] = {"result": result, "error": error[:1000], "at": iso_now()}
        for k in sorted(failed, key=lambda s: (len(s), s))[:-20]:
            del failed[k]

    # --- events (drained into the next status report) ---
    def event(self, level: str, msg: str) -> None:
        text = scrub(msg).replace("\n", " ")[:1000]
        getattr(log, {"info": "info", "warn": "warning", "error": "error"}[level])("%s", text)
        self._events.append({"ts": iso_now(), "level": level, "msg": text})
        del self._events[:-MAX_EVENTS]

    def pending_events(self) -> list[dict[str, str]]:
        return copy.deepcopy(self._events)

    def clear_events(self, upto: int) -> None:
        del self._events[:upto]
