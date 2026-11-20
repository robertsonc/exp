"""Internet-leg control (12 section 4.4): FIFO slots, the admin pause and the runner-driven WAN auto-pause.

The page asks for a slot before it calls Cloudflare. At most ``max_concurrent_internet`` sessions hold one at a time; the
rest get a FIFO queue position (and the on-network + DNS legs immediately). The leg is *paused* by, in this order:

* ``disabled``       -- ``internet_leg.enabled = false`` in the config (state ``unavailable``);
* ``admin_pause``    -- ``internet_leg.paused`` in the config, or the runtime switch ``exp-speedtest pause-internet --on``;
* ``wan_utilization``-- the runner's last ``PUT /local/v1/pause`` says EdgeConnect WAN utilization is above the
  threshold. A value older than 90 s is IGNORED (fail open, CR-m6-spec-resolutions B7): an unreachable runner never
  keeps the leg paused; only the deliberate admin switch does.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

WAN_STALE_S = 90.0
SLOT_TTL_S = 60            # how long a granted slot is held without a release
QUEUE_STALE_S = 15.0       # a queued session that stops polling loses its place
RETRY_AFTER_S = 2


class RuntimeState:
    """The manual runtime switch, a small JSON file next to the state (``exp-speedtest pause-internet`` writes it).
    Re-read at most once a second."""

    def __init__(self, path: Path | None, clock: Callable[[], float] = time.time) -> None:
        self.path = path
        self.clock = clock
        self._cached: tuple[float, bool] = (0.0, False)

    def manual_pause(self) -> bool:
        now = self.clock()
        at, val = self._cached
        if self.path is None or now - at < 1.0:
            return val
        try:
            with open(self.path, encoding="utf-8") as fh:
                doc = json.load(fh)
            val = bool(isinstance(doc, dict) and doc.get("pause_internet") is True)
        except (OSError, ValueError):
            val = False
        self._cached = (now, val)
        return val

    @staticmethod
    def write(path: Path, pause: bool) -> None:
        from exp_common.atomic import atomic_write_json
        atomic_write_json(path, {"schema": "exp.speedtest.runtime/1", "pause_internet": bool(pause),
                                 "set_at": time.time()}, mode=0o644)


class InternetLeg:
    def __init__(self, *, enabled: bool, config_paused: bool, max_concurrent: int, auto_pause_pct: float,
                 runtime: RuntimeState | None = None, clock: Callable[[], float] = time.time) -> None:
        self.enabled = enabled
        self.config_paused = config_paused
        self.max_concurrent = max_concurrent
        self.auto_pause_pct = auto_pause_pct
        self.runtime = runtime
        self.clock = clock
        self._held: dict[str, float] = {}                       # session id -> expiry
        self._queue: OrderedDict[str, float] = OrderedDict()    # session id -> last seen
        self._wan: tuple[float | None, float, bool | None] = (None, 0.0, None)   # util, measured_at, runner verdict
        self._lock = threading.Lock()

    # ------------------------------------------------------------------------------------------------ state
    def put_wan(self, util_pct: float | None, measured_at: float, pause: bool | None) -> None:
        now = self.clock()
        with self._lock:
            self._wan = (util_pct, min(measured_at, now), pause)

    def pause_reason(self) -> str | None:
        """``admin_pause`` | ``wan_utilization`` | None (open). Does not consider ``enabled``."""
        if self.config_paused or (self.runtime is not None and self.runtime.manual_pause()):
            return "admin_pause"
        util, at, verdict = self._wan
        if util is None or self.clock() - at > WAN_STALE_S:
            return None
        if verdict is not None:
            return "wan_utilization" if verdict else None
        return "wan_utilization" if util > self.auto_pause_pct else None

    def state(self) -> tuple[str, str | None]:
        """``("unavailable", "disabled")`` | ``("paused", reason)`` | ``("queued", "capacity")`` | ``("ok", None)``."""
        if not self.enabled:
            return "unavailable", "disabled"
        reason = self.pause_reason()
        if reason:
            return "paused", reason
        with self._lock:
            self._sweep()
            if self._queue or len(self._held) >= self.max_concurrent:
                return "queued", "capacity"
        return "ok", None

    @property
    def paused(self) -> bool:
        return self.enabled and self.pause_reason() is not None

    @property
    def queue_depth(self) -> int:
        with self._lock:
            self._sweep()
            return len(self._queue)

    @property
    def held(self) -> int:
        with self._lock:
            self._sweep()
            return len(self._held)

    def queue_estimate(self) -> int:
        with self._lock:
            return len(self._queue) + 1

    # ----------------------------------------------------------------------------------------------- slots
    def _sweep(self) -> None:
        now = self.clock()
        for sid in [s for s, exp in self._held.items() if exp <= now]:
            del self._held[sid]
        for sid in [s for s, seen in self._queue.items() if now - seen > QUEUE_STALE_S]:
            del self._queue[sid]
        while self._queue and len(self._held) < self.max_concurrent:
            sid, _ = self._queue.popitem(last=False)
            self._held[sid] = now + SLOT_TTL_S

    def acquire(self, sid: str) -> dict[str, Any]:
        """The ``InternetSlot`` document of speedtest.yaml for one acquire call."""
        if not self.enabled:
            return {"state": "unavailable", "queue_position": None, "retry_after_s": None, "ttl_s": None, "reason": "disabled"}
        reason = self.pause_reason()
        with self._lock:
            if reason:
                self._queue.pop(sid, None)
                return {"state": "paused", "queue_position": None, "retry_after_s": 5, "ttl_s": None, "reason": reason}
            now = self.clock()
            self._sweep()
            if sid in self._held:
                return {"state": "granted", "queue_position": None, "retry_after_s": None,
                        "ttl_s": max(1, int(self._held[sid] - now)), "reason": None}
            if sid in self._queue:
                self._queue[sid] = now
            elif not self._queue and len(self._held) < self.max_concurrent:
                self._held[sid] = now + SLOT_TTL_S
                return {"state": "granted", "queue_position": None, "retry_after_s": None, "ttl_s": SLOT_TTL_S, "reason": None}
            else:
                self._queue[sid] = now
            pos = list(self._queue).index(sid) + 1
            return {"state": "queued", "queue_position": pos, "retry_after_s": RETRY_AFTER_S, "ttl_s": None,
                    "reason": "capacity"}

    def release(self, sid: str) -> dict[str, Any]:
        with self._lock:
            self._held.pop(sid, None)
            self._queue.pop(sid, None)
            self._sweep()
        return {"state": "released", "queue_position": None, "retry_after_s": None, "ttl_s": None, "reason": None}

    def forget(self, sid: str) -> None:
        """A session ended: free whatever it held (idempotent)."""
        self.release(sid)

    def housekeeping(self) -> None:
        with self._lock:
            self._sweep()


def runtime_path_ok(path: Path) -> bool:
    return os.access(path.parent, os.W_OK)
