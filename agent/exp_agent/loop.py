"""The main loop (06-agent.md section 2): jittered poll with ETag, reconcile on change, status heartbeat,
backoff while the manager is unreachable (components are never stopped), 401 -> pause 5 min."""

from __future__ import annotations

import logging
import random
import threading
from typing import Any

from . import selfupdate
from .client import UNAUTHORIZED_PAUSE_S, Backoff, jittered
from .context import Context
from .errors import AgentError, ClientError, ManagerUnreachable, Transient, Unauthorized, need
from .metrics import HostMetrics
from .reconcile import Outcome, Reconciler
from .state import iso_now
from .status import build_status

log = logging.getLogger(__name__)

POLL_S = 30
FAST_POLL_S = 5.0
FAST_WINDOW_S = 120.0
STATUS_S = 60


class Agent:
    def __init__(self, ctx: Context, rng: random.Random | None = None) -> None:
        self.ctx = ctx
        self.rng = rng or random.Random()  # noqa: S311 - poll jitter, not security
        self.reconciler = Reconciler(ctx)
        self.metrics = HostMetrics(ctx)
        self.backoff = Backoff()
        self.poll_s: float = POLL_S
        self.status_s: float = STATUS_S
        self.fast_until: float = 0.0
        self.paused_until: float = 0.0
        self.last_status_at: float = 0.0
        self._warned_401 = False
        self._warned_down = False
        self._confirmed = False
        self.retry_at: float | None = None
        self.retry_backoff = Backoff()
        self.stop = threading.Event()
        self.decommissioned = False
        self.restarting = False

    # ------------------------------------------------------------------ helpers
    def enter_fast_mode(self) -> None:
        self.fast_until = self.ctx.monotonic() + FAST_WINDOW_S

    def _apply_intervals(self, doc: dict[str, Any]) -> None:
        ag = doc.get("agent") or {}
        self.poll_s = float(ag.get("poll_interval_s", self.poll_s))
        self.status_s = float(ag.get("status_interval_s", self.status_s))

    def _next_poll_delay(self) -> float:
        fast = self.ctx.monotonic() < self.fast_until
        return jittered(FAST_POLL_S if fast else self.poll_s, 0.2, self.rng)

    # ------------------------------------------------------------------ startup
    def startup(self) -> None:
        ctx = self.ctx
        ctx.state.ensure_dir()
        ctx.state.load()
        selfupdate.absorb_rollback_note(ctx)
        cached = ctx.state.cached_desired()
        if cached:
            self._apply_intervals(cached)
            # converge from the cache (idempotent); never contacts the manager unless a download is needed
            try:
                self._reconcile(cached)
            except Unauthorized:
                self._handle_401()
        if not ctx.state.data.get("last_poll") and ctx.state.data.get("applied_version") is None:
            self.enter_fast_mode()

    # ------------------------------------------------------------------ one iteration
    def tick(self) -> float:
        """One poll cycle. Returns the number of seconds to wait before the next one."""
        ctx, st = self.ctx, self.ctx.state
        now = ctx.monotonic()
        if now < self.paused_until:
            return self.paused_until - now
        client = need(ctx.client, "manager client")
        try:
            code, doc, etag = client.get_desired(st.data.get("etag"))
        except Unauthorized:
            return self._handle_401()
        except ManagerUnreachable as exc:
            delay = max(self.backoff.next(), exc.retry_after or 0.0)
            if not self._warned_down:
                st.event("warn", f"manager unreachable; keeping the applied state, retrying in {delay:.0f}s")
                self._warned_down = True
            return delay
        except (ClientError, AgentError) as exc:
            st.event("error", f"desired-state fetch failed: {exc}")
            return self.backoff.next()
        self.backoff.reset()
        self._warned_down = False
        self._warned_401 = False
        st.data["last_poll"] = iso_now(ctx.clock())
        if code == 200 and doc is not None:
            self._apply_intervals(doc)
            st.cache_desired(doc)
            out = self._reconcile(doc)
            if out is not None and not out.restarting and not out.decommissioned:
                # always remember the etag: a transient failure is retried by _maybe_retry with backoff
                # (30 s -> 5 min) from the cached document, not by re-fetching it every few seconds
                st.data["etag"] = etag
                if out.changed or out.result != "ok":
                    self.enter_fast_mode()
            self._post_status()
        else:
            self._maybe_retry()
            if ctx.monotonic() - self.last_status_at >= self.status_s:
                self._post_status()
        if not self.restarting and not self.decommissioned:
            st.save()
        return self._next_poll_delay()

    def _handle_401(self) -> float:
        if not self._warned_401:
            self.ctx.state.event(
                "error",
                "manager answered 401: credentials revoked or rotated wrongly; "
                "pausing for 5 minutes (nothing is uninstalled)",
            )
            self._warned_401 = True
        self.paused_until = self.ctx.monotonic() + UNAUTHORIZED_PAUSE_S
        return UNAUTHORIZED_PAUSE_S

    def _reconcile(self, doc: dict[str, Any]) -> Outcome | None:
        try:
            out = self.reconciler.run(doc)
        except Unauthorized:
            raise
        self.retry_at = None
        if out.decommissioned:
            self.decommissioned = True
            self.stop.set()
        elif out.restarting:
            self.restarting = True
            self.stop.set()
        elif out.result == "error" and not out.permanent:
            self.retry_at = self.ctx.monotonic() + self.retry_backoff.next()
        else:
            self.retry_backoff.reset()
        return out

    def _maybe_retry(self) -> None:
        if self.retry_at is not None and self.ctx.monotonic() >= self.retry_at:
            cached = self.ctx.state.cached_desired()
            if cached:
                self._reconcile(cached)
                self._post_status()

    def _post_status(self) -> None:
        ctx, st = self.ctx, self.ctx.state
        client = need(ctx.client, "manager client")
        n = len(st.pending_events())
        try:
            doc = build_status(ctx, self.metrics, int(self.status_s))
            client.post_status(doc)
        except Unauthorized:
            self._handle_401()
            return
        except Transient as exc:
            log.warning("status report failed: %s", exc)
            return
        except (ClientError, AgentError) as exc:
            st.event("error", f"status report rejected: {exc}")
            return
        st.clear_events(n)
        self.last_status_at = ctx.monotonic()
        if not self._confirmed:
            self._confirmed = True
            selfupdate.confirm_if_pending(ctx)

    # ------------------------------------------------------------------ run forever
    def run(self) -> int:
        self.startup()
        while not self.stop.is_set():
            try:
                delay = self.tick()
            except Unauthorized:
                delay = self._handle_401()
            except Exception:  # noqa: BLE001 - top of the loop: log (scrubbed) and keep the agent alive
                log.exception("unexpected error in the agent loop")
                delay = self.backoff.next()
            self.stop.wait(delay)
        return 0
