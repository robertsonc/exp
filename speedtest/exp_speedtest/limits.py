"""Bounded in-memory rate limiters (SR-21): per-key sliding windows and token buckets with capped key tables."""
from __future__ import annotations

import threading
from collections import OrderedDict, deque


class SlidingWindow:
    """At most ``limit`` events per ``window_s`` per key. ``check`` does not record; ``record`` does."""

    def __init__(self, limit: int, window_s: float, max_keys: int = 50_000) -> None:
        self.limit, self.window_s, self.max_keys = limit, window_s, max_keys
        self._d: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def _trim(self, q: deque[float], now: float) -> None:
        while q and q[0] <= now - self.window_s:
            q.popleft()

    def retry_after(self, key: str, now: float) -> float:
        """0 when another event is allowed, else seconds until the oldest one leaves the window."""
        with self._lock:
            q = self._d.get(key)
            if not q:
                return 0.0
            self._trim(q, now)
            if len(q) < self.limit:
                return 0.0
            return max(0.0, q[0] + self.window_s - now)

    def record(self, key: str, now: float) -> None:
        with self._lock:
            q = self._d.get(key)
            if q is None:
                q = self._d[key] = deque()
                while len(self._d) > self.max_keys:
                    self._d.popitem(last=False)
            else:
                self._d.move_to_end(key)
            self._trim(q, now)
            q.append(now)

    def prune(self, now: float) -> None:
        with self._lock:
            for k in [k for k, q in self._d.items() if not q or q[-1] <= now - self.window_s]:
                del self._d[k]


class TokenBucket:
    """``rate`` tokens/s with ``burst`` capacity per key; ``take`` returns 0.0 when allowed, else the wait in seconds."""

    def __init__(self, rate: float, burst: float, max_keys: int = 50_000) -> None:
        self.rate, self.burst, self.max_keys = rate, burst, max_keys
        self._d: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str, now: float, cost: float = 1.0) -> float:
        with self._lock:
            st = self._d.get(key)
            if st is None:
                st = self._d[key] = [self.burst, now]
                while len(self._d) > self.max_keys:
                    self._d.popitem(last=False)
            else:
                self._d.move_to_end(key)
                st[0] = min(self.burst, st[0] + max(0.0, now - st[1]) * self.rate)
                st[1] = now
            if st[0] >= cost:
                st[0] -= cost
                return 0.0
            return (cost - st[0]) / self.rate

    def prune(self, now: float) -> None:
        with self._lock:
            idle = self.burst / self.rate + 1.0
            for k in [k for k, st in self._d.items() if now - st[1] > idle]:
                del self._d[k]
