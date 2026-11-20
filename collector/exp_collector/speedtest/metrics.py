"""VictoriaMetrics aggregates of speedtests (12 section 6, Principle 8).

Series (NO per-user or per-device label ever; ``device_key``, IP, MAC and the test id are not labels):

* ``exp_st_down_mbps``, ``exp_st_up_mbps``, ``exp_st_loaded_latency_ms``, ``exp_st_score`` as VictoriaMetrics
  histograms: ``<name>_bucket{vmrange="lo...hi"}`` (cumulative counters, 18 buckets per decade, the format of
  VictoriaMetrics' own histogram library), plus ``<name>_sum`` and ``<name>_count``; labels ``site, zone, leg, ssid,
  band, ap, os_family``;
* ``exp_st_tests_total{site,zone,cause}`` (counter).

Cardinality is bounded: each of ``site, zone, ssid, band, ap, os_family`` admits at most ``label_limit`` distinct
values (default 64); further values are written as ``other``. A global cap on distinct label combinations also
collapses ``zone, ssid, ap, os_family`` to ``other`` for new combinations. Observations are made once per test, when
its evidence is final (zone, AP, SSID are known then). The counters live in memory: a collector restart resets them,
which VictoriaMetrics treats as an ordinary counter reset (``increase()`` / ``rate()`` are unaffected).
"""
from __future__ import annotations

import math
import re
import threading
from collections.abc import Mapping
from typing import Any

from exp_common import speedtest as st_helpers

LABELS = ("site", "zone", "leg", "ssid", "band", "ap", "os_family")
BOUNDED = ("site", "zone", "ssid", "band", "ap", "os_family")
BUCKETS_PER_DECADE = 18
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
HIST = {"exp_st_down_mbps": "down", "exp_st_up_mbps": "up", "exp_st_loaded_latency_ms": "loaded",
        "exp_st_score": "score"}


def vmrange(value: float) -> str:
    """The VictoriaMetrics histogram bucket of a non-negative value."""
    if not math.isfinite(value) or value <= 1e-9:
        return "0...1.000e-09"
    idx = math.floor(math.log10(value) * BUCKETS_PER_DECADE)
    lo, hi = 10.0 ** (idx / BUCKETS_PER_DECADE), 10.0 ** ((idx + 1) / BUCKETS_PER_DECADE)
    if value < lo:         # float edge: log10 rounding put it one bucket too high
        idx -= 1
        lo, hi = 10.0 ** (idx / BUCKETS_PER_DECADE), lo
    elif value >= hi:
        idx += 1
        lo, hi = hi, 10.0 ** ((idx + 1) / BUCKETS_PER_DECADE)
    return f"{lo:.3e}...{hi:.3e}"


class StMetrics:
    def __init__(self, label_limit: int = 64, combo_limit: int = 5000) -> None:
        self.label_limit = label_limit
        self.combo_limit = combo_limit
        self._lock = threading.Lock()
        self._seen: dict[str, set[str]] = {k: set() for k in BOUNDED}
        self._combos: set[tuple[str, ...]] = set()
        self._series: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

    def _bound(self, label: str, value: Any) -> str:
        v = _CTRL.sub("", str(value if value not in (None, "") else "unknown"))[:64] or "unknown"
        seen = self._seen[label]
        if v in seen or v == "other":
            return v
        if len(seen) < self.label_limit:
            seen.add(v)
            return v
        return "other"

    def _labels(self, t: Mapping[str, Any], leg: str) -> dict[str, str]:
        lab = {k: self._bound(k, t.get(k)) for k in BOUNDED}
        key = tuple(lab[k] for k in BOUNDED) + (leg,)
        if key not in self._combos:
            if len(self._combos) >= self.combo_limit:
                for k in ("zone", "ssid", "ap", "os_family"):
                    lab[k] = "other"
                key = tuple(lab[k] for k in BOUNDED) + (leg,)
            self._combos.add(key)
        lab["leg"] = leg
        return lab

    def _bump(self, name: str, labels: Mapping[str, str], by: float, touched: set[Any]) -> None:
        k = (name, tuple(sorted(labels.items())))
        self._series[k] = self._series.get(k, 0.0) + by
        touched.add(k)

    def _observe(self, name: str, labels: Mapping[str, str], value: float, touched: set[Any]) -> None:
        self._bump(name + "_bucket", {**labels, "vmrange": vmrange(value)}, 1.0, touched)
        self._bump(name + "_sum", labels, value, touched)
        self._bump(name + "_count", labels, 1.0, touched)

    def observe(self, t: Mapping[str, Any]) -> list[tuple[str, dict[str, str], float]]:
        """One finished test -> the cumulative series whose value changed ``[(name, labels, value)]``.

        ``t`` carries ``site, zone, ssid, band, ap, os_family, cause, legs`` (the stored ``exp.speedtest/1`` legs) and
        ``score`` (``{"total": ..}`` or None)."""
        touched: set[Any] = set()
        legs = t.get("legs") or {}
        with self._lock:
            for leg in ("local", "internet"):
                d = legs.get(leg)
                if not isinstance(d, Mapping) or d.get("status", "ok") != "ok":
                    continue
                lab = self._labels(t, leg)
                for key, name in (("down_mbps", "exp_st_down_mbps"), ("up_mbps", "exp_st_up_mbps")):
                    v = d.get(key)
                    if isinstance(v, (int, float)) and not isinstance(v, bool):
                        self._observe(name, lab, float(v), touched)
                lat = [x for x in (d.get("loaded_down_ms"), d.get("loaded_up_ms"))
                       if isinstance(x, (int, float)) and not isinstance(x, bool)]
                if lat:
                    self._observe("exp_st_loaded_latency_ms", lab, float(max(lat)), touched)
            basis = st_helpers.score_basis(legs)
            sc = (t.get("score") or {}).get("total") if isinstance(t.get("score"), Mapping) else None
            if basis is not None and isinstance(sc, int):
                self._observe("exp_st_score", self._labels(t, basis[0]), float(sc), touched)
            tl = {k: self._bound(k, t.get(k)) for k in ("site", "zone")}
            tl["cause"] = _CTRL.sub("", str(t.get("cause") or "unknown"))[:32]
            self._bump("exp_st_tests_total", tl, 1.0, touched)
            return [(name, dict(lab), self._series[(name, lab)]) for name, lab in sorted(touched)]

    def series_count(self) -> int:
        with self._lock:
            return len(self._series)
