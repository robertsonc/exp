"""exp measurement schema — the contract every component speaks.

One Measurement = one network transaction a probe ran and measured. Probes emit these;
collectors validate them, store the numeric `metrics` in VictoriaMetrics, and keep the full
record for the event/incident log. The dashboard renders series derived from them.

Design rule: keep series labels LOW-cardinality. High-cardinality values (specific URLs,
per-hop trace data) belong in the record, not as VictoriaMetrics labels.
"""
from __future__ import annotations

import dataclasses
import datetime
import math
import re
from typing import Any, Optional

SCHEMA = "exp.measurement/1"
OUTCOMES = ("ok", "degraded", "fail", "error")
# Built-in test kinds (extensible — a probe may emit its own, lower-cased).
TESTS = ("gateway", "dhcp", "dns", "app", "throughput", "heartbeat")

_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")          # probe / site ids
_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*\Z")            # metric / label names (VM-safe)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")                     # control chars, rejected in free text

# Probe input is untrusted. These labels are set by the trusted base in series() and must never
# be supplied by a probe (else it could spoof another probe's identity or its own outcome).
RESERVED_LABELS = frozenset({"probe", "site", "outcome", "target"})
MAX_LABELS = 20            # cardinality/DoS guard
MAX_METRICS = 50
MAX_LABEL_LEN = 128
MAX_TARGET_LEN = 256


def utcnow() -> str:
    """UTC timestamp, millisecond precision, Z-suffixed."""
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def iso_to_ms(ts: str) -> int:
    return int(datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() * 1000)


@dataclasses.dataclass
class Measurement:
    probe: str                                    # stable probe id (slug)
    test: str                                     # test kind, e.g. "dns"
    outcome: str                                  # ok | degraded | fail | error
    ts: str = ""                                  # UTC ISO8601; set at validate() if empty
    site: str = "default"                         # logical location/site (slug)
    target: str = ""                              # what was tested (host/url/ip)
    duration_ms: Optional[float] = None           # primary timing; mapped to <test>_duration_ms
    metrics: dict[str, float] = dataclasses.field(default_factory=dict)   # numeric → TSDB series
    labels: dict[str, str] = dataclasses.field(default_factory=dict)      # low-card dimensions
    error: Optional[str] = None                   # short error string on fail/error
    agent_ver: str = ""

    def validate(self) -> "Measurement":
        if self.outcome not in OUTCOMES:
            raise ValueError(f"outcome must be one of {OUTCOMES}, got {self.outcome!r}")
        if not _SLUG.match(self.probe or ""):
            raise ValueError(f"probe must be a slug [a-z0-9-], got {self.probe!r}")
        if not _SLUG.match(self.site or ""):
            raise ValueError(f"site must be a slug [a-z0-9-], got {self.site!r}")
        if not self.test or not _NAME.match(self.test):
            raise ValueError(f"test must be a non-empty identifier, got {self.test!r}")
        if len(self.metrics) > MAX_METRICS:
            raise ValueError(f"too many metrics (>{MAX_METRICS})")
        for k, v in self.metrics.items():
            if not _NAME.match(k):
                raise ValueError(f"metric name {k!r} is not a valid series name")
            if not isinstance(v, (int, float)) or isinstance(v, bool) or not math.isfinite(v):
                raise ValueError(f"metric {k} must be a finite number, got {v!r}")
        # target can become a series label, so treat it as untrusted free text
        if not isinstance(self.target, str):
            raise ValueError("target must be a string")
        if len(self.target) > MAX_TARGET_LEN:
            raise ValueError(f"target exceeds {MAX_TARGET_LEN} characters")
        if _CTRL.search(self.target):
            raise ValueError("target contains control characters")
        # labels are untrusted: a probe could spoof reserved keys or explode cardinality
        if len(self.labels) > MAX_LABELS:
            raise ValueError(f"too many labels (>{MAX_LABELS})")
        for k, v in self.labels.items():
            if not _NAME.match(k):
                raise ValueError(f"label name {k!r} is not valid")
            if k in RESERVED_LABELS or k.startswith("__"):
                raise ValueError(f"label name {k!r} is reserved (set by the collector, not the probe)")
            if not isinstance(v, str):
                raise ValueError(f"label {k!r} value must be a string, got {type(v).__name__}")
            if len(v) > MAX_LABEL_LEN:
                raise ValueError(f"label {k!r} value exceeds {MAX_LABEL_LEN} characters")
            if _CTRL.search(v):
                raise ValueError(f"label {k!r} value contains control characters")
        if self.duration_ms is not None and (
                not isinstance(self.duration_ms, (int, float)) or isinstance(self.duration_ms, bool)
                or not math.isfinite(self.duration_ms)):
            raise ValueError("duration_ms must be a finite number or None")
        # ts: fill when empty, else require a parseable ISO-8601 string (fail here, not later in
        # series()). Clock-skew bounding is the collector's job — probes backfill old spool records.
        if not self.ts:
            self.ts = utcnow()
        elif not isinstance(self.ts, str):
            raise ValueError("ts must be an ISO-8601 string")
        else:
            try:
                iso_to_ms(self.ts)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"ts is not a valid ISO-8601 timestamp: {self.ts!r}") from exc
        return self

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["schema"] = SCHEMA
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Measurement":
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known}).validate()

    def series(self) -> list[dict[str, Any]]:
        """Numeric metrics as VictoriaMetrics-ingestable points.

        series name  : exp_<test>_<metric>   (e.g. exp_dns_rtt_ms)
        labels       : probe, site, outcome + low-card labels (+ target if short)
        """
        # probe-supplied labels first; trusted labels applied LAST so a probe cannot override
        # them — defence in depth even if this record was constructed without validate().
        labels = {k: str(v) for k, v in self.labels.items()}
        if self.target and len(self.target) <= 80:
            labels["target"] = self.target
        labels.update(probe=self.probe, site=self.site, outcome=self.outcome)
        metrics = dict(self.metrics)
        if self.duration_ms is not None:
            metrics.setdefault("duration_ms", float(self.duration_ms))
        ts_ms = iso_to_ms(self.ts)
        return [{"metric": f"exp_{self.test}_{name}", "labels": dict(labels),
                 "value": float(val), "timestamp_ms": ts_ms}
                for name, val in metrics.items()]


def measure(probe: str, test: str, outcome: str, **kw: Any) -> Measurement:
    """Convenience constructor that validates immediately."""
    return Measurement(probe=probe, test=test, outcome=outcome, **kw).validate()
