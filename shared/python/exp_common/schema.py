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
import json
import math
import re
from typing import Any

from .ids import is_ulid, new_ulid

SCHEMA = "exp.measurement/1"
OUTCOMES = ("ok", "degraded", "fail", "error")
# Built-in test kinds (extensible — a probe may emit its own, lower-cased).
TESTS = ("gateway", "dhcp", "dns", "app", "throughput", "heartbeat")

_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")          # probe / site ids
_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}\Z")       # metric / label / test names (VM-safe, ≤64)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")                     # control chars, rejected in free text

# Probe input is untrusted. These labels are set by the trusted base in series() and must never
# be supplied by a probe (else it could spoof another probe's identity or its own outcome).
RESERVED_LABELS = frozenset({"probe", "site", "outcome", "target"})
MAX_LABELS = 20            # cardinality/DoS guard
MAX_METRICS = 50
MAX_LABEL_LEN = 128
MAX_TARGET_LEN = 256

# `detail`: bounded high-cardinality record data that never becomes a series label (01-contracts 2).
DETAIL_MAX_BYTES = 8 * 1024        # serialized (compact JSON, UTF-8)
DETAIL_MAX_DEPTH = 4               # the detail object itself is depth 1
DETAIL_MAX_STR = 1024              # characters
DETAIL_MAX_ARRAY = 256
_DETAIL_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")

__all__ = [
    "DETAIL_MAX_ARRAY",
    "DETAIL_MAX_BYTES",
    "DETAIL_MAX_DEPTH",
    "DETAIL_MAX_STR",
    "MAX_LABELS",
    "MAX_LABEL_LEN",
    "MAX_METRICS",
    "MAX_TARGET_LEN",
    "OUTCOMES",
    "RESERVED_LABELS",
    "SCHEMA",
    "TESTS",
    "Measurement",
    "iso_to_ms",
    "measure",
    "utcnow",
    "validate_detail",
]


def utcnow() -> str:
    """UTC timestamp, millisecond precision, Z-suffixed."""
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat(timespec="milliseconds").replace("+00:00", "Z"))


def iso_to_ms(ts: str) -> int:
    """Parse a tz-aware ISO-8601 string to epoch ms. Raises ValueError on bad input:
    non-string, unparseable, naive (no timezone), or out of representable range."""
    if not isinstance(ts, str):
        raise ValueError(f"ts must be a string, got {type(ts).__name__}")
    try:
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"ts is not ISO-8601: {ts!r}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"ts must include a timezone offset (naive timestamps rejected): {ts!r}")
    try:
        return int(dt.timestamp() * 1000)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError(f"ts out of representable range: {ts!r}") from exc


def _as_finite_float(v: Any, what: str) -> float:
    """A finite float, or ValueError. Rejects bool/non-number, NaN/inf, and ints so large
    that converting to float would overflow (a fail-late DoS at series() time)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ValueError(f"{what} must be a number, got {type(v).__name__}")
    try:
        fv = float(v)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{what} is out of range") from exc
    if not math.isfinite(fv):
        raise ValueError(f"{what} must be finite, got {v!r}")
    return fv


def validate_detail(detail: Any) -> None:
    """Enforce the `detail` bounds; raises ValueError. Must be a JSON-compatible object:
    serialized <= 8 KiB, depth <= 4 (the object itself is depth 1), keys [A-Za-z_][A-Za-z0-9_]{0,63},
    strings <= 1024 chars without control characters, arrays <= 256 items, finite numbers."""
    if not isinstance(detail, dict):
        raise ValueError(f"detail must be an object, got {type(detail).__name__}")
    budget = [DETAIL_MAX_BYTES]    # every node serializes to >= 1 byte: bounds work on huge inputs

    def walk(v: Any, depth: int, where: str) -> None:
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError(f"detail exceeds {DETAIL_MAX_BYTES} bytes serialized")
        if isinstance(v, bool) or v is None:
            return
        if isinstance(v, (int, float)):
            _as_finite_float(v, f"detail{where}")
            return
        if isinstance(v, str):
            if len(v) > DETAIL_MAX_STR:
                raise ValueError(f"detail{where} string exceeds {DETAIL_MAX_STR} characters")
            if _CTRL.search(v):
                raise ValueError(f"detail{where} string contains control characters")
            return
        if isinstance(v, (dict, list)):
            if depth > DETAIL_MAX_DEPTH:
                raise ValueError(f"detail nesting deeper than {DETAIL_MAX_DEPTH} at {where or '/'}")
            if isinstance(v, list):
                if len(v) > DETAIL_MAX_ARRAY:
                    raise ValueError(f"detail{where} array exceeds {DETAIL_MAX_ARRAY} items")
                for i, item in enumerate(v):
                    walk(item, depth + 1, f"{where}[{i}]")
            else:
                for k, item in v.items():
                    if not isinstance(k, str) or not _DETAIL_KEY.match(k):
                        raise ValueError(f"detail key {k!r} at {where or '/'} is not a valid identifier")
                    walk(item, depth + 1, f"{where}.{k}")
            return
        raise ValueError(f"detail{where} has non-JSON value of type {type(v).__name__}")

    walk(detail, 1, "")
    size = len(json.dumps(detail, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8"))
    if size > DETAIL_MAX_BYTES:
        raise ValueError(f"detail is {size} bytes serialized (max {DETAIL_MAX_BYTES})")


@dataclasses.dataclass
class Measurement:
    probe: str                                    # stable probe id (slug)
    test: str                                     # test kind, e.g. "dns"
    outcome: str                                  # ok | degraded | fail | error
    ts: str = ""                                  # UTC ISO8601; set at validate() if empty
    site: str = "default"                         # logical location/site (slug)
    target: str = ""                              # what was tested (host/url/ip)
    duration_ms: float | None = None           # primary timing; mapped to <test>_duration_ms
    metrics: dict[str, float] = dataclasses.field(default_factory=dict)   # numeric → TSDB series
    labels: dict[str, str] = dataclasses.field(default_factory=dict)      # low-card dimensions
    error: str | None = None                   # short error string on fail/error
    agent_ver: str = ""
    id: str = ""                                  # ULID; generated by measure(), required at ingest
    detail: dict[str, Any] | None = None       # bounded high-cardinality detail (never a label)

    def validate(self, require_id: bool = False) -> Measurement:
        """Validate in place. `require_id=True` is the ingest-side check: `id` must be a ULID.
        Without it, an empty id is tolerated (a record not yet stamped) but a non-empty id
        must still be a ULID."""
        for fname in ("probe", "test", "outcome", "ts", "site", "target", "agent_ver", "id"):
            if not isinstance(getattr(self, fname), str):
                raise ValueError(f"{fname} must be a string, got {type(getattr(self, fname)).__name__}")
        for fname in ("metrics", "labels"):
            if not isinstance(getattr(self, fname), dict):
                raise ValueError(f"{fname} must be an object")
        if self.error is not None and not isinstance(self.error, str):
            raise ValueError("error must be a string or null")
        if self.id:
            if not is_ulid(self.id):
                raise ValueError(f"id must be a ULID, got {self.id!r}")
        elif require_id:
            raise ValueError("id is required (ULID)")
        if self.detail is not None:
            validate_detail(self.detail)
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
                raise ValueError(f"metric name {k!r} is not a valid series name (≤64 chars)")
            _as_finite_float(v, f"metric {k!r}")
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
        if self.duration_ms is not None:
            _as_finite_float(self.duration_ms, "duration_ms")
        # ts: fill when empty, else require a parseable, tz-aware ISO-8601 string (fail here, not
        # later in series()). Clock-skew bounding is the collector's job — probes backfill spool.
        if not self.ts:
            self.ts = utcnow()
        else:
            iso_to_ms(self.ts)
        return self

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["schema"] = SCHEMA
        if not d.get("id"):
            d.pop("id", None)
        if d.get("detail") is None:
            d.pop("detail", None)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any], require_id: bool = False) -> Measurement:
        known = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known}).validate(require_id=require_id)

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
    """Convenience constructor that validates immediately. Generates `id` (ULID) unless given."""
    if not kw.get("id"):
        kw["id"] = new_ulid()
    return Measurement(probe=probe, test=test, outcome=outcome, **kw).validate()
