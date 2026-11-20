"""``exp.evidence/1`` helpers: envelopes, schema validation, bounding (<= 256 KiB per test across kinds)."""
from __future__ import annotations

import copy
import datetime
import json
import logging
from typing import Any

from exp_common import config as exp_config

log = logging.getLogger(__name__)

KINDS = ("identity", "wifi", "wired", "flows", "wan", "security", "baseline", "dns")
# the source recorded on an "unavailable" placeholder, per kind (an allowed source of that kind's schema)
DEFAULT_SOURCE = {"identity": "exp", "wifi": "mist", "wired": "mist", "flows": "ec", "wan": "ec",
                  "security": "syslog", "baseline": "exp", "dns": "syslog"}
MAX_TOTAL_BYTES = 256 * 1024
MAX_DOC_BYTES = 200 * 1024
MAX_RAW_REFS = 20
STATUSES = ("ok", "partial", "unavailable", "error")


def _fmt(ts: float) -> str:
    d = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def envelope(test_id: str, kind: str, source: str, status: str, data: dict[str, Any], window: dict[str, str],
             collected_at: float, raw_refs: list[str] | None = None) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"bad evidence status {status!r}")
    return {"schema": "exp.evidence/1", "test_id": test_id, "kind": kind, "source": source, "collected_at": _fmt(collected_at),
            "window": dict(window), "status": status, "data": data,
            "raw_refs": [str(r)[:128] for r in (raw_refs or [])][:MAX_RAW_REFS]}


def placeholder(test_id: str, kind: str, status: str, window: dict[str, str], collected_at: float,
                source: str | None = None) -> dict[str, Any]:
    """A kind nobody could deliver: ``unavailable`` / ``error`` with empty data (explicit, never silently missing)."""
    return envelope(test_id, kind, source or DEFAULT_SOURCE[kind], status, {}, window, collected_at)


def size(doc: dict[str, Any]) -> int:
    return len(json.dumps(doc, separators=(",", ":")).encode("utf-8"))


def validation_errors(doc: dict[str, Any]) -> list[str]:
    try:
        return [str(i) for i in exp_config.iter_errors(doc, "evidence")][:5]
    except exp_config.SchemaError as exc:      # pragma: no cover - a broken install
        return [f"schema unusable: {exc}"]


def _lists(node: Any, path: tuple[Any, ...] = (), depth: int = 0):
    if depth > 4:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _lists(v, (*path, k), depth + 1)
    elif isinstance(node, list):
        yield path, node
        for i, v in enumerate(node[:3]):
            yield from _lists(v, (*path, i), depth + 1)


def shrink(doc: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    """Halve the longest list inside ``data`` until the serialized document fits; marks it partial. A document that cannot
    be made to fit is replaced by an ``error`` placeholder."""
    if size(doc) <= max_bytes:
        return doc
    out = copy.deepcopy(doc)
    for _ in range(64):
        if size(out) <= max_bytes:
            break
        best = max(((len(lst), p, lst) for p, lst in _lists(out["data"]) if len(lst) > 1), default=None, key=lambda t: t[0])
        if best is None:
            break
        del best[2][len(best[2]) // 2:]
        if out["kind"] == "security":
            out["data"]["truncated"] = True
    if size(out) > max_bytes:
        out["status"], out["data"] = "error", {}
        return out
    if out["status"] == "ok":
        out["status"] = "partial"
    return out


def fit_total(docs: list[dict[str, Any]], max_total: int = MAX_TOTAL_BYTES) -> list[dict[str, Any]]:
    """Make the whole set fit the per-test budget: shrink the largest documents first."""
    docs = [shrink(d, MAX_DOC_BYTES) for d in docs]
    for _ in range(32):
        total = sum(size(d) for d in docs)
        if total <= max_total:
            break
        i = max(range(len(docs)), key=lambda j: size(docs[j]))
        target = max(1024, size(docs[i]) - (total - max_total) - 256)
        docs[i] = shrink(docs[i], target)
    return docs
