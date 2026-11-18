"""Desired-state handling: validation (exp.desired/1) and the fixed reconcile order."""

from __future__ import annotations

from typing import Any

from exp_common import config as exp_config

from .errors import Refused

ORDER = ("collector", "runner", "dashboard", "probe")
SUPPORTED = frozenset(ORDER)


def validate(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise Refused("desired state is not a JSON object")
    try:
        issues = exp_config.iter_errors(doc, "desired.schema.json")
    except exp_config.SchemaError as exc:
        raise Refused(f"desired schema unusable: {exc}") from None
    if issues:
        raise Refused("invalid desired state: " + "; ".join(str(i) for i in issues[:3]))
    return doc


def split_components(doc: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """(supported components in collector -> runner -> dashboard -> probe order,
    ignored [{type,id,reason}]). One component per type per host (they share /opt/exp/<type>)."""
    by_type: dict[str, dict[str, Any]] = {}
    ignored: list[dict[str, str]] = []
    for comp in doc.get("components", []):
        t = comp.get("type", "")
        cid = str(comp.get("id", ""))[:64]
        if t not in SUPPORTED:
            ignored.append(
                {"type": str(t)[:32], "id": cid, "reason": "component type not supported by this agent"}
            )
        elif t in by_type:
            ignored.append({"type": t, "id": cid, "reason": f"a second {t} on one host is not supported"})
        else:
            by_type[t] = comp
    return [by_type[t] for t in ORDER if t in by_type], ignored
