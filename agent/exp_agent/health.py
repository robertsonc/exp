"""Component health: `exp-<c> health --json` (exp.health/1, 01-contracts.md section 8.1)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from exp_common import config as exp_config
from exp_common.log import scrub

from .context import Context

log = logging.getLogger(__name__)

MAX_HEALTH_BYTES = 64 * 1024


@dataclass
class HealthResult:
    passed: bool  # exit code 0
    status: str = "unknown"  # ok | degraded | fail | unknown
    detail: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    timed_out: bool = False


_FACT_REFS = {
    "tls_fingerprint_sha256": "common.schema.json#/$defs/tls_fingerprint",
    "listen": "common.schema.json#/$defs/hostport",
    "url": "common.schema.json#/$defs/https_url",
}


def clean_facts(doc: Any) -> Any:
    """Drop wiring facts that would make the manager reject the WHOLE status report
    (CR-wp4-status-component-facts): a malformed tls_fingerprint_sha256 / listen / url is removed."""
    if isinstance(doc, dict) and isinstance(doc.get("facts"), dict):
        facts = dict(doc["facts"])
        for key, ref in _FACT_REFS.items():
            if key in facts and exp_config.iter_errors(facts[key], {"$ref": ref}):
                log.warning("dropping malformed component fact %r from a health document", key)
                del facts[key]
        doc = {**doc, "facts": facts}
    return doc


def run_health(ctx: Context, component: str, version: str) -> HealthResult:
    paths = ctx.paths
    binary = paths.version_dir(component, version) / "bin" / f"exp-{component}"
    argv = [str(binary), "health", "--json", "--config", str(paths.config(component))]
    res = ctx.runner.run(
        argv, timeout=ctx.health_timeout_s, env={"CREDENTIALS_DIRECTORY": str(paths.creds_dir(component))}
    )
    if res.timed_out:
        return HealthResult(False, "degraded", "health timeout", timed_out=True)
    out = res.stdout
    parsed: dict[str, Any] | None = None
    problem = ""
    if len(out.encode("utf-8", "replace")) > MAX_HEALTH_BYTES:
        problem = "health output too large"
    else:
        try:
            doc = clean_facts(exp_config.parse_json(out, "health output"))
            exp_config.validate(doc, "health.schema.json")
            parsed = doc
        except exp_config.ConfigError:
            problem = "health output is not valid exp.health/1"
    if parsed is None:
        if res.rc == 0:
            return HealthResult(True, "degraded", problem)
        tail = scrub((res.stderr or "").strip().splitlines()[-1] if (res.stderr or "").strip() else "")
        return HealthResult(False, "fail", (tail or f"health exited {res.rc}")[:500])
    metrics = parsed.get("metrics") if isinstance(parsed.get("metrics"), dict) else {}
    facts = parsed.get("facts") if isinstance(parsed.get("facts"), dict) else {}
    # Reconcile gate: "ok" and "degraded" mean the service is up and answering (a degraded dashboard may
    # only be missing a collector that arrives later); "fail" never passes, even with exit code 0.
    passed = parsed["status"] == "degraded" or (parsed["status"] == "ok" and res.rc == 0)
    return HealthResult(passed, parsed["status"], scrub(str(parsed.get("detail", "")))[:1000], metrics, facts)


def wait_healthy(ctx: Context, component: str, version: str) -> HealthResult:
    """Poll until `health` succeeds (exit 0) or `ctx.health_wait_s` elapsed (poll every health_poll_s)."""
    deadline = ctx.monotonic() + ctx.health_wait_s
    last = HealthResult(False, "fail", "not checked")
    max_tries = int(ctx.health_wait_s / max(ctx.health_poll_s, 0.01)) + 2  # belt and braces vs a stuck clock
    for _ in range(max_tries):
        last = run_health(ctx, component, version)
        if last.passed or ctx.monotonic() >= deadline:
            return last
        ctx.sleep(ctx.health_poll_s)
    return last
