"""Removing components (reconcile step 5) and decommissioning / uninstalling the host (06-agent.md section 5).

Never removes anything outside the allowed roots: every path goes through SafeFS."""

from __future__ import annotations

import logging
from typing import Any

from .context import Context
from .desired import ORDER
from .selfupdate import AGENT_UNITS

log = logging.getLogger(__name__)


def remove_component(ctx: Context, c: str, rec: dict[str, Any] | None, purge: bool = False) -> None:
    """Stop/disable units, remove unit files and /opt/exp/<c>/ (+ the bin link, creds). `purge` also
    removes config and DATA (/var/lib/exp/<c>) -- decommission only."""
    fs, paths, sc = ctx.fs, ctx.paths, ctx.sysctl
    rec = rec or {}
    instances = list(rec.get("instances", []))
    unit_files = list(rec.get("unit_files", []))
    primary = list(rec.get("units", []))
    # stop instances first, then services in reverse start order; a probe's netns unit last so every
    # port goes back to the host (its ExecStop moves them)
    netns = [u for u in primary if "netns" in u]
    rest = [u for u in reversed(primary) if u not in netns]
    sc.stop(instances)
    sc.stop(rest)
    sc.stop(netns)
    sc.disable(instances + primary)
    removed_any = False
    for name in unit_files:
        removed_any |= fs.remove(paths.unit(name))
    if removed_any:
        sc.daemon_reload()
    fs.remove(paths.bin_link(c))
    fs.rmtree(paths.comp_opt(c))
    fs.rmtree(paths.agent_state / "previous" / c)
    fs.rmtree(paths.creds_dir(c))
    if purge:
        fs.rmtree(paths.etc_dir(c))
        fs.rmtree(paths.state_dir(c))
        fs.rmtree(paths.run_dir(c))
    ctx.state.data["components"].pop(c, None)


def local_cleanup(ctx: Context, components: dict[str, Any]) -> None:
    """Remove every component (with data), then the agent itself. Idempotent."""
    for c in ORDER:
        if c in components or ctx.fs.exists(ctx.paths.comp_opt(c)) or ctx.fs.exists(ctx.paths.etc_dir(c)):
            remove_component(ctx, c, components.get(c), purge=True)
    ctx.state.data["components"] = {}


def remove_agent(ctx: Context) -> None:
    """Last step: agent config, units, tree, state. The running process is stopped without blocking."""
    fs, paths, sc = ctx.fs, ctx.paths, ctx.sysctl
    sc.stop(["exp-agent-rollback.timer", "exp-agent-rollback.service"])
    sc.disable(list(AGENT_UNITS))
    for name in AGENT_UNITS:
        fs.remove(paths.unit(name))
    sc.daemon_reload()
    fs.remove(paths.agent_json)
    fs.remove(paths.bin_link("agent"))
    fs.rmtree(paths.comp_opt("agent"))
    fs.rmtree(paths.agent_state)
    ctx.runner.run(["systemctl", "--no-block", "stop", "exp-agent.service"], timeout=30)


def decommission(ctx: Context, components: dict[str, Any], call_manager: bool) -> None:
    local_cleanup(ctx, components)
    if call_manager and ctx.client is not None:
        ctx.client.decommissioned()
    remove_agent(ctx)
