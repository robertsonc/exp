"""Agent self-update and its rollback marker (06-agent.md section 4).

download + verify + unpack to /opt/exp/agent/<new>/ -> write the `pending` marker -> flip `current`
(and `previous`) -> `systemctl --no-block restart exp-agent`. The new agent clears the marker after its
first successful poll + status report. If it never does, exp-agent-rollback.timer runs
/opt/exp/agent/rollback-check (a standalone copy of rollback_check.py, independent of both agent versions,
installed by install.sh and refreshed here), which flips `current` back, restarts the old agent and
leaves a note so that agent reports `agent_rollback` and refuses that version until the manager asks
for a different one.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from . import artifacts, install, units
from .context import Context
from .errors import AgentError, Refused
from .verify import Manifest, version_lt

log = logging.getLogger(__name__)

PENDING = "pending.json"
ROLLED_BACK = "rolled_back.json"
CONFIRM_WINDOW_S = 300
CHECKER_SRC = "lib/exp_agent/rollback_check.py"
CHECKER = "rollback-check"  # /opt/exp/agent/rollback-check
AGENT_UNITS = ("exp-agent.service", "exp-agent-rollback.service", "exp-agent-rollback.timer")


def read_pending(ctx: Context) -> dict[str, Any] | None:
    doc = ctx.state.read_json(PENDING)
    return doc if isinstance(doc, dict) and "to" in doc and "from" in doc else None


def confirm_if_pending(ctx: Context) -> bool:
    """Called after the first successful poll + status report of the NEW agent: clear the marker."""
    p = read_pending(ctx)
    if p and p.get("to") == ctx.agent_version:
        ctx.fs.remove(ctx.paths.agent_state / PENDING)
        ctx.state.event("info", f"agent updated to {ctx.agent_version} (previous {p.get('from')})")
        prune_agent_trees(ctx)
        return True
    return False


def prune_agent_trees(ctx: Context) -> list[str]:
    """Keep only the running tree (`current`) and the rollback target (`previous`) in /opt/exp/agent/.
    Never while an update is unconfirmed (both trees are needed then)."""
    if read_pending(ctx) is not None:
        return []
    try:
        removed = install.prune_versions(ctx.fs, "agent", {ctx.agent_version})
    except (AgentError, OSError) as exc:
        log.warning("pruning old agent trees failed: %s", exc)
        return []
    if removed:
        ctx.state.event("info", "removed old agent trees: " + ", ".join(removed))
    return removed


def absorb_rollback_note(ctx: Context) -> None:
    """On start: if rollback-check restored this (old) agent, report `agent_rollback`, block that version."""
    note = ctx.state.read_json(ROLLED_BACK)
    if not isinstance(note, dict):
        return
    bad = str(note.get("from", ""))
    if bad:
        blocked = set(ctx.state.data.get("bad_agent_versions", []))
        blocked.add(bad)
        ctx.state.data["bad_agent_versions"] = sorted(blocked)[-10:]
    ctx.state.event("error", f"agent_rollback: agent {bad} did not report in time; restored {note.get('to')}")
    ctx.fs.remove(ctx.paths.agent_state / ROLLED_BACK)
    prune_agent_trees(ctx)  # the tree that failed to confirm is gone for good
    ctx.state.save()


def install_checker(ctx: Context, tree: Path) -> bool:
    """Atomically (re)write /opt/exp/agent/rollback-check (root 0755) from `tree`'s copy of the standalone
    checker. A tree without one (older agents) leaves the installed checker alone. True when written."""
    data = ctx.fs.read_bytes(tree / CHECKER_SRC, max_bytes=256 * 1024)
    if data is None:
        return False
    dest = ctx.paths.comp_opt("agent") / CHECKER
    ctx.fs.write(dest, data, 0o755)  # atomic (temp file + rename)
    return True


def update(ctx: Context, doc: dict[str, Any], man: Manifest) -> bool:
    """Self-update to doc['agent']['version'] if it differs. True when a restart was requested."""
    ag = doc.get("agent")
    if not ag:
        return False
    ver = ag["version"]
    if ver == ctx.agent_version:
        return False
    if ver in ctx.state.data.get("bad_agent_versions", []):
        raise Refused(
            f"agent {ver} failed to start properly before; not retrying it until the desired version changes"
        )
    if version_lt(ver, man.min_agent_version):
        raise Refused(f"agent {ver} is older than the manifest's min_agent_version {man.min_agent_version}")
    art_id = ag.get("artifact")
    if not art_id:
        raise Refused("desired agent version has no artifact")
    name = f"exp-agent-{ver}-noarch.tar.gz"
    entry = man.entry(name)
    if entry is None or entry.get("component") != "agent":
        raise Refused(f"{name} is not in the signed manifest")
    fs, paths = ctx.fs, ctx.paths
    prev = install.current_version(fs, "agent") or ctx.agent_version
    if not fs.is_dir(paths.version_dir("agent", prev)):
        raise Refused(
            f"previous agent tree {prev} is missing; refusing a self-update that cannot be rolled back"
        )
    vdir = paths.version_dir("agent", ver)
    rendered: dict[str, str] = {}
    if not fs.exists(vdir):
        art = {
            "id": art_id,
            "name": name,
            "url": f"/api/agent/v1/artifacts/{art_id}",
            "sha256": entry["sha256"],
            "size": entry["size"],
        }
        staging = artifacts.stage_and_unpack(ctx.client, fs, art, entry, "agent", paths.comp_opt("agent"))
        try:
            if not (staging / "bin" / "exp-agent").is_file():
                raise Refused("agent artifact has no bin/exp-agent")
            templates = units.load_templates(staging)
            rendered = {n: units.render(n, t, {}) for n, t in templates.items() if n in AGENT_UNITS}
            install.commit_staging(fs, staging, vdir)
        except BaseException:
            fs.rmtree(staging)
            raise
    else:
        rendered = {
            n: units.render(n, t, {}) for n, t in units.load_templates(vdir).items() if n in AGENT_UNITS
        }
    ctx.state.write_json(
        PENDING, {"from": prev, "to": ver, "started": ctx.clock(), "deadline_s": CONFIRM_WINDOW_S}
    )
    install_checker(ctx, vdir)  # before the flip: the timer must be able to undo this very update
    changed, _ = units.write_units(fs, rendered, set())
    fs.symlink(prev, paths.opt / "agent" / "previous")
    install.flip_current(fs, "agent", ver)
    if changed:
        ctx.sysctl.daemon_reload()
    ctx.state.event("info", f"agent update {prev} -> {ver} installed; restarting")
    ctx.state.save()
    ctx.sysctl.restart_no_block("exp-agent.service")
    return True


def rollback_check(ctx: Context) -> str:
    """Timer entry point. Returns a short status string (for the CLI): idle | waiting | rolled-back."""
    p = read_pending(ctx)
    if p is None:
        return "idle"
    started = float(p.get("started", 0))
    if ctx.clock() < started + float(p.get("deadline_s", CONFIRM_WINDOW_S)):
        return "waiting"
    prev, bad = str(p["from"]), str(p["to"])
    fs = ctx.fs
    if not fs.is_dir(ctx.paths.version_dir("agent", prev)):
        raise AgentError(f"cannot roll back: previous agent tree {prev} is missing")
    install.flip_current(fs, "agent", prev)
    ctx.state.write_json(ROLLED_BACK, {"from": bad, "to": prev, "at": ctx.clock()})
    fs.remove(ctx.paths.agent_state / PENDING)
    ctx.sysctl.restart_no_block("exp-agent.service")
    log.warning("agent %s did not confirm within %ss; rolled back to %s", bad, p.get("deadline_s"), prev)
    return "rolled-back"
