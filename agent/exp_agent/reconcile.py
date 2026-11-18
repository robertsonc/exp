"""Reconcile (06-agent.md section 3): idempotent, ordered, verified, with rollback.

collector -> runner -> dashboard -> probe. For each component: verify (manifest signature + sha256),
safe-unpack, apt allowlist, service users, config + creds + TLS, unit rendering, restart only what
changed, health check within 60 s, rollback on failure and never retry the same desired version.
A failure in one component does not stop the others; the overall result is the worst of them.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from exp_common.log import scrub

from . import artifacts, creds, decommission, desired, install, selfupdate, tls, units
from .context import Context
from .errors import AgentError, Refused, Transient, Unauthorized, need
from .health import wait_healthy
from .state import iso_now
from .verify import Manifest, check_artifact, version_lt

log = logging.getLogger(__name__)

PREV_DIR = "previous"


class RolledBack(AgentError):
    """The new version failed its health check and the previous one was restored."""


@dataclass
class Outcome:
    result: str  # ok | error | rolled_back
    error: str | None = None
    duration_ms: float = 0.0
    changed: bool = False
    permanent: bool = False  # the same desired version must not be retried
    restarting: bool = False  # self-update requested an agent restart
    decommissioned: bool = False
    ignored: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Diff:
    version: bool = False
    config: bool = False
    creds: bool = False
    units: bool = False
    instances: bool = False
    tls: bool = False

    @property
    def any(self) -> bool:
        return self.version or self.config or self.creds or self.units or self.instances or self.tls


@dataclass
class Plan:
    c: str
    version: str
    config: dict[str, Any]
    config_bytes: bytes
    creds: dict[str, bytes]  # desired creds (+ empty referenced files)
    rendered: dict[str, str]  # unit file name -> text
    infos: dict[str, units.UnitInfo]
    instances: list[str]
    reload_ok: bool


def _config_bytes(config: dict[str, Any]) -> bytes:
    return (json.dumps(config, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8"
    )


class Reconciler:
    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx

    # ===================================================================== entry point
    def run(self, doc: Any) -> Outcome:
        ctx = self.ctx
        t0 = ctx.monotonic()
        try:
            out = self._run(doc)
        except Unauthorized:
            raise
        except Refused as exc:
            out = Outcome("error", str(exc), permanent=True)
            ctx.state.event("error", f"reconcile refused: {exc}")
        except Transient as exc:
            out = Outcome("error", str(exc))
            ctx.state.event("warn", f"reconcile will be retried: {exc}")
        except AgentError as exc:
            out = Outcome("error", str(exc))
            ctx.state.event("error", f"reconcile failed: {exc}")
        out.duration_ms = round((ctx.monotonic() - t0) * 1000.0, 1)
        out.error = scrub(out.error)[:1000] if out.error else None
        if out.decommissioned:
            return out
        st = ctx.state
        version = doc.get("version") if isinstance(doc, dict) else None
        st.data["last_reconcile"] = {
            "at": iso_now(ctx.clock()),
            "result": out.result,
            "error": out.error,
            "duration_ms": out.duration_ms,
        }
        if isinstance(version, int):
            st.data["desired_version"] = version
            if out.result == "ok":
                st.data["applied_version"] = version
            if out.result != "ok" and out.permanent and not st.failed_version(version):
                st.mark_failed(version, out.result, out.error or "")
        st.data["ignored"] = out.ignored
        st.save()
        return out

    # ===================================================================== main sequence
    def _run(self, doc: Any) -> Outcome:
        ctx, st = self.ctx, self.ctx.state
        desired.validate(doc)
        failed = st.failed_version(doc["version"])
        if failed:  # never retry the same desired version (rolled back / refused)
            return Outcome(failed["result"], failed["error"], permanent=True)
        if doc["decommission"]:
            decommission.decommission(ctx, dict(st.data["components"]), call_manager=True)
            return Outcome("ok", decommissioned=True)
        comps, ignored = desired.split_components(doc)
        for ig in ignored:
            st.event("warn", f"ignored component {ig['id']!r} (type {ig['type']!r}): {ig['reason']}")
        man = self._manifest(doc, needed=bool(comps) or bool(doc.get("agent")))
        errors: list[str] = []
        permanent = False
        rolled = False
        changed = False
        restarting = False
        if man is not None:
            self._check_min_agent(doc, man)
            try:
                restarting = selfupdate.update(ctx, doc, man)
            except Refused as exc:
                errors.append(f"agent: refused: {exc}")
                st.event("error", f"agent self-update refused: {exc}")
                permanent = True
            if restarting:
                return Outcome("ok", changed=True, restarting=True, ignored=ignored)
        for comp in comps:
            c = comp["type"]
            try:
                changed |= self._apply(comp, need(man, "release manifest"))
            except RolledBack as exc:
                rolled, permanent = True, True
                errors.append(f"{c}: {exc}")
            except Refused as exc:
                permanent = True
                errors.append(f"{c}: refused: {exc}")
                st.event("error", f"{c}: refused: {exc}")
            except Unauthorized:
                raise
            except AgentError as exc:
                errors.append(f"{c}: {exc}")
                st.event("error", f"{c}: {exc}")
        wanted = {c["type"] for c in comps}
        for c in list(st.data["components"]):
            if c not in wanted and not any(i["type"] == c for i in ignored):
                try:
                    decommission.remove_component(ctx, c, st.data["components"][c])
                    st.event("info", f"removed component {c} (data kept under /var/lib/exp/{c})")
                    changed = True
                except AgentError as exc:
                    errors.append(f"remove {c}: {exc}")
        try:
            changed |= self._actions(doc, comps)
        except Transient as exc:
            errors.append(f"actions: {exc}")
        result = "rolled_back" if rolled else ("error" if errors else "ok")
        return Outcome(
            result,
            "; ".join(errors) or None,
            changed=changed,
            permanent=permanent and result != "ok",
            ignored=ignored,
        )

    # ===================================================================== manifest
    def _manifest(self, doc: dict[str, Any], needed: bool) -> Manifest | None:
        ctx = self.ctx
        rel = doc.get("release")
        if not rel:
            if needed:
                raise Refused("desired state carries components but no release")
            return None
        manifests, client = need(ctx.manifests, "manifest cache"), need(ctx.client, "manager client")
        return manifests.get(rel["version"], client.get_manifest)

    def _check_min_agent(self, doc: dict[str, Any], man: Manifest) -> None:
        ctx = self.ctx
        if version_lt(ctx.agent_version, man.min_agent_version):
            target = (doc.get("agent") or {}).get("version")
            if not target or version_lt(target, man.min_agent_version):
                raise Refused(
                    f"this agent ({ctx.agent_version}) is older than the release's min_agent_version "
                    f"{man.min_agent_version} and no newer agent is offered"
                )

    # ===================================================================== one component
    def _plan(self, comp: dict[str, Any], root, version: str) -> Plan:
        ctx = self.ctx
        c = comp["type"]
        templates = units.load_templates(root)
        values = units.placeholder_values(ctx.paths, c, version)
        rendered = units.render_all(templates, values)
        infos = {n: units.inspect(n, t) for n, t in rendered.items()}
        referenced: set[str] = set()
        for info in infos.values():
            referenced |= set(units.referenced_credential_files(info, values["@CREDS@"]))
        cred_map: dict[str, bytes] = {n: v.encode("utf-8") for n, v in comp.get("creds", {}).items()}
        for n in referenced:
            cred_map.setdefault(n, b"")
        config = comp["config"]
        instances = units.instance_units(c, config, set(rendered))
        reload_ok = any(i.has_reload for n, i in infos.items() if not units.is_template(n) and i.has_install)
        return Plan(
            c, version, config, _config_bytes(config), cred_map, rendered, infos, instances, reload_ok
        )

    def _primary(self, plan: Plan) -> list[str]:
        names = [n for n, i in plan.infos.items() if i.has_install and not units.is_template(n)]
        return sorted(names, key=lambda n: (0 if "netns" in n else 1, n))

    def _apply(self, comp: dict[str, Any], man: Manifest) -> bool:
        ctx, st, fs, paths = self.ctx, self.ctx.state, self.ctx.fs, self.ctx.paths
        c, ver = comp["type"], comp["version"]
        art = comp["artifact"]
        check_artifact(man, art, c, ctx.arch)
        if f"exp-{c}-{ver}-" not in art["name"]:
            raise Refused(f"artifact {art['name']} does not match component version {ver}")
        rec = st.data["components"].get(c)
        vdir = paths.version_dir(c, ver)
        staging = None
        installed = False
        try:
            if fs.exists(vdir):
                root = vdir
            else:
                entry = need(man.entry(art["name"]), "manifest entry")
                staging = artifacts.stage_and_unpack(ctx.client, fs, art, entry, c, paths.comp_opt(c))
                root = staging
            if not (root / "bin" / f"exp-{c}").is_file():
                raise Refused(f"artifact has no bin/exp-{c}")
            reqs = install.check_requirements(install.read_requirements(root))
            plan = self._plan(comp, root, ver)
            if staging is not None:
                install.apt_install(ctx.runner, reqs)
            install.ensure_users(ctx.runner, c, ctx.user_exists)
            if staging is not None:
                install.commit_staging(fs, staging, vdir)
                staging = None
                installed = True
        finally:
            if staging is not None:
                fs.rmtree(staging)
                self._rmdir_if_empty(paths.comp_opt(c))
        if installed:
            st.event("info", f"installed exp-{c} {ver}")

        diff = self._diff(plan, rec)
        if not diff.any:
            self._record(plan, comp)
            return installed
        if c == "probe" and diff.config:
            self._preflight(plan)
        if rec and (diff.version or diff.config or diff.creds):
            self._save_previous(c, rec)
        try:
            self._activate(plan, rec, diff, force=False)
        except RolledBack:
            raise
        except AgentError as exc:
            self._rollback(plan, rec, f"activation failed: {exc}")  # raises RolledBack
        health = wait_healthy(ctx, c, ver)
        if not health.passed:
            self._rollback(
                plan,
                rec,
                f"health check failed after {ctx.health_wait_s:.0f}s: {health.detail or health.status}",
            )  # raises RolledBack
        self._record(plan, comp)
        if rec and rec.get("version") != ver:
            keep = {ver, str(rec.get("version"))}
        else:
            keep = {ver}
        install.prune_versions(fs, c, keep)
        st.event("info", f"{c} {ver} is healthy")
        return True

    def _rmdir_if_empty(self, path) -> None:
        try:
            os.rmdir(self.ctx.fs.g(path))
        except OSError:
            pass  # not empty (other versions) or already gone

    # ----------------------------------------------------------------- diff / preflight
    def _diff(self, plan: Plan, rec: dict[str, Any] | None) -> Diff:
        ctx, fs, paths = self.ctx, self.ctx.fs, self.ctx.paths
        c = plan.c
        d = Diff()
        d.version = install.current_version(fs, c) != plan.version
        d.config = fs.read_bytes(paths.config(c)) != plan.config_bytes
        d.creds = creds.snapshot(fs, c) != plan.creds
        old_files = set(rec.get("unit_files", [])) if rec else set()
        d.units = bool(old_files - set(plan.rendered)) or any(
            fs.read_bytes(paths.unit(n)) != t.encode("utf-8") for n, t in plan.rendered.items()
        )
        d.instances = set(plan.instances) != set(rec.get("instances", [])) if rec else bool(plan.instances)
        d.tls = not tls.tls_is_valid(fs, ctx.runner, c, plan.config)
        return d

    def _preflight(self, plan: Plan) -> None:
        """`exp-probe preflight --config <new config>`: refuse the change (keep the old config) on failure."""
        ctx, fs, paths = self.ctx, self.ctx.fs, self.ctx.paths
        fs.mkdir(paths.etc, 0o755)
        fs.mkdir(paths.etc_dir(plan.c), 0o755)
        new_path = paths.etc_dir(plan.c) / "config.json.new"
        fs.write(new_path, plan.config_bytes, 0o644)
        try:
            binary = paths.version_dir(plan.c, plan.version) / "bin" / f"exp-{plan.c}"
            res = ctx.runner.run([str(binary), "preflight", "--config", str(new_path)], timeout=60)
        finally:
            fs.remove(new_path)
        if res.rc != 0:
            reason = (res.stderr.strip() or res.stdout.strip() or f"exit {res.rc}").splitlines()[-1]
            raise Refused(
                f"probe preflight refused the new configuration (previous config kept): {scrub(reason)[:300]}"
            )

    def _save_previous(self, c: str, rec: dict[str, Any]) -> None:
        """/var/lib/exp/agent/previous/<c>/{version,config.json,creds/}: the last applied good state."""
        ctx, fs = self.ctx, self.ctx.fs
        cfg = fs.read_bytes(ctx.paths.config(c))
        if cfg is None:
            return
        base = ctx.paths.agent_state / PREV_DIR / c
        fs.mkdir(ctx.paths.agent_state, 0o700)
        fs.mkdir(ctx.paths.agent_state / PREV_DIR, 0o700)
        fs.rmtree(base)
        fs.mkdir(base, 0o700)
        fs.mkdir(base / "creds", 0o700)
        fs.write(base / "version", str(rec["version"]) + "\n", 0o600)
        fs.write(base / "config.json", cfg, 0o600)
        for name, data in creds.snapshot(fs, c).items():
            fs.write(base / "creds" / name, data, 0o600)

    # ----------------------------------------------------------------- activation
    def _activate(self, plan: Plan, rec: dict[str, Any] | None, diff: Diff, force: bool) -> None:
        ctx, fs, paths, sc = self.ctx, self.ctx.fs, self.ctx.paths, self.ctx.sysctl
        c = plan.c
        fs.mkdir(paths.etc, 0o755)
        fs.mkdir(paths.etc_dir(c), 0o755)
        creds.sync(fs, c, dict(plan.creds), referenced=set())
        if diff.config or force:
            fs.write(paths.config(c), plan.config_bytes, 0o644)
        tls_new = (
            tls.ensure_tls(fs, ctx.runner, c, plan.config, ctx.user_ids) if (diff.tls or force) else False
        )
        old_primary = list(rec.get("units", [])) if rec else []
        old_instances = list(rec.get("instances", [])) if rec else []
        new_primary = self._primary(plan)
        gone = [u for u in old_primary if u not in new_primary]
        gone_inst = [u for u in old_instances if u not in plan.instances]
        if gone or gone_inst:
            sc.stop(gone_inst + gone)
            sc.disable(gone_inst + gone)
        old_files = set(rec.get("unit_files", [])) if rec else set()
        changed_files, removed_files = units.write_units(fs, plan.rendered, old_files)
        if changed_files or removed_files:
            sc.daemon_reload()
        if diff.version or force:
            install.flip_current(fs, c, plan.version)
        known = set(old_primary) | set(old_instances)
        new_units = [u for u in new_primary + plan.instances if u not in known]
        if new_units:
            sc.enable(new_units)
        everything = (
            [u for u in new_primary if "netns" in u]
            + plan.instances
            + [u for u in new_primary if "netns" not in u]
        )
        if force or diff.version or diff.config or diff.units or tls_new or (diff.instances and not rec):
            sc.restart(everything)
        elif diff.creds:
            reloadable = [u for u in new_primary if plan.infos[u].has_reload and u.endswith(".service")]
            if plan.reload_ok and reloadable:
                for u in reloadable:
                    sc.reload(u)
            else:
                sc.restart(everything)
        elif new_units:
            sc.restart([u for u in everything if u in new_units])

    def _record(self, plan: Plan, comp: dict[str, Any]) -> None:
        self.ctx.state.data["components"][plan.c] = {
            "id": comp["id"],
            "component_id": comp["component_id"],
            "version": plan.version,
            "units": self._primary(plan),
            "instances": list(plan.instances),
            "unit_files": sorted(plan.rendered),
            "applied_at": iso_now(self.ctx.clock()),
        }

    # ----------------------------------------------------------------- rollback
    def _rollback(self, bad: Plan, rec: dict[str, Any] | None, why: str) -> None:
        """Restore the previous version, config and creds from /var/lib/exp/agent/previous/<c>/ (or stop a
        first install), restart, re-check, then raise RolledBack. Never returns normally."""
        ctx, fs, paths, st = self.ctx, self.ctx.fs, self.ctx.paths, self.ctx.state
        c = bad.c
        bad_units = self._primary(bad)
        if rec is None:
            ctx.sysctl.stop(bad.instances + bad_units)
            ctx.sysctl.disable(bad.instances + bad_units)
            msg = f"{c} {bad.version}: {why}; no previous version, component stopped"
            st.event("error", msg)
            raise RolledBack(msg)
        base = paths.agent_state / PREV_DIR / c
        prev_ver = (fs.read_bytes(base / "version") or b"").decode().strip() or str(rec["version"])
        prev_cfg = fs.read_bytes(base / "config.json")
        if prev_cfg is None or not fs.is_dir(paths.version_dir(c, prev_ver)):
            msg = f"{c} {bad.version}: {why}; previous state is unavailable"
            st.event("error", msg)
            raise RolledBack(msg)
        prev_creds = {n: (fs.read_bytes(base / "creds" / n) or b"") for n in fs.listdir(base / "creds")}
        try:
            config = json.loads(prev_cfg.decode("utf-8"))
            plan = self._plan(
                {"type": c, "config": config, "creds": {}}, paths.version_dir(c, prev_ver), prev_ver
            )
        except (ValueError, Refused) as exc:
            msg = f"{c} {bad.version}: {why}; previous state is unusable ({type(exc).__name__})"
            st.event("error", msg)
            raise RolledBack(msg) from None
        plan.creds = {n: prev_creds.get(n, b"") for n in set(prev_creds) | set(plan.creds)}
        plan.config_bytes = prev_cfg
        # what is running now is the bad version's units: let _activate stop/remove whatever the old one lacks
        cur = dict(rec)
        cur["units"] = sorted(set(rec.get("units", [])) | set(bad_units))
        cur["instances"] = sorted(set(rec.get("instances", [])) | set(bad.instances))
        cur["unit_files"] = sorted(set(rec.get("unit_files", [])) | set(bad.rendered))
        self._activate(plan, cur, Diff(True, True, True, True, True, False), force=True)
        again = wait_healthy(ctx, c, prev_ver)
        msg = f"{c} {bad.version}: {why}; rolled back to {prev_ver}" + (
            "" if again.passed else " (previous version is also unhealthy)"
        )
        st.event("error", msg)
        raise RolledBack(msg)

    # ===================================================================== actions
    def _actions(self, doc: dict[str, Any], comps: list[dict[str, Any]]) -> bool:
        st = self.ctx.state
        done = st.actions_done()
        did = False
        for a in doc.get("actions", []):
            aid = a["id"]
            if aid in done:
                continue
            kind = a["type"]
            try:
                if kind == "rotate_agent_secret":
                    self._rotate()
                elif kind == "restart_component":
                    self._restart(a["component_id"], comps)
                elif kind == "collect_diagnostics":
                    self._diagnostics(aid)
            except Transient:
                raise
            except AgentError as exc:
                st.event("error", f"action {aid} ({kind}) failed: {exc}")
            st.mark_action(aid)
            did = True
        return did

    def _rotate(self) -> None:
        from .config import AgentConfig, save_agent_config

        ctx = self.ctx
        client, cfg = need(ctx.client, "manager client"), need(ctx.cfg, "agent config")
        secret = client.rotate()
        new = AgentConfig(cfg.manager_url, cfg.agent_id, secret, cfg.release_pubkey_pem)
        save_agent_config(ctx.fs, new)
        ctx.cfg = new
        client.set_secret(secret)
        ctx.state.event("info", "agent secret rotated")

    def _restart(self, component_id: str, comps: list[dict[str, Any]]) -> None:
        ctx = self.ctx
        for comp in comps:
            if comp["component_id"] == component_id:
                rec = ctx.state.data["components"].get(comp["type"])
                if not rec:
                    raise AgentError(f"component {comp['type']} is not installed")
                ctx.sysctl.restart(list(rec.get("instances", [])) + list(rec.get("units", [])))
                ctx.state.event("info", f"restarted {comp['type']} on request")
                return
        raise AgentError("restart_component: no such component on this host")

    def _diagnostics(self, action_id: str) -> None:
        """Sanitized journal excerpts + versions into /var/lib/exp/agent/diagnostics/<id>.txt (0600)."""
        ctx = self.ctx
        lines = [
            f"exp-agent {ctx.agent_version} diagnostics at {iso_now(ctx.clock())}",
            f"desired_version={ctx.state.data.get('desired_version')} "
            f"applied_version={ctx.state.data.get('applied_version')}",
        ]
        for c, rec in sorted(ctx.state.data["components"].items()):
            lines.append(f"component {c} version {rec.get('version')}")
            for u in list(rec.get("units", [])) + list(rec.get("instances", [])):
                res = ctx.runner.run(
                    ["journalctl", "-u", u, "-n", "100", "--no-pager", "-o", "cat"], timeout=30
                )
                lines.append(f"--- {u} (rc={res.rc})")
                lines.append(res.stdout[-16000:])
        text = scrub("\n".join(lines))[: 256 * 1024]
        d = ctx.paths.agent_state / "diagnostics"
        ctx.fs.mkdir(d, 0o700)
        ctx.fs.write(d / f"{action_id}.txt", text, 0o600)
        ctx.state.event(
            "info",
            f"diagnostics collected in /var/lib/exp/agent/diagnostics/{action_id}.txt ({len(text)} bytes)",
        )
