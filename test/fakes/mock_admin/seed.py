"""Deterministic seed data for mock_admin (WP-5 manager UI development).

``build_world(now)`` returns plain dicts shaped like the admin API objects (shared/openapi/admin.yaml). Keys
starting with ``_`` are internal (profiles, last-seen epoch...) and are stripped before anything is served.
Everything is a pure function of ``now`` (shape) and fixed seeds (values), so two runs at the same
instant produce identical data. Time series are not stored: they are computed on demand from per-entity
profiles, which gives the "48 h of 5-minute and 30 d of 1-hour" series the fleet UI needs at any range.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "shared" / "python"))
from exp_common import ids as exp_ids  # noqa: E402

import fakes_common as fc  # noqa: E402

OWNER_EMAIL = "owner@example.com"
ORG_NAME = "HPE Event NOC"
MANAGER_HOST = "exp-control.harnessed.cloud"

RANGES = {"1h": (300, 12), "6h": (300, 72), "24h": (300, 288), "7d": (3600, 168), "30d": (3600, 720)}
HOST_KEYS = ("cpu_pct", "mem_pct", "disk_pct", "load1", "net_rx_pps", "net_tx_pps", "net_rx_bps",
             "net_tx_bps", "disk_write_kbps")
COMPONENT_KEYS = {
    "probe": ("measurements_per_min", "fail_per_min", "push_lag_s", "spool_depth", "cpu_pct", "rss_mb"),
    "collector": ("ingest_records_per_s", "rejects_per_min", "vm_lag_s", "probes_reporting", "cpu_pct", "rss_mb"),
    "dashboard": ("sessions_active", "cpu_pct", "rss_mb"),
    "runner": ("drills_active", "correlations_per_hour", "evidence_lag_s_p95", "syslog_lines_per_s",
               "syslog_dropped_per_min", "cpu_pct", "rss_mb"),
    "speedtest": ("tests_per_hour", "active_tests", "queue_depth", "internet_leg_paused", "local_leg_gbps_p95",
                  "rejected_per_hour", "cpu_pct", "rss_mb"),
}
PCT_KEYS = {"cpu_pct", "mem_pct", "disk_pct"}
# CR-wp5-fleet-api-gaps item 5: per-test measurements per minute (test names of 01-contracts section 3), chartable
# for probes on request (not part of the default key list of a metrics response).
BY_TEST_NAMES = ("gateway", "dhcp_hb", "dns_hb", "trace", "ping", "dhcp", "dns", "app", "throughput", "path",
                 "wifi_hb", "wifi_join", "target_access", "probe_self")
PROBE_BY_TEST_KEYS = tuple(f"by_test_{n}" for n in BY_TEST_NAMES)
# CR-wp5-fleet-api-gaps item 3: per-interface history (5-minute buckets, 48 h).
IFACE_RANGES = {"1h": (300, 12), "6h": (300, 72), "24h": (300, 288), "48h": (300, 576)}
IFACE_KEYS = ("rx_pps", "tx_pps", "rx_bps", "tx_bps", "errors", "drops")


def iso(sec: float) -> str:
    return fc.iso_from_epoch(sec)


def fingerprint(seed: str) -> str:
    h = hashlib.sha256(f"fixture:{seed}".encode()).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


def sha256_of(seed: str) -> str:
    return hashlib.sha256(f"fixture:{seed}".encode()).hexdigest()


# ---------------------------------------------------------------------------------------- series

def _noise(seed: str, bucket: int) -> float:
    h = hashlib.sha256(f"{seed}:{bucket}".encode()).digest()
    return int.from_bytes(h[:4], "big") / 2**31 - 1.0   # [-1, 1)


def metric_value(entity: str, key: str, profile: dict[str, tuple[float, float, float]], t: float) -> float:
    """Deterministic value of `key` at epoch second `t`: base + daily swing + noise (clamped)."""
    base, amp, noise = profile.get(key, (0.0, 0.0, 0.0))
    daily = math.sin(2 * math.pi * ((t % 86400) / 86400.0) - 1.0)
    v = base + amp * daily + noise * _noise(f"{entity}:{key}", int(t // 300))
    if key in PCT_KEYS:
        v = min(100.0, max(0.0, v))
    return round(max(0.0, v), 2)


def series_points(entity: str, key: str, profile: dict[str, tuple[float, float, float]], range_: str,
                  as_of: float, until: float | None) -> list[dict[str, Any]]:
    """MetricPoints for `range_`; buckets after `until` (last_seen of a stale/offline host) are null."""
    step, n = RANGES[range_]
    end = int(as_of // step) * step
    pts = []
    for i in range(n):
        t = end - (n - 1 - i) * step
        if until is not None and t > until:
            pts.append({"t": t, "avg": None, "max": None})
            continue
        avg = metric_value(entity, key, profile, t + step / 2)
        spread = abs(_noise(f"{entity}:{key}:max", t // step)) * (profile.get(key, (0, 0, 0))[2] * 0.6 + 0.01)
        mx = min(100.0, avg + spread) if key in PCT_KEYS else avg + spread
        pts.append({"t": t, "avg": avg, "max": round(max(mx, avg), 2)})
    return pts


def iface_profile(host_id: str, iface: str, mgmt: bool, role: str) -> dict[str, tuple[float, float, float]]:
    """Per-interface profile: the management interface follows the host `net_*` figures; others are quieter and the
    interface name decides whether it shows a few errors / drops (for the error charts)."""
    host = host_profile(role)
    scale = 1.0 if mgmt else 0.35
    lossy = int(hashlib.sha256(f"lossy:{host_id}:{iface}".encode()).hexdigest()[:2], 16) % 4 == 0
    return {"rx_pps": tuple(v * scale for v in host["net_rx_pps"]), "tx_pps": tuple(v * scale for v in host["net_tx_pps"]),
            "rx_bps": tuple(v * scale for v in host["net_rx_bps"]), "tx_bps": tuple(v * scale for v in host["net_tx_bps"]),
            "errors": (0.6, 0.4, 0.8) if lossy else (0.0, 0.0, 0.0),
            "drops": (1.2, 0.8, 1.5) if lossy else (0.0, 0.0, 0.0)}  # type: ignore[dict-item]


def iface_series(entity: str, key: str, profile: dict[str, tuple[float, float, float]], range_: str,
                 as_of: float, until: float | None) -> list[dict[str, Any]]:
    """Like series_points but over IFACE_RANGES and with a null max (interface roll-ups keep averages only)."""
    step, n = IFACE_RANGES[range_]
    end = int(as_of // step) * step
    pts = []
    for i in range(n):
        t = end - (n - 1 - i) * step
        if until is not None and t > until:
            continue          # buckets without samples are absent (the real API never returns null points here)
        pts.append({"t": t, "avg": metric_value(entity, key, profile, t + step / 2), "max": None})
    return pts


def host_profile(role: str, hot: str | None = None) -> dict[str, tuple[float, float, float]]:
    """(base, daily amplitude, noise) per host key. `hot` pushes one resource over its issue threshold."""
    cpu = {"collector": 35.0, "probe": 12.0, "runner": 8.0}.get(role, 10.0)
    p = {"cpu_pct": (cpu, cpu * 0.35, 4.0), "mem_pct": (28.0 if role != "collector" else 45.0, 3.0, 1.5),
         "disk_pct": (22.0, 0.5, 0.2), "load1": (cpu / 30.0, 0.2, 0.1),
         "net_rx_pps": (900.0 if role == "collector" else 150.0, 80.0, 25.0),
         "net_tx_pps": (600.0 if role == "collector" else 120.0, 60.0, 20.0),
         "net_rx_bps": (4.5e6 if role == "collector" else 3.4e5, 4e5, 6e4),
         "net_tx_bps": (2.1e6 if role == "collector" else 1.2e5, 2e5, 4e4),
         "disk_write_kbps": (340.0, 90.0, 40.0)}
    if hot == "disk":
        p["disk_pct"] = (88.5, 0.3, 0.2)
    elif hot == "mem":
        p["mem_pct"] = (92.5, 2.0, 1.0)
    elif hot == "cpu":
        p["cpu_pct"] = (93.0, 3.0, 2.0)
    return p


def component_profile(ctype: str, bad: bool = False) -> dict[str, tuple[float, float, float]]:
    p: dict[str, tuple[float, float, float]] = {"cpu_pct": (6.0, 2.0, 1.5), "rss_mb": (96.0, 4.0, 3.0)}
    if ctype == "probe":
        p.update(measurements_per_min=(140.0, 10.0, 6.0), fail_per_min=(0.5, 0.3, 0.4),
                 push_lag_s=(0.6, 0.2, 0.2), spool_depth=(0.0, 0.0, 0.0))
        p.update(by_test_gateway=(12.0, 0.0, 0.0), by_test_dhcp_hb=(6.0, 0.0, 0.0), by_test_dns_hb=(12.0, 0.0, 0.0),
                 by_test_trace=(6.0, 0.0, 0.0), by_test_ping=(12.0, 0.0, 0.0), by_test_wifi_hb=(6.0, 0.0, 0.0),
                 by_test_app=(2.0, 1.0, 0.5), by_test_dns=(0.5, 0.3, 0.2), by_test_path=(0.2, 0.1, 0.1),
                 by_test_probe_self=(1.0, 0.0, 0.0))
        if bad:
            p.update(fail_per_min=(12.0, 3.0, 2.0), push_lag_s=(150.0, 20.0, 30.0), spool_depth=(2400.0, 200.0, 100.0))
    elif ctype == "collector":
        p.update(ingest_records_per_s=(305.0, 40.0, 12.0), rejects_per_min=(0.2, 0.1, 0.3),
                 vm_lag_s=(0.4, 0.1, 0.2), probes_reporting=(6.0, 0.0, 0.0), cpu_pct=(30.0, 8.0, 3.0),
                 rss_mb=(410.0, 20.0, 10.0))
    elif ctype == "dashboard":
        p.update(sessions_active=(3.0, 2.0, 1.0))
    elif ctype == "runner":
        p.update(drills_active=(0.0, 0.0, 0.0), correlations_per_hour=(58.0, 20.0, 6.0), evidence_lag_s_p95=(9.0, 3.0, 2.0),
                 syslog_lines_per_s=(75.0, 30.0, 8.0), syslog_dropped_per_min=(0.0, 0.0, 0.0))
    elif ctype == "speedtest":
        p.update(tests_per_hour=(64.0, 40.0, 8.0), active_tests=(2.0, 2.0, 1.0), queue_depth=(0.0, 0.0, 0.0),
                 internet_leg_paused=(0.0, 0.0, 0.0), local_leg_gbps_p95=(1.4, 0.6, 0.2), rejected_per_hour=(1.0, 1.0, 0.5))
    return p


# ------------------------------------------------------------------------------------------- hosts

SITES = [
    {"site": "hall-b", "name": "Hall B", "timezone": "America/Chicago", "subnet": "10.32.98", "release": "0.1.1"},
    {"site": "hall-c", "name": "Hall C", "timezone": "America/Chicago", "subnet": "10.33.98", "release": "0.1.0"},
    {"site": "keynote", "name": "Keynote Arena", "timezone": "America/Chicago", "subnet": "10.34.98", "release": "0.1.1"},
]

# (name, site, shapes, state, last-octet, extras)
HOST_PLAN: list[tuple[str, str, list[str], str, int, dict[str, Any]]] = [
    ("hb-col-01", "hall-b", ["collector", "dashboard"], "enrolled", 25, {"hot": "disk"}),
    *[(f"hb-probe-{i:02d}", "hall-b", ["probe"],
       {6: "stale", 8: "offline"}.get(i, "enrolled"), 30 + i,
       {"bad": i == 5, "drift": i == 4, "runway": i == 2}) for i in range(1, 9)],
    # M6 all-in-one box: runner + speedtest (+ its routed interface eno2) on one host
    ("hb-run-01", "hall-b", ["runner", "speedtest"], "enrolled", 40, {}),
    ("hc-col-01", "hall-c", ["collector"], "enrolled", 25, {"hot": "mem"}),
    ("hc-dash-01", "hall-c", ["dashboard"], "enrolled", 30, {}),
    *[(f"hc-probe-{i:02d}", "hall-c", ["probe"],
       {4: "stale", 5: "offline", 6: "pending"}.get(i, "enrolled"), 30 + i, {"bad": i == 2}) for i in range(1, 7)],
    ("kn-col-01", "keynote", ["collector", "dashboard"], "enrolled", 25, {"hot": "cpu"}),
    *[(f"kn-probe-{i:02d}", "keynote", ["probe"],
       {3: "stale", 5: "pending"}.get(i, "enrolled"), 30 + i, {}) for i in range(1, 6)],
]


def make_facts(name: str, ip: str, probe_ports: int, role: str) -> dict[str, Any]:
    ifaces: list[dict[str, Any]] = [{
        "name": "eno1", "mac": _mac(name, 0), "state": "up", "speed_mbps": 1000, "driver": "tg3",
        "addrs": [f"{ip}/23"], "default_route": True, "in_use_by": "mgmt"}]
    for i in range(probe_ports):
        ifaces.append({"name": f"enp10s0f{i}", "mac": _mac(name, i + 1), "state": "up" if i < probe_ports - 1 else "down",
                       "speed_mbps": 1000 if i < probe_ports - 1 else None, "driver": "igb", "addrs": [],
                       "default_route": False, "in_use_by": "none"})
    return {"hostname": name, "machine_id": hashlib.sha256(name.encode()).hexdigest()[:32],
            "os": {"id": "ubuntu", "version": "24.04"}, "kernel": "6.8.0-45-generic", "arch": "amd64",
            "cpus": 8 if role == "collector" else 4, "mem_mb": 32000 if role == "collector" else 8000,
            "disk_free_mb": 400000, "python": "3.12.3",
            "time": {"synced": True, "source": "systemd-timesyncd", "offset_ms": 1.2}, "interfaces": ifaces}


def _mac(name: str, i: int) -> str:
    h = hashlib.sha256(f"{name}:{i}".encode()).digest()
    return "18:66:da:" + ":".join(f"{b:02x}" for b in h[:3])


def build_world(now: float) -> dict[str, Any]:
    day = 86400.0
    world: dict[str, Any] = {"now": now, "org": {"id": "default", "name": ORG_NAME}}
    # --- sites
    sites: dict[str, dict[str, Any]] = {}
    for s in SITES:
        sites[s["site"]] = {
            "site": s["site"], "name": s["name"], "timezone": s["timezone"], "edge_label": "EC",
            "release_version": s["release"], "canary_host_id": None, "canary_state": None,
            "retention": {"metrics_days": 30, "records_days": 7},
            "created_at": iso(now - 20 * day), "updated_at": iso(now - 2 * day), "_subnet": s["subnet"]}
    world["sites"] = sites
    # --- hosts + components
    hosts: dict[str, dict[str, Any]] = {}
    comps: dict[str, dict[str, Any]] = {}
    reports: dict[str, dict[str, Any]] = {}
    col_by_site: dict[str, dict[str, Any]] = {}
    probe_ids_by_site: dict[str, list[str]] = {s: [] for s in sites}
    plan = [(fc.det_id("h_", f"host:{p[0]}"), idx, *p) for idx, p in enumerate(HOST_PLAN)]
    for hid, idx, name, site, shapes, state, octet, extra in plan:
        sub = sites[site]["_subnet"]
        ip = f"{sub}.{octet}"
        role = "collector" if "collector" in shapes else shapes[0]
        online = state in ("enrolled", "stale", "offline")
        last_seen = None
        if state == "enrolled":
            last_seen = now - 20 - (idx % 5) * 7
        elif state == "stale":
            last_seen = now - 11 * 60
        elif state == "offline":
            last_seen = now - 3 * 3600
        site_rel = sites[site]["release_version"]
        agent_ver = "0.1.0" if extra.get("drift") else site_rel
        desired_v = 40 + idx if online else None
        applied_v = (desired_v - 1) if (extra.get("drift") and desired_v) else desired_v
        facts = make_facts(name, ip, 4 if role == "probe" else 0, role) if online else None
        if facts is not None and "speedtest" in shapes:
            facts["interfaces"].append({"name": "eno2", "mac": _mac(name, 9), "state": "up", "speed_mbps": 10000, "driver": "ixgbe",
                                        "addrs": ["10.0.0.9/24"], "default_route": False, "in_use_by": "none"})
        host = {
            "host_id": hid, "name": name, "site": site, "shapes": list(shapes), "state": state,
            "mgmt_ip": ip if online else None, "facts": facts,
            "last_seen": iso(last_seen) if last_seen else None,
            "agent_version": agent_ver if online else None,
            "desired_version": desired_v, "applied_version": applied_v,
            "created_at": iso(now - 18 * day + idx * 3600), "updated_at": iso(last_seen or now - 3600),
            "_last_seen": last_seen, "_profile": host_profile(role, extra.get("hot")),
            "_role": role, "_extra": extra}
        hosts[hid] = host
    world["hosts"] = hosts
    # --- components
    cmp_seq = 0
    for hid, _idx, name, site, shapes, _state, _octet, extra in plan:
        host = hosts[hid]
        for shape in shapes:
            cmp_seq += 1
            cid_slug = _component_slug(shape, name, site)
            cid = fc.det_id("cmp_", f"cmp:{shape}:{cid_slug}")
            health = _component_health(host, shape, extra)
            comp = {
                "component_id": cid, "host_id": hid, "type": shape, "id": cid_slug, "config": {}, "rendered_config": None,
                "enabled": True, "health": health, "version": host["agent_version"] if host["state"] != "pending" else None,
                "facts": {}, "created_at": iso(now - 17 * day + cmp_seq * 600), "updated_at": iso(now - day),
                "_profile": component_profile(shape, bool(extra.get("bad")) and shape == "probe"),
                "_rotated_at": None, "_detail": _detail_of(shape, health)}
            comps[cid] = comp
            if shape == "collector":
                col_by_site[site] = comp
    world["components"] = comps
    for site in sites:
        probe_ids_by_site[site] = [c["id"] for c in comps.values() if c["type"] == "probe"
                                   and hosts[c["host_id"]]["site"] == site]
    # configs need the collector of the site
    for comp in comps.values():
        host = hosts[comp["host_id"]]
        site = host["site"]
        col = col_by_site.get(site)
        comp["config"] = _config_for(comp, host, col, probe_ids_by_site[site], comps, hosts)
        comp["rendered_config"] = copy.deepcopy(comp["config"]) if host["state"] != "pending" else None
        if comp["type"] == "collector":
            comp["facts"] = {"tls_fingerprint_sha256": fingerprint(comp["id"]), "listen": f"{host['mgmt_ip']}:8443"}
        elif comp["type"] == "dashboard":
            comp["facts"] = {"url": f"https://{host['mgmt_ip']}", "listen": f"{host['mgmt_ip']}:443"}
    # port usage in host facts
    for comp in comps.values():
        if comp["type"] == "probe":
            _apply_port_usage(hosts[comp["host_id"]], comp)
    # --- status reports
    for host in hosts.values():
        if host["state"] in ("enrolled", "stale", "offline"):
            reports[host["host_id"]] = make_report(host, [c for c in comps.values() if c["host_id"] == host["host_id"]],
                                                   host["_last_seen"] or now)
    world["reports"] = reports
    world["col_by_site"] = {s: c["component_id"] for s, c in col_by_site.items()}
    _seed_rest(world, now)
    return world


def _component_slug(shape: str, hostname: str, site: str) -> str:
    if shape == "probe":
        return "probe-" + hostname.split("-")[0] + hostname.split("-")[-1]
    if shape == "collector":
        return "col-" + site.replace("-", "")
    if shape == "dashboard":
        return "dash-main" if site == "hall-b" else "dash-" + site.replace("-", "")
    if shape == "runner":
        return "run-" + site.replace("-", "")
    if shape == "speedtest":
        return "spd-" + site.replace("-", "")
    return f"{shape}-{site}"


def _component_health(host: dict[str, Any], shape: str, extra: dict[str, Any]) -> str:
    if host["state"] != "enrolled":
        return "unknown"
    if shape == "probe" and extra.get("bad"):
        return "fail" if host["name"] == "hb-probe-05" else "degraded"
    if shape == "collector" and extra.get("hot") == "mem":
        return "degraded"
    return "ok"


def _detail_of(shape: str, health: str) -> str:
    if health == "ok" or health == "unknown":
        return ""
    return {"probe": "dns failing on c01", "collector": "memory pressure; vm lag rising"}.get(shape, "unhealthy")


def _config_for(comp: dict[str, Any], host: dict[str, Any], col: dict[str, Any] | None, probes: list[str],
                comps: dict[str, dict[str, Any]], hosts: dict[str, dict[str, Any]]) -> dict[str, Any]:
    site = host["site"]
    col_host = hosts[col["host_id"]] if col else None
    col_url = f"https://{col_host['mgmt_ip']}:8443" if col_host else "https://10.32.98.25:8443"
    col_fp = fingerprint(col["id"]) if col else fingerprint("col-hallb")
    t = comp["type"]
    if t == "probe":
        cfg = fc.load_fixture("configs/probe.json")
        cfg.update(probe_id=comp["id"], site=site)
        cfg["collector"].update(url=col_url, tls_fingerprint_sha256=col_fp)
        cfg["drills"] = []
        cfg["ports"] = cfg["ports"][:1]
        cfg["ports"][0]["dhcp"]["hostname"] = f"exp-{site.replace('-', '')}-{comp['id'][-4:]}"[:63]
        return cfg
    if t == "collector":
        cfg = fc.load_fixture("configs/collector.json")
        dashes = [c["id"] for c in comps.values() if c["type"] == "dashboard" and hosts[c["host_id"]]["site"] == site]
        cfg.update(collector_id=comp["id"], site=site, listen=f"{host['mgmt_ip']}:8443",
                   dashboards=dashes or ["dash-main"],
                   probes=[{"probe_id": p, "site": site, "label": p.replace("probe-", "Probe ").upper()} for p in probes])
        cfg["alerts"]["timezone"] = "America/Chicago"
        return cfg
    if t == "dashboard":
        cfg = fc.load_fixture("configs/dashboard.json")
        cfg.update(dashboard_id=comp["id"], title=f"HPE EXP - {site}", url=f"https://{host['mgmt_ip']}")
        cfg["collectors"] = [{"collector_id": col["id"] if col else "col-hallb", "site": site, "url": col_url,
                              "tls_fingerprint_sha256": col_fp}]
        cfg["auth"]["sso"] = {"manager_url": f"https://{MANAGER_HOST}", "issuer": "exp-manager:default"}
        return cfg
    if t == "runner":
        cfg = fc.load_fixture("configs/runner.json")
        cfg.update(runner_id=comp["id"], site=site)
        cfg["collector"].update(url=col_url, tls_fingerprint_sha256=col_fp)
        cfg["drills"] = []
        if any(c["type"] == "speedtest" and c["host_id"] == comp["host_id"] for c in comps.values()):
            cfg["correlation"] = fc.load_fixture("configs/runner.correlation.json")["correlation"]
        return cfg
    if t == "speedtest":
        cfg = fc.load_fixture("configs/speedtest.json")
        cfg.update(speedtest_id=comp["id"], site=site)
        cfg["collector"].update(url=col_url, tls_fingerprint_sha256=col_fp)
        return cfg
    return {}


def _apply_port_usage(host: dict[str, Any], comp: dict[str, Any]) -> None:
    cfg = comp["config"]
    if not host.get("facts"):
        return
    ports = {p["iface"]: p["id"] for p in cfg.get("ports", [])}
    for iface in host["facts"]["interfaces"]:
        if iface["in_use_by"] != "mgmt":
            pid = ports.get(iface["name"])
            iface["in_use_by"] = f"probe:{pid}" if pid else "none"


# days_to_full per collector host (CR-wp5-fleet-api-gaps item 1): one under 7 days, one under 2, the rest healthy.
DAYS_TO_FULL = {"hb-col-01": 5.4, "kn-col-01": 1.6, "hc-col-01": 41.0}


def collector_metrics(host: dict[str, Any], comp: dict[str, Any], at: float) -> dict[str, Any]:
    """The full exp.health/1 collector metric set (01-contracts section 8.1), deterministic per component."""
    prof, cid = comp["_profile"], comp["component_id"]
    days = DAYS_TO_FULL.get(host["name"], 60.0)
    free_gb = round(days * 6.5, 1)
    return {
        "ingest_records_per_s": metric_value(cid, "ingest_records_per_s", prof, at),
        "ingest_rejected_per_min": metric_value(cid, "rejects_per_min", prof, at),
        "ingest_duplicates_per_min": 1.4, "ingest_bytes_per_s": 182000.0,
        "probes_total": 6, "probes_reporting": 6, "vm_up": 1, "vm_backlog_points": 0, "vm_series": 5200,
        "vm_storage_gb": 1.2, "records_db_gb": 0.4, "storage_free_gb": free_gb, "days_to_full": days,
        "sse_clients": 2, "open_incidents": 0, "webhook_failures_1h": 0, "rules_eval_ms_p95": 3.2,
        "probes": probe_rows(comp, at)}


def probe_rows(comp: dict[str, Any], at: float) -> list[dict[str, Any]]:
    """Per-probe rows of the collector's `probes[]` health metric (CR-wp5-fleet-api-gaps item 2): the probes of its
    configuration, one of them behind on its clock."""
    rows = []
    for i, p in enumerate(comp.get("config", {}).get("probes", [])[:500]):
        rows.append({"probe_id": p["probe_id"], "last_seen": iso(at - (3 + 4 * i)),
                     "records_per_min": round(120.0 + 6 * ((i * 7) % 5), 1),
                     "clock_offset_ms": 1450.0 if i == 2 else round(0.4 + 0.3 * i, 1)})
    return rows


def make_report(host: dict[str, Any], comps: list[dict[str, Any]], at: float) -> dict[str, Any]:
    prof = host["_profile"]
    r = fc.load_fixture("status/collector-host.json" if host["_role"] == "collector" else "status/probe-host.json")
    r["agent"].update(version=host["agent_version"], desired_version=host["desired_version"],
                      applied_version=host["applied_version"], last_poll=iso(at))
    r["facts"] = copy.deepcopy(host["facts"])
    m = r["metrics"]
    m["cpu"]["pct"] = metric_value(host["host_id"], "cpu_pct", prof, at)
    m["mem"]["pct"] = metric_value(host["host_id"], "mem_pct", prof, at)
    disk = metric_value(host["host_id"], "disk_pct", prof, at)
    for d in m["disk"]:
        d["pct"] = disk
        d["used_gb"] = round(d["total_gb"] * disk / 100.0, 1)
    m["net"][0].update(iface="eno1", rx_pps=metric_value(host["host_id"], "net_rx_pps", prof, at),
                       tx_pps=metric_value(host["host_id"], "net_tx_pps", prof, at),
                       rx_bps=metric_value(host["host_id"], "net_rx_bps", prof, at),
                       tx_bps=metric_value(host["host_id"], "net_tx_bps", prof, at))
    template = {c["type"]: c for c in r["components"]}
    out = []
    for c in comps:
        tpl = copy.deepcopy(template.get(c["type"]) or next(iter(template.values())))
        tpl.update(type=c["type"], id=c["id"], version=c["version"] or host["agent_version"], state="running",
                   health=c["health"], detail=c.get("_detail", ""), since=iso(at - 86400))
        if c["type"] == "collector":
            tpl["facts"] = dict(c["facts"])
            tpl["metrics"] = collector_metrics(host, c, at)
        elif c["type"] == "speedtest":
            tpl["facts"] = {"url": "http://speed.summit.example/", "tls_mode": "none"}
            tpl["metrics"] = {k: metric_value(c["component_id"], k, c["_profile"], at) for k in COMPONENT_KEYS["speedtest"][:6]}
        elif c["type"] == "runner":
            tpl["facts"] = {}
            tpl["metrics"] = {k: metric_value(c["component_id"], k, c["_profile"], at) for k in COMPONENT_KEYS["runner"][:5]}
        elif c["type"] == "probe":
            tpl["metrics"]["by_test_per_min"] = {t: round(metric_value(c["component_id"], f"by_test_{t}", c["_profile"], at))
                                                 for t in BY_TEST_NAMES if f"by_test_{t}" in c["_profile"]}
        else:
            tpl["metrics"], tpl["facts"] = {}, {}
        out.append(tpl)
    r["components"] = out
    r["reconcile"] = {"at": iso(at - 120), "result": "ok", "error": None, "duration_ms": 5400}
    r["events"] = [{"ts": iso(at - 120), "level": "info", "msg": f"reconciled desired v{host['desired_version']}"}]
    return r


# ------------------------------------------------------------------------------------------- rest

def _seed_rest(world: dict[str, Any], now: float) -> None:
    day, hour = 86400.0, 3600.0
    hosts, comps = world["hosts"], world["components"]
    by_name = {h["name"]: h for h in hosts.values()}

    def hid(name: str) -> str:
        return by_name[name]["host_id"]

    def cid_of(name: str, ctype: str) -> str | None:
        for c in comps.values():
            if c["host_id"] == hid(name) and c["type"] == ctype:
                return c["component_id"]
        return None

    # --- issues: (kind, severity, host, component type or None, opened_ago_s, resolved_ago_s|None, value, detail)
    spec = [
        ("host_stale", "warn", "hb-probe-06", None, 11 * 60, None, 660.0, "no status report for 11 min"),
        ("host_stale", "warn", "hc-probe-04", None, 14 * 60, None, 840.0, "no status report for 14 min"),
        ("host_stale", "warn", "kn-probe-03", None, 12 * 60, None, 720.0, "no status report for 12 min"),
        ("host_offline", "crit", "hb-probe-08", None, 3 * hour, None, 10800.0, "no status report for 3 h"),
        ("host_offline", "crit", "hc-probe-05", None, 5 * hour, None, 18000.0, "no status report for 5 h"),
        ("disk_high", "warn", "hb-col-01", None, 6 * hour, None, 88.5, "/var/lib/exp at 88.5 %"),
        ("storage_runway", "warn", "hb-probe-02", None, 2 * hour, None, 6.2, "disk full in about 6 days at current growth"),
        ("mem_low", "warn", "hc-col-01", None, 50 * 60, None, 7.5, "7.5 % memory available for 10 min"),
        ("cpu_high", "crit", "kn-col-01", None, 35 * 60, None, 93.0, "CPU 93 % average over 15 min"),
        ("clock", "warn", "hb-probe-03", None, 4 * hour, 3 * hour, 1450.0, "clock offset 1450 ms"),
        ("component_unhealthy", "crit", "hb-probe-05", "probe", 25 * 60, None, None, "probe-hb05 health fail: dns failing on c01"),
        ("component_unhealthy", "warn", "hc-probe-02", "probe", 40 * 60, None, None, "probe-hc02 health degraded"),
        ("crash_loop", "crit", "hb-probe-07", "probe", 9 * hour, 8 * hour, 5.0, "5 restarts in 15 min"),
        ("reconcile_failed", "warn", "hc-probe-03", None, 3 * hour, 2.5 * hour, None, "reconcile rolled_back: unit failed to start"),
        ("version_drift", "warn", "hb-probe-04", None, 25 * 60, None, 1.0, "applied v43 behind desired v44 for 25 min"),
        ("clock", "warn", "kn-probe-01", None, 90 * 60, None, 1800.0, "clock offset 1800 ms; chrony not synced"),
        ("probe_ports", "warn", "hb-probe-01", "probe", 5 * hour, 4 * hour, 1.0, "port c01 link down"),
        ("probe_push_lag", "crit", "hb-probe-05", "probe", 20 * 60, None, 150.0, "oldest unpushed record 150 s"),
        ("probe_spool", "warn", "hb-probe-05", "probe", 18 * 60, None, 62.0, "spool at 62 % of max"),
        ("probe_collector", "warn", "hc-probe-02", "probe", 41 * 60, None, None, "collector unreachable from probe-hc02"),
        ("collector_rejects", "warn", "hb-col-01", "collector", 7 * hour, 6 * hour, 12.0, "12 rejects in the last minute (identity_mismatch)"),
        ("collector_vm", "crit", "hc-col-01", "collector", 45 * 60, None, 95.0, "VictoriaMetrics lag 95 s"),
        ("collector_probes", "warn", "kn-col-01", "collector", 30 * 60, None, 4.0, "4 of 5 probes reporting"),
        ("dashboard_collectors", "warn", "hc-dash-01", "dashboard", 3 * hour, 2 * hour, 1.0, "collector col-hallc unreachable from dash-hallc"),
        ("iface_errors", "warn", "hb-col-01", None, 80 * 60, None, 0.4, "eno1 rx errors 0.4 % over 15 min"),
        ("disk_high", "crit", "hb-probe-03", None, 2 * day, 1.5 * day, 96.0, "/ at 96 %"),
    ]
    issues = []
    for i, (kind, sev, hname, ctype, opened_ago, resolved_ago, val, detail) in enumerate(spec):
        h = hosts[hid(hname)]
        issues.append({
            "issue_id": "iss_" + fc.det_id("", f"issue:{i}:{kind}:{hname}"), "kind": kind, "severity": sev,
            "host_id": h["host_id"], "component_id": cid_of(hname, ctype) if ctype else None,
            "component_type": ctype if ctype else None, "site": h["site"],
            "opened_at": iso(now - opened_ago), "resolved_at": iso(now - resolved_ago) if resolved_ago else None,
            "last_value": val, "detail": detail, "snoozed_until": None})
    issues[7]["snoozed_until"] = iso(now + 50 * 60)           # mem_low snoozed
    issues[24]["snoozed_until"] = "resolved"                   # iface_errors: snoozed until resolved
    world["issues"] = issues
    world["snoozes"] = {}
    for it in issues:
        if it["snoozed_until"]:
            world["snoozes"][it["issue_id"]] = {"issue_id": it["issue_id"], "kind": it["kind"], "host_id": it["host_id"],
                                                "until": it["snoozed_until"], "created_by": OWNER_EMAIL}
    # --- releases
    world["releases"] = [_release(v, now - age, sites) for v, age, sites in
                         (("0.1.0", 15 * day, ["hall-c"]), ("0.1.1", 3 * day, ["hall-b", "keynote"]))]
    world["github_catalog"] = {"0.1.0", "0.1.1", "0.2.0"}
    # --- dashboards users / noc tokens
    world["dash_users"] = {}
    world["noc_tokens"] = {}
    for c in comps.values():
        if c["type"] != "dashboard":
            continue
        did = c["id"]
        world["dash_users"][did] = [
            {"usr_id": fc.det_id("usr_", f"usr:{did}:admin"), "username": "admin", "role": "admin", "created_at": iso(now - 14 * day)},
            {"usr_id": fc.det_id("usr_", f"usr:{did}:noc-op"), "username": "noc-op", "role": "operator", "created_at": iso(now - 10 * day)},
            {"usr_id": fc.det_id("usr_", f"usr:{did}:viewer1"), "username": "viewer1", "role": "viewer", "created_at": iso(now - 9 * day)}]
        world["noc_tokens"][did] = [
            {"noc_id": fc.det_id("noc_", f"noc:{did}:wall"), "label": "NOC wall display", "role": "viewer",
             "expires_at": iso(now + 20 * day), "revoked_at": None, "created_at": iso(now - 5 * day)},
            {"noc_id": fc.det_id("noc_", f"noc:{did}:old"), "label": "Old kiosk", "role": "viewer",
             "expires_at": None, "revoked_at": iso(now - 2 * day), "created_at": iso(now - 12 * day)}]
    # --- settings
    world["settings"] = {
        "org_name": ORG_NAME, "drills_enabled": True, "drills_two_person": True,
        "default_retention": {"metrics_days": 30, "records_days": 7}, "release_channel": "stable",
        "owner": OWNER_EMAIL,
        "admins": [{"email": OWNER_EMAIL, "role": "owner", "disabled": False, "last_seen": iso(now - 60)},
                   {"email": "admin@example.com", "role": "admin", "disabled": False, "last_seen": iso(now - 3 * hour)},
                   {"email": "operator@example.com", "role": "operator", "disabled": False, "last_seen": iso(now - day)},
                   {"email": "viewer@example.com", "role": "viewer", "disabled": False, "last_seen": None},
                   {"email": "former@example.com", "role": "admin", "disabled": True, "last_seen": iso(now - 9 * day)}],
        "updated_at": iso(now - 2 * day)}
    world["thresholds"] = {
        "disk_high": {"warn_pct": 85, "crit_pct": 95}, "storage_runway": {"warn_days": 7, "crit_days": 2},
        "mem_low": {"available_pct": 10, "for_min": 10}, "cpu_high": {"pct": 90, "avg_min": 15},
        "probe_push_lag": {"warn_s": 120, "crit_s": 600}, "probe_spool": {"pct": 50},
        "crash_loop": {"restarts": 3, "window_min": 15}, "version_drift": {"minutes": 10},
        "clock": {"offset_ms": 1000}, "iface_errors": {"pct": 0.1, "window_min": 15}}
    world["alerts"] = {}
    for s in world["sites"]:
        world["alerts"][s] = {
            "config": {"enabled": True, "board_url": None, "timezone": "America/Chicago", "voice": "sysadmin",
                       "hold_down_s": 20, "hold_back_s": 60, "reopen_s": 300, "calm_s": 600},
            "webhooks": [{"id": "wh_1", "format": "slack", "_url": "https://hooks.example.invalid/services/FIXTURE",
                          "_updated": iso(now - 6 * day)}]}
    # --- M6 speedtest settings (admin.yaml tag speedtest): intent only; hall-b is configured, the others show defaults
    st = fc.load_fixture("configs/speedtest.json")
    keep = ("zones", "zone_labels", "branding", "display", "targets", "limits", "internet_leg", "serve", "tls", "dns_leg",
            "path", "privacy", "core_guard")
    st_settings = {k: copy.deepcopy(st[k]) for k in keep}
    st_settings["branding"].pop("logo_artifact", None)
    st_settings["internet_leg"].pop("paused", None)
    world["speedtest"] = {"hall-b": {"settings": st_settings, "consent": {"text": st["consent"]["text"], "version": 3}, "paused": False,
                                      "logo": None, "updated_at": iso(now - 3 * day)}}
    world["speedtest_history"] = {"hall-b": [
        {"version": 1, "text": "We measure your speed. No name or email is collected.", "changed_by": OWNER_EMAIL, "created_at": iso(now - 9 * day)},
        {"version": 2, "text": "We measure your speed and look at this device's Wi-Fi metadata to diagnose it.",
         "changed_by": "admin@example.com", "created_at": iso(now - 6 * day)},
        {"version": 3, "text": st["consent"]["text"], "changed_by": "admin@example.com", "created_at": iso(now - 3 * day)}]}
    world["speedtest_tls"] = {}
    world["device_key"] = {"set": True, "updated_at": iso(now - 5 * day), "version": 1}
    world["platform_webhook"] = {"format": "slack", "_url": "https://hooks.example.invalid/services/PLATFORM",
                                 "_updated": iso(now - 4 * day)}
    world["integrations"] = {
        "ec": {"kind": "ec", "config": {"orchestrator_url": "https://orch.example.invalid", "poll_interval_s": 60},
               "credentials": {"set": True, "updated_at": iso(now - 7 * day)}, "allowlist": [
                   {"nePk": "1.NE", "interfaces": ["wan0"], "vrrp_groups": [101]}], "updated_at": iso(now - 7 * day)},
        "mist": {"kind": "mist", "config": {"org_id": "mist-org-1", "site_ids": ["mist-site-1"]},
                 "credentials": {"set": False, "updated_at": None}, "allowlist": [], "updated_at": None},
        "central": {"kind": "central", "config": {"api_base": "https://us1.api.central.arubanetworks.com"},
                    "credentials": {"set": True, "updated_at": iso(now - 2 * day)}, "allowlist": [],
                    "updated_at": iso(now - 2 * day)}}
    # --- ops board (GET /ops/devices): Mist is not connected (no token), Central reports counts
    world["ops_devices"] = {"central": {"total": 212, "online": 205, "offline": 7,
                                        "by_type": {"ap": {"total": 180, "online": 175}, "switch": {"total": 28, "online": 27},
                                                    "gateway": {"total": 4, "online": 3}},
                                        "counts_at": iso(now - 40),
                                        # the 7 offline devices, longest down first (names / sites only, as the Worker stores them)
                                        "down": [
                                            {"name": "gw-hall-b-02", "type": "gateway", "site": "Hall B", "since": iso(now - 3 * 3600 - 600)},
                                            {"name": "ap-hall-b-117", "type": "ap", "site": "Hall B", "since": iso(now - 2 * 3600)},
                                            {"name": "ap-foyer-03", "type": "ap", "site": "Foyer", "since": iso(now - 47 * 60)},
                                            {"name": "sw-stage-left", "type": "switch", "site": "Main stage", "since": iso(now - 21 * 60)},
                                            {"name": "ap-hall-b-122", "type": "ap", "site": "Hall B", "since": iso(now - 9 * 60)},
                                            {"name": None, "type": "ap", "site": None, "since": iso(now - 5 * 60)},
                                            {"name": "ap-press-room", "type": "ap", "site": "Press centre", "since": iso(now - 2 * 60)}]}}
    # --- drills
    d_done = fc.det_id("drl_", "drill:dns-block")
    d_pend = fc.det_id("drl_", "drill:wan-down")
    run_done = fc.det_id("run_", "run:dns-block:1")
    world["drills"] = [
        {"drl_id": d_done, "name": "DNS block hall B", "type": "local.dns_block", "site": "hall-b",
         "params": {"port": "c01"}, "duration_s": 120,
         "expectation": {"line": "dns", "state": "fail", "where": "dns", "within_s": 60},
         "schedule": {"mode": "once", "start_at": iso(now - 2 * day), "every_s": None}, "state": "done",
         "created_by": OWNER_EMAIL, "approved_by": "admin@example.com", "last_run_id": run_done,
         "created_at": iso(now - 3 * day), "updated_at": iso(now - 2 * day)},
        {"drl_id": d_pend, "name": "EC WAN down keynote", "type": "ec.wan_down", "site": "keynote",
         "params": {"nePk": "1.NE", "interface": "wan0"}, "duration_s": 180,
         "expectation": {"line": "internet", "state": "fail", "within_s": 90},
         "schedule": {"mode": "once", "start_at": None, "every_s": None}, "state": "pending_approval",
         "created_by": "operator@example.com", "approved_by": None, "last_run_id": None,
         "created_at": iso(now - 3 * hour), "updated_at": iso(now - 3 * hour)}]
    world["runs"] = {run_done: {
        "run_id": run_done, "drl_id": d_done, "state": "done", "start": iso(now - 2 * day),
        "until": iso(now - 2 * day + 120), "abort_requested": False, "reason": None,
        "report": {"result": "pass", "observed": {"ttd_s": 14.0, "ttr_s": 22.0, "lines_impacted": ["dns"]}}}}
    # --- audit
    actions = [("site.create", "site:hall-b"), ("site.create", "site:hall-c"), ("site.create", "site:keynote"),
               ("host.create", "host:hb-col-01"), ("component.create", "component:col-hallb"),
               ("release.import", "release:0.1.0"), ("release.import", "release:0.1.1"),
               ("site.release", "site:hall-b"), ("settings.update", "settings"), ("alerts.update", "site:hall-b"),
               ("host.enrol", "host:hb-probe-01"), ("noc_token.create", "dashboard:dash-main"),
               ("dashboard_user.create", "dashboard:dash-main"), ("drill.create", "drill:dns-block"),
               ("drill.approve", "drill:dns-block"), ("issue.snooze", "issue:mem_low")]
    audit = []
    for i in range(48):
        action, resource = actions[i % len(actions)]
        audit.append({"evt_id": fc.det_id("evt_", f"audit:{i}"), "ts": iso(now - (48 - i) * 2.5 * hour), "actor":
                      OWNER_EMAIL if i % 3 else "admin@example.com", "action": action, "resource": resource,
                      "details": {}, "ip": "203.0.113.10"})
    world["audit"] = audit


def _release(version: str, created: float, sites: list[str]) -> dict[str, Any]:
    arts = []
    for comp in ("agent", "probe", "collector", "dashboard", "runner"):
        for arch in (("amd64", "arm64") if comp == "collector" else ("noarch",)):
            name = f"exp-{comp}-{version}-{arch}.tar.gz"
            arts.append({"artifact_id": fc.det_id("art_", name), "name": name, "component": comp, "arch": arch,
                         "sha256": sha256_of(name), "size": 800000 + len(name)})
    return {"rel_id": fc.det_id("rel_", f"rel:{version}"), "version": version, "source": "github",
            "verified_at": iso(created + 60), "notes_url": f"https://github.com/example-org/exp/releases/tag/v{version}",
            "min_agent_version": "0.1.0", "created": iso(created), "artifacts": arts, "sites": sites}


def public(obj: dict[str, Any]) -> dict[str, Any]:
    """Deep copy without internal ``_`` keys."""
    def strip(x: Any) -> Any:
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if not k.startswith("_")}
        if isinstance(x, list):
            return [strip(i) for i in x]
        return x
    return strip(json.loads(json.dumps(obj, default=str)))


def new_facts_for(name: str, ip: str, shapes: list[str]) -> dict[str, Any]:
    role = "collector" if "collector" in shapes else (shapes[0] if shapes else "probe")
    return make_facts(name, ip, 4 if role == "probe" else 0, role)


def fake_token(kind: str = "expe") -> str:
    return exp_ids.new_token(kind)
