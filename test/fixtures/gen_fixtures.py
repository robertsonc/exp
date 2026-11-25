#!/usr/bin/env python3
"""Generate every JSON fixture and INDEX.json (deterministic; rerun is byte-identical).

Usage: gen_fixtures.py [OUTDIR]   (default: this directory)
The converted EXM outage is produced separately by convert_exm.py.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "shared", "python"))
from exp_common import speedtest as _st  # noqa: E402  (device_key / score reference implementation)
from fixture_util import fid, fingerprint, iso_to_ms, sha256_hex, token, ulid  # noqa: E402

PROBE, SITE = "probe-a1", "hall-b"
FP = fingerprint("collector-hallb")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
INDEX: dict[str, dict[str, str]] = {}


def put(path: str, doc: Any, schema: str, expected: str = "valid") -> None:
    full = os.path.join(OUT, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    INDEX[path] = {"schema": schema, "expected": expected}


# ---------------------------------------------------------------- measurements
_seq = [0]


def meas(test: str, outcome: str = "ok", ts: str = "2026-11-18T20:00:00.123Z", **kw: Any) -> dict:
    _seq[0] += 1
    d: dict[str, Any] = {"schema": "exp.measurement/1", "id": ulid(iso_to_ms(ts), "m%d" % _seq[0]), "ts": ts,
                         "probe": PROBE, "site": SITE, "test": test, "outcome": outcome}
    d.update(kw)
    d["agent_ver"] = "0.1.0"
    return d


def gen_measurements() -> dict[str, dict]:
    M: dict[str, dict] = {}
    T = lambda s: "2026-11-18T20:00:%02d.123Z" % s  # noqa: E731

    def add(name: str, doc: dict) -> None:
        M[name] = doc
        put("measurements/%s.json" % name, doc, "measurement.schema.json")

    gl = {"port": "c01", "iface": "enp10s0f0"}
    add("gateway.ok", meas("gateway", "ok", T(1), labels=gl, duration_ms=0.58,
                           metrics={"link_up": 1, "rtt_ms": 0.58, "loss_pct": 0, "carrier_changes": 2}, detail={"gateway_ip": "10.1.0.1", "gateway_mac": "00:00:5e:00:01:65"}))
    add("gateway.degraded", meas("gateway", "degraded", T(2), labels=gl, duration_ms=48.0,
                                 metrics={"link_up": 1, "rtt_ms": 48.0, "loss_pct": 20, "carrier_changes": 2}, detail={"gateway_ip": "10.1.0.1"}))
    add("gateway.fail", meas("gateway", "fail", T(3), labels=gl, metrics={"link_up": 1, "loss_pct": 100, "carrier_changes": 2},
                             detail={"gateway_ip": "10.1.0.1"}, error="no reply from 10.1.0.1"))
    add("gateway.error", meas("gateway", "error", T(4), labels=gl, error="namespace for port c01 is missing"))
    pl = {"port": "c01", "server": "10.1.0.2"}
    add("dhcp_hb.ok", meas("dhcp_hb", "ok", T(5), labels=pl, metrics={"offer_ms": 12.4, "offers": 1}, detail={"offered_ip": "10.1.0.31", "options": {"router": "10.1.0.1", "lease_time": 598}}))
    add("dhcp_hb.degraded", meas("dhcp_hb", "degraded", T(6), labels=pl, metrics={"offer_ms": 1000.55, "offers": 1}, detail={"offered_ip": "10.1.0.31"}))
    add("dhcp_hb.fail", meas("dhcp_hb", "fail", T(7), labels={"port": "c01", "server": "none"}, metrics={"offers": 0}, error="no DHCPOFFER within 3 s"))
    add("dhcp_hb.error", meas("dhcp_hb", "error", T(8), labels={"port": "c01", "server": "none"}, error="raw socket denied"))
    dl = {"port": "c01", "resolver": "8.8.8.8", "resolver_kind": "dhcp"}
    add("dns_hb.ok", meas("dns_hb", "ok", T(9), labels=dl, duration_ms=12.2, metrics={"rtt_ms": 12.2, "rcode": 0, "answers": 6, "ping_rtt_ms": 11.9}, detail={"name": "google.com"}))
    add("dns_hb.alternate", meas("dns_hb", "ok", T(10), labels=dict(dl, resolver="1.1.1.1", resolver_kind="alternate"), metrics={"rtt_ms": 9.8, "rcode": 0, "answers": 4}, detail={"name": "google.com"}))
    add("dns_hb.degraded", meas("dns_hb", "degraded", T(11), labels=dl, metrics={"rtt_ms": 1450.0, "rcode": 0, "answers": 1}, detail={"name": "apple.com"}))
    add("dns_hb.fail", meas("dns_hb", "fail", T(12), labels=dl, detail={"name": "google.com"}, error="no answer from 8.8.8.8 within 2 s"))
    add("dns_hb.error", meas("dns_hb", "error", T(13), labels=dl, error="port c01 has no lease (no resolver known)"))
    tl = {"port": "c01", "path": "test"}
    hops = [[1, "10.1.0.2", 0.4], [2, "10.1.0.1", 0.9], [3, None, None], [4, "8.8.8.8", 11.3]]
    add("trace.ok", meas("trace", "ok", T(14), labels=tl, metrics={"reached": 1, "hops": 4, "last_ttl": 4, "rtt_ms": 11.3}, detail={"hops": hops, "last_ip": "8.8.8.8", "target": "8.8.8.8"}))
    add("trace.degraded", meas("trace", "degraded", T(15), labels=tl, metrics={"reached": 1, "hops": 4, "last_ttl": 4, "rtt_ms": 260.0}, detail={"hops": hops, "last_ip": "8.8.8.8", "target": "8.8.8.8"}))
    add("trace.fail", meas("trace", "fail", T(16), labels=tl, metrics={"reached": 0, "hops": 1, "last_ttl": 1}, detail={"hops": [[1, "10.1.0.2", 302.7]], "last_ip": "10.1.0.2", "target": "8.8.8.8"},
                           error="no reply from 8.8.8.8; path stops after 10.1.0.2 (hop 1)"))
    add("trace.error", meas("trace", "error", T(17), labels=tl, error="ICMP socket unavailable"))
    add("trace.control", meas("trace", "ok", T(18), labels={"port": "c01", "path": "control"}, metrics={"reached": 1, "hops": 5, "last_ttl": 5, "rtt_ms": 14.0}, detail={"last_ip": "1.1.1.1", "target": "1.1.1.1"}))
    pg = {"port": "c01"}
    add("ping.ok", meas("ping", "ok", T(19), target="1.1.1.1", labels=pg, metrics={"rtt_ms": 10.2, "loss_pct": 0}))
    add("ping.degraded", meas("ping", "degraded", T(20), target="1.1.1.1", labels=pg, metrics={"rtt_ms": 90.0, "loss_pct": 30}))
    add("ping.fail", meas("ping", "fail", T(21), target="8.8.8.8", labels=pg, metrics={"loss_pct": 100}, error="100% loss"))
    add("ping.error", meas("ping", "error", T(22), target="8.8.8.8", labels=pg, error="ICMP socket unavailable"))
    sl = {"port": "c01", "server": "10.1.0.2"}
    add("dhcp.ok", meas("dhcp", "ok", T(23), labels=sl, duration_ms=45.0, metrics={"discover_offer_ms": 20.0, "request_ack_ms": 25.0, "total_ms": 45.0, "lease_s": 598, "offers": 1},
                        detail={"ip": "10.1.0.31", "router": "10.1.0.1", "dns": ["8.8.8.8"], "options": {"subnet_mask": "255.255.255.0"}}))
    add("dhcp.fail", meas("dhcp", "fail", T(24), labels={"port": "c01", "server": "none"}, metrics={"offers": 0}, error="no DHCPOFFER after 3 discovers"))
    add("dns.ok", meas("dns", "ok", T(25), labels={"port": "c01", "resolver": "8.8.8.8"}, target="www.google.com", metrics={"rtt_ms": 19.3, "rcode": 0, "answers": 6},
                       detail={"name": "www.google.com", "answers": ["142.250.80.100", "142.250.80.101"]}))
    add("dns.fail", meas("dns", "fail", T(26), labels={"port": "c01", "resolver": "8.8.8.8"}, target="www.google.com", metrics={"answers": 0}, detail={"name": "www.google.com"}, error="no answers (24 timeouts, 0 errors)"))
    al = {"port": "c01", "app": "google-search"}
    add("app.ok", meas("app", "ok", T(27), labels=al, duration_ms=210.0,
                       metrics={"dns_ms": 21.4, "connect_ms": 30.0, "tls_ms": 52.0, "ttfb_ms": 98.0, "total_ms": 210.0, "status_code": 200, "bytes": 18432, "apdex": 1.0},
                       detail={"url": "https://www.google.com/", "ip": "142.250.80.100", "tls_version": "TLSv1.3"}))
    add("app.degraded", meas("app", "degraded", T(28), labels=al, duration_ms=2400.0, metrics={"total_ms": 2400.0, "status_code": 200, "apdex": 0.5}, detail={"url": "https://www.google.com/"}))
    add("app.fail", meas("app", "fail", T(29), labels=al, metrics={"status_code": 0, "apdex": 0.0}, detail={"url": "https://www.google.com/"}, error="Resolving timed out after 10000 milliseconds"))
    add("throughput.ok", meas("throughput", "ok", T(30), labels={"port": "c01", "provider": "cloudflare"}, duration_ms=3500.0,
                              metrics={"down_mbps": 719.85, "up_mbps": 270.76, "latency_idle_ms": 40.6, "latency_loaded_ms": 31.9, "jitter_ms": 7.0, "retransmits": 0},
                              detail={"server": "162.159.140.220", "streams": 1}))
    add("throughput.error", meas("throughput", "error", T(31), labels={"port": "c01", "provider": "iperf3"}, error="iperf3 server s01 unreachable"))
    add("path.ok", meas("path", "ok", T(32), labels={"port": "c01", "peer": "s01", "proto": "udp"},
                        metrics={"rtt_ms": 1.2, "jitter_ms": 0.3, "loss_fwd_pct": 0.0, "loss_rev_pct": 0.0, "mos": 4.4, "pqi": 98.0, "experience": 4.5}, detail={"loss_pattern": "none", "dscp": 0}))
    add("path.degraded", meas("path", "degraded", T(33), labels={"port": "c01", "peer": "s01", "proto": "udp"},
                              metrics={"rtt_ms": 30.0, "jitter_ms": 12.0, "loss_fwd_pct": 2.0, "loss_rev_pct": 1.5, "mos": 3.2, "pqi": 60.0, "experience": 3.0}, detail={"loss_pattern": "burst", "dscp": 46}))
    wl = {"port": "w01", "ssid": "ACME_CORP", "band": "5"}
    add("wifi_hb.ok", meas("wifi_hb", "ok", T(34), labels=wl, metrics={"link_up": 1, "rssi_dbm": -52, "noise_dbm": -92, "snr_db": 40, "tx_rate_mbps": 243, "channel": 108, "gw_rtt_ms": 2.4},
                           detail={"bssid": "aa:bb:cc:00:11:22", "security": "wpa3-sae", "on_target": True}))
    add("wifi_hb.degraded", meas("wifi_hb", "degraded", T(35), labels=wl, metrics={"link_up": 1, "rssi_dbm": -78, "noise_dbm": -90, "snr_db": 12, "tx_rate_mbps": 24, "channel": 108, "gw_rtt_ms": 180.0},
                                 detail={"bssid": "aa:bb:cc:00:11:22", "security": "wpa3-sae", "on_target": True}))
    add("wifi_hb.fail", meas("wifi_hb", "fail", T(36), labels=wl, metrics={"link_up": 1, "rssi_dbm": -51, "noise_dbm": -90, "snr_db": 39, "tx_rate_mbps": 365, "channel": 108},
                             detail={"bssid": "aa:bb:cc:00:11:22", "on_target": False}, error="no reply from gateway 10.1.0.1 over Wi-Fi"))
    add("wifi_hb.error", meas("wifi_hb", "error", T(37), labels=wl, error="wpa_supplicant not running"))
    add("wifi_join.ok", meas("wifi_join", "ok", T(38), labels={"port": "w01", "ssid": "ACME_CORP"}, metrics={"assoc_ms": 120.0, "auth_ms": 45.0, "dhcp_ms": 210.0, "total_ms": 375.0},
                             detail={"bssid": "aa:bb:cc:00:11:22", "reason": "roam"}))
    add("target_access.ok", meas("target_access", "ok", T(39), labels={"port": "s01", "proto": "tcp"}, metrics={"requests": 120, "errors": 0, "p50_ms": 3.0},
                                 detail={"top_clients": [{"ip": "10.1.0.31", "n": 40}, {"ip": "10.1.0.32", "n": 22}]}))
    add("probe_self.ok", meas("probe_self", "ok", T(40), metrics={"spool_depth": 0, "spool_bytes": 0, "push_lag_s": 0.4, "clock_offset_ms": 1.1, "cpu_pct": 7.5, "rss_mb": 96, "dropped_total": 0},
                              detail={"ntp_synced": True}))
    add("ext_mist.ok", meas("ext_mist", "ok", T(41), labels={"kind": "ap_offline", "severity": "warn"}, metrics={"count": 1}, detail={"ap": "ap-12", "site_id": "mist-site-1"}))
    add("ext_ec.ok", meas("ext_ec", "ok", T(42), labels={"kind": "wan_down", "severity": "critical"}, metrics={"count": 1}, detail={"nePk": "1.NE", "interface": "wan0"}))
    drl = {"run": fid("run", "1"), "phase": "start", "type": "local.dns_block"}
    add("drill.ok", meas("drill", "ok", T(43), labels=drl, metrics={"ok": 1}, detail={"target": "c01", "params": {"port": "c01"}}))
    add("drill.failed", meas("drill", "fail", T(44), labels=dict(drl, phase="failed"), metrics={"ok": 0}, detail={"verification": {"expected": "dns blocked", "observed": "dns ok"}}, error="verification failed"))
    # optional-field coverage
    add("minimal.ok", {"schema": "exp.measurement/1", "id": ulid(iso_to_ms(T(45)), "min"), "ts": "2026-11-18T20:00:45Z", "probe": PROBE, "site": SITE, "test": "custom_test", "outcome": "ok"})
    return M


def gen_invalid_measurements(M: dict[str, dict]) -> None:
    base = M["gateway.ok"]

    def bad(name: str, mutate) -> None:
        d = copy.deepcopy(base)
        mutate(d)
        put("invalid/measurements/%s.json" % name, d, "measurement.schema.json", "invalid")

    def setlab(k: str, v: Any):
        return lambda d: d["labels"].__setitem__(k, v)

    for k in ("probe", "site", "outcome", "target", "__name"):
        bad("reserved-label-%s" % k.strip("_"), setlab(k, "x"))
    bad("naive-ts", lambda d: d.update(ts="2026-11-18T20:00:00.123"))
    bad("offset-ts", lambda d: d.update(ts="2026-11-18T22:00:00.123+02:00"))
    bad("lowercase-z-ts", lambda d: d.update(ts="2026-11-18t20:00:00.123z"))
    bad("slug-probe-uppercase", lambda d: d.update(probe="Probe-A1"))
    bad("slug-site-underscore", lambda d: d.update(site="hall_b"))
    bad("missing-id", lambda d: d.pop("id"))
    bad("missing-ts", lambda d: d.pop("ts"))
    bad("missing-probe", lambda d: d.pop("probe"))
    bad("bad-ulid-forbidden-letter", lambda d: d.update(id="01JDU" + "0" * 21))
    bad("bad-ulid-lowercase", lambda d: d.update(id=d["id"].lower()))
    bad("bad-ulid-short", lambda d: d.update(id=d["id"][:25]))
    bad("metrics-51", lambda d: d.update(metrics={"m%d" % i: float(i) for i in range(51)}))
    bad("metric-string-value", lambda d: d["metrics"].__setitem__("rtt_ms", "0.58"))
    bad("metric-name-dash", lambda d: d["metrics"].__setitem__("rtt-ms", 1.0))
    bad("metric-null-value", lambda d: d["metrics"].__setitem__("rtt_ms", None))
    bad("label-value-129", setlab("zone", "x" * 129))
    bad("label-value-control-char", setlab("zone", "a\nb"))
    bad("label-value-not-string", setlab("zone", 5))
    bad("labels-21", lambda d: d.update(labels={"l%d" % i: "v" for i in range(21)}))
    bad("target-257", lambda d: d.update(target="t" * 257))
    bad("error-513", lambda d: d.update(error="e" * 513))
    bad("detail-key-dash", lambda d: d.update(detail={"gateway-ip": "10.1.0.1"}))
    bad("detail-too-deep", lambda d: d.update(detail={"a": {"b": {"c": {"d": {"e": 1}}}}}))
    bad("detail-string-1025", lambda d: d.update(detail={"s": "x" * 1025}))
    bad("detail-string-control-char", lambda d: d.update(detail={"s": "a\x00b"}))
    bad("detail-array-257", lambda d: d.update(detail={"a": list(range(257))}))
    bad("detail-not-object", lambda d: d.update(detail=[1, 2]))
    bad("unknown-outcome", lambda d: d.update(outcome="pwned"))
    bad("test-not-ident", lambda d: d.update(test="../../etc/passwd"))
    bad("test-too-long", lambda d: d.update(test="t" * 65))
    bad("wrong-schema", lambda d: d.update(schema="exp.measurement/2"))
    bad("duration-string", lambda d: d.update(duration_ms="fast"))


# ---------------------------------------------------------------- configs
def collector_cfg() -> dict:
    return {"schema": "exp.collector.config/1", "collector_id": "col-hallb", "site": SITE, "listen": "10.32.98.25:8443",
            "probes": [{"probe_id": PROBE, "site": SITE, "label": "Hall B east"}], "dashboards": ["dash-main"],
            "retention": {"metrics_days": 30, "records_days": 7}, "vm": {"listen": "127.0.0.1:8428", "memory_allowed_pct": 40},
            "rules": {"edge_label": "EC", "lines": ["network", "dhcp", "dns", "internet", "apps", "wifi", "path"]},
            "alerts": {"enabled": True, "board_url": "https://10.32.98.30", "timezone": "America/Chicago", "voice": "sysadmin",
                       "hold_down_s": 20, "hold_back_s": 60, "reopen_s": 300, "calm_s": 600},
            "reflector": {"enabled": True, "port": 8862}, "iperf3": {"enabled": True, "port": 5201},
            "ingest": {"max_body_mb": 4, "max_records": 1000}}


def probe_cfg() -> dict:
    return {"schema": "exp.probe.config/1", "probe_id": PROBE, "site": SITE,
            "collector": {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": FP, "fallback": []},
            "mode": "netns", "mgmt_iface": "eno1",
            "ports": [{"id": "c01", "iface": "enp10s0f0", "role": "client", "vlan": None,
                       "dhcp": {"hostname": "exp-hallb-c01", "vendor_class": "exp-probe", "client_id": "mac"}},
                      {"id": "s01", "iface": "enp130s1f0", "role": "target", "address": "10.1.0.250/24", "gateway": "10.1.0.1",
                       "serve": {"http": True, "https": True, "icmp": True, "reflector": True, "iperf3": False}, "faults_allowed": True}],
            "heartbeat": {"interval_s": 10, "gateway": True, "dhcp": True, "dns": True,
                          "trace": {"target": "8.8.8.8", "pace_ms": 20, "max_hops": 30, "timeout_s": 2, "control_path": True},
                          "ping": ["1.1.1.1", "8.8.8.8"], "dns_names": ["google.com", "apple.com", "microsoft.com", "cloudflare.com"],
                          "alternate_resolver": "1.1.1.1"},
            "tests": {"dhcp": {"interval_s": 300, "offer_collect_s": 3.0},
                      "dns": {"interval_s": 300, "names": ["www.google.com", "teams.microsoft.com"]},
                      "app": {"interval_s": 300, "targets": [{"app": "google-search", "url": "https://www.google.com/", "apdex_t_ms": 500}]},
                      "throughput": {"interval_s": 600, "providers": ["cloudflare"], "iperf3": {"server": "s01", "duration_s": 10}},
                      "path": {"interval_s": 60, "peers": [{"peer": "s01", "address": "10.1.0.250", "port": 8862, "proto": ["udp", "tcp"], "duration_s": 10, "rate_kbps": 256}]},
                      "wifi": None},
            "spool": {"max_mb": 500, "max_days": 7}, "labels": {"zone": "floor-1"},
            "drills": [{"run_id": fid("run", "1"), "type": "local.dns_block", "params": {"port": "c01"},
                        "start": "2026-11-18T21:00:00.000Z", "until": "2026-11-18T21:02:00.000Z", "abort": False}]}


def dashboard_cfg() -> dict:
    return {"schema": "exp.dashboard.config/1", "dashboard_id": "dash-main", "title": "HPE EXP — Hall B", "url": "https://10.32.98.30",
            "listen": {"https": "0.0.0.0:443", "http_redirect": "0.0.0.0:80"},
            "collectors": [{"collector_id": "col-hallb", "site": SITE, "url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": FP}],
            "voice": "sysadmin", "timezone": "America/Chicago",
            "auth": {"sso": {"manager_url": "https://exp.example.com", "issuer": "exp-manager:default"}, "session_hours": 12, "local_users": True, "noc_tokens": True},
            "tls": {"mode": "self_signed"}}


def runner_cfg() -> dict:
    return {"schema": "exp.runner.config/1", "runner_id": "run-hallb", "site": SITE,
            "collector": {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": FP},
            "drills_enabled": True,
            "pullers": [{"source": "mist", "interval_s": 60, "site_ids": ["mist-site-1"]}, {"source": "ec", "interval_s": 60}],
            "allowlist": {"ec": [{"nePk": "1.NE", "interfaces": ["wan0"], "vrrp_groups": [101]}]},
            "drills": [{"run_id": fid("run", "2"), "type": "ec.wan_down", "params": {"nePk": "1.NE", "interface": "wan0"},
                        "start": "2026-11-18T21:00:00.000Z", "until": "2026-11-18T21:02:00.000Z", "abort": False}]}


def gen_configs() -> None:
    put("configs/probe.json", probe_cfg(), "probe.config.schema.json")
    host = {"schema": "exp.probe.config/1", "probe_id": "probe-vm1", "site": SITE, "collector": {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": FP, "fallback": ["https://10.32.98.26:8443"]},
            "mode": "host", "mgmt_iface": "ens160",
            "ports": [{"id": "c01", "iface": "ens192", "role": "client", "vlan": 120}],
            "heartbeat": {"interval_s": 10, "gateway": True, "dhcp": False, "dns": True, "ping": ["1.1.1.1"], "dns_names": ["google.com"], "alternate_resolver": "1.1.1.1"},
            "tests": {"dns": {"interval_s": 300, "names": ["www.google.com"]}}, "spool": {"max_mb": 100, "max_days": 3}}
    put("configs/probe.host-mode.json", host, "probe.config.schema.json")
    nullc = copy.deepcopy(probe_cfg())
    nullc["collector"] = None
    nullc["drills"] = []
    put("configs/probe.collector-null.json", nullc, "probe.config.schema.json")
    wifi = copy.deepcopy(probe_cfg())
    wifi["ports"].append({"id": "w01", "iface": "wlp3s0", "role": "wifi", "ssid": "ACME_CORP", "band": "5"})
    wifi["tests"]["wifi"] = {"interval_s": 300}
    put("configs/probe.wifi.json", wifi, "probe.config.schema.json")
    put("configs/collector.json", collector_cfg(), "collector.config.schema.json")
    put("configs/dashboard.json", dashboard_cfg(), "dashboard.config.schema.json")
    dprov = dashboard_cfg()
    dprov["tls"] = {"mode": "provided"}
    put("configs/dashboard.tls-provided.json", dprov, "dashboard.config.schema.json")
    put("configs/runner.json", runner_cfg(), "runner.config.schema.json")
    # CR-wp2-webhook-allowlist: alerts.webhook_allow (IP, CIDR, host name; max 16)
    cwa = collector_cfg()
    cwa["alerts"]["webhook_allow"] = ["10.32.98.40", "10.40.0.0/16", "Chat.Corp.Example"]
    put("configs/collector.webhook-allow.json", cwa, "collector.config.schema.json")
    # CR-wp1-test-options / CR-wp1-allow-shared: optional per-test knobs, allow_shared (host mode)
    pto = copy.deepcopy(host)
    pto["allow_shared"] = True
    pto["tests"].update({
        "dhcp": {"interval_s": 300, "offer_collect_s": 3.0, "thresholds": {"offer_ms": 800, "total_ms": 1200}, "allowed_servers": ["10.1.0.1"]},
        "dns": {"interval_s": 300, "names": ["www.google.com"], "thresholds": {"rtt_ms": 200}},
        "app": {"interval_s": 300, "thresholds": {"slow_factor": 3, "apdex_min": 0.9},
                "targets": [{"app": "captive-check", "url": "http://connectivitycheck.gstatic.com/generate_204", "apdex_t_ms": 500, "expect_status": 204, "expect_body": ""}]},
        "trace": {"thresholds": {"rtt_ms": 300}}, "ping": {"thresholds": {"rtt_ms": 300}}})
    put("configs/probe.test-options.json", pto, "probe.config.schema.json")

    def bad(name: str, base: dict, schema: str, mutate) -> None:
        d = copy.deepcopy(base)
        mutate(d)
        put("invalid/configs/%s.json" % name, d, schema, "invalid")

    P, C, D, R = probe_cfg(), collector_cfg(), dashboard_cfg(), runner_cfg()
    bad("collector-webhook-allow-too-many", C, "collector.config.schema.json", lambda d: d["alerts"].update(webhook_allow=["10.0.0.%d" % i for i in range(17)]))
    bad("collector-webhook-allow-bad-entry", C, "collector.config.schema.json", lambda d: d["alerts"].update(webhook_allow=["10.0.0.1; rm -rf /"]))
    bad("probe-apdex-min-over-1", P, "probe.config.schema.json", lambda d: d["tests"]["app"].update(thresholds={"apdex_min": 2}))
    bad("probe-allow-shared-not-bool", P, "probe.config.schema.json", lambda d: d.update(allow_shared="yes"))
    bad("probe-bad-mode", P, "probe.config.schema.json", lambda d: d.update(mode="bridge"))
    bad("probe-bad-port-role", P, "probe.config.schema.json", lambda d: d["ports"][0].update(role="monitor"))
    bad("probe-iface-traversal", P, "probe.config.schema.json", lambda d: d["ports"][0].update(iface="../../etc/passwd"))
    bad("probe-iface-too-long", P, "probe.config.schema.json", lambda d: d["ports"][0].update(iface="enp10s0f0abcdefgh"))
    bad("probe-collector-http", P, "probe.config.schema.json", lambda d: d["collector"].update(url="http://10.32.98.25:8443"))
    bad("probe-fingerprint-lowercase", P, "probe.config.schema.json", lambda d: d["collector"].update(tls_fingerprint_sha256=FP.lower()))
    bad("probe-collector-missing-pin", P, "probe.config.schema.json", lambda d: d["collector"].pop("tls_fingerprint_sha256"))
    bad("probe-target-port-no-address", P, "probe.config.schema.json", lambda d: d["ports"][1].pop("address"))
    bad("probe-no-ports", P, "probe.config.schema.json", lambda d: d.update(ports=[]))
    bad("probe-missing-mgmt-iface", P, "probe.config.schema.json", lambda d: d.pop("mgmt_iface"))
    bad("probe-reserved-label", P, "probe.config.schema.json", lambda d: d["labels"].update(site="x"))
    bad("probe-ping-shell-injection", P, "probe.config.schema.json", lambda d: d["heartbeat"].update(ping=["1.1.1.1; reboot"]))
    bad("probe-wrong-schema-const", P, "probe.config.schema.json", lambda d: d.update(schema="exp.probe.config/2"))
    bad("collector-vm-public", C, "collector.config.schema.json", lambda d: d["vm"].update(listen="0.0.0.0:8428"))
    bad("collector-ingest-over-limit", C, "collector.config.schema.json", lambda d: d["ingest"].update(max_records=5000))
    bad("collector-unknown-line", C, "collector.config.schema.json", lambda d: d["rules"].update(lines=["network", "bogus"]))
    bad("collector-bad-voice", C, "collector.config.schema.json", lambda d: d["alerts"].update(voice="shouty"))
    bad("dashboard-missing-collectors", D, "dashboard.config.schema.json", lambda d: d.pop("collectors"))
    bad("dashboard-bad-tls-mode", D, "dashboard.config.schema.json", lambda d: d["tls"].update(mode="letsencrypt"))
    bad("dashboard-http-url", D, "dashboard.config.schema.json", lambda d: d.update(url="http://10.32.98.30"))
    bad("runner-bad-puller-source", R, "runner.config.schema.json", lambda d: d["pullers"][0].update(source="meraki"))
    bad("runner-missing-collector", R, "runner.config.schema.json", lambda d: d.pop("collector"))


# ---------------------------------------------------------------- desired
def artifact(component: str, arch: str, seed: str, ver: str = "0.1.0") -> dict:
    aid = fid("art", seed)
    return {"id": aid, "name": "exp-%s-%s-%s.tar.gz" % (component, ver, arch), "url": "/api/agent/v1/artifacts/" + aid,
            "sha256": sha256_hex("artifact:" + seed), "size": 23456789}


def comp_collector() -> dict:
    return {"type": "collector", "id": "col-hallb", "component_id": fid("cmp", "col-hallb"), "version": "0.1.0",
            "artifact": artifact("collector", "amd64", "collector"), "config": collector_cfg(),
            "creds": {"ingest_tokens.json": json.dumps({PROBE: sha256_hex("token:" + PROBE)}, separators=(",", ":")),
                      "dashboard_tokens.json": json.dumps({"dash-main": sha256_hex("token:dash-main")}, separators=(",", ":")),
                      "webhooks.json": json.dumps([{"id": "wh_1", "format": "slack", "url": "https://hooks.example.invalid/services/FIXTURE"}], separators=(",", ":"))}}


def comp_probe() -> dict:
    return {"type": "probe", "id": PROBE, "component_id": fid("cmp", PROBE), "version": "0.1.0",
            "artifact": artifact("probe", "noarch", "probe"), "config": probe_cfg(), "creds": {"ingest_token": token("expi", PROBE)}}


def comp_dashboard() -> dict:
    users = [{"username": "admin", "role": "admin", "hash": "pbkdf2_sha256$600000$%s$%s" % (
        base64.b64encode(hashlib.sha256(b"fixture:salt").digest()[:16]).decode(), base64.b64encode(hashlib.sha256(b"fixture:hash").digest()).decode())}]
    return {"type": "dashboard", "id": "dash-main", "component_id": fid("cmp", "dash-main"), "version": "0.1.0",
            "artifact": artifact("dashboard", "noarch", "dashboard"), "config": dashboard_cfg(),
            "creds": {"collector_tokens.json": json.dumps({"col-hallb": token("expd", "dash-main")}, separators=(",", ":")),
                      "sso_secret": base64.b64encode(hashlib.sha256(b"fixture:sso").digest()).decode(),
                      "local_users.json": json.dumps(users, separators=(",", ":")),
                      "noc_tokens.json": "[]"}}


def desired(host: str, comps: list[dict], version: int = 42, **kw: Any) -> dict:
    d = {"schema": "exp.desired/1", "host_id": fid("h", host), "version": version, "generated_at": "2026-11-18T20:00:00.000Z",
         "org": {"id": "default", "name": "HPE Event NOC"}, "site": {"id": SITE, "name": "Hall B", "timezone": "America/Chicago"},
         "agent": {"version": "0.1.0", "artifact": fid("art", "agent"), "poll_interval_s": 30, "status_interval_s": 60},
         "release": {"version": "0.1.0", "manifest_url": "/api/agent/v1/releases/0.1.0/manifest", "signature_url": "/api/agent/v1/releases/0.1.0/manifest.sig"},
         "components": comps, "actions": [], "decommission": False}
    d.update(kw)
    return d


def gen_desired() -> dict:
    D = {}
    D["collector-host"] = desired("srv-01", [comp_collector()])
    D["probe-host"] = desired("srv-02", [comp_probe()])
    D["dashboard-host"] = desired("srv-03", [comp_dashboard()])
    D["all-in-one"] = desired("srv-04", [comp_collector(), comp_dashboard(), comp_probe()])
    D["decommission"] = desired("srv-02", [], version=43, decommission=True)
    D["rotate"] = desired("srv-02", [comp_probe()], version=44, actions=[
        {"id": fid("act", "rotate"), "type": "rotate_agent_secret"},
        {"id": fid("act", "restart"), "type": "restart_component", "component_id": fid("cmp", PROBE)},
        {"id": fid("act", "diag"), "type": "collect_diagnostics"}])
    unk = desired("srv-02", [comp_probe(), {"type": "futurething", "id": "ft-1", "extra": 1}], version=45)
    D["unknown-component-type"] = unk
    for k, v in D.items():
        put("desired/%s.json" % k, v, "desired.schema.json")
    # invalid
    base = D["probe-host"]

    def bad(name: str, mutate) -> None:
        d = copy.deepcopy(base)
        mutate(d)
        put("invalid/desired/%s.json" % name, d, "desired.schema.json", "invalid")

    bad("creds-path-traversal", lambda d: d["components"][0]["creds"].update({"../../etc/shadow": "x"}))
    bad("creds-non-string", lambda d: d["components"][0]["creds"].update({"ingest_token": 5}))
    bad("action-arbitrary-command", lambda d: d.update(actions=[{"id": fid("act", "x"), "type": "run_shell", "cmd": "id"}]))
    bad("restart-without-component", lambda d: d.update(actions=[{"id": fid("act", "x"), "type": "restart_component"}]))
    bad("bad-host-id", lambda d: d.update(host_id="host-1"))
    bad("missing-decommission", lambda d: d.pop("decommission"))
    bad("artifact-url-foreign", lambda d: d["components"][0]["artifact"].update(url="https://evil.example/x.tar.gz"))
    bad("probe-config-invalid-inside", lambda d: d["components"][0]["config"].update(mode="bridge"))
    return D


# ---------------------------------------------------------------- status / health
def host_facts(name: str, ifaces: list[dict]) -> dict:
    return {"hostname": name, "machine_id": hashlib.md5(name.encode()).hexdigest(), "os": {"id": "ubuntu", "version": "24.04"}, "kernel": "6.8.0-45-generic",
            "arch": "amd64", "cpus": 8, "mem_mb": 32000, "disk_free_mb": 400000, "python": "3.12.3",
            "time": {"synced": True, "source": "systemd-timesyncd", "offset_ms": 1.2}, "interfaces": ifaces}


def host_metrics(rates: bool = True) -> dict:
    r = (lambda v: v) if rates else (lambda v: None)
    return {"interval_s": 60, "uptime_s": 1234567,
            "cpu": {"pct": r(23.4), "iowait_pct": r(1.2), "steal_pct": r(0.0), "load1": 0.8, "load5": 0.6, "load15": 0.5},
            "mem": {"total_mb": 32000, "used_mb": 8200, "available_mb": 23800, "pct": 25.6, "swap_used_mb": 0},
            "disk": [{"mount": "/", "total_gb": 437.0, "used_gb": 13.1, "pct": 3.0}, {"mount": "/var/lib/exp", "total_gb": 437.0, "used_gb": 13.1, "pct": 3.0}],
            "disk_io": {"read_kbps": r(12.0), "write_kbps": r(340.5)},
            "net": [{"iface": "eno1", "role": "mgmt", "link": "up", "speed_mbps": 1000, "rx_pps": r(120.5), "tx_pps": r(98.2), "rx_bps": r(340000), "tx_bps": r(120000),
                     "rx_errors": r(0), "tx_errors": r(0), "rx_drops": r(0), "tx_drops": r(0)}],
            "temp_c_max": 54}


def gen_status_health() -> None:
    mg = {"name": "eno1", "mac": "18:66:da:00:00:01", "state": "up", "speed_mbps": 1000, "driver": "tg3", "addrs": ["10.32.98.25/23"], "default_route": True, "in_use_by": "mgmt"}
    agent = {"version": "0.1.0", "desired_version": 42, "applied_version": 42, "uptime_s": 86400, "last_poll": "2026-11-18T20:00:30.000Z"}
    col = {"type": "collector", "id": "col-hallb", "version": "0.1.0", "state": "running", "health": "ok", "detail": "", "since": "2026-11-17T20:00:00.000Z",
           "process": {"cpu_pct": 12.5, "rss_mb": 410, "restarts": 0, "uptime_s": 86000},
           "metrics": {"ingest_records_per_s": 305.2, "probes_total": 1, "probes_reporting": 1, "vm_up": 1},
           "facts": {"tls_fingerprint_sha256": FP, "listen": "10.32.98.25:8443"}}
    put("status/collector-host.json", {"schema": "exp.status/1", "agent": agent, "facts": host_facts("srv-01", [mg]), "metrics": host_metrics(), "components": [col],
                                       "reconcile": {"at": "2026-11-18T19:59:00.000Z", "result": "ok", "error": None, "duration_ms": 5400},
                                       "events": [{"ts": "2026-11-18T19:59:00.000Z", "level": "info", "msg": "installed exp-collector 0.1.0"}]}, "status.schema.json")
    ports = []
    for pid, iface in (("c01", "enp10s0f0"), ("c02", "enp10s0f1")):
        ports.append({"id": pid, "iface": iface, "role": "client", "link": "up", "leased": True, "ip": "10.1.0.31", "gateway": "10.1.0.1", "rx_pps": 12.0, "tx_pps": 11.0,
                      "rx_bps": 9000, "tx_bps": 8000, "rx_errors": 0, "tx_errors": 0, "rx_drops": 0, "tx_drops": 0, "last": {"network": "ok", "dhcp": "ok", "dns": "fail"}})
    pr = {"type": "probe", "id": PROBE, "version": "0.1.0", "state": "running", "health": "degraded", "detail": "dns failing on c01", "since": "2026-11-17T20:00:00.000Z",
          "process": {"cpu_pct": 7.5, "rss_mb": 96, "restarts": 1, "uptime_s": 5000},
          "metrics": {"measurements_per_min": 140, "by_test_per_min": {"gateway": 12, "dns_hb": 12}, "fail_per_min": 12, "error_per_min": 0, "spool_depth": 0, "spool_bytes": 0,
                      "push_lag_s": 0.4, "clock_offset_ms": 1.1, "skipped_per_hour": 0, "ports": ports},
          "facts": {"collector_reachable": True, "collector_url": "https://10.32.98.25:8443", "mode": "netns"}}
    pifs = [dict(mg, name="eno1", addrs=["10.32.98.26/23"]),
            {"name": "enp10s0f0", "mac": "00:e0:ed:90:89:3a", "state": "up", "speed_mbps": 1000, "driver": "igb", "addrs": [], "default_route": False, "in_use_by": "probe:c01"},
            {"name": "enp10s0f1", "mac": "00:e0:ed:90:89:3b", "state": "down", "speed_mbps": None, "driver": "igb", "addrs": [], "default_route": False, "in_use_by": "none"}]
    put("status/probe-host.json", {"schema": "exp.status/1", "agent": agent, "facts": host_facts("srv-02", pifs), "metrics": host_metrics(), "components": [pr],
                                   "reconcile": {"at": "2026-11-18T19:59:00.000Z", "result": "ok", "error": None, "duration_ms": 7100}, "events": []}, "status.schema.json")
    first = {"schema": "exp.status/1", "agent": dict(agent, desired_version=None, applied_version=None, uptime_s=3, last_poll=None),
             "facts": host_facts("srv-05", [dict(mg, name="eno1")]), "metrics": host_metrics(rates=False), "components": [],
             "reconcile": None, "events": [{"ts": "2026-11-18T20:00:00.000Z", "level": "info", "msg": "agent started"}]}
    first["metrics"]["net"][0]["speed_mbps"] = 1000
    put("status/first-report-null-rates.json", first, "status.schema.json")
    failed = copy.deepcopy(json.load(open(os.path.join(OUT, "status/probe-host.json"))))
    failed["reconcile"] = {"at": "2026-11-18T20:00:00.000Z", "result": "rolled_back", "error": "health check failed after upgrade to 0.1.1", "duration_ms": 31000}
    failed["events"] = [{"ts": "2026-11-18T20:00:00.000Z", "level": "error", "msg": "exp-probe 0.1.1 failed health; rolled back to 0.1.0"}]
    put("status/rolled-back.json", failed, "status.schema.json")

    def bad(name: str, mutate) -> None:
        d = copy.deepcopy(json.load(open(os.path.join(OUT, "status/probe-host.json"))))
        mutate(d)
        put("invalid/status/%s.json" % name, d, "status.schema.json", "invalid")

    bad("negative-rate", lambda d: d["metrics"]["net"][0].update(rx_bps=-5))
    bad("bad-in-use-by", lambda d: d["facts"]["interfaces"][1].update(in_use_by="probe:Bad Port"))
    bad("bad-reconcile-result", lambda d: d["reconcile"].update(result="maybe"))
    bad("bad-tls-fingerprint", lambda d: d["components"][0]["facts"].update(tls_fingerprint_sha256="AB:CD"))
    bad("missing-agent", lambda d: d.pop("agent"))

    # health
    def h(name: str, status: str, detail: str, metrics: dict, facts: dict) -> None:
        put("health/%s.json" % name, {"schema": "exp.health/1", "status": status, "detail": detail, "version": "0.1.0", "uptime_s": 86000, "metrics": metrics, "facts": facts}, "health.schema.json")

    h("probe", "ok", "", pr["metrics"] | {"ports": ports}, pr["facts"])
    h("probe-degraded", "degraded", "collector unreachable; spooling", {"measurements_per_min": 140, "spool_depth": 4200, "spool_bytes": 3100000, "push_lag_s": 600.0}, {"collector_reachable": False, "collector_url": "https://10.32.98.25:8443", "mode": "netns"})
    h("collector", "ok", "", {"ingest_records_per_s": 305.2, "ingest_rejected_per_min": 0, "ingest_duplicates_per_min": 2, "ingest_bytes_per_s": 123456, "probes_total": 1, "probes_reporting": 1, "vm_up": 1,
                              "vm_backlog_points": 0, "vm_series": 5200, "vm_storage_gb": 1.2, "records_db_gb": 0.4, "storage_free_gb": 390.0, "days_to_full": None, "sse_clients": 2, "open_incidents": 0,
                              "webhook_failures_1h": 0, "rules_eval_ms_p95": 14.0}, {"tls_fingerprint_sha256": FP, "listen": "10.32.98.25:8443"})
    h("dashboard", "ok", "", {"sessions_active": 3, "requests_per_min": 40, "sse_clients": 3, "collectors_total": 1, "collectors_reachable": 1, "login_failures_1h": 0},
      {"tls_fingerprint_sha256": fingerprint("dashboard"), "url": "https://10.32.98.30"})
    h("runner", "ok", "", {"drills_active": 0, "pullers": [{"source": "mist", "last_ok": "2026-11-18T20:00:00.000Z", "errors_1h": 0}, {"source": "ec", "last_ok": None, "errors_1h": 3}]},
      {"inventory": {"ec": [{"nePk": "1.NE", "interfaces": ["wan0"]}]}})
    put("health/collector-fail.json", {"schema": "exp.health/1", "status": "fail", "detail": "victoriametrics down; storing to SQLite only", "version": "0.1.0", "uptime_s": 60, "metrics": {"vm_up": 0}, "facts": {}}, "health.schema.json")
    put("invalid/health/bad-status.json", {"schema": "exp.health/1", "status": "healthy", "detail": "", "version": "0.1.0", "uptime_s": 1, "metrics": {}, "facts": {}}, "health.schema.json", "invalid")
    put("invalid/health/metrics-not-object.json", {"schema": "exp.health/1", "status": "ok", "detail": "", "version": "0.1.0", "uptime_s": 1, "metrics": [], "facts": {}}, "health.schema.json", "invalid")


# ---------------------------------------------------------------- state / beats / incidents / manifest
def chain(**states: str) -> list[dict]:
    order = ["ports", "switch", "gateway", "edge", "isp", "dns", "apps"]
    return [{"seg": s, "state": states.get(s, "unknown")} for s in order]


def line(key: str, label: str, state: str, word: str, since: Any, detail: str, flaps: int = 0, last: Any = None) -> dict:
    return {"key": key, "label": label, "state": state, "word": word, "since": since, "detail": detail, "last_outage": last, "flaps": flaps}


def gen_state_etc() -> None:
    base = {"schema": "exp.state/1", "probe": PROBE, "site": SITE, "at": "2026-11-18T20:06:00.000Z", "live": True, "newest_s": 3}
    allok = dict(base, verdict={"severity": "ok", "headline": "Everything looks good.", "sub": "", "voice": "sysadmin", "where": None},
                 lines=[line(k, lbl, "ok", "ok", None, "") for k, lbl in (("network", "Network"), ("dhcp", "DHCP"), ("dns", "DNS"), ("internet", "Internet"), ("apps", "Apps"), ("wifi", "Wi-Fi"), ("path", "Path"))],
                 failing=[])
    put("state/all-ok.json", allok, "state.schema.json")
    gw = dict(base, verdict={"severity": "fail", "headline": "Nobody can reach the gateway.", "sub": "Gateway 10.1.0.1 isn't answering on 12 of 12 ports since 22:00:21.", "voice": "sysadmin",
                             "where": {"seg": "gateway", "label": "Gateway", "ip": "10.1.0.1",
                                       "explain": "Nobody gets to 10.1.0.1, wired or wireless. It's the gateway or the cable to it.",
                                       "chain": chain(ports="ok", switch="ok", gateway="fail")}},
              lines=[line("network", "Network", "fail", "unstable", "2026-11-18T03:00:21.000Z", "10.1.0.1 not answering (12 of 12 ports)")],
              failing=[{"line": "network", "items": [{"text": "no reply from 10.1.0.1", "count": 12, "ports": ["c01", "c02"], "tests": ["gateway"]}]}])
    put("state/gateway-fail.json", gw, "state.schema.json")
    dns = dict(base, verdict={"severity": "fail", "headline": "DNS isn't answering.", "sub": "The resolver 8.8.8.8 is silent on every port; the internet itself is fine.", "voice": "plain",
                              "where": {"seg": "resolver", "label": "Resolver", "ip": "8.8.8.8", "explain": "Both the DHCP resolver and the alternate stopped answering while traffic still flows.",
                                        "chain": chain(ports="ok", switch="ok", gateway="ok", edge="ok", isp="ok", dns="fail", apps="unknown")}},
               lines=[line("network", "Network", "ok", "ok", None, ""), line("dns", "DNS", "fail", "down", "2026-11-18T20:03:00.000Z", "no answer from 8.8.8.8 (9 of 9 ports)", flaps=1,
                                                                            last={"start": "2026-11-18T19:40:00.000Z", "end": "2026-11-18T19:42:30.000Z", "open": False})],
               failing=[{"line": "dns", "items": [{"text": "no answer from 8.8.8.8 within 2 s", "count": 9, "ports": ["c01"], "tests": ["dns_hb", "dns"]}]}])
    put("state/dns-fail.json", dns, "state.schema.json")
    warn = dict(base, live=False, newest_s=None, verdict={"severity": "unknown", "headline": "No recent data.", "sub": "", "voice": "plain", "where": None}, lines=[], failing=[])
    put("state/no-data.json", warn, "state.schema.json")
    b = copy.deepcopy(gw)
    b["lines"][0]["state"] = "broken"
    put("invalid/state/bad-line-state.json", b, "state.schema.json", "invalid")
    b = copy.deepcopy(gw)
    b["verdict"]["where"]["seg"] = "toaster"
    put("invalid/state/bad-seg.json", b, "state.schema.json", "invalid")
    b = copy.deepcopy(gw)
    b["lines"][0]["key"] = "internets"
    put("invalid/state/bad-line-key.json", b, "state.schema.json", "invalid")
    b = copy.deepcopy(gw)
    b["verdict"]["voice"] = "angry"
    put("invalid/state/bad-voice.json", b, "state.schema.json", "invalid")

    t0 = 1763496360000
    beats = {"schema": "exp.beats/1", "probe": PROBE, "from": "2026-11-18T20:00:00.000Z", "to": "2026-11-18T20:06:00.000Z",
             "lines": {"network": [[t0, 0], [t0 + 10000, 2], [t0 + 20000, 3], [t0 + 30000, 1]], "dns": [[t0 + 2000, 0]]},
             "markers": [{"t": t0 + 20000, "kind": "incident", "text": "DNS down", "ref": fid("inc", "1").replace("inc_", "inc_")},
                         {"t": t0 + 40000, "kind": "drill", "text": "dns_block start"}, {"t": t0 + 50000, "kind": "ext", "text": "AP ap-12 offline"}]}
    put("beats/beats.json", beats, "beats.schema.json")
    put("beats/empty.json", {"schema": "exp.beats/1", "probe": PROBE, "from": "2026-11-18T20:00:00.000Z", "to": "2026-11-18T20:06:00.000Z", "lines": {}, "markers": []}, "beats.schema.json")
    for name, mut in (("value-4", lambda d: d["lines"]["network"].append([t0 + 1, 4])), ("bad-line", lambda d: d["lines"].update(bogus=[[t0, 0]])),
                      ("bad-marker-kind", lambda d: d["markers"][0].update(kind="alarm")), ("triple", lambda d: d["lines"]["dns"].append([t0, 0, 1]))):
        d = copy.deepcopy(beats)
        mut(d)
        put("invalid/beats/%s.json" % name, d, "beats.schema.json", "invalid")

    def inc(n: str, kind: str, **kw: Any) -> dict:
        d = {"id": fid("inc", n), "probe": PROBE, "site": SITE, "line": "dns", "kind": kind, "start": "2026-11-18T15:13:42.000Z", "end": None,
             "where": {"seg": "edge", "ip": "10.1.0.2"}, "facts": ["No answers from 1.1.1.1 since 15:13:42"], "folded_into": None, "acked_by": None,
             "link": "https://10.32.98.30/probe/probe-a1?at=2026-11-18T15:13:42Z"}
        d.update(kw)
        return d

    put("incidents/down.json", inc("down", "down"), "incident.schema.json")
    put("incidents/back.json", inc("back", "back", end="2026-11-18T15:16:00.000Z"), "incident.schema.json")
    put("incidents/again.json", inc("again", "again", start="2026-11-18T15:20:00.000Z"), "incident.schema.json")
    put("incidents/flapping.json", inc("flap", "flapping", facts=["3 outages in 10 minutes"], where=None), "incident.schema.json")
    put("incidents/folded.json", inc("folded", "down", line="internet", folded_into=fid("inc", "down"), acked_by="op@example.invalid"), "incident.schema.json")
    put("incidents/probe-silent.json", inc("probe", "down", line="probe", where=None, facts=["No records from probe-a1 for 90 s"]), "incident.schema.json")
    for name, mut in (("bad-line", lambda d: d.update(line="bogus")), ("bad-kind", lambda d: d.update(kind="sideways")), ("bad-id-prefix", lambda d: d.update(id="incident-1")), ("bad-where-seg", lambda d: d.update(where={"seg": "nope"})),
                      ("naive-start", lambda d: d.update(start="2026-11-18T15:13:42")), ("missing-start", lambda d: d.pop("start"))):
        d = inc("x", "down")
        mut(d)
        put("invalid/incidents/%s.json" % name, d, "incident.schema.json", "invalid")

    man = {"schema": "exp.manifest/1", "version": "0.1.0", "created": "2026-11-18T19:00:00.000Z", "min_agent_version": "0.1.0",
           "artifacts": [{"name": "exp-%s-0.1.0-%s.tar.gz" % (c, a), "component": c, "arch": a, "sha256": sha256_hex("artifact:" + c), "size": 800000 + i}
                         for i, (c, a) in enumerate([("agent", "noarch"), ("probe", "noarch"), ("collector", "amd64"), ("collector", "arm64"), ("dashboard", "noarch"), ("runner", "noarch")])],
           "notes_url": "https://github.com/example-org/exp/releases/tag/v0.1.0"}
    put("manifest/manifest.json", man, "manifest.schema.json")
    for name, mut in (("bad-artifact-name", lambda d: d["artifacts"][0].update(name="../../exp-agent.tar.gz")), ("bad-arch", lambda d: d["artifacts"][0].update(arch="riscv")),
                      ("bad-sha", lambda d: d["artifacts"][0].update(sha256="abc")), ("no-artifacts", lambda d: d.update(artifacts=[])), ("bad-component", lambda d: d["artifacts"][0].update(component="manager"))):
        d = copy.deepcopy(man)
        mut(d)
        put("invalid/manifest/%s.json" % name, d, "manifest.schema.json", "invalid")


# ---------------------------------------------------------------- M6 speedtest (12-speedtest-analytics.md)
ST_SECRET = token("expk", "device-key-secret")
ST_MAC = "f0:18:98:aa:bb:01"
ST_IP = "10.60.14.77"
ST_START, ST_END = "2026-11-18T14:02:11.120Z", "2026-11-18T14:02:27.540Z"
ST_WIN = {"from": "2026-11-18T13:57:11.120Z", "to": "2026-11-18T14:04:27.540Z"}


def st_leg(down, up, idle, jit, ld, lu, cv, nbytes, server, **kw: Any) -> dict:
    d = {"status": "ok", "down_mbps": down, "up_mbps": up, "idle_ms": idle, "jitter_ms": jit, "loaded_down_ms": ld, "loaded_up_ms": lu,
         "rpm": int(60000 / max(ld, lu)), "cv": cv, "failures": 0, "bytes": nbytes, "server": server}
    d.update(kw)
    return d


def st_result(name: str, **kw: Any) -> dict:
    legs = {"local": st_leg(212.4, 88.1, 6.2, 1.1, 41.0, 55.3, 0.12, 190000000, "spd-core"),
            "internet": st_leg(184.0, 61.7, 18.9, 2.4, 96.0, 120.4, 0.21, 150000000, "cloudflare:FRA"),
            "dns": {"cold_ms": 38.0, "warm_ms": 2.1, "resolver_ip": "10.0.0.53", "source": "browser"},
            "path": {"gateway_ms": {"idle": 0.4, "loaded": 0.9, "samples": 40}, "edge_ms": {"idle": 0.7, "loaded": 1.8, "samples": 40},
                     "edge1_ms": {"idle": 4.1, "loaded": 9.6, "samples": 40}, "edge1_addr": "203.0.113.1", "device_icmp_ms": 5.9}}
    d = {"schema": "exp.speedtest/1", "id": fid("st", name), "site": SITE, "zone": "hallb-row12", "zone_source": "mist",
         "started": ST_START, "ended": ST_END,
         "client": {"ip": ST_IP, "ua": {"os_family": "iOS", "os_version": "18.1", "browser": "Safari", "device_class": "phone"}, "connection_hint": "wifi"},
         "consent": {"text_version": 3}, "legs": legs, "score": None, "flags": [],
         "observed": {"received_at": "2026-11-18T14:02:27.900Z", "server_id": "spd-core", "local_bytes_down": 190000000, "local_bytes_up": 61000000, "session_ms": 16780}}
    d.update(kw)
    d["score"] = _st.compute_score(d["legs"], {"down_mbps": 25, "up_mbps": 10}) if d["score"] is None else d["score"]
    return d


def st_ev(test: str, kind: str, source: str, data: dict, status: str = "ok", **kw: Any) -> dict:
    d = {"schema": "exp.evidence/1", "test_id": fid("st", test), "kind": kind, "source": source, "collected_at": "2026-11-18T14:03:40.000Z",
         "window": dict(ST_WIN), "status": status, "data": data, "raw_refs": []}
    d.update(kw)
    return d


def speedtest_cfg() -> dict:
    return {"schema": "exp.speedtest.config/1", "speedtest_id": "spd-core", "site": SITE,
            "zones": [{"id": "hall-a", "name": "Hall A"}, {"id": "hall-b", "name": "Hall B"}, {"id": "hallb-row12", "name": "Hall B, row 12"}],
            "zone_labels": {"subnets": [{"cidr": "10.60.0.0/16", "zone": "hall-a"}, {"cidr": "10.61.0.0/16", "zone": "hall-b"}]},
            "branding": {"title": "Summit speed check", "logo_artifact": fid("art", "st-logo"),
                         "colors": {"primary": "#01a982", "accent": "#7630ea", "background": "#0b1320", "text": "#f7f7f7"},
                         "languages": ["en", "de"], "copy": {"start_button": "Start", "verdict_good": "Your connection is great."}},
            "consent": {"text": "We measure your speed and look at this device's Wi-Fi and traffic metadata to diagnose it. No name or email is collected.", "version": 3},
            "display": {"show_network_details": False}, "targets": {"down_mbps": 25, "up_mbps": 10},
            "limits": {"tests_per_10min_per_ip": 6, "max_concurrent_per_ip": 1, "max_concurrent_tests": 20, "max_concurrent_internet": 10,
                       "bytes_local": 200000000, "bytes_internet": 200000000, "leg_token_ttl_s": 60, "result_deadline_s": 180},
            "internet_leg": {"enabled": True, "provider": "cloudflare", "paused": False, "auto_pause_wan_util_pct": 80},
            "serve": {"placement": "core", "hostname": "speed.summit.example", "listen_ip": "10.0.0.9", "require_real_client_ip": True,
                      "client_subnets": ["10.60.0.0/16", "10.61.0.0/16"], "translated_addresses": ["10.0.0.2"]},
            "tls": {"mode": "none"}, "dns_leg": {"enabled": True, "zone": "t.speed.summit.example"},
            "path": {"gateway": "auto", "edge": "10.0.0.2", "edge1": "auto", "note": "infrastructure context, not per-user"},
            "privacy": {"retention_days": 30, "scrub_after_diagnosis": False},
            "core_guard": {"iface": "eno2", "util_pct": 70, "min_bytes": 5000000},
            "collector": {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": FP},
            "local_channel": {"listen": "127.0.0.1:8480"}}


def runner_corr_cfg() -> dict:
    return {"schema": "exp.runner.config/1", "runner_id": "run-core", "site": SITE,
            "collector": {"url": "https://10.32.98.25:8443", "tls_fingerprint_sha256": FP}, "drills_enabled": False,
            "correlation": {
                "enabled": True, "window_before_s": 300, "window_after_s": 120, "poll_interval_s": 5,
                "sources": {
                    "mist": {"sites": [{"site_id": "00000000-0000-0000-0000-00000000aa01", "name": "Summit venue"}],
                             "zone_map": [{"zone": "hall-b", "ap_name_prefix": "hallb-ap-"}, {"zone": "hall-a", "ap_macs": ["5c:5b:35:00:01:a0"]}],
                             "max_calls_per_test": 6, "cache_ttl_s": 30},
                    "ec": {"appliances": [{"ne_pk": "1.NE", "hostname": "ec-core", "wan_interfaces": ["wan0"]}], "max_flows": 50,
                           "wan_util": {"enabled": True, "interval_s": 30}},
                    "syslog": {"listen": ["udp:5514", "tcp:5514", "tls:6514"], "bind": "0.0.0.0", "allow": ["10.0.0.0/8"], "rate_limit_lines_per_s": 200,
                               "max_line_bytes": 4096, "ring_minutes": 60, "tls": {"mode": "self_signed"}},
                    "sse": {"enabled": False}},
                # compiled by the manager from the same site settings as the box's serve block (CR-m6-runner-network)
                "network": runner_network(),
                "privacy": {"scrub_after_diagnosis": False},
                "speedtest_channel": {"url": "http://127.0.0.1:8480/local/v1"}}}


def runner_network() -> dict:
    """The runner's identity inputs mirror the speedtest's serve + zone_labels (one source, two configs)."""
    st = speedtest_cfg()
    return {"require_real_client_ip": st["serve"]["require_real_client_ip"],
            "client_subnets": list(st["serve"]["client_subnets"]),
            "translated_addresses": list(st["serve"]["translated_addresses"]),
            "zone_subnets": [dict(z) for z in st["zone_labels"]["subnets"]]}


def collector_speedtests_cfg() -> dict:
    c = collector_cfg()
    c["speedtests"] = {"enabled": True, "speedtests": ["spd-core"], "runners": ["run-core"], "retention_days": 30, "scrub_after_diagnosis": False,
                       "targets": {"down_mbps": 25, "up_mbps": 10}, "max_evidence_kib": 256, "stream_replay_s": 300}
    return c


def gen_speedtest() -> None:
    # ---- results (exp.speedtest/1)
    ok = st_result("ok")
    put("speedtest/result.ok.json", ok, "speedtest.schema.json")
    pb = st_result("policy-block", zone="hallb-row12",
                   legs={"local": st_leg(240.0, 95.0, 5.5, 0.9, 30.0, 33.0, 0.08, 180000000, "spd-core"),
                         "internet": st_leg(0.4, 0.2, 21.0, 3.0, 480.0, 510.0, 0.62, 800000, "cloudflare:FRA", failures=40),
                         "dns": {"cold_ms": 36.0, "warm_ms": 2.0, "resolver_ip": "10.0.0.53", "source": "browser"}},
                   comment="Teams and speed.cloudflare.com won't load at my booth")
    put("speedtest/result.policy-block.json", pb, "speedtest.schema.json")
    nat = st_result("nat", zone="unresolved", zone_source="unresolved", flags=["nat_suspected"])
    nat["client"]["ip"] = "10.0.0.2"
    put("speedtest/result.unresolved-nat.json", nat, "speedtest.schema.json")
    iu = st_result("inet-down", zone="hall-b", zone_source="subnet", flags=["internet_unavailable", "dns_fallback"],
                   legs={"local": st_leg(310.0, 120.0, 4.8, 0.7, 22.0, 25.0, 0.05, 195000000, "spd-core"),
                         "internet": {"status": "unavailable", "server": "cloudflare"},
                         "dns": {"warm_ms": None, "cold_ms": None, "resolver_ip": None, "source": "probe"}})
    put("speedtest/result.internet-unavailable.json", iu, "speedtest.schema.json")
    q = st_result("queued", flags=["internet_queued"], legs={"local": st_leg(150.0, 60.0, 7.0, 1.0, 50.0, 60.0, 0.15, 150000000, "spd-core"),
                                                            "internet": {"status": "queued"}})
    put("speedtest/result.internet-queued.json", q, "speedtest.schema.json")
    scr = st_result("scrubbed")
    scr["client"].pop("ip")
    put("speedtest/result.scrubbed.json", scr, "speedtest.schema.json")
    cd = st_result("counters", flags=["counters_disagree", "bytes_capped"])
    put("speedtest/result.counters-disagree.json", cd, "speedtest.schema.json")

    def bad(name: str, mutate, schema: str = "speedtest.schema.json", base: dict | None = None) -> None:
        d = copy.deepcopy(base or ok)
        mutate(d)
        put("invalid/speedtest/%s.json" % name, d, schema, "invalid")

    bad("result-bad-id", lambda d: d.update(id="st_notaulid"))
    bad("result-person-name", lambda d: d["client"].update(name="Alice Example"))
    bad("result-person-email", lambda d: d.update(email="alice@example.invalid"))
    bad("result-top-level-person", lambda d: d.update(person={"full_name": "A B"}))
    bad("result-down-over-100gbps", lambda d: d["legs"]["local"].update(down_mbps=100001))
    bad("result-duration-over-60s", lambda d: d["legs"]["internet"].update(idle_ms=60001))
    bad("result-comment-too-long", lambda d: d.update(comment="x" * 501))
    bad("result-comment-control-char", lambda d: d.update(comment="bad\x07bell"))
    bad("result-bad-zone-source", lambda d: d.update(zone_source="gps"))
    bad("result-bad-zone", lambda d: d.update(zone="Hall B / Row 12"))
    bad("result-unknown-flag", lambda d: d.update(flags=["happy"]))
    bad("result-naive-timestamp", lambda d: d.update(started="2026-11-18T14:02:11"))
    bad("result-missing-observed", lambda d: d.pop("observed"))
    bad("result-score-over-100", lambda d: d["score"].update(total=101))
    bad("result-bad-leg-status", lambda d: d["legs"]["internet"].update(status="meh"))
    bad("result-dns-bad-source", lambda d: d["legs"]["dns"].update(source="guess"))
    bad("result-ua-unknown-class", lambda d: d["client"]["ua"].update(device_class="toaster"))
    bad("result-raw-user-agent", lambda d: d["client"].update(user_agent="Mozilla/5.0 (iPhone)"))

    # ---- submissions (exp.speedtest.submission/1)
    sub = {"schema": "exp.speedtest.submission/1",
           "legs": {"local": {"down_mbps": 205.0, "up_mbps": 85.0, "idle_ms": 6.0, "jitter_ms": 1.0, "loaded_down_ms": 40.0, "loaded_up_ms": 52.0, "rpm": 1150, "cv": 0.12, "failures": 0, "bytes": 188000000},
                    "internet": {"down_mbps": 180.0, "up_mbps": 60.0, "idle_ms": 19.0, "jitter_ms": 2.4, "loaded_down_ms": 95.0, "loaded_up_ms": 118.0, "rpm": 520, "cv": 0.2, "failures": 0, "bytes": 150000000, "colo": "FRA"},
                    "dns": {"cold_ms": 38.0, "warm_ms": 2.1, "resolver_ip": "10.0.0.53", "source": "browser"}},
           "client": {"connection_hint": "wifi"}, "zone_hint": "hallb-row12", "comment": "video calls freeze at my booth", "started_offset_ms": 4100, "duration_ms": 16400}
    put("speedtest/submission.full.json", sub, "speedtest.submission.schema.json")
    put("speedtest/submission.minimal.json", {"schema": "exp.speedtest.submission/1", "legs": {"local": {"down_mbps": 50.0, "up_mbps": 20.0, "idle_ms": 8.0}}}, "speedtest.submission.schema.json")
    put("speedtest/submission.internet-unavailable.json", {"schema": "exp.speedtest.submission/1", "legs": {"local": {"down_mbps": 50.0, "up_mbps": 20.0, "idle_ms": 8.0}, "internet": {"status": "unavailable"}}},
        "speedtest.submission.schema.json")
    sb = lambda n, m: bad("submission-" + n, m, "speedtest.submission.schema.json", sub)  # noqa: E731
    sb("sets-client-ip", lambda d: d["client"].update(ip="10.9.9.9"))
    sb("sets-score", lambda d: d.update(score={"total": 100, "speed": 100, "responsiveness": 100, "stability": 100}))
    sb("sets-observed", lambda d: d.update(observed={"received_at": "2026-11-18T14:02:27.900Z", "server_id": "x"}))
    sb("missing-local", lambda d: d["legs"].pop("local"))
    sb("negative-speed", lambda d: d["legs"]["local"].update(down_mbps=-1))
    sb("over-100gbps", lambda d: d["legs"]["internet"].update(up_mbps=100001))
    sb("comment-control-char", lambda d: d.update(comment="a\x00b"))
    sb("person-field", lambda d: d.update(name="Alice"))
    sb("bad-zone-hint", lambda d: d.update(zone_hint="Hall B"))
    sb("wrong-schema-const", lambda d: d.update(schema="exp.speedtest/1"))

    # ---- evidence (exp.evidence/1), one valid per kind plus the interesting states
    ev: dict[str, dict] = {}
    ident = {"resolved_by": "mist", "ip": ST_IP, "mac": ST_MAC, "device_key": _st.device_key(ST_SECRET, ST_MAC), "hostname": "alices-iphone", "username": "guest-portal-7731",
             "manufacture": "Apple", "os_family": "iOS", "wired": False, "zone": "hallb-row12", "zone_source": "mist", "site_id": "00000000-0000-0000-0000-00000000aa01",
             "ap_mac": "5c:5b:35:00:01:a0", "ap_name": "hallb-ap-12", "ssid": "Summit-Guest", "band": "5", "vlan": 160, "candidates": 1, "nat_suspected": False, "scrubbed": False}
    ev["identity.mist"] = st_ev("ok", "identity", "mist", ident, raw_refs=["mist:client:f018:98aabb01"])
    ev["identity.dhcp-fallback"] = st_ev("ok", "identity", "syslog", {"resolved_by": "dhcp", "ip": ST_IP, "mac": ST_MAC, "device_key": _st.device_key(ST_SECRET, ST_MAC),
                                                                       "hostname": "alices-iphone", "zone": "hall-a", "zone_source": "subnet", "candidates": 0, "nat_suspected": False},
                                         status="partial", raw_refs=["syslog:dhcp:1"])
    ev["identity.nat-suspected"] = st_ev("nat", "identity", "mist", {"resolved_by": "none", "ip": "10.0.0.2", "zone": "unresolved", "zone_source": "unresolved",
                                                                      "candidates": 0, "nat_suspected": True, "nat_reason": "translated_address"}, status="partial")
    ev["identity.scrubbed"] = st_ev("ok", "identity", "mist", {"resolved_by": "mist", "device_key": _st.device_key(ST_SECRET, ST_MAC), "manufacture": "Apple", "os_family": "iOS",
                                                                "zone": "hallb-row12", "zone_source": "mist", "ap_name": "hallb-ap-12", "ssid": "Summit-Guest", "band": "5",
                                                                "candidates": 1, "nat_suspected": False, "scrubbed": True})
    wifi = {"client": {"mac": ST_MAC, "ap_mac": "5c:5b:35:00:01:a0", "bssid": "5c:5b:35:00:01:a2", "ssid": "Summit-Guest", "band": "5", "channel": 44, "proto": "ax", "rssi": -61, "snr": 34,
                       "tx_rate_mbps": 433.3, "rx_rate_mbps": 390.0, "tx_retries": 812, "rx_retries": 40, "tx_pkts": 96000, "rx_pkts": 120000, "idle_time_s": 0.2, "uptime_s": 1820,
                       "power_saving": False, "dual_band": True, "key_mgmt": "WPA2-PSK/CCMP", "vlan_id": "160", "manufacture": "Apple", "os": "iOS", "last_seen": 1763474547, "retry_pct": 0.85},
            "ap": {"mac": "5c:5b:35:00:01:a0", "ap_name": "hallb-ap-12", "model": "AP45", "num_clients": 74, "status": "connected",
                   "radio": {"band": "5", "channel": 44, "bandwidth_mhz": 80, "power_dbm": 15, "noise_floor_dbm": -92, "num_clients": 61, "util_all": 81, "util_tx": 22,
                             "util_rx_in_bss": 31, "util_rx_other_bss": 20, "util_non_wifi": 8}},
            "roams": [{"timestamp": 1763474500, "from_ap_mac": "5c:5b:35:00:01:b0", "ap_mac": "5c:5b:35:00:01:a0", "type": "success", "latency_s": 0.11, "ssid": "Summit-Guest"}],
            "events": [{"timestamp": 1763474500, "type": "CLIENT_ASSOC", "type_code": 0, "ssid": "Summit-Guest", "band": "5", "channel": 44, "proto": "ax"}],
            "roam_count": 1, "auth_failures": 0}
    ev["wifi.ok"] = st_ev("ok", "wifi", "mist", wifi, raw_refs=["mist:stats/clients/f01898aabb01"])
    ev["wifi.unavailable"] = st_ev("nat", "wifi", "mist", {}, status="unavailable")
    ev["wired.ok"] = st_ev("ok", "wired", "mist", {
        "client": {"mac": ST_MAC, "ip": [ST_IP], "vlan": [160], "port_id": ["ge-0/0/12"], "device_mac": ["5c:5b:35:00:09:01"], "auth_state": "authenticated", "dhcp_hostname": "booth-pc-12", "timestamp": 1763474540},
        "port": {"switch_mac": "5c:5b:35:00:09:01", "port_id": "ge-0/0/12", "up": True, "speed_mbps": 100, "full_duplex": False, "rx_errors": 1450, "tx_errors": 12, "stp_state": "forwarding",
                 "poe_on": False, "uplink": False}, "events": [{"timestamp": 1763474400, "type": "SW_PORT_DOWN", "port_id": "ge-0/0/12", "device_name": "hallb-sw-1"}]})
    flows = [{"application": "https", "ip1": ST_IP, "port1": 51022, "ip2": "104.18.1.1", "port2": 443, "protocol": "tcp", "bytes_in_tx": 1000, "bytes_in_rx": 150000000, "bytes_out_rx": 900, "bytes_out_tx": 61000000,
              "bytes_total": 211001900, "uptime_ms": 16000, "outbound_tunnel": "to_dc", "overlay": "DefaultOverlay", "lan_vlan": 160, "traffic_class": 5, "lan_dscp": "trust-lan", "wan_dscp": "trust-lan",
              "app_type": "Bulk_Data_transfer", "start_s": 1763474531, "end_s": 1763474547, "firewall_dropped": 0, "drop_reason": 0, "nat_type": "LAN_SNAT", "domain": "speed.cloudflare.com"},
             {"application": "teams", "ip1": ST_IP, "port1": 51100, "ip2": "52.112.0.1", "port2": 3478, "protocol": "udp", "bytes_in_tx": 0, "bytes_in_rx": 0, "bytes_out_rx": 0, "bytes_out_tx": 4000,
              "bytes_total": 4000, "uptime_ms": 9000, "traffic_class": 2, "app_type": "Voice", "firewall_dropped": 1, "drop_reason": 1}]
    ev["flows.ok"] = st_ev("ok", "flows", "ec", {"appliance": "1.NE", "counts": {"total_flows": 8123, "matched_flows": 2, "returned_flows": 2, "flows_firewall_dropped": 1, "flows_route_dropped": 0}, "flows": flows},
                           raw_refs=["ec:flow:1.NE"])
    ev["wan.ok"] = st_ev("ok", "wan", "ec", {"appliances": [{
        "ne_pk": "1.NE", "hostname": "ec-core", "state": 1,
        "interfaces": [{"ifname": "wan0", "wan_if": True, "lan_if": False, "admin": True, "oper": True, "if_speed": "1000", "duplex": "full (auto)", "label": "2", "public_ip": "203.0.113.2",
                        "max_wan_bandwidth_kbps": 200000, "rx_bps": 185000000, "tx_bps": 60000000, "util_pct": 92.5}],
        "health": {"latency": [{"tunnel_id": "to_dc", "health_status": "HEALTHY", "critical_mins": 0, "major_mins": 3, "normal_mins": 57, "max": 38}],
                   "loss": [{"tunnel_id": "to_dc", "health_status": "HEALTHY", "critical_mins": 0, "major_mins": 0, "normal_mins": 60, "max": 0.2}], "jitter": [], "mos": []},
        "alarms": [{"sequence_id": 551, "severity": "major", "type": "tunnel", "alarm_name": "Tunnel state", "description": "Tunnel to_dc degraded", "time_occurred_ms": 1763474400000,
                    "occurrence_count": 2, "service_affect": True, "closed": False, "host_name": "ec-core"}],
        "timeseries": {"columns": ["time", "rx_bps", "tx_bps"], "rows": [[1763474460, 180000000, 59000000], [1763474520, 185000000, 60000000]]}}], "wan_util_pct": 92.5})
    ev["security.policy-block"] = st_ev("policy-block", "security", "syslog", {
        "events": [{"ts": "2026-11-18T14:02:12.000Z", "source": "syslog", "format": "kv", "action": "deny", "category": "zbf", "src_ip": ST_IP, "src_port": 51100, "dst_ip": "52.112.0.1", "dst_port": 3478, "proto": "udp",
                    "rule": "guest-to-internet-deny-rtc", "zone_from": "guest", "zone_to": "internet", "count": 31,
                    "raw": "action=deny src=10.60.14.77 spt=51100 dst=52.112.0.1 dpt=3478 proto=udp rule=guest-to-internet-deny-rtc"},
                   {"ts": "2026-11-18T14:02:15.000Z", "source": "syslog", "format": "cef", "action": "block", "category": "url", "src_ip": ST_IP, "dst_ip": "104.18.1.1", "host": "speed.cloudflare.com", "reason": "category: speed test",
                    "raw": "CEF:0|Example|FW|1|100|URL blocked|5|src=10.60.14.77 dst=104.18.1.1 act=block"}],
        "counts": {"deny": 31, "drop": 0, "block": 1, "session_limit": 0}, "ec_dropped_flows": 1, "truncated": False}, raw_refs=["syslog:1", "syslog:2"])
    ev["baseline.ok"] = st_ev("ok", "baseline", "exp", {"probe": PROBE, "site": SITE, "distance": "same_zone", "at": "2026-11-18T14:02:20.000Z", "severity": "ok",
                                                       "lines": [{"key": "network", "state": "ok"}, {"key": "dns", "state": "ok"}, {"key": "wifi", "state": "warn", "detail": "rssi -71 dBm"}],
                                                       "throughput": {"down_mbps": 230.0, "up_mbps": 90.0, "latency_idle_ms": 8.0, "latency_loaded_ms": 40.0, "ts": "2026-11-18T14:00:00.000Z"},
                                                       "wifi": {"ssid": "Summit-Guest", "band": "5", "rssi_dbm": -71, "snr_db": 24}})
    ev["dns.ok"] = st_ev("ok", "dns", "syslog", {"resolver_ip": "10.0.0.53", "queries": [{"ts": "2026-11-18T14:02:14.000Z", "qname": "speed.cloudflare.com", "qtype": "A", "rcode": "NOERROR", "rtt_ms": 410.0, "client_ip": ST_IP}],
                                                 "failures": 0, "slow": 1, "slowest_ms": 410.0, "probe_dns": {"state": "ok", "rtt_ms": 12.0, "resolver": "10.0.0.53"}})
    for k, v in ev.items():
        put("evidence/%s.json" % k, v, "evidence.schema.json")

    def eb(name: str, base: str, mutate) -> None:
        d = copy.deepcopy(ev[base])
        mutate(d)
        put("invalid/evidence/%s.json" % name, d, "evidence.schema.json", "invalid")

    eb("kind-data-mismatch", "wifi.ok", lambda d: d.update(kind="flows"))
    eb("unknown-kind", "wifi.ok", lambda d: d.update(kind="app"))
    eb("wifi-client-email", "wifi.ok", lambda d: d["data"]["client"].update(email="alice@example.invalid"))
    eb("wifi-guest-object", "wifi.ok", lambda d: d["data"].update(guest={"name": "Alice", "email": "a@example.invalid"}))
    eb("wifi-rssi-positive", "wifi.ok", lambda d: d["data"]["client"].update(rssi=5))
    eb("wifi-bad-band", "wifi.ok", lambda d: d["data"]["client"].update(band="60"))
    eb("flows-over-50", "flows.ok", lambda d: d["data"].update(flows=[dict(flows[0], port1=40000 + i) for i in range(51)]))
    eb("flows-full-url-field", "flows.ok", lambda d: d["data"]["flows"][0].update(url="https://example.invalid/secret?token=1"))
    eb("security-over-200-lines", "security.policy-block", lambda d: d["data"].update(events=[dict(d["data"]["events"][0], count=1) for _ in range(201)]))
    eb("security-bad-action", "security.policy-block", lambda d: d["data"]["events"][0].update(action="permit-ish"))
    eb("bad-status", "wifi.ok", lambda d: d.update(status="fine"))
    eb("bad-source", "wifi.ok", lambda d: d.update(source="ldap"))
    eb("missing-test-id", "wifi.ok", lambda d: d.pop("test_id"))
    eb("naive-window", "wifi.ok", lambda d: d["window"].update(to="2026-11-18T14:04:27"))
    eb("identity-person-name", "identity.mist", lambda d: d["data"].update(name="Alice Example"))
    eb("identity-email", "identity.mist", lambda d: d["data"].update(email="alice@example.invalid"))
    eb("identity-bad-device-key", "identity.mist", lambda d: d["data"].update(device_key="abc"))
    eb("identity-bad-nat-reason", "identity.nat-suspected", lambda d: d["data"].update(nat_reason="because"))

    # ---- configs
    put("configs/speedtest.json", speedtest_cfg(), "speedtest.config.schema.json")
    tp = speedtest_cfg()
    tp["tls"] = {"mode": "provided"}
    tp["serve"]["hostname"] = "speed.summit.example"
    put("configs/speedtest.tls-provided.json", tp, "speedtest.config.schema.json")
    put("configs/speedtest.minimal.json", {"schema": "exp.speedtest.config/1", "speedtest_id": "spd-lab", "site": SITE,
                                            "serve": {"hostname": "10.0.0.9", "listen_ip": "10.0.0.9"}, "tls": {"mode": "none"},
                                            "collector": {"url": "https://127.0.0.1:8443", "tls_fingerprint_sha256": FP}}, "speedtest.config.schema.json")
    put("configs/runner.correlation.json", runner_corr_cfg(), "runner.config.schema.json")
    put("configs/collector.speedtests.json", collector_speedtests_cfg(), "collector.config.schema.json")

    def cb(name: str, base: dict, schema: str, mutate) -> None:
        d = copy.deepcopy(base)
        mutate(d)
        put("invalid/configs/%s.json" % name, d, schema, "invalid")

    SC, RC, CC = speedtest_cfg(), runner_corr_cfg(), collector_speedtests_cfg()
    sch = "speedtest.config.schema.json"
    cb("speedtest-bad-tls-mode", SC, sch, lambda d: d["tls"].update(mode="self_signed"))
    cb("speedtest-bytes-local-tiny", SC, sch, lambda d: d["limits"].update(bytes_local=10))
    cb("speedtest-bad-client-subnet", SC, sch, lambda d: d["serve"].update(client_subnets=["10.60.0.0/33"]))
    cb("speedtest-listen-ip-hostname", SC, sch, lambda d: d["serve"].update(listen_ip="speed.summit.example"))
    cb("speedtest-logo-not-art-id", SC, sch, lambda d: d["branding"].update(logo_artifact="logo.png"))
    cb("speedtest-collector-http", SC, sch, lambda d: d["collector"].update(url="http://10.32.98.25:8443"))
    cb("speedtest-channel-not-loopback", SC, sch, lambda d: d["local_channel"].update(listen="0.0.0.0:8480"))
    cb("speedtest-auto-pause-over-100", SC, sch, lambda d: d["internet_leg"].update(auto_pause_wan_util_pct=150))
    cb("speedtest-bad-color", SC, sch, lambda d: d["branding"]["colors"].update(primary="green"))
    cb("speedtest-unknown-provider", SC, sch, lambda d: d["internet_leg"].update(provider="ookla"))
    cb("speedtest-unknown-key", SC, sch, lambda d: d.update(person_lookup=True))
    cb("runner-correlation-negative-window", RC, "runner.config.schema.json", lambda d: d["correlation"].update(window_before_s=-5))
    cb("runner-syslog-ring-over-60", RC, "runner.config.schema.json", lambda d: d["correlation"]["sources"]["syslog"].update(ring_minutes=61))
    cb("runner-syslog-bad-listen", RC, "runner.config.schema.json", lambda d: d["correlation"]["sources"]["syslog"].update(listen=["icmp:5514"]))
    cb("runner-channel-not-loopback", RC, "runner.config.schema.json", lambda d: d["correlation"]["speedtest_channel"].update(url="http://10.0.0.9:8480/local/v1"))
    cb("runner-mist-flows-over-50", RC, "runner.config.schema.json", lambda d: d["correlation"]["sources"]["ec"].update(max_flows=500))
    cb("collector-speedtests-retention-zero", CC, "collector.config.schema.json", lambda d: d["speedtests"].update(retention_days=0))
    cb("collector-speedtests-evidence-over-256", CC, "collector.config.schema.json", lambda d: d["speedtests"].update(max_evidence_kib=512))

    # ---- desired: the all-in-one profile (probe + collector + runner + speedtest on ONE box)
    col = comp_collector()
    col["config"] = collector_speedtests_cfg()
    col["creds"] = dict(col["creds"], **{"speedtest_tokens.json": json.dumps({"spd-core": hashlib.sha256(token("exps", "spd-core").encode()).hexdigest()}, separators=(",", ":")),
                                         "runner_tokens.json": json.dumps({"run-core": hashlib.sha256(token("expr", "run-core").encode()).hexdigest()}, separators=(",", ":")),
                                         "device_key_secret": ST_SECRET})
    run = {"type": "runner", "id": "run-core", "component_id": fid("cmp", "run-core"), "version": "0.1.0", "artifact": artifact("runner", "noarch", "runner"),
           "config": runner_corr_cfg(),
           "creds": {"integrations.json": json.dumps({"mist": {"api_base": "https://api.mist.example", "token": "FIXTURE-MIST-TOKEN"}, "ec": {"url": "https://orch.example", "api_key": "FIXTURE-EC-KEY"}}, separators=(",", ":")),
                     "ingest_token": token("expi", "run-core"), "collector_token": token("expr", "run-core"),
                     "speedtest_channel_token": token("expl", "spd-core"), "device_key_secret": ST_SECRET}}
    spd = {"type": "speedtest", "id": "spd-core", "component_id": fid("cmp", "spd-core"), "version": "0.1.0", "artifact": artifact("speedtest", "noarch", "speedtest"),
           "config": speedtest_cfg(),
           "assets": [{"name": "logo", "content_type": "image/svg+xml", "artifact": {"id": fid("art", "st-logo"), "name": "exp-speedtest-0.1.0-noarch.tar.gz", "url": "/api/agent/v1/artifacts/" + fid("art", "st-logo"),
                                                                                       "sha256": sha256_hex("artifact:st-logo"), "size": 18000}}],
           "creds": {"collector_token": token("exps", "spd-core"), "runner_channel_token_sha256": hashlib.sha256(token("expl", "spd-core").encode()).hexdigest()}}
    prb = comp_probe()
    aio = desired("srv-core", [col, prb, run, spd], version=50)
    put("desired/all-in-one-speedtest.json", aio, "desired.schema.json")
    for name, mut in (("speedtest-config-invalid-inside", lambda d: d["components"][3]["config"]["tls"].update(mode="self_signed")),
                      ("speedtest-asset-traversal-name", lambda d: d["components"][3]["assets"][0].update(name="../logo")),
                      ("speedtest-asset-bad-content-type", lambda d: d["components"][3]["assets"][0].update(content_type="text/html")),
                      ("runner-correlation-invalid-inside", lambda d: d["components"][2]["config"]["correlation"].update(poll_interval_s=0))):
        d = copy.deepcopy(aio)
        mut(d)
        put("invalid/desired/%s.json" % name, d, "desired.schema.json", "invalid")


def main() -> None:
    M = gen_measurements()
    gen_invalid_measurements(M)
    gen_configs()
    gen_desired()
    gen_status_health()
    gen_state_etc()
    gen_speedtest()
    idx_path = os.path.join(OUT, "INDEX.json")
    with open(idx_path, "w", encoding="utf-8") as f:
        json.dump(dict(sorted(INDEX.items())), f, indent=2)
        f.write("\n")
    print("wrote %d fixtures" % len(INDEX))


if __name__ == "__main__":
    main()
