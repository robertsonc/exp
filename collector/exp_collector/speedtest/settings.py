"""Speedtest settings parsed from ``exp.collector.config/1`` ``speedtests`` (schema-validated already).

``Thresholds`` are the 12 section 5.3 rule defaults; every one is a tunable (``speedtests.diagnosis``).
"""
from __future__ import annotations

import dataclasses
from collections.abc import Mapping
from typing import Any

DEFAULT_EXPECT_MBPS: dict[str, float] = {
    "24/20": 60.0, "24/40": 100.0,
    "5/20": 120.0, "5/40": 240.0, "5/80": 450.0, "5/160": 800.0,
    "6/20": 140.0, "6/40": 280.0, "6/80": 520.0, "6/160": 900.0,
}
MAX_EVIDENCE_KIB = 256


@dataclasses.dataclass(frozen=True)
class Thresholds:
    none_score: int = 80
    wifi_rssi_dbm: float = -72.0
    wifi_snr_db: float = 20.0
    local_slow_pct: float = 50.0
    wifi_expect_mbps: Mapping[str, float] = dataclasses.field(default_factory=lambda: dict(DEFAULT_EXPECT_MBPS))
    wifi_util_pct: float = 70.0
    wifi_clients: int = 60
    roams: int = 2
    roam_slack_s: int = 300
    wired_errors: int = 100
    wired_speed_mbps: int = 100
    wan_util_pct: float = 85.0
    internet_loaded_ms: float = 250.0
    qos_limited_classes: tuple[int, ...] = (7, 8, 9, 10)
    dns_slow_ms: float = 500.0
    dns_slow_count: int = 3
    dns_cold_ms: float = 1000.0
    policy_min_events: int = 1
    network_wide_age_s: int = 120

    @classmethod
    def from_dict(cls, d: Mapping[str, Any] | None) -> Thresholds:
        d = dict(d or {})
        kw: dict[str, Any] = {}
        for f in dataclasses.fields(cls):
            if f.name not in d:
                continue
            v = d[f.name]
            if f.name == "wifi_expect_mbps":
                merged = dict(DEFAULT_EXPECT_MBPS)
                merged.update({str(k): float(x) for k, x in dict(v).items()})
                kw[f.name] = merged
            elif f.name == "qos_limited_classes":
                kw[f.name] = tuple(int(x) for x in v)
            elif f.type == "float":
                kw[f.name] = float(v)
            else:
                kw[f.name] = int(v)
        return cls(**kw)


@dataclasses.dataclass(frozen=True)
class SpeedtestSettings:
    enabled: bool = False
    speedtests: tuple[str, ...] = ()
    runners: tuple[str, ...] = ()
    retention_days: int = 30
    scrub_after_diagnosis: bool = False
    target_down_mbps: float = 25.0
    target_up_mbps: float = 10.0
    max_evidence_bytes: int = MAX_EVIDENCE_KIB * 1024
    stream_replay_s: int = 300
    window_before_s: int = 300
    window_after_s: int = 120
    finalize_after_s: int = 300
    metric_label_limit: int = 64
    thresholds: Thresholds = dataclasses.field(default_factory=Thresholds)

    @property
    def targets(self) -> dict[str, float]:
        return {"down_mbps": self.target_down_mbps, "up_mbps": self.target_up_mbps}

    @classmethod
    def from_config(cls, raw: Mapping[str, Any] | None) -> SpeedtestSettings:
        d = dict(raw or {})
        if not d:
            return cls()
        tg = d.get("targets") or {}
        win = d.get("correlation_window") or {}
        return cls(
            enabled=bool(d.get("enabled", False)),
            speedtests=tuple(d.get("speedtests", ())), runners=tuple(d.get("runners", ())),
            retention_days=int(d.get("retention_days", 30)),
            scrub_after_diagnosis=bool(d.get("scrub_after_diagnosis", False)),
            target_down_mbps=float(tg.get("down_mbps", 25.0)), target_up_mbps=float(tg.get("up_mbps", 10.0)),
            max_evidence_bytes=int(d.get("max_evidence_kib", MAX_EVIDENCE_KIB)) * 1024,
            stream_replay_s=int(d.get("stream_replay_s", 300)),
            window_before_s=int(win.get("before_s", 300)), window_after_s=int(win.get("after_s", 120)),
            finalize_after_s=int(d.get("finalize_after_s", 300)),
            metric_label_limit=int(d.get("metric_label_limit", 64)),
            thresholds=Thresholds.from_dict(d.get("diagnosis")),
        )
