"""Shared helpers for the runner tests (module name is unique on purpose: several components have their own conftest)."""
from __future__ import annotations

import copy
import json
import time
from pathlib import Path
from typing import Any

import fakes_common as fc
from exp_common import ids as exp_ids
from exp_common import speedtest as st_helpers

from exp_runner.config import RunnerConfig, parse_config

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "test" / "fixtures"
PIN = "DC:2B:CE:95:F2:A0:0C:B9:5B:3A:CF:F5:00:CB:0C:DE:E7:BD:CA:AC:63:CC:83:95:F6:30:EA:F1:27:34:6D:C6"


def load_fixture(rel: str) -> Any:
    return json.loads((FIX / rel).read_text("utf-8"))


def secret() -> str:
    """A per-test deterministic expk_ secret built at runtime (never committed)."""
    return fc.fixture_token("expk", "runner-tests")


def base_config(mist: bool = False, **corr: Any) -> dict[str, Any]:
    doc = copy.deepcopy(load_fixture("configs/runner.correlation.json"))
    c = doc["correlation"]
    c["sources"]["syslog"]["allow"] = ["127.0.0.0/8"]
    c["sources"]["syslog"]["listen"] = ["udp:5514", "tcp:5514"]
    if not mist:
        c["sources"].pop("mist", None)
    c["sources"].pop("ec", None)
    c["network"] = {"require_real_client_ip": True, "client_subnets": ["10.60.0.0/16"], "translated_addresses": ["10.0.0.2"],
                    "zone_subnets": [{"cidr": "10.60.0.0/16", "zone": "hall-b"}, {"cidr": "10.60.14.0/24", "zone": "hallb-row12"}]}
    c.pop("speedtest_channel", None)
    for k, v in corr.items():
        c[k] = v
    return doc


def make_cfg(mist: bool = False, **corr: Any) -> RunnerConfig:
    return parse_config(base_config(mist=mist, **corr))


def st_result(n: int = 1, *, now: float | None = None, ip: str = "10.60.14.77", site: str = "hall-b", server: str = "spd-core",
              age_s: float = 900.0) -> dict[str, Any]:
    """An ``exp.speedtest/1`` result that ended ``age_s - 20`` seconds ago (so its correlation window has closed)."""
    now = time.time() if now is None else now
    doc = copy.deepcopy(load_fixture("speedtest/result.ok.json"))
    doc["id"] = fc.det_id("st_", f"runner-test-{n}")
    doc["observed"]["server_id"], doc["site"], doc["client"]["ip"] = server, site, ip
    doc["started"] = fc.iso_from_epoch(now - age_s)
    doc["ended"] = fc.iso_from_epoch(now - age_s + 20)
    doc["observed"]["received_at"] = fc.iso_from_epoch(now - age_s + 21)
    doc["zone"], doc["zone_source"] = "unresolved", "unresolved"
    doc.pop("flags", None)
    assert exp_ids  # keep import used for token helpers below
    return doc


def runner_token(toks: dict[str, Any]) -> str:
    return toks["runner"]["runner-core"]["token"]


def device_key_of(mac: str) -> str:
    return st_helpers.device_key(secret(), mac)
