"""The collector's configuration: /etc/exm/collector.toml plus one file per probe in /etc/exm/probes.d/.

A probe file describes one source of results:

  kind = "linux"   an exm-probe VM, streamed over SSH from its management address
                   (the collector's key there may only run `exm stream`)
  kind = "mac"     a Wi-Fi laptop running the beta Mac agent; its results become
                   the Wi-Fi row of the board named in attach_to
  local = true     a probe on this same host (all-in-one): its results are read
                   in place, nothing is streamed

Each linux or local probe is a board on the dashboard. The board reads its own
results directory plus those of the laptops attached to it.
"""
from __future__ import annotations

import glob
import hashlib
import os
import re
import tomllib
import zoneinfo

from .version import version

DEFAULT_CONFIG = "/etc/exm/collector.toml"
PROBES_DIR = "/etc/exm/probes.d"
DATA_DIR = "/var/lib/exm-collector"
KEY_DIR = "/etc/exm/collector/keys"
USER = "exm-collector"
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
HOST = re.compile(r"[A-Za-z0-9.:-]{1,253}")
LOGIN = re.compile(r"[A-Za-z0-9._-]{1,64}")
VERSION = version()


class ConfigError(Exception):
    pass


def _probe(p: dict, where: str, data_dir: str) -> dict:
    name = p.get("name", "")
    if not NAME.fullmatch(str(name)):
        raise ConfigError(f"{where}: name {name!r} must be lower-case letters, digits and dashes (it names a unit and a directory)")
    kind = p.setdefault("kind", "linux")
    if kind not in ("linux", "mac"):
        raise ConfigError(f"{where}: kind must be linux or mac")
    p.setdefault("label", name)
    p["local"] = bool(p.get("local", False))
    if p["local"]:
        if kind != "linux":
            raise ConfigError(f"{where}: only a linux probe can be local")
        p.setdefault("results_dir", "/var/lib/exm/results")
    else:
        if not HOST.fullmatch(str(p.get("host", ""))):
            raise ConfigError(f"{where}: host = \"address\" is required (the probe's management address)")
        p.setdefault("user", "exm-stream" if kind == "linux" else "")
        if not LOGIN.fullmatch(str(p["user"])):
            raise ConfigError(f"{where}: user must be a login name")
        p.setdefault("port", 22)
        if not (isinstance(p["port"], int) and 0 < p["port"] < 65536):
            raise ConfigError(f"{where}: port must be a TCP port")
        p["results_dir"] = os.path.join(data_dir, "probes", name)
        p.setdefault("key", os.path.join(KEY_DIR, f"{name}_ed25519"))
        p.setdefault("known_hosts", os.path.join(KEY_DIR, "known_hosts"))
    if kind == "mac":
        if not NAME.fullmatch(str(p.get("attach_to", ""))):
            raise ConfigError(f"{where}: a mac probe needs attach_to = \"<linux probe name>\" (whose board shows its Wi-Fi row)")
        ssid = p.get("ssid")
        if ssid is not None and not (isinstance(ssid, str) and 1 <= len(ssid.encode()) <= 32 and ssid.isprintable()):
            raise ConfigError(f"{where}: ssid must be 1-32 bytes of printable text")
    return p


def load(path: str | None = None, probes_dir: str | None = None) -> dict:
    path = path or os.environ.get("EXM_COLLECTOR_CONFIG", DEFAULT_CONFIG)
    probes_dir = probes_dir or os.environ.get("EXM_PROBES_DIR", PROBES_DIR)
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        cfg = tomllib.loads(raw.decode("utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    cfg["_path"], cfg["_probes_dir"] = path, probes_dir
    data_dir = cfg.setdefault("data_dir", DATA_DIR)
    cfg.setdefault("retention_days", 14)
    cfg.setdefault("backfill_hours", 24)
    w = cfg.setdefault("web", {})
    w.setdefault("bind", "0.0.0.0")
    w.setdefault("port", 80)
    w.setdefault("voice", "sysadmin")
    w.setdefault("edge_label", "WAN edge")
    a = cfg.setdefault("alerts", {})
    if a.get("format", "slack") not in ("slack", "teams", "json"):
        raise ConfigError(f"{path}: [alerts] format must be slack, teams or json")
    try:
        zoneinfo.ZoneInfo(a.get("timezone", "UTC"))
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"{path}: [alerts] timezone {a.get('timezone')!r} is not a known zone (e.g. America/Chicago)")
    if a.get("board_url") and not re.fullmatch(r"https?://[^\s]+", a["board_url"]):
        raise ConfigError(f"{path}: [alerts] board_url must be an http(s) URL")

    probes, digest = [], hashlib.sha256(raw)
    for i, p in enumerate(cfg.pop("probe", [])):
        probes.append(_probe(dict(p), f"{path} [[probe]] #{i + 1}", data_dir))
    for f in sorted(glob.glob(os.path.join(probes_dir, "*.toml"))):
        with open(f, "rb") as fh:
            b = fh.read()
        digest.update(b)
        try:
            p = tomllib.loads(b.decode("utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{f}: {exc}") from exc
        p.setdefault("name", os.path.basename(f)[:-5])
        if p["name"] != os.path.basename(f)[:-5]:
            raise ConfigError(f"{f}: name {p['name']!r} must match the file name")
        probes.append(_probe(p, f, data_dir))
    names = [p["name"] for p in probes]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise ConfigError(f"probe names used twice: {', '.join(sorted(dup))}")
    boards = {p["name"] for p in probes if p["kind"] == "linux"}
    for p in probes:
        if p["kind"] == "mac" and p["attach_to"] not in boards:
            raise ConfigError(f"probe {p['name']}: attach_to {p['attach_to']!r} is not a linux probe here")
    cfg["probes"] = probes
    cfg["_ver"] = digest.hexdigest()[:12]
    return cfg


def get(cfg: dict, name: str) -> dict:
    for p in cfg["probes"]:
        if p["name"] == name:
            return p
    raise ConfigError(f"no probe named {name} (sudo exm-collector probe list)")


def boards(cfg: dict) -> list[dict]:
    return [p for p in cfg["probes"] if p["kind"] == "linux"]


def board_cfg(cfg: dict, board: dict) -> dict:
    """The view of one board that the dashboard hub and the alerter work from."""
    macs = [p for p in cfg["probes"] if p["kind"] == "mac" and p["attach_to"] == board["name"]]
    return {
        "probe_id": board["name"], "label": board["label"], "results_dir": board["results_dir"],
        "results_dirs": [board["results_dir"]] + [m["results_dir"] for m in macs],
        "remote": [{"name": m["name"], "label": m["label"], "ssid": m.get("ssid"), "results_dir": m["results_dir"]}
                   for m in macs],
        "state_dir": os.path.join(cfg["data_dir"], "state"), "web": cfg["web"], "alerts": cfg["alerts"],
        "incidents": os.path.join(cfg["data_dir"], "incidents", f"{board['name']}.jsonl"),
        "_path": cfg["_path"], "client": [],
    }


def state_path(cfg: dict, name: str) -> str:
    d = os.path.join(cfg["data_dir"], "state")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)
