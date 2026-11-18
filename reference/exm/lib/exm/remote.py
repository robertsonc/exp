"""The collector's followers: each probe's results, streamed in over SSH (exm-follow@<name>.service).

The collector holds a key each probe accepts only with a forced command:
  linux probes  `exm stream` (lib/exm/stream.py), as the exm-stream user; asked
                for everything since the last line this collector stored, so an
                outage on either side leaves no gap
  mac (beta)    mac/stream.sh, a tail of the laptop's one results file; asked
                for the Wi-Fi network to monitor too
The follower keeps one SSH session open, checks every line, and appends accepted
ones to /var/lib/exm-collector/probes/<name>/<day>/<test>.jsonl, where the
dashboard and the alerter read them like local results.

Every line is untrusted input, whatever sent it:
- timestamps must be well formed and not in the future;
- the test name becomes a file name, so it must be a plain identifier;
- probe_id is overwritten with the configured name;
- lines already stored are dropped.
Laptop lines are rebuilt from a fixed schema (types checked, numbers finite,
strings and maps bounded, unknown keys dropped). Probe lines carry every test's
own structure, so they are bounded instead: depth, sizes, finite numbers. Either
way, a bad line costs only itself.
"""
from __future__ import annotations

import datetime
import fcntl
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time

from . import collector as K
from . import config as C
from . import tail

ALLOWED_TESTS = {"wifi_hb", "wifi_app", "wifi_speed"}          # what a laptop may send
TEST_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")                   # what a probe may send: it names a file
MAX_LINE = 16384
P_MAX_LINE, P_MAX_DEPTH, P_MAX_STR, P_MAX_LIST, P_MAX_KEYS, P_MAX_ABS = 262144, 10, 4096, 5000, 500, 1e15
DEDUP_WINDOW_S = 300            # a probe's files interleave: lines this close to the newest may still arrive
DEDUP_MAX = 50000               # hard cap on remembered keys, whatever a probe sends
RESUME_OVERLAP_S = 120          # ask for a little before the newest stored line on reconnect
TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
FUTURE_SLACK_S = 300

OUTCOMES = {C.OK, C.DEGRADED, C.FAIL, C.PORTAL, C.HARNESS}
SHORT_FIELDS = ("client_id", "iface", "vlan", "zone", "target", "resolver", "agent_ver", "config_ver", "hw_class")
MAX_STR, MAX_ERROR, MAX_KEYS, MAX_LIST = 200, 500, 40, 10
MAX_ABS = 1e12


class Refused(ValueError):
    pass


def _reject_constant(name):
    raise Refused(f"non-finite number {name}")


def _num(x) -> bool:
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return False
    return math.isfinite(x) and abs(x) <= MAX_ABS


def _key(k) -> str:
    if not (isinstance(k, str) and 0 < len(k) <= 40):
        raise Refused("bad key")
    return k


def _phase_ms(d) -> dict:
    if d is None:
        return {}
    if not isinstance(d, dict) or len(d) > MAX_KEYS:
        raise Refused("phase_ms is not a small map")
    out = {}
    for k, v in d.items():
        if v is not None and not _num(v):
            raise Refused(f"phase_ms.{str(k)[:40]} is not a number")
        out[_key(k)] = v
    return out


def _scalar(v, where: str):
    if v is None or isinstance(v, bool) or _num(v):
        return v
    if isinstance(v, str) and len(v) <= MAX_STR:
        return v
    raise Refused(f"{where} is not a short scalar")


def _value(d) -> dict:
    if d is None:
        return {}
    if not isinstance(d, dict) or len(d) > MAX_KEYS:
        raise Refused("value is not a small map")
    out = {}
    for k, v in d.items():
        where = f"value.{str(k)[:40]}"
        if isinstance(v, list):
            if len(v) > MAX_LIST:
                raise Refused(f"{where} is too long")
            out[_key(k)] = [_scalar(x, where) for x in v]
        else:
            out[_key(k)] = _scalar(v, where)
    return out


def _clean(ev: dict, test: str, ts: str, emitted: str, name: str) -> dict:
    """The accepted event, rebuilt from the schema. ts first: the tail reader depends on it."""
    outcome = ev.get("outcome")
    if outcome not in OUTCOMES:
        raise Refused(f"outcome {str(outcome)[:40]!r} is not known")
    err = ev.get("error")
    if err is not None and not isinstance(err, str):
        raise Refused("error is not text")
    out = {"ts": ts, "probe_id": name, "test": test}
    for k in SHORT_FIELDS:
        v = ev.get(k)
        if v is not None:
            if not isinstance(v, str) or len(v) > MAX_STR:
                raise Refused(f"{k} is not short text")
            out[k] = v
    out.update(outcome=outcome, phase_ms=_phase_ms(ev.get("phase_ms")), value=_value(ev.get("value")),
               error=err[:MAX_ERROR] if err else None, source=f"remote:{name}", emitted=emitted)
    return out


def _bounded(x, depth: int = 0) -> None:
    """A probe line's structure, bounded: nothing the dashboard and the alerter can choke on."""
    if depth > P_MAX_DEPTH:
        raise Refused("nested too deep")
    if x is None or isinstance(x, bool):
        return
    if isinstance(x, (int, float)):
        if not (math.isfinite(x) and abs(x) <= P_MAX_ABS):
            raise Refused("number out of range")
        return
    if isinstance(x, str):
        if len(x) > P_MAX_STR:
            raise Refused("string too long")
        return
    if isinstance(x, list):
        if len(x) > P_MAX_LIST:
            raise Refused("list too long")
        for v in x:
            _bounded(v, depth + 1)
        return
    if isinstance(x, dict):
        if len(x) > P_MAX_KEYS:
            raise Refused("map too big")
        for k, v in x.items():
            if not (isinstance(k, str) and 0 < len(k) <= 128):
                raise Refused("bad key")
            _bounded(v, depth + 1)
        return
    raise Refused("unexpected type")


def _probe_line(ev: dict, test: str, ts: str, emitted: str, name: str) -> dict:
    """An accepted probe event: bounded, outcome known, renamed to the configured probe, ts first."""
    if ev.get("outcome") not in OUTCOMES:
        raise Refused(f"outcome {str(ev.get('outcome'))[:40]!r} is not known")
    _bounded(ev)
    out = {"ts": ts}
    out.update((k, v) for k, v in ev.items() if k != "ts")
    out.update(probe_id=name, test=test, source=f"probe:{name}", emitted=emitted)
    return out


def _iso_minus(iso: str, seconds: int) -> str:
    t = datetime.datetime.fromisoformat(iso.replace("Z", "+00:00")) - datetime.timedelta(seconds=seconds)
    return t.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Ingest:
    """Checks and stores one probe's lines. policy: "probe" (an exm-probe) or "wifi" (a laptop)."""

    def __init__(self, out_dir: str, state: str, name: str, policy: str = "wifi"):
        self.out_dir, self.state, self.name, self.policy = out_dir, state, name, policy
        try:
            with open(self.state) as fh:
                st = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            st = {}
        self.hwm = st.get("hwm") or st.get("last_emitted", "")     # the newest emitted time stored
        self.floor = _iso_minus(self.hwm, DEDUP_WINDOW_S) if self.hwm else ""
        self.recent: dict[int, str] = {}
        self.saved_at = 0.0
        if policy == "probe" and self.hwm:
            self._remember_stored()

    def _remember_stored(self) -> None:
        """After a restart, the lines already stored near the cursor, so the resume overlap isn't stored twice."""
        floor = datetime.datetime.fromisoformat(self.floor.replace("Z", "+00:00"))
        since = floor - datetime.timedelta(seconds=tail.SLACK_S)
        for day in sorted({since.date().isoformat(), datetime.datetime.now(datetime.timezone.utc).date().isoformat()}):
            d = os.path.join(self.out_dir, day)
            for f in (sorted(os.listdir(d)) if os.path.isdir(d) else []):
                if f.endswith(".jsonl"):
                    for ev in tail.lines_since(os.path.join(d, f), since):
                        emitted = ev.get("emitted") or ev.get("ts")
                        if isinstance(emitted, str) and emitted > self.floor:
                            self.recent[hash((emitted, str(ev.get("test")), str(ev.get("client_id")), str(ev.get("target")),
                                              str(ev.get("resolver"))))] = emitted

    def save(self, force: bool = False) -> None:
        if not force and time.time() - self.saved_at < 2:
            return
        with open(self.state + ".tmp", "w") as fh:
            json.dump({"hwm": self.hwm, "last_emitted": self.hwm}, fh)
        os.replace(self.state + ".tmp", self.state)
        self.saved_at = time.time()

    def cursor(self, backfill_hours: float) -> str:
        """Where to ask the probe to resume: just before the newest stored line, within the backfill limit."""
        now = datetime.datetime.now(datetime.timezone.utc)
        floor = (now - datetime.timedelta(hours=backfill_hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if not self.hwm:
            return floor
        return max(floor, _iso_minus(self.hwm, RESUME_OVERLAP_S))

    def _seen(self, ev: dict, emitted: str) -> bool:
        if self.policy == "wifi":
            return emitted <= self.hwm                  # one file, written in order
        if emitted <= self.floor:
            return True
        k = hash((emitted, str(ev.get("test")), str(ev.get("client_id")), str(ev.get("target")), str(ev.get("resolver"))))
        if k in self.recent:
            return True
        self.recent[k] = emitted
        if len(self.recent) > DEDUP_MAX:          # checked on every insert: lines that never advance hwm can't grow it
            self.recent = {x: v for x, v in self.recent.items() if v > self.floor}
            if len(self.recent) > DEDUP_MAX:
                keep = sorted(self.recent.items(), key=lambda kv: kv[1])[-DEDUP_MAX // 2:]
                self.recent = dict(keep)
        return False

    def line(self, raw: bytes) -> str | None:
        """Ingest one line. Returns None when stored, else why it was refused."""
        if len(raw) > (P_MAX_LINE if self.policy == "probe" else MAX_LINE):
            return "line too long"
        try:
            ev = json.loads(raw, parse_constant=_reject_constant)
        except Refused as exc:
            return str(exc)
        except (ValueError, RecursionError):              # JSONDecodeError and UnicodeDecodeError are ValueErrors
            return "not JSON"
        if not isinstance(ev, dict):
            return "not a JSON object"
        test = ev.get("test")
        if self.policy == "wifi" and test not in ALLOWED_TESTS:
            return f"test {str(test)[:40]!r} is not accepted from a laptop"
        if self.policy == "probe" and not (isinstance(test, str) and TEST_NAME.fullmatch(test)):
            return f"test {str(test)[:40]!r} is not a plain name"
        ts, emitted = ev.get("ts"), ev.get("emitted") or ev.get("ts")
        if not (isinstance(ts, str) and TS.match(ts) and isinstance(emitted, str) and TS.match(emitted)):
            return "bad timestamp"
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=FUTURE_SLACK_S)
        if emitted > future.isoformat(timespec="milliseconds").replace("+00:00", "Z"):
            return "timestamp in the future (clock skew?)"
        if self._seen(ev, emitted):
            return "duplicate"
        try:
            out = _probe_line(ev, test, ts, emitted, self.name) if self.policy == "probe" else _clean(ev, test, ts, emitted, self.name)
        except Refused as exc:
            return str(exc)
        except RecursionError:
            return "nested too deep"
        day_dir = os.path.join(self.out_dir, ts[:10])
        os.makedirs(day_dir, mode=0o755, exist_ok=True)
        fd = os.open(os.path.join(day_dir, f"{test}.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, (json.dumps(out, separators=(",", ":"), allow_nan=False) + "\n").encode())
        finally:
            os.close(fd)
        if emitted > self.hwm:
            self.hwm = emitted
            self.floor = _iso_minus(emitted, DEDUP_WINDOW_S)
        self.save()
        return None


def ensure_key(key: str, name: str) -> str:
    """Create the collector's key for a probe if missing; return the public key line."""
    os.makedirs(os.path.dirname(key), mode=0o700, exist_ok=True)
    if not os.path.exists(key):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"exm-collector@{os.uname().nodename}:{name}",
                        "-f", key], check=True)
    with open(key + ".pub") as fh:
        return fh.read().strip()


def stream_command(r: dict) -> str:
    """What we ask a laptop's forced command for: the stream, plus the network to monitor (hex, so any SSID is safe)."""
    return "stream" + (f" ssid-hex={r['ssid'].encode().hex()}" if r.get("ssid") else "")


def follow(cfg: dict, name: str) -> int:
    """Keep one probe's stream flowing into the collector, reconnecting with backoff."""
    p = K.get(cfg, name)
    if p["local"]:
        raise SystemExit(f"exm-collector: {name} is local; its results are read in place, nothing to follow")
    os.makedirs(p["results_dir"], mode=0o755, exist_ok=True)
    policy = "wifi" if p["kind"] == "mac" else "probe"
    ing = Ingest(p["results_dir"], K.state_path(cfg, f"follow-{name}.json"), name, policy)
    backoff = 5
    while True:
        command = stream_command(p) if policy == "wifi" else f"stream since={ing.cursor(float(cfg['backfill_hours']))}"
        argv = ["ssh", "-T", "-p", str(p["port"]), "-i", p["key"], "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={p['known_hosts']}",
                "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "-o", "ConnectTimeout=10",
                "-o", "LogLevel=ERROR", f"{p['user']}@{p['host']}", command]
        with tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err)
            print(f"follow {name}: connecting to {p['user']}@{p['host']} ({command})", flush=True)
            stored = refused = dup = 0
            last_note = 0.0
            for raw in proc.stdout:
                why = ing.line(raw.rstrip(b"\r\n"))
                if why is None:
                    stored += 1
                    backoff = 5
                elif why == "duplicate":
                    dup += 1
                else:
                    refused += 1
                    if time.time() - last_note > 60:       # say why, but never flood the journal
                        print(f"follow {name}: refused a line: {why}", flush=True)
                        last_note = time.time()
            rc = proc.wait()
            ing.save(force=True)
            err.seek(0)
            msg = err.read().decode(errors="replace").strip().splitlines()[-1:] or [""]
        print(f"follow {name}: stream ended (exit {rc}) after {stored} new, {dup} already stored and {refused} refused "
              f"lines; {msg[0][:200]} retrying in {backoff}s", flush=True)
        time.sleep(backoff)
        backoff = min(backoff * 2, 60)
