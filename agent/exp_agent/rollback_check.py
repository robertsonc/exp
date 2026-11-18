#!/usr/bin/python3
"""Version-independent rollback checker (06-agent.md section 4). STANDALONE: stdlib only, no import from
exp_agent, so it keeps working whatever state either agent version is in.

Installed (atomic write, root 0755) by install.sh and by the agent's self-update as
/opt/exp/agent/rollback-check; exp-agent-rollback.service runs it every 5 minutes (exp-agent-rollback.timer).

  * no pending-update marker (/var/lib/exp/agent/pending.json), a malformed one, or no previous agent tree
    -> do nothing, exit 0 (this is the normal state on a fresh install);
  * marker younger than its deadline -> do nothing, exit 0;
  * otherwise flip /opt/exp/agent/current back to the `from` version, leave
    /var/lib/exp/agent/rolled_back.json (the restored agent reports `agent_rollback` from it and
    refuses that version), drop the marker and
    `systemctl --no-block restart exp-agent.service`.

Only paths under /opt/exp and /var/lib/exp are touched; symlinks are never followed when reading the marker
and the version trees are checked with lstat; no shell is ever involved.
"""

import json
import os
import re
import stat
import subprocess
import sys
import time

VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?\Z")  # as in exp_agent.pathguard
DEFAULT_WINDOW_S = 300.0
MAX_MARKER = 64 * 1024


def _read_marker(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        raw = os.read(fd, MAX_MARKER + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MARKER:
        return None
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _is_real_dir(path):
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _atomic_write(path, data, mode):
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def run(root="/", systemctl="systemctl", now=None):
    """Returns a short status: idle | waiting | rolled-back (exit code 0 for all of them)."""
    opt = os.path.join(root, "opt/exp/agent")
    state = os.path.join(root, "var/lib/exp/agent")
    pending = os.path.join(state, "pending.json")
    marker = _read_marker(pending)
    if marker is None:
        return "idle"
    prev, bad = marker.get("from"), marker.get("to")
    if not all(isinstance(v, str) and VERSION_RE.match(v) for v in (prev, bad)):
        return "idle"
    try:
        started = float(marker.get("started", 0))
        window = float(marker.get("deadline_s", DEFAULT_WINDOW_S))
    except (TypeError, ValueError):
        return "idle"
    if (time.time() if now is None else now) < started + window:
        return "waiting"
    if not _is_real_dir(os.path.join(opt, prev)):
        print(
            f"exp rollback-check: previous agent tree {prev} is missing; nothing to roll back to",
            file=sys.stderr,
        )
        return "idle"
    tmp = os.path.join(opt, f".current.{os.getpid()}.lnk")
    try:
        os.unlink(tmp)
    except OSError:
        pass
    os.symlink(prev, tmp)
    os.replace(tmp, os.path.join(opt, "current"))
    note = {"from": bad, "to": prev, "at": time.time() if now is None else now}
    _atomic_write(os.path.join(state, "rolled_back.json"), json.dumps(note, sort_keys=True).encode(), 0o600)
    os.unlink(pending)
    subprocess.run([systemctl, "--no-block", "restart", "exp-agent.service"], check=False, shell=False)  # noqa: S603
    print(f"exp rollback-check: agent {bad} did not report in time; restored {prev}")
    return "rolled-back"


def main(argv):
    root, systemctl = "/", "systemctl"
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--root" and args:
            root = args.pop(0)
        elif a == "--systemctl" and args:
            systemctl = args.pop(0)
        elif a in ("--config",) and args:
            args.pop(0)  # accepted for compatibility with `exp-agent rollback-check --config`
        else:
            print("usage: rollback-check [--root DIR] [--systemctl CMD]", file=sys.stderr)
            return 2
    try:
        run(root, systemctl)
    except OSError as exc:
        print(f"exp rollback-check: failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
