"""Speedtest (M6) reference helpers shared by speedtest, collector, runner and tests (stdlib only).

Contracts: ``docs/spec/01-contracts.md`` section 14, ``docs/spec/12-speedtest-analytics.md`` sections 4.2, 5.1,
7.1. Everything here is deterministic and side-effect free.

* ``new_speedtest_id`` / ``is_speedtest_id``  -- ``st_`` + ULID (the test id in ``/st/r/{id}``).
* ``compute_score``                            -- the exp score (0..100) of 12 section 4.2 with worked examples.
* ``counters_disagree``                        -- local-leg client-vs-server byte counter cross-check (> 20 %).
* ``device_key``                               -- HMAC-SHA256(per-org secret, MAC), the low-cardinality device key.
* ``new_view_key`` / ``view_proof`` / ``view_verifier`` / ``verify_view_proof`` -- the fragment-key scheme that
  authorizes the full result view without the key ever reaching a server log.
* Bounds (``MAX_MBPS`` ...) the schema and the server both enforce.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets
from collections.abc import Mapping
from typing import Any

from .ids import is_prefixed_id, new_id, token_hash, tokens_equal

# ----------------------------------------------------------------------------- bounds (12 section 7.1)
MAX_MBPS = 100_000.0          # 100 Gb/s
MAX_DURATION_S = 60.0         # any single client-reported duration
MAX_MS = MAX_DURATION_S * 1000.0
MAX_COMMENT_CHARS = 500
MAX_BYTES = 1 << 40           # 1 TiB: a sanity ceiling, the configured cap is far lower
COUNTER_TOLERANCE = 0.20      # > 20 % client/server disagreement => flag counters_disagree

# ----------------------------------------------------------------------------- score constants (12 section 4.2)
DEFAULT_TARGET_DOWN_MBPS = 25.0
DEFAULT_TARGET_UP_MBPS = 10.0
RESP_FULL_MS = 30.0           # 100 % responsiveness at or below this loaded latency
RESP_ZERO_MS = 300.0          # 0 % at or above this
CV_ZERO = 0.5                 # a coefficient of variation >= 0.5 makes the CV part of stability 0
FAILURE_PENALTY = 0.1         # each failed request subtracts 10 points of stability (floor 0)
WEIGHT_SPEED, WEIGHT_RESPONSIVENESS, WEIGHT_STABILITY = 40.0, 40.0, 20.0


def new_speedtest_id() -> str:
    """``st_`` + ULID."""
    return new_id("st_")


def is_speedtest_id(value: object) -> bool:
    return is_prefixed_id(value, "st_")


# ----------------------------------------------------------------------------- score
def _num(v: Any) -> float | None:
    """A finite non-negative number, else None (bool, str, NaN, inf, negative are all 'no data')."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    f = float(v)
    if not math.isfinite(f) or f < 0:
        return None
    return f


def _clamp01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else x


def _half_up(x: float) -> int:
    return int(math.floor(x + 0.5 + 1e-9))


def score_basis(legs: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]] | None:
    """The leg the score is computed from: the internet leg when it produced numbers (that is what the user
    actually gets), else the on-network leg, else None (no score). A leg counts when it has at least one of
    ``down_mbps`` / ``up_mbps``."""
    for name in ("internet", "local"):
        leg = legs.get(name)
        if isinstance(leg, Mapping) and (_num(leg.get("down_mbps")) is not None or _num(leg.get("up_mbps")) is not None):
            return name, leg
    return None


def compute_score(legs: Mapping[str, Any], targets: Mapping[str, Any] | None = None, failures: int = 0) -> dict[str, int] | None:
    """The exp score of a result's ``legs``: ``{"total","speed","responsiveness","stability"}`` (ints, 0..100) or
    ``None`` when no leg has any throughput number.

    total = 40 * speed + 40 * responsiveness + 20 * stability (each part 0..1), floored (a score never rounds up
    to the next point); the three parts are reported as rounded percentages.

    * speed          = mean of min(down / target_down, 1) and min(up / target_up, 1) over the directions that
                       were measured (one direction measured counts alone). Targets default 25 / 10 Mb/s.
    * responsiveness = 1 at <= 30 ms loaded latency, 0 at >= 300 ms, linear in between. Loaded latency is the
                       worse (larger) of ``loaded_down_ms`` and ``loaded_up_ms``; with neither, ``idle_ms`` is
                       used; with no latency at all the part is 0 (unknown responsiveness earns nothing).
    * stability      = (1 - cv / 0.5) clamped to 0..1, minus 0.1 per failed request (``failures``), floor 0;
                       a missing ``cv`` counts as 0.5 (no evidence of stability earns nothing).
    """
    basis = score_basis(legs)
    if basis is None:
        return None
    _name, leg = basis
    t = targets or {}
    td = _num(t.get("down_mbps")) or DEFAULT_TARGET_DOWN_MBPS
    tu = _num(t.get("up_mbps")) or DEFAULT_TARGET_UP_MBPS
    parts = []
    down, up = _num(leg.get("down_mbps")), _num(leg.get("up_mbps"))
    if down is not None:
        parts.append(_clamp01(down / td))
    if up is not None:
        parts.append(_clamp01(up / tu))
    speed = sum(parts) / len(parts)

    lat = [x for x in (_num(leg.get("loaded_down_ms")), _num(leg.get("loaded_up_ms"))) if x is not None]
    if not lat:
        idle = _num(leg.get("idle_ms"))
        lat = [idle] if idle is not None else []
    resp = 0.0 if not lat else _clamp01((RESP_ZERO_MS - max(lat)) / (RESP_ZERO_MS - RESP_FULL_MS))

    cv = _num(leg.get("cv"))
    cv = CV_ZERO if cv is None else cv
    stab = _clamp01(1.0 - cv / CV_ZERO)
    stab = _clamp01(stab - FAILURE_PENALTY * max(0, int(failures)))

    total = WEIGHT_SPEED * speed + WEIGHT_RESPONSIVENESS * resp + WEIGHT_STABILITY * stab
    return {"total": int(math.floor(total + 1e-9)), "speed": _half_up(speed * 100),
            "responsiveness": _half_up(resp * 100), "stability": _half_up(stab * 100)}


def counters_disagree(client_bytes: float, server_bytes: float, tolerance: float = COUNTER_TOLERANCE) -> bool:
    """True when the browser's byte count and the box's counter differ by more than ``tolerance`` (relative to the
    larger of the two). Two zero counters agree; one zero and one non-zero disagree. Bad inputs disagree
    (fail toward the flag)."""
    c, s = _num(client_bytes), _num(server_bytes)
    if c is None or s is None:
        return True
    big = max(c, s)
    if big == 0:
        return False
    return abs(c - s) / big > tolerance


# ----------------------------------------------------------------------------- device_key

def normalize_mac(mac: str) -> str:
    """Lower-case colon-separated MAC (accepts ``-``, ``.``-grouped and bare-hex spellings). ValueError otherwise."""
    if not isinstance(mac, str):
        raise ValueError("MAC must be a string")
    h = re.sub(r"[:.\-]", "", mac.strip().lower())
    if not re.fullmatch(r"[0-9a-f]{12}", h):
        raise ValueError("not a MAC address")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _secret_bytes(secret: str) -> bytes:
    """The 32 key bytes of an ``expk_`` secret."""
    if not isinstance(secret, str) or not secret.startswith("expk_"):
        raise ValueError("device_key secret must be an expk_ secret")
    body = secret[5:]
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", body):
        raise ValueError("malformed expk_ secret")
    return base64.urlsafe_b64decode(body + "=")


def device_key(secret: str, mac: str) -> str:
    """``HMAC-SHA256(secret_bytes, normalized MAC)`` as 64 lower-case hex chars: stable per device and org,
    not reversible without the secret. Only the runner (and the collector's purge tool) hold the secret."""
    return hmac.new(_secret_bytes(secret), normalize_mac(mac).encode("ascii"), hashlib.sha256).hexdigest()


# ----------------------------------------------------------------------------- result-page key (12 section 4.1)
VIEW_PROOF_PREFIX = "expv_"
_B64URL43 = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def new_view_key() -> str:
    """The fragment key ``k`` of ``/st/r/{id}#k=...``: 32 random bytes, base64url, 43 chars. Generated by the page;
    reproduced here for tests and tools. It never leaves the browser."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def view_proof(key: str, session_id: str) -> str:
    """``expv_`` + base64url(HMAC-SHA256(k_bytes, "exp.st.view/1:" + session_id)). The page derives this from the
    fragment key and sends it in ``X-Exp-View-Proof``; the key itself is never transmitted."""
    if not isinstance(key, str) or not _B64URL43.match(key):
        raise ValueError("malformed view key")
    if not is_speedtest_session_id(session_id):
        raise ValueError("malformed session id")
    mac = hmac.new(base64.urlsafe_b64decode(key + "="), ("exp.st.view/1:" + session_id).encode("ascii"), hashlib.sha256).digest()
    return VIEW_PROOF_PREFIX + base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def view_verifier(proof: str) -> str:
    """What the server stores at session creation: sha256 hex of the proof (the page computes the proof, hashes it and
    posts the hash as ``view_verifier``); the server never stores the proof or the key."""
    if not isinstance(proof, str) or not proof.startswith(VIEW_PROOF_PREFIX) or not _B64URL43.match(proof[5:]):
        raise ValueError("malformed view proof")
    return token_hash(proof)


def verify_view_proof(stored_verifier: str, presented_proof: str) -> bool:
    """Constant-time check of a presented proof against the stored verifier. Malformed input is False, never raises."""
    try:
        return tokens_equal(stored_verifier, view_verifier(presented_proof))
    except ValueError:
        return False


def is_speedtest_session_id(value: object) -> bool:
    """Session ids are the result id: ``st_`` + ULID (one session produces one test)."""
    return is_speedtest_id(value)
