"""Authentication: SSO handoff JWT, local PBKDF2 accounts, NOC tokens, throttling, credential reload.

Failure reasons are logged as short codes only: never a token, a password or a submitted body.
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from exp_common import creds as _creds
from exp_common import ids

from .config import Settings
from .sessions import Session, SessionStore

log = logging.getLogger(__name__)

ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 1}      # admin == operator on the dashboard
PBKDF2_PREFIX = "pbkdf2_sha256"
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 10_000_000
MAX_PASSWORD_CHARS = 1024
MAX_TOKEN_BYTES = 4096
JTI_TTL_S = 600
SKEW_S = 60
MAX_TOKEN_LIFETIME_S = 300
THROTTLE_WINDOW_S = 15 * 60
THROTTLE_PER_USER = 5
THROTTLE_PER_IP = 20
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@+-]{1,64}$")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


class AuthError(Exception):
    """Authentication refused. ``code`` is for logs/metrics only; clients get generic text."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Throttled(AuthError):
    def __init__(self, retry_after: int) -> None:
        super().__init__("throttled")
        self.retry_after = max(1, int(retry_after))


def clean_text(value: Any, limit: int = 128) -> str:
    """Printable, bounded text for logs and X-Exp-User (control characters removed)."""
    s = _CTRL_RE.sub("", str(value))
    return s[:limit]


def user_header(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._@+:-]", "_", name)[:128] or "unknown"


def b64url_decode(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ------------------------------------------------------------------------------------ passwords

def hash_password(password: str, iterations: int = 600_000, salt: bytes | None = None) -> str:
    salt = salt if salt is not None else os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return (f"{PBKDF2_PREFIX}${iterations}${base64.b64encode(salt).decode()}"
            f"${base64.b64encode(dk).decode()}")


def parse_hash(stored: Any) -> tuple[int, bytes, bytes] | None:
    if not isinstance(stored, str) or len(stored) > 512:
        return None
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] != PBKDF2_PREFIX or not parts[1].isdigit():
        return None
    iters = int(parts[1])
    if not MIN_ITERATIONS <= iters <= MAX_ITERATIONS:
        return None
    try:
        salt = base64.b64decode(parts[2], validate=True)
        dk = base64.b64decode(parts[3], validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(salt) < 8 or len(dk) < 16:
        return None
    return iters, salt, dk


def verify_password(password: str, stored: str) -> bool:
    parsed = parse_hash(stored)
    if parsed is None or len(password) > MAX_PASSWORD_CHARS:
        return False
    iters, salt, dk = parsed
    got = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=len(dk))
    return hmac.compare_digest(got, dk)


_DUMMY_HASH = hash_password("dummy-not-a-password", 600_000, b"\x00" * 16)


# ------------------------------------------------------------------------------------ SSO JWT

@dataclass(frozen=True)
class SsoClaims:
    sub: str
    name: str
    role: str
    jti: str


def verify_sso_token(token: str, secret: bytes, *, issuer: str, audience: str, now: float) -> SsoClaims:
    """Verify an HS256 handoff token (01-contracts.md section 12). Raises AuthError(code).
    Signature first (constant time), then claims. The jti is NOT consumed here."""
    if not isinstance(token, str) or not token or len(token.encode("utf-8", "replace")) > MAX_TOKEN_BYTES:
        raise AuthError("malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed")
    try:
        header = json.loads(b64url_decode(parts[0]))
        sig = b64url_decode(parts[2])
        payload_raw = b64url_decode(parts[1])
    except (ValueError, UnicodeDecodeError):
        raise AuthError("malformed") from None
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        raise AuthError("bad_alg")          # also rejects alg=none and every other algorithm
    want = hmac.new(secret, f"{parts[0]}.{parts[1]}".encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(want, sig):
        raise AuthError("bad_signature")
    try:
        claims = json.loads(payload_raw)
    except (ValueError, RecursionError):
        raise AuthError("malformed") from None
    if not isinstance(claims, dict):
        raise AuthError("malformed")
    if claims.get("iss") != issuer:
        raise AuthError("bad_iss")
    if claims.get("aud") != audience:
        raise AuthError("bad_aud")
    exp, iat = claims.get("exp"), claims.get("iat")
    for v in (exp, iat):
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or abs(v) > 4e10:
            raise AuthError("bad_time")
    if exp < now - SKEW_S:
        raise AuthError("expired")
    if iat > now + SKEW_S or exp - iat > MAX_TOKEN_LIFETIME_S or exp < iat:
        raise AuthError("bad_time")
    jti, sub, role = claims.get("jti"), claims.get("sub"), claims.get("role")
    if not isinstance(jti, str) or not 8 <= len(jti) <= 128:
        raise AuthError("bad_jti")
    if not isinstance(sub, str) or not 1 <= len(sub) <= 254 or _CTRL_RE.search(sub):
        raise AuthError("bad_sub")
    if role not in ROLES:
        raise AuthError("bad_role")
    name = claims.get("name")
    name = clean_text(name) if isinstance(name, str) and name else sub
    return SsoClaims(sub, name, role, jti)


class JtiCache:
    """Single-use jti cache (10 min). Bounded; entries are added only after a valid signature."""

    def __init__(self, clock: Callable[[], float] = time.time, limit: int = 50_000) -> None:
        self._clock, self._limit = clock, limit
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, jti: str) -> bool:
        """True the first time a jti is seen within the TTL."""
        now = self._clock()
        with self._lock:
            if len(self._seen) >= self._limit // 2:
                self._seen = {k: v for k, v in self._seen.items() if v > now}
            if len(self._seen) >= self._limit:
                return False                       # fail closed under flood
            if self._seen.get(jti, 0) > now:
                return False
            self._seen[jti] = now + JTI_TTL_S
            return True


# ------------------------------------------------------------------------------------ throttle

class LoginThrottle:
    """5 failures per username and 20 per IP within 15 minutes -> 429."""

    def __init__(self, clock: Callable[[], float] = time.time, window: float = THROTTLE_WINDOW_S,
                 per_user: int = THROTTLE_PER_USER, per_ip: int = THROTTLE_PER_IP) -> None:
        self._clock, self.window, self.per_user, self.per_ip = clock, window, per_user, per_ip
        self._users: dict[str, deque[float]] = {}
        self._ips: dict[str, deque[float]] = {}
        self._all: deque[float] = deque()          # failures, for the 1 h metric
        self._lock = threading.Lock()

    def _prune(self, d: dict[str, deque[float]], key: str, now: float) -> deque[float]:
        q = d.get(key)
        if q is None:
            return deque()
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            d.pop(key, None)
        return q

    def check(self, username: str | None, ip: str) -> None:
        now = self._clock()
        with self._lock:
            uq = self._prune(self._users, username.lower(), now) if username is not None else deque()
            iq = self._prune(self._ips, ip, now)
            waits = []
            if len(uq) >= self.per_user:
                waits.append(uq[0] + self.window - now)
            if len(iq) >= self.per_ip:
                waits.append(iq[0] + self.window - now)
        if waits:
            raise Throttled(max(waits))

    def fail(self, username: str | None, ip: str) -> None:
        now = self._clock()
        with self._lock:
            if username is not None:
                if len(self._users) > 20_000:
                    self._users.clear()
                self._users.setdefault(username.lower(), deque()).append(now)
            if len(self._ips) > 20_000:
                self._ips.clear()
            self._ips.setdefault(ip, deque()).append(now)
            self._all.append(now)

    def failures_last_hour(self) -> int:
        now = self._clock()
        with self._lock:
            while self._all and self._all[0] <= now - 3600:
                self._all.popleft()
            return len(self._all)


# ------------------------------------------------------------------------------- credential store

@dataclass(frozen=True)
class LocalUser:
    username: str
    role: str
    hash: str

    @property
    def binding(self) -> str:
        return hashlib.sha256(f"{self.hash}|{self.role}".encode()).hexdigest()[:24]


@dataclass(frozen=True)
class NocToken:
    id: str
    sha256: str
    label: str
    expires: float

    @property
    def binding(self) -> str:
        return self.sha256[:24]


@dataclass
class Creds:
    collector_tokens: dict[str, str] = field(default_factory=dict)
    sso_secret: bytes | None = None
    users: dict[str, LocalUser] = field(default_factory=dict)
    noc: list[NocToken] = field(default_factory=list)

    @property
    def sso_binding(self) -> str:
        return hashlib.sha256(self.sso_secret or b"").hexdigest()[:24]


def _parse_time(v: Any) -> float | None:
    if not isinstance(v, str):
        return None
    try:
        d = dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        return None
    return d.timestamp()


CRED_FILES = ("collector_tokens.json", "sso_secret", "local_users.json", "noc_tokens.json")


class CredentialStore:
    """Reads the credential files and reloads them when they change (stat stamp).

    Anything unreadable or malformed is treated as EMPTY (fail closed) and logged without content.
    ``on_change`` is called after each reload that changed something."""

    def __init__(self, settings: Settings, on_change: Callable[[Creds], None] | None = None) -> None:
        self.settings = settings
        self.on_change = on_change
        self._lock = threading.Lock()
        self._stamp: tuple | None = None
        self.creds = Creds()
        self.reload(force=True)

    def _stat_stamp(self) -> tuple:
        out = []
        for n in CRED_FILES:
            try:
                st = os.lstat(self.settings.creds_dir / n)
                out.append((n, st.st_mtime_ns, st.st_size, st.st_ino))
            except OSError:
                out.append((n, None))
        return tuple(out)

    def reload(self, force: bool = False) -> bool:
        with self._lock:
            stamp = self._stat_stamp()
            if not force and stamp == self._stamp:
                return False
            self._stamp = stamp
            new = self._load()
            self.creds = new
        log.info("credentials (re)loaded: %d local user(s), %d NOC token(s), %d collector token(s), sso=%s",
                 len(new.users), len(new.noc), len(new.collector_tokens), bool(new.sso_secret))
        if self.on_change is not None:
            self.on_change(new)
        return True

    def _json(self, name: str, kind: type) -> Any:
        try:
            doc = _creds.read_credential_json(name, self.settings.creds_dir)
        except _creds.CredentialMissing:
            return kind()
        except _creds.CredentialError as exc:
            if "not valid JSON" in str(exc) or "nested" in str(exc):
                log.error("credential %s is malformed; treated as empty", name)
            else:
                log.error("credential %s unusable (%s); treated as empty", name, exc)
            return kind()
        if not isinstance(doc, kind):
            log.error("credential %s has the wrong shape; treated as empty", name)
            return kind()
        return doc

    def _text(self, name: str) -> str:
        try:
            return _creds.read_credential(name, self.settings.creds_dir).strip()
        except _creds.CredentialMissing:
            return ""
        except _creds.CredentialError as exc:
            log.error("credential %s unusable (%s); treated as empty", name, exc)
            return ""

    def _load(self) -> Creds:
        c = Creds()
        for cid, tok in self._json("collector_tokens.json", dict).items():
            if isinstance(cid, str) and ids.is_token(tok, "expd"):
                c.collector_tokens[cid] = tok
            else:
                log.error("collector_tokens.json: ignoring malformed entry for %s", clean_text(cid, 64))
        raw = self._text("sso_secret")
        if raw:
            try:
                sec = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
            except (binascii.Error, ValueError):
                sec = b""
            if len(sec) == 32:
                c.sso_secret = sec
            else:
                log.error("sso_secret is not 32 bytes of base64; SSO disabled")
        for u in self._json("local_users.json", list):
            if not isinstance(u, dict):
                continue
            name, role, h = u.get("username"), u.get("role"), u.get("hash")
            if not (isinstance(name, str) and _USERNAME_RE.match(name)) or role not in ROLES \
                    or parse_hash(h) is None:
                log.error("local_users.json: ignoring invalid entry")
                continue
            if role == "admin":
                role = "operator"                   # admin is SSO-only on the dashboard
            c.users[name.lower()] = LocalUser(name, role, h)
        for t in self._json("noc_tokens.json", list):
            if not isinstance(t, dict):
                continue
            tid, sha, exp = t.get("id"), t.get("sha256"), _parse_time(t.get("expires"))
            if not (isinstance(tid, str) and 1 <= len(tid) <= 64 and _USERNAME_RE.match(tid)) \
                    or not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)) or exp is None:
                log.error("noc_tokens.json: ignoring invalid entry")
                continue
            c.noc.append(NocToken(tid, sha, clean_text(t.get("label", ""), 64), exp))
        return c

    # -- session validity against the CURRENT credentials ---------------------------------------
    def session_valid(self, s: Session, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        c = self.creds
        st = self.settings
        if s.kind == "local":
            u = c.users.get(s.subject.lower())
            return bool(st.local_users and u and u.binding == s.binding and u.role == s.role)
        if s.kind == "noc":
            if not st.noc_tokens:
                return False
            for t in c.noc:
                if t.id == s.subject:
                    return t.binding == s.binding and t.expires > now
            return False
        if s.kind == "sso":
            return bool(c.sso_secret and st.sso_issuer and c.sso_binding == s.binding)
        return False


# ------------------------------------------------------------------------------------- service

class AuthService:
    def __init__(self, settings: Settings, store: CredentialStore, sessions: SessionStore,
                 clock: Callable[[], float] = time.time) -> None:
        self.settings, self.store, self.sessions, self._clock = settings, store, sessions, clock
        self.throttle = LoginThrottle(clock)
        self.jti = JtiCache(clock)

    @property
    def ttl_s(self) -> float:
        return self.settings.session_hours * 3600.0

    def sso(self, token: Any) -> tuple[str, Session]:
        c = self.store.creds
        if not (c.sso_secret and self.settings.sso_issuer):
            raise AuthError("sso_disabled")
        if not isinstance(token, str):
            raise AuthError("malformed")
        claims = verify_sso_token(token, c.sso_secret, issuer=self.settings.sso_issuer,
                                  audience=self.settings.dashboard_id, now=self._clock())
        if not self.jti.consume(claims.jti):
            raise AuthError("replay")
        return self.sessions.create(kind="sso", subject=claims.sub, username=claims.sub,
                                    role=claims.role, binding=c.sso_binding, ttl_s=self.ttl_s)

    def login(self, username: Any, password: Any, ip: str) -> tuple[str, Session]:
        if not self.settings.local_users:
            raise AuthError("local_disabled")
        uname = username if isinstance(username, str) and 0 < len(username) <= 128 else None
        self.throttle.check(uname, ip)
        pw = password if isinstance(password, str) and 0 < len(password) <= MAX_PASSWORD_CHARS else None
        user = self.store.creds.users.get(uname.lower()) if uname else None
        # always burn one PBKDF2 so unknown users and bad inputs cost the same
        ok = verify_password(pw or "x", user.hash if user else _DUMMY_HASH)
        if not (ok and user and pw and uname):
            self.throttle.fail(uname, ip)
            raise AuthError("bad_credentials")
        return self.sessions.create(kind="local", subject=user.username, username=user.username,
                                    role=user.role, binding=user.binding, ttl_s=self.ttl_s)

    def noc(self, token: Any, ip: str) -> tuple[str, Session]:
        if not self.settings.noc_tokens:
            raise AuthError("noc_disabled")
        self.throttle.check(None, ip)
        found: NocToken | None = None
        if isinstance(token, str) and ids.is_token(token, "expn"):
            digest = ids.token_hash(token)
            for t in self.store.creds.noc:          # constant-time over every entry
                if ids.tokens_equal(digest, t.sha256):
                    found = t
        now = self._clock()
        if found is None or found.expires <= now:
            self.throttle.fail(None, ip)
            raise AuthError("bad_token")
        ttl = self.ttl_s
        return self.sessions.create(kind="noc", subject=found.id, username=f"noc:{found.id}",
                                    role="viewer", binding=found.binding, ttl_s=ttl,
                                    hard_ttl_s=found.expires - now)

    def renew_if_noc(self, s: Session) -> Session:
        if s.kind != "noc":
            return s
        return self.sessions.renew(s, self.ttl_s)
