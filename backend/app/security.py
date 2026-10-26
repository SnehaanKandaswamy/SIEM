import hmac
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher

from .config import get_settings

_ph = PasswordHasher()


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except Exception:  # mismatch, invalid hash, etc. -> never reveal why
        return False


def _secret() -> str:
    s = get_settings().jwt_secret
    if len(s) < 32:
        raise RuntimeError("SIEM_JWT_SECRET must be set to at least 32 characters")
    return s


def create_token(username: str, role: str, kind: str = "access") -> str:
    st = get_settings()
    if kind == "access":
        delta = timedelta(minutes=st.access_token_minutes)
    else:
        delta = timedelta(days=st.refresh_token_days)
    payload = {"sub": username, "role": role, "typ": kind, "exp": datetime.now(UTC) + delta}
    return jwt.encode(payload, _secret(), algorithm=st.jwt_algorithm)


def decode_token(token: str, kind: str = "access") -> dict:
    data = jwt.decode(token, _secret(), algorithms=[get_settings().jwt_algorithm])
    if data.get("typ") != kind:
        raise jwt.InvalidTokenError("wrong token type")
    return data


def key_matches(candidate: str, valid: list[str]) -> bool:
    ok = False
    for k in valid:
        ok |= hmac.compare_digest(candidate.encode(), k.encode())
    return ok


class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary string (in-process, per worker)."""

    def __init__(self) -> None:
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if len(self.hits) > 10_000:  # bound memory
            self.hits.pop(next(iter(self.hits)))
        return True

    def reset(self) -> None:
        self.hits.clear()


limiter = RateLimiter()
