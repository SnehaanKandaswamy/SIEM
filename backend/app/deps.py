"""Shared FastAPI dependencies: auth, RBAC, audit, ingest credentials, app state."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import AuditLog, User
from .security import decode_token, key_matches, limiter
from .store import EventStore

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class AppState:
    store: EventStore | None = None
    seq: int = 0
    recent: deque = field(default_factory=lambda: deque(maxlen=500))  # bounded live-stream buffer
    parse_errors: deque = field(default_factory=lambda: deque(maxlen=200))


state = AppState()


def get_store() -> EventStore:
    assert state.store is not None, "store not initialised"
    return state.store


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def audit(
    db: Session, actor: str, action: str, target: str = "", outcome: str = "success", detail: str = "", ip: str = ""
) -> None:
    db.add(
        AuditLog(
            actor=actor[:64],
            action=action,
            target=target[:128],
            outcome=outcome,
            detail=detail[:1000],
            remote_ip=ip[:64],
        )
    )
    db.commit()


def current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", headers={"WWW-Authenticate": "Bearer"})
    try:
        data = decode_token(authorization[7:].strip())
    except (jwt.PyJWTError, RuntimeError):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from None
    user = db.scalars(select(User).where(User.username == data["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or disabled user")
    return user  # role is read from the DB, not the token, so demotions apply immediately


def require(role: str):
    need = ROLE_RANK[role]

    def dep(user: User = Depends(current_user)) -> User:
        if ROLE_RANK.get(user.role, 0) < need:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role '{role}' or higher")
        return user

    return dep


viewer = require("viewer")
analyst = require("analyst")
admin = require("admin")


def ingest_credential(request: Request, x_ingest_key: str | None = Header(default=None)) -> str:
    s = get_settings()
    if not x_ingest_key or not s.ingest_keys or not key_matches(x_ingest_key, s.ingest_keys):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid ingest credentials")
    if not limiter.allow("ingest:" + x_ingest_key[:8], s.ingest_rate_per_minute):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Ingest rate limit exceeded")
    return x_ingest_key[:4] + "…"
