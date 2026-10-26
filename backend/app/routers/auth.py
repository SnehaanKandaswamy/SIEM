import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..deps import admin, audit, client_ip, current_user
from ..models import User
from ..schemas import LoginIn, RefreshIn, TokenOut, UserCreate, UserOut, UserUpdate
from ..security import create_token, decode_token, hash_password, limiter, verify_password

router = APIRouter(prefix="/api", tags=["auth"])

# Hash used to equalise timing when the username does not exist.
_DUMMY = hash_password("not-a-real-password")


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    if not limiter.allow(f"login:{ip}", get_settings().login_rate_per_minute):
        audit(db, body.username, "login", outcome="rate_limited", ip=ip)
        raise HTTPException(429, "Too many login attempts; try again later")
    user = db.scalars(select(User).where(User.username == body.username)).first()
    ok = verify_password(body.password, user.password_hash if user else _DUMMY)
    if not (user and ok and user.is_active):
        audit(db, body.username, "login", outcome="failure", ip=ip)
        raise HTTPException(401, "Invalid credentials")
    audit(db, user.username, "login", outcome="success", ip=ip)
    return TokenOut(
        access_token=create_token(user.username, user.role),
        role=user.role,
        username=user.username,
        refresh_token=create_token(user.username, user.role, "refresh"),
    )


@router.post("/auth/refresh", response_model=TokenOut)
def refresh(body: RefreshIn, db: Session = Depends(get_db)):
    try:
        data = decode_token(body.refresh_token, "refresh")
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid refresh token") from None
    user = db.scalars(select(User).where(User.username == data["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(401, "Unknown or disabled user")
    return TokenOut(
        access_token=create_token(user.username, user.role),
        role=user.role,
        username=user.username,
        refresh_token=create_token(user.username, user.role, "refresh"),
    )


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(admin)):
    return db.scalars(select(User).order_by(User.id)).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)):
    if db.scalars(select(User).where(User.username == body.username)).first():
        raise HTTPException(409, "Username already exists")
    u = User(username=body.username, email=body.email, password_hash=hash_password(body.password), role=body.role)
    db.add(u)
    db.commit()
    audit(db, me.username, "user_create", body.username, detail=f"role={body.role}", ip=client_ip(request))
    return u


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int, body: UserUpdate, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)
):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "User not found")
    if u.id == me.id and (body.is_active is False or (body.role and body.role != "admin")):
        raise HTTPException(400, "Administrators cannot demote or disable themselves")
    changes = []
    if body.role:
        u.role = body.role
        changes.append(f"role={body.role}")
    if body.is_active is not None:
        u.is_active = body.is_active
        changes.append(f"active={body.is_active}")
    if body.password:
        u.password_hash = hash_password(body.password)
        changes.append("password reset")
    db.commit()
    audit(db, me.username, "user_update", u.username, detail=", ".join(changes), ip=client_ip(request))
    return u
