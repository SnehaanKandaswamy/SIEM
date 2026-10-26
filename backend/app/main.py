import logging
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import select, text

from . import metrics
from .config import get_settings
from .db import Base, engine, session_factory
from .deps import state
from .detection.engine import seed_rules
from .models import CollectorStatus, User
from .routers import admin, alerts, auth, events, incidents, reports
from .security import hash_password
from .store import build_store

log = logging.getLogger("siem")


def bootstrap(settings) -> None:
    """Explicit bootstrap only: an admin is created iff credentials are provided and no admin exists."""
    with session_factory()() as db:
        seed_rules(db)
        if settings.bootstrap_admin_username and settings.bootstrap_admin_password:
            if not db.scalars(select(User).where(User.role == "admin")).first():
                if len(settings.bootstrap_admin_password) < 12:
                    raise RuntimeError("SIEM_BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters")
                db.add(
                    User(
                        username=settings.bootstrap_admin_username,
                        email=settings.bootstrap_admin_email,
                        password_hash=hash_password(settings.bootstrap_admin_password),
                        role="admin",
                    )
                )
                db.commit()
                log.warning("bootstrap administrator '%s' created", settings.bootstrap_admin_username)


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    if len(s.jwt_secret) < 32:
        raise RuntimeError(
            'SIEM_JWT_SECRET must be set (>=32 chars). Generate with: python -c "import secrets;print(secrets.token_urlsafe(48))"'
        )
    if s.database_url.startswith("sqlite"):  # dev/test convenience; PostgreSQL schema is managed by Alembic
        Base.metadata.create_all(engine())
    if state.store is None:
        state.store = build_store(s)
    for attempt in range(1, 31):  # dependency readiness: wait for OpenSearch instead of assuming start order
        try:
            state.store.ensure_ready()
            break
        except Exception as e:
            log.warning("search backend not ready (attempt %d): %s", attempt, type(e).__name__)
            time.sleep(2)
    bootstrap(s)
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(
        title="SIEM Dashboard for DevOps",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs" if s.env != "production" else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if s.env != "production" else None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=s.cors_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Ingest-Key", "X-Collector"],
    )

    @app.middleware("http")
    async def observe(request: Request, call_next):
        start = time.perf_counter()
        status = 500
        try:
            resp = await call_next(request)
            status = resp.status_code
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Cache-Control"] = resp.headers.get("Cache-Control", "no-store")
            return resp
        finally:
            route = request.scope.get("route")
            path = getattr(route, "path", "unmatched")  # templated path -> bounded label cardinality
            metrics.HTTP_REQUESTS.labels(request.method, path, str(status)).inc()
            metrics.HTTP_LATENCY.labels(path).observe(time.perf_counter() - start)

    for r in (auth, events, alerts, incidents, reports, admin):
        app.include_router(r.router)

    @app.get("/healthz", tags=["health"])
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    def readyz(response: Response):
        checks = {}
        try:
            with engine().connect() as c:
                c.execute(text("SELECT 1"))
            checks["database"] = "ok"
            metrics.DB_UP.set(1)
        except Exception:
            checks["database"] = "down"
            metrics.DB_UP.set(0)
        try:
            h = state.store.health()
            checks["search"] = "ok" if h.get("status") in ("green", "yellow") else h.get("status", "down")
            metrics.SEARCH_UP.set(1 if checks["search"] == "ok" else 0)
        except Exception:
            checks["search"] = "down"
            metrics.SEARCH_UP.set(0)
        ready = all(v == "ok" for v in checks.values())
        if not ready:
            response.status_code = 503
        return {"status": "ready" if ready else "degraded", "checks": checks}

    @app.get("/metrics", include_in_schema=False)
    def prom():
        try:
            with session_factory()() as db:
                last = db.scalar(select(CollectorStatus.last_seen).order_by(CollectorStatus.last_seen.desc()).limit(1))
            if last:
                metrics.COLLECTOR_AGE.set((datetime.now(UTC) - last).total_seconds())
        except Exception:  # metrics must never break scraping
            log.debug("collector age unavailable")
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    return app


app = create_app()
