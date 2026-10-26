from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import metrics
from ..config import get_settings
from ..db import get_db
from ..demo import flat
from ..deps import admin, audit, client_ip, get_store
from ..ingest.pipeline import ingest_records
from ..models import AuditLog, CollectorStatus, NotificationDelivery, User
from ..services import notify

router = APIRouter(prefix="/api", tags=["admin"])


@router.get("/admin/audit")
def audit_logs(
    action: str | None = None,
    actor: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(admin),
):
    conds = []
    if action:
        conds.append(AuditLog.action == action)
    if actor:
        conds.append(AuditLog.actor == actor)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*conds)) or 0
    rows = db.scalars(
        select(AuditLog).where(*conds).order_by(AuditLog.id.desc()).offset((page - 1) * size).limit(size)
    ).all()
    return {
        "total": total,
        "page": page,
        "size": size,
        "items": [
            {
                "id": r.id,
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "outcome": r.outcome,
                "detail": r.detail,
                "remote_ip": r.remote_ip,
                "created_at": r.created_at,
            }
            for r in rows
        ],
    }


@router.get("/admin/collectors")
def collectors(db: Session = Depends(get_db), _: User = Depends(admin)):
    now = datetime.now(UTC)
    return [
        {
            "name": c.name,
            "source_type": c.source_type,
            "events_total": c.events_total,
            "errors_total": c.errors_total,
            "last_seen": c.last_seen,
            "healthy": (now - c.last_seen).total_seconds() < 300,
        }
        for c in db.scalars(select(CollectorStatus).order_by(CollectorStatus.name))
    ]


@router.get("/admin/integrations")
def integrations(db: Session = Depends(get_db), _: User = Depends(admin)):
    """Reports configuration state only; secrets are never returned."""
    s = get_settings()
    stats = dict(
        db.execute(select(NotificationDelivery.status, func.count()).group_by(NotificationDelivery.status)).all()
    )
    return {
        "email": {
            "configured": bool(s.smtp_host and s.notify_email_to),
            "min_severity": s.notify_email_min_severity,
            "host": s.smtp_host,
            "to": s.notify_email_to,
        },
        "slack": {"configured": bool(s.slack_webhook_url), "min_severity": s.notify_slack_min_severity},
        "geoip": {"mmdb_configured": bool(s.geoip_db_path), "static_configured": bool(s.geoip_static_path)},
        "deliveries": stats,
        "environment": s.env,
    }


@router.post("/admin/integrations/test")
def test_notification(
    request: Request,
    channel: str = Query(pattern="^(email|slack)$"),
    db: Session = Depends(get_db),
    me: User = Depends(admin),
):
    s = get_settings()
    ch = notify.EmailChannel(s) if channel == "email" else notify.SlackChannel(s)
    if channel == "email" and not (s.smtp_host and s.notify_email_to):
        raise HTTPException(409, "Email is not configured")
    if channel == "slack" and not s.slack_webhook_url:
        raise HTTPException(409, "Slack is not configured")
    try:
        ch.send("[SIEM TEST] Notification test", "This is a test message from the SIEM Dashboard.")
        outcome = "success"
    except Exception as e:
        outcome = "failure"
        audit(db, me.username, "notification_test", channel, outcome, str(type(e).__name__), client_ip(request))
        raise HTTPException(502, f"Delivery failed: {type(e).__name__}") from None
    metrics.NOTIFICATIONS.labels(channel=channel, status="sent").inc()
    audit(db, me.username, "notification_test", channel, outcome, ip=client_ip(request))
    return {"status": "sent"}


@router.get("/admin/settings")
def system_settings(_: User = Depends(admin)):
    s = get_settings()
    return {
        "environment": s.env,
        "access_token_minutes": s.access_token_minutes,
        "ingest_max_batch": s.ingest_max_batch,
        "ingest_rate_per_minute": s.ingest_rate_per_minute,
        "detections_enabled": s.detections_enabled,
        "demo_endpoints_enabled": s.allow_demo_endpoints,
        "index_prefix": s.index_prefix,
        "retention_days": 30,
    }


@router.post("/demo/ingest")
def demo_ingest(request: Request, scenario: str = "all", db: Session = Depends(get_db), me: User = Depends(admin)):
    """Loads labelled synthetic events. Disabled unless SIEM_ALLOW_DEMO_ENDPOINTS=true (never in production)."""
    s = get_settings()
    if not s.allow_demo_endpoints or s.env == "production":
        raise HTTPException(403, "Demo endpoints are disabled")
    try:
        recs = flat(only=scenario)
    except SystemExit as e:
        raise HTTPException(400, str(e)) from None
    res = ingest_records(
        db, get_store(), s, recs, host="synthetic", source_type=None, collector="synthetic-generator", synthetic=True
    )
    audit(db, me.username, "demo_ingest", scenario, ip=client_ip(request))
    return res
