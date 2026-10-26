from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import admin, analyst, audit, client_ip, get_store, viewer
from ..detection.rules import validate_rule_config
from ..models import SEVERITIES, Alert, DetectionRule, User
from ..schemas import AlertDetail, AlertOut, RuleUpdate

router = APIRouter(prefix="/api", tags=["alerts"])

SORT_COLUMNS = {
    "last_seen": Alert.last_seen,
    "first_seen": Alert.first_seen,
    "severity": Alert.severity,
    "event_count": Alert.event_count,
    "status": Alert.status,
    "id": Alert.id,
}


def alert_filters(severity, status, rule_id, source, host, start, end, synthetic):
    conds = []
    if severity:
        conds.append(Alert.severity.in_(severity))
    if status:
        conds.append(Alert.status.in_(status))
    if rule_id:
        conds.append(Alert.rule_id.in_(rule_id))
    if source:
        conds.append(Alert.source == source)
    if host:
        conds.append(Alert.host == host)
    if start:
        conds.append(Alert.last_seen >= start)
    if end:
        conds.append(Alert.last_seen <= end)
    if synthetic is not None:
        conds.append(Alert.synthetic.is_(synthetic))
    return conds


@router.get("/alerts")
def list_alerts(
    severity: list[str] = Query(default=[]),
    status: list[str] = Query(default=[]),
    rule_id: list[str] = Query(default=[]),
    source: str | None = None,
    host: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    synthetic: bool | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    sort: str = "last_seen",
    order: str = "desc",
    db: Session = Depends(get_db),
    _: User = Depends(viewer),
):
    if sort not in SORT_COLUMNS or order not in ("asc", "desc"):
        raise HTTPException(400, "invalid sort")
    conds = alert_filters(severity, status, rule_id, source, host, start, end, synthetic)
    total = db.scalar(select(func.count()).select_from(Alert).where(*conds)) or 0
    col = SORT_COLUMNS[sort]
    if sort == "severity":  # sort by rank, not alphabetically
        from sqlalchemy import case

        col = case({s: i for i, s in enumerate(SEVERITIES)}, value=Alert.severity)
    q = select(Alert).where(*conds).order_by(col.desc() if order == "desc" else col.asc(), Alert.id.desc())
    rows = db.scalars(q.offset((page - 1) * size).limit(size)).all()
    return {"total": total, "page": page, "size": size, "items": [AlertOut.model_validate(r) for r in rows]}


def _get(db: Session, alert_id: int) -> Alert:
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    return a


@router.get("/alerts/{alert_id}")
def alert_detail(alert_id: int, db: Session = Depends(get_db), _: User = Depends(viewer)):
    a = _get(db, alert_id)
    events = get_store().get_many((a.event_ids or [])[-100:])
    events.sort(key=lambda e: e["@timestamp"])
    return {"alert": AlertDetail.model_validate(a), "events": events}


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge(alert_id: int, request: Request, db: Session = Depends(get_db), me: User = Depends(analyst)):
    a = _get(db, alert_id)
    if a.status != "open":
        raise HTTPException(409, f"Alert is {a.status}; only open alerts can be acknowledged")
    a.status, a.acknowledged_by = "acknowledged", me.username
    db.commit()
    audit(db, me.username, "alert_acknowledge", f"alert:{a.id}", ip=client_ip(request))
    return a


@router.post("/alerts/{alert_id}/resolve", response_model=AlertOut)
def resolve(alert_id: int, request: Request, db: Session = Depends(get_db), me: User = Depends(analyst)):
    a = _get(db, alert_id)
    if a.status == "resolved":
        raise HTTPException(409, "Alert already resolved")
    a.status, a.resolved_by = "resolved", me.username
    db.commit()
    audit(db, me.username, "alert_resolve", f"alert:{a.id}", ip=client_ip(request))
    return a


# ----------------------------------------------------------------- rules & MITRE
@router.get("/rules")
def list_rules(db: Session = Depends(get_db), _: User = Depends(viewer)):
    rows = db.scalars(select(DetectionRule).order_by(DetectionRule.rule_id)).all()
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "enabled": r.enabled,
            "severity": r.severity,
            "config": r.config,
            "mitre": r.mitre,
        }
        for r in rows
    ]


@router.patch("/rules/{rule_id}")
def update_rule(
    rule_id: str, body: RuleUpdate, request: Request, db: Session = Depends(get_db), me: User = Depends(admin)
):
    r = db.scalars(select(DetectionRule).where(DetectionRule.rule_id == rule_id)).first()
    if not r:
        raise HTTPException(404, "Rule not found")
    changes = []
    if body.enabled is not None:
        r.enabled = body.enabled
        changes.append(f"enabled={body.enabled}")
    if body.severity:
        r.severity = body.severity
        changes.append(f"severity={body.severity}")
    if body.config is not None:
        try:
            validate_rule_config(rule_id, body.config)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        r.config = {**(r.config or {}), **body.config}
        changes.append("config")
    db.commit()
    audit(db, me.username, "rule_update", rule_id, detail=", ".join(changes), ip=client_ip(request))
    return {"rule_id": r.rule_id, "enabled": r.enabled, "severity": r.severity, "config": r.config}


@router.get("/mitre")
def mitre(db: Session = Depends(get_db), _: User = Depends(viewer)):
    """Implemented technique mappings with live alert counts. Rules without a justified mapping are listed
    separately so coverage is never overstated."""
    rules = db.scalars(select(DetectionRule).order_by(DetectionRule.rule_id)).all()
    counts = {
        (r, s): c
        for r, s, c in db.execute(
            select(Alert.rule_id, Alert.severity, func.count()).group_by(Alert.rule_id, Alert.severity)
        )
    }
    techniques: dict[str, dict] = {}
    unmapped = []
    for r in rules:
        if not r.mitre:
            unmapped.append(
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "reason": "Indicator matches are not technique-specific; no mapping claimed.",
                }
            )
        for m in r.mitre:
            t = techniques.setdefault(
                m["technique_id"],
                {
                    **m,
                    "url": "https://attack.mitre.org/techniques/" + m["technique_id"].replace(".", "/") + "/",
                    "rules": [],
                    "alert_count": 0,
                    "by_severity": {},
                },
            )
            t["rules"].append({"rule_id": r.rule_id, "name": r.name, "enabled": r.enabled})
            for (rid, sev), c in counts.items():
                if rid == r.rule_id:
                    t["alert_count"] += c
                    t["by_severity"][sev] = t["by_severity"].get(sev, 0) + c
    return {
        "techniques": sorted(techniques.values(), key=lambda t: t["technique_id"]),
        "unmapped_rules": unmapped,
        "reference": "https://attack.mitre.org/",
    }
