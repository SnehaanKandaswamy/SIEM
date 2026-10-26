from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import analyst, audit, client_ip, get_store, viewer
from ..models import SEVERITIES, Alert, Incident, IncidentHistory, IncidentNote, User
from ..schemas import IncidentCreate, IncidentUpdate, LinkAlerts, NoteIn

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

TRANSITIONS = {
    "open": {"investigating", "closed"},
    "investigating": {"resolved", "open"},
    "resolved": {"closed", "investigating"},
    "closed": set(),  # terminal; create a new incident instead
}


def _out(i: Incident) -> dict:
    return {
        "id": i.id,
        "title": i.title,
        "severity": i.severity,
        "status": i.status,
        "assignee": i.assignee.username if i.assignee else None,
        "assignee_id": i.assignee_id,
        "resolution_summary": i.resolution_summary,
        "created_by": i.created_by,
        "created_at": i.created_at,
        "updated_at": i.updated_at,
        "alert_count": len(i.alerts),
    }


def _hist(i: Incident, actor: str, action: str, detail: str = "") -> None:
    i.history.append(IncidentHistory(actor=actor, action=action, detail=detail[:1000]))


def _get(db: Session, incident_id: int) -> Incident:
    i = db.get(Incident, incident_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    return i


def _assignee(db: Session, user_id: int) -> User:
    u = db.get(User, user_id)
    if not u or not u.is_active or u.role == "viewer":
        raise HTTPException(422, "Assignee must be an active analyst or administrator")
    return u


@router.get("")
def list_incidents(
    status: list[str] = Query(default=[]),
    assignee_id: int | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
    _: User = Depends(viewer),
):
    conds = []
    if status:
        conds.append(Incident.status.in_(status))
    if assignee_id:
        conds.append(Incident.assignee_id == assignee_id)
    total = db.scalar(select(func.count()).select_from(Incident).where(*conds)) or 0
    rows = db.scalars(
        select(Incident)
        .where(*conds)
        .order_by(Incident.updated_at.desc(), Incident.id.desc())
        .offset((page - 1) * size)
        .limit(size)
    ).all()
    return {"total": total, "page": page, "size": size, "items": [_out(i) for i in rows]}


@router.post("", status_code=201)
def create_incident(body: IncidentCreate, request: Request, db: Session = Depends(get_db), me: User = Depends(analyst)):
    alerts = db.scalars(select(Alert).where(Alert.id.in_(body.alert_ids))).all()
    if len(alerts) != len(set(body.alert_ids)):
        raise HTTPException(404, "One or more alerts not found")
    sev = max((a.severity for a in alerts), key=SEVERITIES.index)
    inc = Incident(title=body.title, severity=sev, status="open", created_by=me.username, alerts=list(alerts))
    if body.assignee_id:
        inc.assignee_id = _assignee(db, body.assignee_id).id
    _hist(inc, me.username, "created", f"from alerts {sorted(body.alert_ids)}")
    db.add(inc)
    db.commit()
    audit(db, me.username, "incident_create", f"incident:{inc.id}", ip=client_ip(request))
    return _out(inc)


@router.get("/{incident_id}")
def detail(incident_id: int, db: Session = Depends(get_db), _: User = Depends(viewer)):
    i = _get(db, incident_id)
    ids: list[str] = []
    for a in i.alerts:
        ids.extend((a.event_ids or [])[-25:])
    events = get_store().get_many(list(dict.fromkeys(ids))[:200])
    events.sort(key=lambda e: e["@timestamp"])
    return {
        **_out(i),
        "alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "rule_id": a.rule_id,
                "last_seen": a.last_seen,
            }
            for a in i.alerts
        ],
        "notes": [{"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at} for n in i.notes],
        "history": [
            {"id": h.id, "actor": h.actor, "action": h.action, "detail": h.detail, "created_at": h.created_at}
            for h in i.history
        ],
        "events": events,
    }


@router.patch("/{incident_id}")
def update(
    incident_id: int, body: IncidentUpdate, request: Request, db: Session = Depends(get_db), me: User = Depends(analyst)
):
    i = _get(db, incident_id)
    if i.status == "closed":
        raise HTTPException(409, "Closed incidents are read-only")
    if body.resolution_summary is not None:
        i.resolution_summary = body.resolution_summary
        _hist(i, me.username, "resolution_summary_updated")
    if body.assignee_id is not None:
        u = _assignee(db, body.assignee_id)
        _hist(i, me.username, "assigned", f"{i.assignee.username if i.assignee else 'unassigned'} -> {u.username}")
        i.assignee_id, i.assignee = u.id, u
    if body.status and body.status != i.status:
        if body.status not in TRANSITIONS[i.status]:
            raise HTTPException(409, f"Transition {i.status} -> {body.status} is not allowed")
        if body.status in ("resolved", "closed") and not (i.resolution_summary or "").strip():
            raise HTTPException(422, "A resolution summary is required before resolving or closing")
        _hist(i, me.username, "status_changed", f"{i.status} -> {body.status}")
        i.status = body.status
    db.commit()
    audit(db, me.username, "incident_update", f"incident:{i.id}", ip=client_ip(request))
    return _out(i)


@router.post("/{incident_id}/notes", status_code=201)
def add_note(
    incident_id: int, body: NoteIn, request: Request, db: Session = Depends(get_db), me: User = Depends(analyst)
):
    i = _get(db, incident_id)
    if i.status == "closed":
        raise HTTPException(409, "Closed incidents are read-only")
    n = IncidentNote(author=me.username, body=body.body)
    i.notes.append(n)
    _hist(i, me.username, "note_added")
    db.commit()
    audit(db, me.username, "incident_note", f"incident:{i.id}", ip=client_ip(request))
    return {"id": n.id, "author": n.author, "body": n.body, "created_at": n.created_at}


@router.post("/{incident_id}/alerts", status_code=200)
def link_alerts(incident_id: int, body: LinkAlerts, db: Session = Depends(get_db), me: User = Depends(analyst)):
    i = _get(db, incident_id)
    if i.status == "closed":
        raise HTTPException(409, "Closed incidents are read-only")
    alerts = db.scalars(select(Alert).where(Alert.id.in_(body.alert_ids))).all()
    if len(alerts) != len(set(body.alert_ids)):
        raise HTTPException(404, "One or more alerts not found")
    have = {a.id for a in i.alerts}
    added = [a for a in alerts if a.id not in have]
    i.alerts.extend(added)
    i.severity = max([i.severity, *(a.severity for a in added)], key=SEVERITIES.index)
    _hist(i, me.username, "alerts_linked", str(sorted(a.id for a in added)))
    db.commit()
    return _out(i)
