import asyncio
import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .. import metrics
from ..config import get_settings
from ..db import get_db
from ..deps import analyst, get_store, ingest_credential, state, viewer
from ..ingest.pipeline import ingest_records
from ..models import User
from ..schemas import IngestBatch
from ..store import SearchError, SearchParams

router = APIRouter(prefix="/api", tags=["events"])
SLICE = 500


@router.post("/ingest")
async def ingest(request: Request, key: str = Depends(ingest_credential), db: Session = Depends(get_db)):
    s = get_settings()
    body = await request.body()
    if len(body) > s.ingest_max_body_bytes:
        metrics.EVENTS_REJECTED.labels(reason="too_large").inc()
        raise HTTPException(413, "Request body too large")
    try:
        payload = json.loads(body)
    except ValueError:
        metrics.EVENTS_REJECTED.labels(reason="bad_json").inc()
        raise HTTPException(400, "Body is not valid JSON") from None
    if isinstance(payload, list):  # Fluent Bit sends a bare JSON array of records
        payload = {
            "records": payload,
            "source_type": request.headers.get("x-source-type", "auto"),
            "host": request.headers.get("x-source-host", "unknown"),
        }
    try:
        batch = IngestBatch.model_validate(payload)
    except Exception as e:
        metrics.EVENTS_REJECTED.labels(reason="schema").inc()
        raise HTTPException(422, f"Invalid batch: {str(e)[:300]}") from None
    if len(batch.records) > s.ingest_max_batch:
        metrics.EVENTS_REJECTED.labels(reason="batch_size").inc()
        raise HTTPException(413, f"Batch exceeds {s.ingest_max_batch} records")
    totals = {"received": 0, "accepted": 0, "indexed": 0, "duplicates": 0, "rejected": 0, "alerts_created": 0}
    errors: list = []
    try:
        for i in range(0, len(batch.records), SLICE):  # bounded work per DB/search round trip
            res = await run_in_threadpool(
                ingest_records,
                db,
                get_store(),
                s,
                batch.records[i : i + SLICE],
                host=batch.host,
                source_type=None if batch.source_type == "auto" else batch.source_type,
                collector=request.headers.get("x-collector", batch.host),
                synthetic=batch.synthetic,
            )
            for k in totals:
                totals[k] += res[k]
            errors += [{**e, "index": e["index"] + i} for e in res["errors"]]
    except Exception:
        metrics.BACKGROUND_FAILURES.labels(task="indexing").inc()
        raise HTTPException(503, "Event storage unavailable; retry later") from None
    return {**totals, "errors": errors[:20]}


@router.get("/ingest/diagnostics")
def diagnostics(_: User = Depends(analyst)):
    return {"recent_parse_errors": list(state.parse_errors)[-50:]}


@router.get("/events/search")
def search(
    q: str = Query("", max_length=500),
    start: datetime | None = None,
    end: datetime | None = None,
    host: list[str] = Query(default=[]),
    source_type: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    category: list[str] = Query(default=[]),
    action: list[str] = Query(default=[]),
    outcome: list[str] = Query(default=[]),
    src_ip: str | None = Query(None, max_length=64),
    user: str | None = Query(None, max_length=128),
    synthetic: bool | None = None,
    page: int = Query(1, ge=1, le=1000),
    size: int = Query(50, ge=1, le=200),
    sort: str = Query("@timestamp", max_length=32),
    order: str = Query("desc"),
    _: User = Depends(viewer),
):
    if src_ip:
        from ..ingest.normalize import valid_ip

        if not valid_ip(src_ip):
            raise HTTPException(400, "src_ip is not a valid IP address")
    p = SearchParams(
        q=q,
        start=start,
        end=end,
        hosts=host,
        source_types=source_type,
        severities=severity,
        categories=category,
        actions=action,
        outcomes=outcome,
        src_ip=src_ip,
        user=user,
        synthetic=synthetic,
        page=page,
        size=size,
        sort_field=sort,
        sort_order=order,
    )
    try:
        total, hits = get_store().search(p)
    except SearchError as e:
        raise HTTPException(400, str(e)) from None
    except Exception:
        raise HTTPException(503, "Search backend unavailable") from None
    return {"total": total, "page": page, "size": size, "items": hits}


@router.get("/events/recent")
def recent(after: int = 0, limit: int = Query(100, ge=1, le=500), _: User = Depends(viewer)):
    """Polling fallback for the live stream."""
    items = [e for e in state.recent if e["seq"] > after][-limit:]
    return {"items": items, "last_seq": state.seq}


@router.get("/events/stream")
async def stream(request: Request, _: User = Depends(viewer)):
    """Server-sent events. Authenticated via the Authorization header (client uses fetch streaming)."""

    async def gen():
        last = state.seq
        yield "retry: 3000\n\n"
        idle = 0
        while not await request.is_disconnected():
            fresh = [e for e in state.recent if e["seq"] > last]
            if fresh:
                last = fresh[-1]["seq"]
                for e in fresh[-100:]:
                    yield f"id: {e['seq']}\ndata: {json.dumps(e, default=str)}\n\n"
                idle = 0
            else:
                idle += 1
                if idle % 15 == 0:
                    yield ": keepalive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(
        gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@router.get("/events/{event_id}")
def get_event(event_id: str, _: User = Depends(viewer)):
    if not event_id.isalnum() or len(event_id) > 64:
        raise HTTPException(400, "Invalid event id")
    hits = get_store().get_many([event_id])
    if not hits:
        raise HTTPException(404, "Event not found")
    return hits[0]


@router.get("/dashboard/overview")
def overview(minutes: int = Query(60, ge=5, le=1440), db: Session = Depends(get_db), _: User = Depends(viewer)):
    from sqlalchemy import func, select

    from ..models import Alert, CollectorStatus, Incident

    since = datetime.now(UTC) - timedelta(minutes=minutes)
    bucket = 1 if minutes <= 60 else 5 if minutes <= 360 else 15
    st = get_store().stats(since, bucket)
    sev = dict(
        db.execute(
            select(Alert.severity, func.count()).where(Alert.status != "resolved").group_by(Alert.severity)
        ).all()
    )
    by_rule = dict(
        db.execute(select(Alert.rule_id, func.count()).where(Alert.last_seen >= since).group_by(Alert.rule_id)).all()
    )
    inc = dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
    recent_alerts = db.scalars(select(Alert).order_by(Alert.last_seen.desc()).limit(8)).all()
    collectors = db.scalars(select(CollectorStatus).order_by(CollectorStatus.last_seen.desc())).all()
    now = datetime.now(UTC)
    return {
        "window_minutes": minutes,
        "events_total": st["total_all"],
        "events_window": st["total_window"],
        "events_per_minute": round(st["total_window"] / minutes, 2),
        "timeline": st["timeline"],
        "alerts_by_severity": sev,
        "detections_by_rule": by_rule,
        "incidents_by_status": inc,
        "top_src_ips": st["top_src_ips"],
        "top_hosts": st["top_hosts"],
        "by_source_type": st["by_source_type"],
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "last_seen": a.last_seen,
                "rule_id": a.rule_id,
                "status": a.status,
            }
            for a in recent_alerts
        ],
        "collectors": [
            {
                "name": c.name,
                "source_type": c.source_type,
                "events_total": c.events_total,
                "errors_total": c.errors_total,
                "last_seen": c.last_seen,
                "healthy": (now - c.last_seen).total_seconds() < 300,
            }
            for c in collectors
        ],
        "search_backend": get_store().health(),
    }


@router.get("/dashboard/geo")
def geo(minutes: int = Query(1440, ge=5, le=10080), _: User = Depends(viewer)):
    """Suspicious source locations: events that triggered detections, aggregated by located public IP."""
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    events = [e for e in get_store().fetch(since, {}, limit=5000) if e.get("detections") and e.get("src_ip")]
    agg: dict[str, dict] = {}
    unlocated = 0
    for e in events:
        g = e.get("geo") or {}
        if not g.get("located"):
            unlocated += 1
            continue
        a = agg.setdefault(
            e["src_ip"],
            {
                "ip": e["src_ip"],
                "country": g.get("country", ""),
                "city": g.get("city", ""),
                "lat": g["location"]["lat"],
                "lon": g["location"]["lon"],
                "count": 0,
                "rules": set(),
            },
        )
        a["count"] += 1
        a["rules"].update(e["detections"])
    pts = [{**a, "rules": sorted(a["rules"])} for a in agg.values()]
    return {"points": sorted(pts, key=lambda p: -p["count"]), "unlocated_events": unlocated}
