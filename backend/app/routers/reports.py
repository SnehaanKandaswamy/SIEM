"""CSV and PDF exports. Authorised (analyst+), filter-aware and size-limited."""

import csv
import io
from datetime import UTC, datetime
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import analyst, audit, client_ip, get_store
from ..models import Alert, Incident, User
from ..store import SearchParams
from .alerts import alert_filters

router = APIRouter(prefix="/api/reports", tags=["reports"])
MAX_ROWS = 5000
CSV_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def _cell(v) -> str:
    """Neutralise spreadsheet formula injection from untrusted log text."""
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(CSV_DANGEROUS) else s


def _csv(headers: list[str], rows: list[list]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(headers)
    for r in rows:
        w.writerow([_cell(c) for c in r])
    return buf.getvalue().encode("utf-8")


def _pdf(title: str, subtitle: str, headers: list[str], rows: list[list], widths: list[float] | None = None) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=landscape(A4), title=title, leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24
    )
    ss = getSampleStyleSheet()
    cell = ss["BodyText"].clone("cell", fontSize=7, leading=9)
    data = [[Paragraph(f"<b>{escape(h)}</b>", cell) for h in headers]]
    data += [[Paragraph(escape(str(c if c is not None else ""))[:300], cell) for c in r] for r in rows]
    t = Table(data, repeatRows=1, colWidths=widths)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    doc.build([Paragraph(escape(title), ss["Title"]), Paragraph(escape(subtitle), ss["Normal"]), Spacer(1, 10), t])
    return buf.getvalue()


def _respond(fmt: str, name: str, title: str, subtitle: str, headers: list[str], rows: list[list]) -> Response:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    if fmt == "csv":
        return Response(
            _csv(headers, rows),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{name}-{stamp}.csv"'},
        )
    return Response(
        _pdf(title, subtitle, headers, rows),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{name}-{stamp}.pdf"'},
    )


def _fmt(fmt: str) -> str:
    if fmt not in ("csv", "pdf"):
        raise HTTPException(400, "format must be csv or pdf")
    return fmt


@router.get("/alerts")
def alerts_report(
    request: Request,
    format: str = "csv",
    severity: list[str] = Query(default=[]),
    status: list[str] = Query(default=[]),
    rule_id: list[str] = Query(default=[]),
    start: datetime | None = None,
    end: datetime | None = None,
    db: Session = Depends(get_db),
    me: User = Depends(analyst),
):
    _fmt(format)
    conds = alert_filters(severity, status, rule_id, None, None, start, end, None)
    rows = db.scalars(select(Alert).where(*conds).order_by(Alert.last_seen.desc()).limit(MAX_ROWS)).all()
    audit(db, me.username, "report_alerts", format, detail=f"rows={len(rows)}", ip=client_ip(request))
    headers = [
        "ID",
        "Severity",
        "Status",
        "Rule",
        "Title",
        "Host",
        "Source",
        "Events",
        "First seen",
        "Last seen",
        "MITRE",
        "Synthetic",
    ]
    data = [
        [
            a.id,
            a.severity,
            a.status,
            a.rule_id,
            a.title,
            a.host,
            a.source,
            a.event_count,
            a.first_seen.isoformat(),
            a.last_seen.isoformat(),
            ";".join(m["technique_id"] for m in a.mitre),
            a.synthetic,
        ]
        for a in rows
    ]
    return _respond(
        format,
        "alerts",
        "SIEM Alert Report",
        f"Generated {datetime.now(UTC).isoformat()} - {len(rows)} alerts (limit {MAX_ROWS})",
        headers,
        data,
    )


@router.get("/incidents")
def incidents_report(
    request: Request,
    format: str = "csv",
    status: list[str] = Query(default=[]),
    db: Session = Depends(get_db),
    me: User = Depends(analyst),
):
    _fmt(format)
    q = select(Incident).order_by(Incident.updated_at.desc()).limit(MAX_ROWS)
    if status:
        q = q.where(Incident.status.in_(status))
    rows = db.scalars(q).all()
    audit(db, me.username, "report_incidents", format, detail=f"rows={len(rows)}", ip=client_ip(request))
    headers = ["ID", "Title", "Severity", "Status", "Assignee", "Alerts", "Created", "Resolution summary"]
    data = [
        [
            i.id,
            i.title,
            i.severity,
            i.status,
            i.assignee.username if i.assignee else "",
            len(i.alerts),
            i.created_at.isoformat(),
            i.resolution_summary,
        ]
        for i in rows
    ]
    return _respond(
        format,
        "incidents",
        "SIEM Incident Report",
        f"Generated {datetime.now(UTC).isoformat()} - {len(rows)} incidents",
        headers,
        data,
    )


@router.get("/events")
def events_report(
    request: Request,
    format: str = "csv",
    q: str = Query("", max_length=500),
    start: datetime | None = None,
    end: datetime | None = None,
    severity: list[str] = Query(default=[]),
    host: list[str] = Query(default=[]),
    db: Session = Depends(get_db),
    me: User = Depends(analyst),
):
    _fmt(format)
    p = SearchParams(q=q, start=start, end=end, severities=severity, hosts=host, page=1, size=200)
    events: list[dict] = []
    while len(events) < MAX_ROWS:
        total, hits = get_store().search(p)
        events += hits
        if not hits or len(events) >= total:
            break
        p.page += 1
        if p.page * p.size > 10_000:
            break
    events = events[:MAX_ROWS]
    headers = [
        "Timestamp",
        "Host",
        "Source",
        "Category",
        "Action",
        "Outcome",
        "Severity",
        "User",
        "Src IP",
        "Message",
        "Detections",
        "Synthetic",
    ]
    data = [
        [
            e["@timestamp"],
            e["host"],
            e["source_type"],
            e["category"],
            e["action"],
            e["outcome"],
            e["severity"],
            e.get("user"),
            e.get("src_ip"),
            (e.get("message") or "")[:300],
            ";".join(e.get("detections", [])),
            e.get("synthetic"),
        ]
        for e in events
    ]
    audit(db, me.username, "report_events", format, detail=f"rows={len(events)}", ip=client_ip(request))
    return _respond(
        format,
        "events",
        "SIEM Event Report",
        f"Generated {datetime.now(UTC).isoformat()} - {len(events)} events (limit {MAX_ROWS})",
        headers,
        data,
    )
