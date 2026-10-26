"""Ingestion pipeline: normalise -> enrich -> index -> detect -> notify -> publish to live stream."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..config import Settings
from ..deps import state
from ..detection.engine import run_detections
from ..models import CollectorStatus
from ..services import notify
from ..store import EventStore
from .geo import get_resolver
from .normalize import ParseError, normalize

log = logging.getLogger("siem.ingest")


def enrich(ev: dict) -> dict:
    geo = get_resolver()
    ev["geo"] = geo.lookup(ev.get("src_ip"))
    return ev


def ingest_records(
    db: Session,
    store: EventStore,
    settings: Settings,
    records: list[Any],
    *,
    host: str,
    source_type: str | None,
    collector: str,
    synthetic: bool = False,
) -> dict:
    events, errors = [], []
    for i, rec in enumerate(records):
        try:
            ev = enrich(normalize(rec, host, source_type))
            if synthetic or (isinstance(rec, dict) and rec.get("synthetic")):
                ev["synthetic"] = True
            events.append(ev)
        except ParseError as e:
            st = source_type or "auto"
            metrics.PARSE_FAILURES.labels(
                source_type=st if st in ("windows", "linux", "nginx", "docker", "json", "auto") else "other"
            ).inc()
            snippet = (rec if isinstance(rec, str) else str(rec))[:200]
            errors.append({"index": i, "error": str(e), "snippet": snippet})
            state.parse_errors.append(
                {"at": datetime.now(UTC).isoformat(), "collector": collector, "error": str(e), "snippet": snippet}
            )
    new = dup = 0
    if events:
        new, dup = store.index(events)  # raises on storage failure -> caller returns 503 so the agent retries
        for ev in events:
            metrics.EVENTS_ACCEPTED.labels(source_type=ev["source_type"]).inc()
        if dup:
            metrics.EVENTS_DUPLICATE.inc(dup)
    # Detection and notification failures must not lose already-indexed events.
    created = []
    if settings.detections_enabled and new:
        try:
            created = run_detections(db, store, events)
        except Exception:
            metrics.BACKGROUND_FAILURES.labels(task="detection").inc()
            log.exception("detection pass failed")
    for alert in created:
        try:
            notify.dispatch(db, settings, alert)
        except Exception:
            metrics.BACKGROUND_FAILURES.labels(task="notify").inc()
            log.exception("notification dispatch failed")
    if new:
        for ev in events:
            state.seq += 1
            state.recent.append({"seq": state.seq, **ev})
    _touch_collector(db, collector, source_type or "auto", len(events), len(errors))
    return {
        "received": len(records),
        "accepted": len(events),
        "indexed": new,
        "duplicates": dup,
        "rejected": len(errors),
        "errors": errors[:20],
        "alerts_created": len(created),
    }


def _touch_collector(db: Session, name: str, source_type: str, ok: int, bad: int) -> None:
    row = db.scalars(select(CollectorStatus).where(CollectorStatus.name == name[:128])).first()
    if not row:
        row = CollectorStatus(name=name[:128], source_type=source_type[:32], events_total=0, errors_total=0)
        db.add(row)
    row.last_seen = datetime.now(UTC)
    row.events_total = (row.events_total or 0) + ok
    row.errors_total = (row.errors_total or 0) + bad
    db.commit()
