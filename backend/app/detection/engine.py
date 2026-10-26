"""Runs enabled rules after each ingested batch and turns findings into deduplicated alerts."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..models import SEVERITIES, Alert, DetectionRule
from ..store import EventStore
from .rules import MAX_IDS, REGISTRY, Finding

log = logging.getLogger("siem.detection")


def seed_rules(db: Session) -> None:
    """Create DB rows for registered rules that don't exist yet (idempotent; keeps admin edits)."""
    existing = {r.rule_id for r in db.scalars(select(DetectionRule))}
    for rid, rule in REGISTRY.items():
        if rid not in existing:
            db.add(
                DetectionRule(
                    rule_id=rid,
                    name=rule.name,
                    description=rule.description,
                    enabled=True,
                    severity=rule.severity,
                    config=rule.default_config,
                    mitre=rule.mitre,
                )
            )
    db.commit()


def _rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


def upsert_alert(
    db: Session, f: Finding, severity: str, suppression: int, mitre: list, synthetic: bool, mitre_enabled: bool = True
) -> tuple[Alert, bool]:
    """Return (alert, created). Ongoing activity updates one alert instead of creating a new one."""
    cutoff = f.last_seen - timedelta(seconds=suppression)
    existing = db.scalars(
        select(Alert)
        .where(
            Alert.correlation_key == f.correlation_key,
            Alert.status.in_(("open", "acknowledged")),
            Alert.last_seen >= cutoff,
        )
        .order_by(Alert.id.desc())
    ).first()
    if existing:
        merged = list(dict.fromkeys([*existing.event_ids, *f.event_ids]))[-MAX_IDS:]
        existing.event_ids = merged
        existing.event_count = max(existing.event_count, f.count, len(merged))
        existing.last_seen = max(existing.last_seen, f.last_seen)
        existing.first_seen = min(existing.first_seen, f.first_seen)
        if _rank(severity) > _rank(existing.severity):
            existing.severity = severity
        ev = dict(existing.evidence or {})
        ev.update({k: v for k, v in f.evidence.items() if k != "samples"})
        ev["samples"] = f.evidence.get("samples", ev.get("samples", []))
        ev["repeat_updates"] = int(ev.get("repeat_updates", 0)) + 1
        existing.evidence = ev  # reassign so JSON change is tracked
        metrics.ALERTS_SUPPRESSED.labels(rule=f.rule_id).inc()
        return existing, False
    alert = Alert(
        rule_id=f.rule_id,
        title=f.title,
        severity=severity,
        status="open",
        correlation_key=f.correlation_key,
        source=f.source[:255],
        host=f.host[:255],
        event_count=max(f.count, len(f.event_ids)),
        first_seen=f.first_seen,
        last_seen=f.last_seen,
        evidence=f.evidence,
        event_ids=f.event_ids,
        mitre=mitre if mitre_enabled else [],
        synthetic=synthetic,
    )
    db.add(alert)
    db.flush()
    metrics.ALERTS_CREATED.labels(rule=f.rule_id, severity=severity).inc()
    return alert, True


def run_detections(db: Session, store: EventStore, batch: list[dict]) -> list[Alert]:
    """Evaluate every enabled rule that has at least one relevant event in `batch`.
    Returns newly created alerts (callers dispatch notifications)."""
    if not batch:
        return []
    created: list[Alert] = []
    rules = {r.rule_id: r for r in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True)))}
    for rid, rule in REGISTRY.items():
        row = rules.get(rid)
        relevant = [e for e in batch if rule.relevant(e)] if row is not None else []
        if not relevant:
            continue
        # evaluate as of the newest event relevant to this rule (so back-dated batches still correlate)
        ref = max(datetime.fromisoformat(e["@timestamp"]) for e in relevant)
        cfg = {**rule.default_config, **(row.config or {})}
        try:
            findings = rule.evaluate(store, ref, cfg)
            for f in findings:
                synthetic = all(e.get("synthetic") for e in store.get_many(f.event_ids[:20])) if f.event_ids else False
                alert, is_new = upsert_alert(
                    db, f, row.severity, int(cfg.get("suppression_seconds", 900)), row.mitre or [], synthetic
                )
                if is_new:
                    created.append(alert)
                store.mark_detections(f.event_ids, rid)
            db.commit()
        except Exception:
            db.rollback()
            metrics.DETECTION_FAILURES.labels(rule=rid).inc()
            log.exception("rule %s failed", rid)
    return created
