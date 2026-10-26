"""Email and Slack notification adapters with severity routing, bounded retries and dedupe."""

from __future__ import annotations

import logging
import smtplib
import time
from email.message import EmailMessage
from typing import Protocol

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import metrics
from ..config import Settings
from ..models import SEVERITIES, Alert, NotificationDelivery

log = logging.getLogger("siem.notify")


def _clean(text: str, limit: int = 300) -> str:
    """Strip control characters / markup-ish chars so untrusted log text can't break or spoof messages."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(text))
    return text.replace("<", "‹").replace(">", "›")[:limit]


def format_alert(a: Alert) -> tuple[str, str]:
    subject = f"[SIEM {a.severity.upper()}] {_clean(a.title, 120)}"
    ev = a.evidence or {}
    lines = [
        f"Rule: {a.rule_id}",
        f"Severity: {a.severity}",
        f"Host: {_clean(a.host)}",
        f"Source: {_clean(a.source)}",
        f"Events: {a.event_count}",
        f"First seen: {a.first_seen.isoformat()}",
        f"Last seen: {a.last_seen.isoformat()}",
    ]
    if a.mitre:
        lines.append("MITRE: " + ", ".join(f"{m['technique_id']} {m['technique']}" for m in a.mitre))
    for s in (ev.get("samples") or [])[:3]:
        lines.append("  evidence: " + _clean(s.get("message", "")))
    if a.synthetic:
        lines.append("NOTE: synthetic demo data")
    return subject, "\n".join(lines)


class Channel(Protocol):
    name: str

    def destination(self) -> str: ...
    def send(self, subject: str, body: str) -> None: ...


class EmailChannel:
    name = "email"

    def __init__(self, s: Settings):
        self.s = s

    def destination(self) -> str:
        return self.s.notify_email_to

    def send(self, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["Subject"], msg["From"], msg["To"] = subject.replace("\n", " "), self.s.smtp_from, self.s.notify_email_to
        msg.set_content(body)
        with smtplib.SMTP(self.s.smtp_host, self.s.smtp_port, timeout=10) as smtp:
            if self.s.smtp_starttls:
                smtp.starttls()
            if self.s.smtp_user:
                smtp.login(self.s.smtp_user, self.s.smtp_password)
            smtp.send_message(msg)


class SlackChannel:
    name = "slack"

    def __init__(self, s: Settings, client: httpx.Client | None = None):
        self.s, self.client = s, client

    def destination(self) -> str:
        return "slack-webhook"  # never persist the webhook URL itself

    def send(self, subject: str, body: str) -> None:
        payload = {"text": f"*{subject}*\n```{body}```"}
        client = self.client or httpx.Client(timeout=10)
        r = client.post(self.s.slack_webhook_url, json=payload)
        r.raise_for_status()


def channels_for(s: Settings, severity: str) -> list[Channel]:
    out: list[Channel] = []
    rank = SEVERITIES.index(severity)
    if s.smtp_host and s.notify_email_to and rank >= SEVERITIES.index(s.notify_email_min_severity):
        out.append(EmailChannel(s))
    if s.slack_webhook_url and rank >= SEVERITIES.index(s.notify_slack_min_severity):
        out.append(SlackChannel(s))
    return out


def dispatch(db: Session, s: Settings, alert: Alert, channels: list[Channel] | None = None, sleep=time.sleep) -> None:
    """Send once per (alert, channel, destination). Failures are recorded, never raised to the ingest path."""
    subject, body = format_alert(alert)
    for ch in channels if channels is not None else channels_for(s, alert.severity):
        dest = ch.destination()
        row = db.scalars(
            select(NotificationDelivery).where(
                NotificationDelivery.alert_id == alert.id,
                NotificationDelivery.channel == ch.name,
                NotificationDelivery.destination == dest,
            )
        ).first()
        if row and row.status == "sent":
            continue  # duplicate suppression
        row = row or NotificationDelivery(
            alert_id=alert.id, channel=ch.name, destination=dest, status="failed", attempts=0
        )
        err = ""
        for attempt in range(1, s.notify_max_attempts + 1):
            row.attempts += 1
            try:
                ch.send(subject, body)
                row.status, err = "sent", ""
                break
            except Exception as e:
                row.status, err = "failed", f"{type(e).__name__}: {e}"[:500]
                log.warning("notification %s attempt %d failed: %s", ch.name, attempt, type(e).__name__)
                if attempt < s.notify_max_attempts:
                    sleep(min(2**attempt, 8))
        row.error = err
        metrics.NOTIFICATIONS.labels(channel=ch.name, status=row.status).inc()
        db.add(row)
        db.commit()
