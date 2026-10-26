import httpx
import pytest
from conftest import INGEST

from app import db as dbmod
from app.config import Settings
from app.demo import scenarios
from app.models import Alert, NotificationDelivery, utcnow
from app.services import notify


class Flaky:
    name = "email"

    def __init__(self, fail_times):
        self.calls, self.fail = 0, fail_times

    def destination(self):
        return "ops@example.com"

    def send(self, subject, body):
        self.calls += 1
        if self.calls <= self.fail:
            raise ConnectionError("smtp down")


def make_alert(db):
    a = Alert(
        rule_id="SIEM-001",
        title="Brute-force <b>from</b> 1.2.3.4\nInjected: header",
        severity="high",
        correlation_key="k",
        first_seen=utcnow(),
        last_seen=utcnow(),
        event_count=3,
        host="h",
        source="s",
        evidence={"samples": [{"message": "evil\x1b[31m text"}]},
        mitre=[{"technique_id": "T1110", "technique": "Brute Force"}],
    )
    db.add(a)
    db.commit()
    return a


def test_format_is_safe(client):
    with dbmod.session_factory()() as db:
        subject, body = notify.format_alert(make_alert(db))
    assert "\n" not in subject and "<b>" not in subject and "\x1b" not in body
    assert "T1110" in body


def test_retry_then_success_and_dedupe(client):
    s = Settings(notify_max_attempts=3)
    with dbmod.session_factory()() as db:
        a = make_alert(db)
        ch = Flaky(fail_times=2)
        notify.dispatch(db, s, a, [ch], sleep=lambda _: None)
        assert ch.calls == 3
        row = db.query(NotificationDelivery).one()
        assert row.status == "sent" and row.attempts == 3
        notify.dispatch(db, s, a, [ch], sleep=lambda _: None)  # duplicate suppression
        assert ch.calls == 3


def test_failure_recorded_not_raised(client):
    s = Settings(notify_max_attempts=2)
    with dbmod.session_factory()() as db:
        a = make_alert(db)
        notify.dispatch(db, s, a, [Flaky(fail_times=99)], sleep=lambda _: None)
        row = db.query(NotificationDelivery).one()
        assert row.status == "failed" and "ConnectionError" in row.error


def test_severity_routing():
    s = Settings(
        smtp_host="h",
        notify_email_to="a@example.com",
        notify_email_min_severity="high",
        slack_webhook_url="https://hooks.example.com/x",
        notify_slack_min_severity="medium",
    )
    assert [c.name for c in notify.channels_for(s, "critical")] == ["email", "slack"]
    assert [c.name for c in notify.channels_for(s, "medium")] == ["slack"]
    assert notify.channels_for(s, "low") == []
    assert notify.channels_for(Settings(), "critical") == []


def test_slack_adapter_posts_json_and_raises_on_http_error():
    seen = {}

    def handler(req):
        seen["body"] = req.content
        return httpx.Response(500 if "bad" in str(req.url) else 200)

    c = httpx.Client(transport=httpx.MockTransport(handler))
    notify.SlackChannel(Settings(slack_webhook_url="https://hooks.example.com/ok"), c).send("subj", "body")
    assert b"subj" in seen["body"]
    with pytest.raises(httpx.HTTPStatusError):
        notify.SlackChannel(Settings(slack_webhook_url="https://hooks.example.com/bad"), c).send("s", "b")


def test_pipeline_sends_notification_end_to_end(client, monkeypatch):
    sent = []

    class C:
        name = "email"

        def destination(self):
            return "x@example.com"

        def send(self, subj, body):
            sent.append(subj)

    monkeypatch.setattr(notify, "channels_for", lambda s, sev: [C()])
    client.post("/api/ingest", json={"records": scenarios()["malware_indicator"]}, headers=INGEST)
    assert any("CRITICAL" in s for s in sent)


def test_email_adapter_delivers_to_a_real_smtp_server(client):
    """Spins up an in-process SMTP server (aiosmtpd) and sends through the real EmailChannel / smtplib."""
    from aiosmtpd.controller import Controller

    received = []

    class Handler:
        async def handle_DATA(self, server, session, envelope):
            received.append(envelope)
            return "250 OK"

    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    ctl = Controller(Handler(), hostname="127.0.0.1", port=port)
    ctl.start()
    try:
        s = Settings(
            smtp_host="127.0.0.1",
            smtp_port=port,
            notify_email_to="soc@example.com",
            smtp_from="siem@example.com",
        )
        with dbmod.session_factory()() as db:
            a = make_alert(db)
            notify.dispatch(db, s, a, [notify.EmailChannel(s)], sleep=lambda _: None)
            row = db.query(NotificationDelivery).one()
            assert row.status == "sent" and row.destination == "soc@example.com"
    finally:
        ctl.stop()
    assert len(received) == 1
    msg = received[0].content.decode()
    assert "Subject: [SIEM HIGH]" in msg and "T1110" in msg and received[0].rcpt_tos == ["soc@example.com"]
    assert "\x1b" not in msg
