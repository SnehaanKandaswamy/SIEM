import json
import os
from datetime import UTC, datetime

from conftest import INGEST

from app import db as dbmod
from app.config import get_settings
from app.demo import scenarios
from app.ingest.geo import GeoResolver
from app.main import bootstrap
from app.models import User


def seed(client):
    recs = [r for v in scenarios().values() for r in v]
    return client.post("/api/ingest", json={"records": recs}, headers=INGEST).json()


# ------------------------------------------------------------------ auth / RBAC
def test_login_and_me(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-Test-Password!"})
    tok = r.json()
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok['access_token']}"}).json()
    assert me["role"] == "admin" and "password_hash" not in me
    assert client.post("/api/auth/refresh", json={"refresh_token": tok["refresh_token"]}).status_code == 200
    # a refresh token must not work as an access token and vice versa
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok['refresh_token']}"}).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": tok["access_token"]}).status_code == 401


def test_requires_auth_everywhere(client):
    for path in (
        "/api/alerts",
        "/api/incidents",
        "/api/events/search",
        "/api/mitre",
        "/api/users",
        "/api/admin/audit",
        "/api/dashboard/overview",
        "/api/reports/alerts",
        "/api/rules",
        "/api/events/recent",
    ):
        assert client.get(path).status_code == 401, path
    assert client.get("/api/alerts", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_rbac_matrix(client, viewer_h, analyst_h, admin_h):
    seed(client)
    aid = client.get("/api/alerts", headers=viewer_h).json()["items"][0]["id"]
    assert client.get("/api/alerts", headers=viewer_h).status_code == 200
    assert client.post(f"/api/alerts/{aid}/acknowledge", headers=viewer_h).status_code == 403
    assert client.post("/api/incidents", json={"title": "xyz", "alert_ids": [aid]}, headers=viewer_h).status_code == 403
    assert client.get("/api/reports/alerts", headers=viewer_h).status_code == 403
    assert client.get("/api/ingest/diagnostics", headers=viewer_h).status_code == 403
    assert client.get("/api/users", headers=viewer_h).status_code == 403
    assert client.post(f"/api/alerts/{aid}/acknowledge", headers=analyst_h).status_code == 200
    assert client.get("/api/reports/alerts", headers=analyst_h).status_code == 200
    assert client.get("/api/users", headers=analyst_h).status_code == 403
    assert client.patch("/api/rules/SIEM-001", json={"enabled": False}, headers=analyst_h).status_code == 403
    assert client.get("/api/admin/audit", headers=analyst_h).status_code == 403
    assert client.post("/api/demo/ingest", headers=analyst_h).status_code == 403
    assert client.get("/api/users", headers=admin_h).status_code == 200
    assert client.get("/api/admin/audit", headers=admin_h).status_code == 200


def test_user_management(client, admin_h, analyst_h):
    new = {"username": "newbie", "email": "n@example.com", "password": "long-enough-pass-1", "role": "viewer"}
    assert client.post("/api/users", json=new, headers=admin_h).status_code == 201
    assert client.post("/api/users", json=new, headers=admin_h).status_code == 409
    weak = {"username": "weak", "email": "w@example.com", "password": "short"}
    assert client.post("/api/users", json=weak, headers=admin_h).status_code == 422
    users = client.get("/api/users", headers=admin_h).json()
    uid = next(u["id"] for u in users if u["username"] == "ana")
    client.patch(f"/api/users/{uid}", json={"is_active": False}, headers=admin_h)
    assert client.get("/api/alerts", headers=analyst_h).status_code == 401  # disabled -> token useless
    me_id = next(u["id"] for u in users if u["username"] == "admin")
    assert client.patch(f"/api/users/{me_id}", json={"role": "viewer"}, headers=admin_h).status_code == 400


def test_login_rate_limit_and_audit(client, admin_h):
    n = get_settings().login_rate_per_minute
    codes = [client.post("/api/auth/login", json={"username": "x", "password": "y"}).status_code for _ in range(n + 2)]
    assert 429 in codes
    audit = client.get("/api/admin/audit?action=login", headers=admin_h).json()
    assert any(i["outcome"] == "failure" for i in audit["items"])


def test_no_default_admin_without_bootstrap(monkeypatch):
    monkeypatch.delenv("SIEM_BOOTSTRAP_ADMIN_USERNAME")
    monkeypatch.delenv("SIEM_BOOTSTRAP_ADMIN_PASSWORD")
    get_settings.cache_clear()
    dbmod.init_engine("sqlite+pysqlite://")
    dbmod.Base.metadata.create_all(dbmod.engine())
    bootstrap(get_settings())
    with dbmod.session_factory()() as db:
        assert db.query(User).count() == 0
    get_settings.cache_clear()
    assert os.environ.get("SIEM_BOOTSTRAP_ADMIN_USERNAME") is None


# ------------------------------------------------------------------ ingestion
def test_ingest_auth_and_validation(client):
    body = {"records": [{"message": "hi", "host": "h"}]}
    assert client.post("/api/ingest", json=body).status_code == 401
    assert client.post("/api/ingest", json=body, headers={"X-Ingest-Key": "nope"}).status_code == 401
    assert client.post("/api/ingest", json={"records": []}, headers=INGEST).status_code == 422
    assert client.post("/api/ingest", content=b"{not json", headers=INGEST).status_code == 400
    assert client.post("/api/ingest", json=body, headers=INGEST).status_code == 200


def test_ingest_limits(client):
    s = get_settings()
    too_many = {"records": [{"message": str(i)} for i in range(s.ingest_max_batch + 1)]}
    assert client.post("/api/ingest", json=too_many, headers=INGEST).status_code == 413
    big = b'{"records":["' + b"a" * (s.ingest_max_body_bytes + 10) + b'"]}'
    assert client.post("/api/ingest", content=big, headers=INGEST).status_code == 413


def test_bare_array_from_fluent_bit_and_parse_errors_tracked(client, analyst_h):
    arr = [
        {"log": "2026-01-02T03:04:05+00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"},
        {"timestamp": "garbage", "host": "x", "source_type": "json"},
    ]
    r = client.post("/api/ingest", json=arr, headers={**INGEST, "X-Source-Type": "auto"}).json()
    assert r["accepted"] == 1 and r["rejected"] == 1 and r["errors"][0]["error"]
    diag = client.get("/api/ingest/diagnostics", headers=analyst_h).json()
    assert len(diag["recent_parse_errors"]) == 1


def test_ingest_ratelimit(client, monkeypatch):
    monkeypatch.setenv("SIEM_INGEST_RATE_PER_MINUTE", "2")
    get_settings.cache_clear()
    b = {"records": [{"message": "x"}]}
    codes = [client.post("/api/ingest", json=b, headers=INGEST).status_code for _ in range(4)]
    assert codes[:2] == [200, 200] and 429 in codes
    get_settings.cache_clear()


def test_store_failure_returns_503(client, monkeypatch):
    from app.deps import state

    def boom(evs):
        raise RuntimeError("down")

    monkeypatch.setattr(state.store, "index", boom)
    r = client.post("/api/ingest", json={"records": [{"message": "x"}]}, headers=INGEST)
    assert r.status_code == 503


# ------------------------------------------------------------------ search / dashboard
def test_search_filters_and_errors(client, viewer_h):
    seed(client)
    assert client.get("/api/events/search?q=powershell", headers=viewer_h).json()["total"] >= 1
    r = client.get("/api/events/search?source_type=windows&severity=low&size=5&page=1", headers=viewer_h).json()
    assert r["total"] > 0 and all(e["source_type"] == "windows" for e in r["items"])
    assert client.get("/api/events/search?src_ip=198.51.100.23", headers=viewer_h).json()["total"] == 8
    assert client.get("/api/events/search?src_ip=notanip", headers=viewer_h).status_code == 400
    assert client.get("/api/events/search?sort=__proto__", headers=viewer_h).status_code == 400
    assert client.get("/api/events/search?size=1000", headers=viewer_h).status_code == 422
    assert client.get("/api/events/search?q=zzzz-no-match", headers=viewer_h).json()["items"] == []
    old = datetime(2000, 1, 1, tzinfo=UTC).isoformat().replace("+", "%2B")
    assert client.get(f"/api/events/search?end={old}", headers=viewer_h).json()["total"] == 0


def test_event_detail(client, viewer_h):
    seed(client)
    e = client.get("/api/events/search?size=1", headers=viewer_h).json()["items"][0]
    assert client.get(f"/api/events/{e['event_id']}", headers=viewer_h).status_code == 200
    assert client.get("/api/events/..%2F..%2Fetc", headers=viewer_h).status_code in (400, 404)
    assert client.get("/api/events/deadbeef", headers=viewer_h).status_code == 404


def test_overview_reflects_real_data(client, viewer_h):
    empty = client.get("/api/dashboard/overview", headers=viewer_h).json()
    assert empty["events_total"] == 0 and empty["alerts_by_severity"] == {}
    res = seed(client)
    d = client.get("/api/dashboard/overview", headers=viewer_h).json()
    assert d["events_total"] == res["indexed"] and sum(d["alerts_by_severity"].values()) == res["alerts_created"]
    assert d["detections_by_rule"] and d["top_src_ips"] and d["collectors"][0]["healthy"] is True


def test_live_stream_polling_fallback(client, viewer_h):
    assert client.get("/api/events/recent", headers=viewer_h).json()["items"] == []
    seed(client)
    r = client.get("/api/events/recent?limit=5", headers=viewer_h).json()
    assert len(r["items"]) == 5 and r["last_seq"] > 5
    assert client.get(f"/api/events/recent?after={r['last_seq']}", headers=viewer_h).json()["items"] == []


def test_geo_private_and_unknown(client, viewer_h):
    seed(client)
    g = client.get("/api/dashboard/geo", headers=viewer_h).json()
    assert g["points"] == [] and g["unlocated_events"] > 0  # documentation ranges never get coordinates
    r = GeoResolver()
    assert r.lookup("10.1.2.3") == {"scope": "private", "located": False}
    assert r.lookup("127.0.0.1")["scope"] == "loopback"
    assert r.lookup("8.8.8.8") == {"scope": "public", "located": False}  # no DB configured -> unknown, not invented
    assert r.lookup("garbage") is None


def test_geo_static_mapping(tmp_path):
    p = tmp_path / "geo.json"
    p.write_text(json.dumps({"198.51.100.0/24": {"lat": 1.5, "lon": 2.5, "country": "ZZ", "city": "Demo"}}))
    g = GeoResolver(static_path=str(p)).lookup("198.51.100.23")
    assert g["located"] and g["location"] == {"lat": 1.5, "lon": 2.5} and g["source"] == "static"


# ------------------------------------------------------------------ incidents
def _alert_ids(client, h):
    return [a["id"] for a in client.get("/api/alerts?size=50", headers=h).json()["items"]]


def test_incident_workflow(client, analyst_h, viewer_h, admin_h):
    seed(client)
    ids = _alert_ids(client, analyst_h)
    r = client.post("/api/incidents", json={"title": "Possible intrusion", "alert_ids": ids[:2]}, headers=analyst_h)
    assert r.status_code == 201, r.text
    iid = r.json()["id"]
    bad = {"title": "bad one", "alert_ids": [99999]}
    assert client.post("/api/incidents", json=bad, headers=analyst_h).status_code == 404
    uid = client.get("/api/auth/me", headers=analyst_h).json()["id"]
    assert (
        client.patch(f"/api/incidents/{iid}", json={"assignee_id": uid}, headers=analyst_h).json()["assignee"] == "ana"
    )
    vid = client.get("/api/auth/me", headers=viewer_h).json()["id"]
    assert client.patch(f"/api/incidents/{iid}", json={"assignee_id": vid}, headers=analyst_h).status_code == 422
    assert client.patch(f"/api/incidents/{iid}", json={"status": "resolved"}, headers=analyst_h).status_code == 409
    assert client.patch(f"/api/incidents/{iid}", json={"status": "investigating"}, headers=analyst_h).status_code == 200
    assert client.patch(f"/api/incidents/{iid}", json={"status": "resolved"}, headers=analyst_h).status_code == 422
    n = client.post(
        f"/api/incidents/{iid}/notes", json={"body": "<script>alert(1)</script> contained"}, headers=analyst_h
    )
    assert n.status_code == 201
    assert client.post(f"/api/incidents/{iid}/notes", json={"body": "x"}, headers=viewer_h).status_code == 403
    res = {"status": "resolved", "resolution_summary": "Blocked IP"}
    assert client.patch(f"/api/incidents/{iid}", json=res, headers=analyst_h).status_code == 200
    link = client.post(f"/api/incidents/{iid}/alerts", json={"alert_ids": ids[2:3]}, headers=analyst_h)
    assert link.json()["alert_count"] == 3
    assert client.patch(f"/api/incidents/{iid}", json={"status": "closed"}, headers=analyst_h).status_code == 200
    assert client.patch(f"/api/incidents/{iid}", json={"status": "open"}, headers=analyst_h).status_code == 409
    d = client.get(f"/api/incidents/{iid}", headers=viewer_h).json()
    assert [h["action"] for h in d["history"]][:2] == ["created", "assigned"]
    assert len(d["alerts"]) == 3 and d["events"] and d["notes"][0]["body"].startswith("<script>")
    assert client.get("/api/incidents?status=closed", headers=viewer_h).json()["total"] == 1
    assert client.get("/api/incidents/9999", headers=viewer_h).status_code == 404
    acts = {a["action"] for a in client.get("/api/admin/audit?size=200", headers=admin_h).json()["items"]}
    assert {"incident_create", "incident_update", "incident_note"} <= acts


def test_alert_state_machine(client, analyst_h):
    seed(client)
    aid = _alert_ids(client, analyst_h)[0]
    assert client.post(f"/api/alerts/{aid}/acknowledge", headers=analyst_h).json()["status"] == "acknowledged"
    assert client.post(f"/api/alerts/{aid}/acknowledge", headers=analyst_h).status_code == 409
    assert client.post(f"/api/alerts/{aid}/resolve", headers=analyst_h).json()["resolved_by"] == "ana"
    assert client.post(f"/api/alerts/{aid}/resolve", headers=analyst_h).status_code == 409
    assert client.post("/api/alerts/99999/resolve", headers=analyst_h).status_code == 404
    q = "status=resolved&severity=high&severity=critical&rule_id=SIEM-001"
    assert client.get(f"/api/alerts?{q}", headers=analyst_h).json()["total"] <= 1


# ------------------------------------------------------------------ reports
def test_reports(client, analyst_h):
    seed(client)
    c = client.get("/api/reports/alerts?format=csv&severity=critical", headers=analyst_h)
    assert c.status_code == 200 and c.headers["content-type"].startswith("text/csv")
    assert "SIEM-005" in c.text and "SIEM-001" not in c.text
    p = client.get("/api/reports/alerts?format=pdf", headers=analyst_h)
    assert p.content[:5] == b"%PDF-" and "attachment" in p.headers["content-disposition"]
    assert client.get("/api/reports/events?format=csv&q=powershell", headers=analyst_h).text.count("\n") >= 2
    assert client.get("/api/reports/incidents?format=pdf", headers=analyst_h).content[:5] == b"%PDF-"
    assert client.get("/api/reports/alerts?format=exe", headers=analyst_h).status_code == 400


def test_csv_formula_injection_neutralised():
    from app.routers.reports import _csv

    assert b"'=cmd" in _csv(["a"], [["=cmd|calc"]])


# ------------------------------------------------------------------ health / metrics / demo / admin
def test_health_and_metrics(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"] == {"database": "ok", "search": "ok"}
    seed(client)
    m = client.get("/metrics").text
    assert "siem_events_accepted_total" in m and "siem_alerts_created_total" in m
    assert "198.51.100" not in m and "powershell" not in m  # no unbounded/sensitive labels
    assert client.get("/healthz").headers["x-content-type-options"] == "nosniff"


def test_demo_endpoint_gated(client, admin_h, monkeypatch):
    assert client.post("/api/demo/ingest?scenario=port_scan", headers=admin_h).json()["alerts_created"] == 1
    assert client.post("/api/demo/ingest?scenario=nope", headers=admin_h).status_code == 400
    monkeypatch.setenv("SIEM_ENV", "production")
    get_settings.cache_clear()
    assert client.post("/api/demo/ingest", headers=admin_h).status_code == 403
    get_settings.cache_clear()


def test_admin_endpoints(client, admin_h):
    seed(client)
    assert client.get("/api/admin/collectors", headers=admin_h).json()[0]["events_total"] > 0
    i = client.get("/api/admin/integrations", headers=admin_h).json()
    assert i["email"]["configured"] is False and "password" not in str(i).lower()
    assert client.post("/api/admin/integrations/test?channel=email", headers=admin_h).status_code == 409
    assert client.get("/api/admin/settings", headers=admin_h).json()["retention_days"] == 30
