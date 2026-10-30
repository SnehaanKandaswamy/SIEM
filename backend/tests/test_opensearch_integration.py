"""Full pipeline against a real OpenSearch. Skipped unless SIEM_TEST_OPENSEARCH_URL is set (CI sets it)."""

import os
import uuid

import pytest
from conftest import INGEST

from app import db as dbmod
from app.config import get_settings
from app.demo import DISTRIBUTED_ATTACKERS, scenarios
from app.deps import state
from app.security import limiter
from app.store import OpenSearchStore, SearchParams

URL = os.environ.get("SIEM_TEST_OPENSEARCH_URL")
pytestmark = pytest.mark.skipif(not URL, reason="SIEM_TEST_OPENSEARCH_URL not set")


@pytest.fixture()
def os_client():
    from fastapi.testclient import TestClient

    from app.main import create_app

    get_settings.cache_clear()
    dbmod.init_engine("sqlite+pysqlite://")
    limiter.reset()
    store = OpenSearchStore(URL, prefix=f"it-{uuid.uuid4().hex[:8]}")
    state.store = store
    state.recent.clear()
    with TestClient(create_app()) as c:
        yield c, store
    store.client.indices.delete(index=store.pattern, ignore_unavailable=True)
    store.client.indices.delete_index_template(name=f"{store.prefix}-template", ignore=[404])


def login(c):
    r = c.post("/api/auth/login", json={"username": "admin", "password": "Adm1n-Test-Password!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_template_is_idempotent(os_client):
    _, store = os_client
    store.ensure_ready()
    store.ensure_ready()
    t = store.client.indices.get_index_template(name=f"{store.prefix}-template")
    assert t["index_templates"][0]["index_template"]["version"] == 1


def test_event_to_alert_to_search_end_to_end(os_client):
    c, store = os_client
    h = login(c)
    recs = [r for v in scenarios().values() for r in v]
    res = c.post("/api/ingest", json={"records": recs}, headers=INGEST).json()
    assert (
        res["rejected"] == 0 and res["alerts_created"] == 5 + len(DISTRIBUTED_ATTACKERS) and res["indexed"] == len(recs)
    )
    # duplicates are rejected by the _id (create op)
    assert c.post("/api/ingest", json={"records": recs}, headers=INGEST).json()["duplicates"] == len(recs)
    store.client.indices.refresh(index=store.pattern)
    s = c.get("/api/events/search?q=powershell", headers=h).json()
    assert s["total"] >= 1
    s = c.get("/api/events/search?src_ip=198.51.100.23&sort=@timestamp&order=asc", headers=h).json()
    assert s["total"] == 8 and all("SIEM-001" in e["detections"] for e in s["items"])
    # malformed query syntax must not 500 or inject DSL
    for q in ['"unclosed', "a AND OR (", '{"match_all":{}}', "user:*"]:
        assert c.get("/api/events/search", params={"q": q}, headers=h).status_code == 200
    ov = c.get("/api/dashboard/overview", headers=h).json()
    assert ov["events_total"] == len(recs) and ov["top_src_ips"] and ov["timeline"]
    assert ov["search_backend"]["backend"] == "opensearch"
    alert = c.get("/api/alerts?rule_id=SIEM-003", headers=h).json()["items"][0]
    d = c.get(f"/api/alerts/{alert['id']}", headers=h).json()
    assert len(d["events"]) >= 15
    assert c.get("/readyz").status_code == 200
    ev = store.fetch(store_window(), {"category": "network"})
    assert ev and all(e["category"] == "network" for e in ev)
    total, _ = store.search(SearchParams(q="eicar"))
    assert total >= 1


def store_window():
    from datetime import UTC, datetime, timedelta

    return datetime.now(UTC) - timedelta(hours=1)
