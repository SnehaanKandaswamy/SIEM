"""Each rule: positive and negative fixtures via the full ingest path (normalise -> store -> detect -> alert)."""

from datetime import UTC, datetime, timedelta

import pytest
from conftest import INGEST

from app.demo import scenarios


def ingest(client, recs):
    r = client.post("/api/ingest", json={"records": recs, "host": "t"}, headers=INGEST)
    assert r.status_code == 200, r.text
    return r.json()


def alerts(client, h):
    return client.get("/api/alerts?size=100", headers=h).json()["items"]


def rules_of(client, h):
    return sorted({a["rule_id"] for a in alerts(client, h)})


def r1(client, h):
    return [a for a in alerts(client, h) if a["rule_id"] == "SIEM-001"]


@pytest.mark.parametrize(
    "scenario,expected",
    [
        ("bruteforce_ssh", ["SIEM-001"]),
        ("failed_logins_windows", ["SIEM-002"]),
        ("port_scan", ["SIEM-003"]),
        ("suspicious_command", ["SIEM-004"]),
        ("malware_indicator", ["SIEM-005"]),
    ],
)
def test_positive(client, admin_h, scenario, expected):
    res = ingest(client, scenarios()[scenario])
    assert res["rejected"] == 0
    assert rules_of(client, admin_h) == expected


def test_negative_cases_and_normal_activity_do_not_alert(client, admin_h):
    sc = scenarios()
    ingest(client, sc["negative_cases"] + sc["normal_activity"])
    assert alerts(client, admin_h) == []


def test_all_scenarios_together(client, admin_h):
    ingest(client, [r for recs in scenarios().values() for r in recs])
    assert rules_of(client, admin_h) == ["SIEM-001", "SIEM-002", "SIEM-003", "SIEM-004", "SIEM-005"]


def test_severity_and_mitre_and_evidence(client, admin_h):
    ingest(client, [r for recs in scenarios().values() for r in recs])
    by = {a["rule_id"]: a for a in alerts(client, admin_h)}
    assert by["SIEM-005"]["severity"] == "critical" and by["SIEM-005"]["mitre"] == []
    assert by["SIEM-001"]["severity"] == "high" and by["SIEM-001"]["mitre"][0]["technique_id"] == "T1110"
    assert by["SIEM-003"]["mitre"][0]["technique_id"] == "T1046"
    detail = client.get(f"/api/alerts/{by['SIEM-001']['id']}", headers=admin_h).json()
    assert len(detail["events"]) >= 5 and detail["alert"]["evidence"]["attempts"] >= 5
    assert all(e["synthetic"] for e in detail["events"])
    assert "SIEM-001" in detail["events"][0]["detections"]
    order = client.get("/api/alerts?sort=severity&order=desc", headers=admin_h).json()["items"]
    assert order[0]["severity"] == "critical"


def test_below_threshold_no_alert(client, admin_h):
    ingest(client, scenarios()["bruteforce_ssh"][:4])
    assert alerts(client, admin_h) == []


def test_suppression_updates_existing_alert(client, admin_h):
    now = datetime.now(UTC)
    ingest(client, scenarios(now)["bruteforce_ssh"])
    assert len(r1(client, admin_h)) == 1
    # the attack continues 60s later: same correlation key -> same alert, higher counters
    more = scenarios(now + timedelta(seconds=60))["bruteforce_ssh"]
    ingest(client, more)
    a = r1(client, admin_h)
    assert len(a) == 1
    assert a[0]["event_count"] > 8
    # idempotent re-send of the same batch changes nothing
    res = ingest(client, more)
    assert res["duplicates"] == len(more) and len(r1(client, admin_h)) == 1


def test_resolved_alert_allows_new_alert(client, admin_h):
    now = datetime.now(UTC)
    ingest(client, scenarios(now)["bruteforce_ssh"])
    aid = r1(client, admin_h)[0]["id"]
    assert client.post(f"/api/alerts/{aid}/resolve", headers=admin_h).status_code == 200
    ingest(client, scenarios(now + timedelta(seconds=90))["bruteforce_ssh"])
    assert len(r1(client, admin_h)) == 2


def test_disabled_rule_does_not_fire(client, admin_h):
    assert client.patch("/api/rules/SIEM-003", json={"enabled": False}, headers=admin_h).status_code == 200
    ingest(client, scenarios()["port_scan"])
    assert alerts(client, admin_h) == []


def test_configurable_threshold(client, admin_h):
    client.patch("/api/rules/SIEM-001", json={"config": {"threshold": 3}}, headers=admin_h)
    ingest(client, scenarios()["bruteforce_ssh"][:3])
    assert rules_of(client, admin_h) == ["SIEM-001"]


def test_rule_config_validation(client, admin_h):
    for bad in ({"nope": 1}, {"threshold": "x"}, {"threshold": 0}, {"threshold": True}):
        assert client.patch("/api/rules/SIEM-001", json={"config": bad}, headers=admin_h).status_code == 422
    r = client.patch("/api/rules/SIEM-004", json={"config": {"patterns": {"x": "(["}}}, headers=admin_h)
    assert r.status_code == 422


def test_windows_logons_are_not_scan_telemetry(client, admin_h):
    ingest(
        client,
        [
            {
                "source_type": "windows",
                "EventID": 4625,
                "Computer": "x",
                "TimeCreated": datetime.now(UTC).isoformat(),
                "EventData": {"TargetUserName": f"u{i}", "IpAddress": "9.9.9.9"},
            }
            for i in range(30)
        ],
    )
    assert "SIEM-003" not in rules_of(client, admin_h)


def test_mitre_endpoint(client, admin_h):
    ingest(client, scenarios()["bruteforce_ssh"])
    m = client.get("/api/mitre", headers=admin_h).json()
    t = {x["technique_id"]: x for x in m["techniques"]}
    assert t["T1110"]["alert_count"] == 1 and t["T1110"]["url"].endswith("/T1110/")
    assert [u["rule_id"] for u in m["unmapped_rules"]] == ["SIEM-005"]
