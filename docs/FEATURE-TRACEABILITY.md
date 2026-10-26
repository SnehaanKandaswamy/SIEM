# Feature traceability

Source of requirements: the project brief (`docs/SIEM-Project-Proposal.pdf` was not present). Status values mirror `TASKS.md`
(✅ verified, 🟡 implemented but not verified here). Test files: `B:` = `backend/tests/`, `F:` = `frontend/src/test/app.test.tsx`.

## §6 Collection, ingestion, normalisation

| Requirement | Implementation | API | Evidence |
|---|---|---|---|
| Windows Security/system events | `scripts/windows/Send-WindowsEvents.ps1`, `Install-WindowsCollector.ps1`; `ingest/normalize.py::parse_windows` | `POST /api/ingest` | B:`test_normalize` (4625, 4688, Sysmon, StringInserts) ✅; live Application log ✅; live Security log 🟡 |
| Linux auth/system logs | `normalize.py::parse_syslog`; `deploy/fluent-bit/fluent-bit-linux-host.conf` | same | B:`test_normalize` ✅; host config 🟡 |
| Docker container logs | `deploy/fluent-bit/fluent-bit.conf` (tail json-file) ; `parse_docker` | same | live events `source_type=docker` ✅ |
| Nginx access/error | `frontend/nginx.conf` (logs to volume) + Fluent Bit tail; `parse_nginx` | same | B:`test_normalize`; live nginx events ✅ |
| Structured JSON / configurable parsers | `parse_generic` | same | B:`test_normalize` ✅ |
| Synthetic generator | `backend/app/demo.py` (CLI + `POST /api/demo/ingest`) | `/api/demo/ingest` | B:`test_detection`, smoke ✅ |
| Auth, size limit, rate limit, validation | `deps.py::ingest_credential`, `routers/events.py`, `schemas.py` | `/api/ingest` 401/413/422/429 | B:`test_api` (`test_ingest_*`) ✅ |
| UTC normalisation, enrichment, dedupe | `normalize.py::parse_ts/event_id_for`, `ingest/geo.py`, OpenSearch `create` | – | B:`test_normalize`, `test_suppression…` ✅ |
| Bounded retries / diagnostics / metrics | Fluent Bit `Retry_Limit`, forwarder retry loop, `state.parse_errors`, `metrics.py` | `/api/ingest/diagnostics`, `/metrics` | B:`test_bare_array…parse_errors_tracked`, `test_store_failure_returns_503` ✅ |
| Normalised schema | `normalize.py::base_event`, `store.py::_template` | – | OpenSearch integration test ✅ |

## §7–8 Detections and MITRE

| Requirement | Implementation | Evidence |
|---|---|---|
| Rule 1 brute force | `detection/rules.py::BruteForce` (SIEM-001) | B:`test_positive[bruteforce_ssh]`, `test_below_threshold_no_alert` ✅ |
| Rule 2 multiple failed logins | `MultipleFailedLogins` (SIEM-002) | B:`test_positive[failed_logins_windows]` ✅ |
| Rule 3 port scan | `PortScan` (SIEM-003); needs `dst_port` telemetry | B:`test_positive[port_scan]`, `test_windows_logons_are_not_scan_telemetry`, negative 30×:443 ✅ |
| Rule 4 suspicious command | `SuspiciousCommand` (SIEM-004) | B:`test_positive[suspicious_command]`, negative `notepad` ✅ |
| Rule 5 malware indicators | `MalwareIndicator` (SIEM-005); EICAR hash, `.invalid` domain, TEST-NET IP | B:`test_positive[malware_indicator]`, negative random hash ✅ |
| Rule metadata, thresholds, windows, enable/disable | `Rule` base, `DetectionRule` model, `PATCH /api/rules/{id}`, `validate_rule_config` | B:`test_configurable_threshold`, `test_disabled_rule…`, `test_rule_config_validation` ✅ |
| Evidence, first/last seen, event refs | `Finding`, `Alert.evidence/event_ids/first_seen/last_seen` | B:`test_severity_and_mitre_and_evidence` ✅ |
| Dedup / suppression / repeat handling | `engine.py::upsert_alert` | B:`test_suppression_updates_existing_alert`, `test_resolved_alert_allows_new_alert` ✅ |
| MITRE mapping + dashboard | `Rule.mitre`, `GET /api/mitre`, `pages/Mitre.tsx` | B:`test_mitre_endpoint`; browser ✅ (SIEM-005 shown as unmapped by design) |
| How to add rules | `docs/ARCHITECTURE.md#adding-a-rule` | – |

## §9 Alerts and incidents

| Requirement | Implementation | Evidence |
|---|---|---|
| Severities, list/detail, filters, pagination, sorting | `routers/alerts.py`, `pages/Alerts.tsx`, `AlertDetail.tsx` | B:`test_alert_state_machine`, severity sort; F:alerts tests ✅ |
| Acknowledge / resolve | `POST /api/alerts/{id}/acknowledge|resolve` | B + F ✅ |
| Incidents: create from alerts, multi-alert, assign, states, notes, summary, history | `routers/incidents.py`, `pages/Incidents.tsx` | B:`test_incident_workflow`; F:incident tests ✅ |
| Enforced server-side | `deps.py::require`, transition table in `incidents.py` | B:`test_rbac_matrix` ✅ |

## §10 Authentication and RBAC

| Requirement | Implementation | Evidence |
|---|---|---|
| Argon2, JWT, refresh, roles, rate limit, audit, CORS, secrets from env, explicit bootstrap, no default admin | `security.py`, `routers/auth.py`, `main.py::bootstrap`, `config.py` | B:`test_login_and_me`, `test_requires_auth_everywhere`, `test_rbac_matrix`, `test_login_rate_limit_and_audit`, `test_no_default_admin_without_bootstrap` ✅ |
| Dev vs production auth documented | `docs/DEPLOYMENT.md §4`, `docs/SECURITY.md` | – |
| SQLi / XSS / IDOR protections | ORM + whitelists, React escaping + CSP, id validation | B:`test_search_filters_and_errors`, `test_event_detail`; F:hostile-text tests ✅ |

## §11 Frontend

| Requirement | Implementation | Evidence |
|---|---|---|
| A Overview (real data) | `pages/Overview.tsx`, `GET /api/dashboard/overview` | B:`test_overview_reflects_real_data`; F ✅; screenshot ✅ |
| B Live stream | `pages/Live.tsx`, `GET /api/events/stream|recent` | F:stream + polling fallback ✅; curl through Nginx ✅ |
| C Severity cards | Overview cards link to filtered alerts | F ✅ |
| D Incident management | `pages/Incidents.tsx` | F ✅ |
| E Log explorer | `pages/Explorer.tsx`, `GET /api/events/search` | F:explorer; OpenSearch integration test ✅ |
| F GeoIP map | `ingest/geo.py`, `GET /api/dashboard/geo`, `pages/Geo.tsx` | B:`test_geo_*` ✅; real MaxMind DB 🟡 |
| G MITRE view | see §8 | ✅ |
| H PDF/CSV exports | `routers/reports.py`, `pages/Reports.tsx` | B:`test_reports`, `test_csv_formula_injection_neutralised`; F:export ✅ |
| I Email/Slack | `services/notify.py`, Admin → Integrations | B:`test_notify` (real SMTP ✅, Slack mock 🟡) |
| J Administration | `pages/Admin.tsx`, `routers/auth.py`, `routers/admin.py` | B:`test_user_management`, `test_admin_endpoints`; F:admin guard ✅ |

## §12 Data design

| Requirement | Implementation | Evidence |
|---|---|---|
| PostgreSQL models + Alembic | `models.py`, `alembic/versions/0001_initial_schema.py` | B:`test_migrations`; Compose `migrate` ✅ |
| OpenSearch mappings, template versioning, aggregations, health, retention | `store.py` (`TEMPLATE_VERSION`, `_ism_policy`, `stats`, `health`) | B:`test_opensearch_integration` ✅; ISM deletion 🟡 |

## §13–16 Operations

| Requirement | Implementation | Evidence |
|---|---|---|
| Compose (base/dev/prod), Dockerfiles, health checks, non-root, volumes, internal network, loopback ports | `docker-compose*.yml`, `backend/Dockerfile`, `frontend/Dockerfile` | stack running ✅; `Test-WindowsHost.ps1` ✅; prod overlay 🟡 |
| PowerShell workflow | `scripts/siem.ps1`, `smoke.ps1`, `backup.ps1`, `restore.ps1` | executed ✅ |
| Windows validation | `scripts/windows/Test-WindowsHost.ps1` | executed on Windows 11 ✅ |
| CI | `.github/workflows/ci.yml` | commands run locally ✅; workflow 🟡 |
| CD, GHCR, environments, deploy health, rollback | `.github/workflows/cd.yml`, `scripts/deploy.sh`, `docs/DEVOPS.md` | 🟡 not run |
| Prometheus / Grafana / alert rules | `deploy/prometheus/*`, `deploy/grafana/*`, `metrics.py` | scrape + dashboard ✅ (smoke); rules loaded, not fired 🟡 |
| Metrics with bounded labels | `metrics.py`, templated route label | B:`test_health_and_metrics` ✅ |
| Backup/restore, retention, recovery verification | `scripts/backup.ps1`, `restore.ps1`, `docs/DEPLOYMENT.md §7` | executed round-trip ✅ |

## §17–19 Testing, seed data, docs

| Requirement | Evidence |
|---|---|
| Backend / frontend / integration tests | 62 backend (incl. real OpenSearch), 21 frontend, 13 smoke checks — see TASKS.md |
| Deterministic synthetic data with negatives, labelled, never auto-seeded in production | `demo.py`, UI "synthetic" tags, demo endpoint refuses `SIEM_ENV=production` (B:`test_demo_endpoint_gated`) |
| Required documents | all present in repo root and `docs/` |
