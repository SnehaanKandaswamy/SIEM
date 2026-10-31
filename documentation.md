# SIEM Dashboard for DevOps

## Project Submission Document

**GitHub:** https://github.com/SnehaanKandaswamy/SIEM

---

## 1. Application Overview

### 1.1 What it does

A self-hosted Security Information and Event Management (SIEM) platform. It collects logs from Windows, Linux, Nginx and Docker, normalises them into a single schema, indexes them, runs detection rules, raises alerts, and gives security analysts a web dashboard to investigate and report.

**Pipeline:** collect → normalise → index → detect → alert → investigate → report.

#### Key features

- **Five detection rules**, mapped to MITRE ATT&CK where justified:
  - SIEM-001 Brute force
  - SIEM-002 Multiple failed logins
  - SIEM-003 Port scan
  - SIEM-004 Suspicious command
  - SIEM-005 Malware indicators

  Rules include correlation, suppression and evidence.

- **Alert workflow:** Acknowledge and resolve alerts. Incidents support assignment, notes, a state machine, and an audit timeline.

- **Role-based access control:** Viewer, analyst, and admin roles with Argon2 password hashing and JWT access/refresh tokens.

- **Investigation interface:** Overview dashboard, live event stream (SSE with polling fallback), OpenSearch log explorer, GeoIP attack map, and MITRE ATT&CK view.

- **Reporting and notifications:** CSV and PDF reports, Email and Slack notifications, and admin screens for users, rules, collectors, integrations, and audit.

- **Monitoring:** Prometheus metrics and a provisioned Grafana dashboard.

### 1.2 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy, Alembic |
| Frontend | React, TypeScript, Vite, Tailwind CSS, served by Nginx |
| Databases | PostgreSQL 16 (alerts, users, incidents), OpenSearch 2.17 (events) |
| Log Collection | Fluent Bit 3.1, Windows PowerShell forwarder |
| Monitoring | Prometheus 2.54, Grafana |
| DevOps | Docker, Docker Compose, GitHub Actions (CI/CD), GHCR, Trivy, gitleaks, Dependabot |
| Demo Hosting | Render (backend), Vercel (frontend) |

---

## 2. How It Works

The SIEM platform processes security events through the following stages:

1. **Collect:** Fluent Bit tails Docker container logs and Nginx logs. A PowerShell forwarder sends Windows Event Log records. Both POST to the backend ingest API using an API key.

2. **Normalise:** The backend parses Windows (4624/4625/4688), Linux auth/sudo/firewall, Nginx, Docker and generic JSON into one schema, with UTC timestamps and a deterministic `event_id` for de-duplication. It also adds GeoIP enrichment.

3. **Index:** Events are stored in OpenSearch using a versioned index template, with 30-day retention (ISM).

4. **Detect:** The detection engine evaluates the five rules over the events. Matches are correlated and suppressed so repeats merge into one alert. Each alert has a severity and MITRE mapping.

5. **Alert and Notify:** Alerts are saved in PostgreSQL and sent by Email (SMTP) or Slack.

6. **Investigate:** Analysts use the React UI to triage alerts, open incidents, search logs, and view the attack map and MITRE coverage.

7. **Report and Monitor:** CSV/PDF export. Prometheus scrapes `/metrics` and Grafana shows the operations dashboard.

### Container Architecture

**Container view:**

- Frontend (Nginx) → Backend (FastAPI)
- Backend → PostgreSQL + OpenSearch
- Fluent Bit → Backend
- Prometheus → Backend
- Grafana → Prometheus

The data network (PostgreSQL, OpenSearch) is internal-only with no external route. Only the UI is published, and only on loopback (`127.0.0.1:8080`).

---

## 3. How Others Can Run It

### 3.1 Option A: Docker Compose from Source (Tested)

**Prerequisites:**

- Docker Desktop (WSL2 backend, Linux containers)
- Approximately 8 GB RAM (16 GB recommended)
- 20 GB disk space
- `vm.max_map_count ≥ 262144`

#### Setup and Execution

Clone the repository:

```bash
git clone https://github.com/SnehaanKandaswamy/SIEM.git
cd SIEM
```

Set the OpenSearch virtual memory requirement:

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

Run the project setup and validation commands:

```powershell
.\scripts\siem.ps1 doctor
.\scripts\siem.ps1 setup
.\scripts\siem.ps1 up
.\scripts\siem.ps1 demo
.\scripts\siem.ps1 smoke
```

These commands:

- Perform environment checks.
- Generate `.env` with random secrets.
- Print the admin password.
- Build and start the services.
- Load labelled synthetic events (all five detections fire).
- Run 13 end-to-end checks.

#### Accessing the Services

| Service | URL / Credentials |
|---|---|
| SIEM UI | http://localhost:8080 |
| Default User | `admin` |
| Password | Printed by setup |
| Grafana | http://localhost:3000 |
| Grafana Dashboard | SIEM - Operations |

Stop the services while retaining data:

```powershell
.\scripts\siem.ps1 down
```

Wipe all project data:

```powershell
.\scripts\siem.ps1 reset
```

#### Plain Docker Compose (Linux/macOS)

Create the environment file:

```bash
cp .env.example .env
```

Set the following environment variables:

- `POSTGRES_PASSWORD`
- `SIEM_JWT_SECRET`
- `SIEM_INGEST_API_KEYS`
- `SIEM_COLLECTOR_KEY`
- Admin password

Start the services:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build --wait
```

### 3.2 Option B: Run from Published Images (GHCR)

CI/CD publishes two images:

- `sha-<7 chars>` for main
- `vX.Y.Z` for releases

The `latest` tag is never used.

Pull the images:

```bash
docker pull ghcr.io/snehaankandaswamy/siem-backend:<tag>
docker pull ghcr.io/snehaankandaswamy/siem-frontend:<tag>
```

Set the image namespace and version:

```bash
export SIEM_IMAGE_NAMESPACE=snehaankandaswamy/siem
export SIEM_VERSION=<tag>
```

Start the production Compose configuration:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --wait
```

The production overlay enables the OpenSearch security plugin. Replace the demo TLS certificates before real use.

### 3.3 Option C: Linux Server with the Deploy Script

Deploy a selected image version:

```bash
IMAGE_NS=snehaankandaswamy/siem ./scripts/deploy.sh v1.0.0
```

**Rollback:** Re-run the deployment script with an older image tag.

### 3.4 Live Demo (Presentation Only)

- Frontend hosted on Vercel.
- Backend hosted on Render (`render.yaml`).
- Uses SQLite and an in-memory event store, so data resets on restart.
- Load data with Admin → System → "Load synthetic scenarios".

**Backend URL:** https://siem-backend-li9r.onrender.com

**Frontend URL:** Paste your Vercel URL.

---

## 4. Docker and Image Publishing

### 4.1 Dockerfiles

**Backend:**
- Multi-stage build based on `python:3.12-slim`.
- Runs as non-root (UID 10001).
- Has a `HEALTHCHECK` on `/healthz`.
- Uses a single Uvicorn worker with graceful shutdown.

**Frontend:**
- Vite build served by unprivileged Nginx.
- Nginx also proxies `/api` to the backend.

**Compose Hardening:**
- Backend `read_only`.
- `cap_drop ALL`.
- `no-new-privileges`.
- Internal-only data network.
- Log rotation.
- Health checks.
- `depends_on service_healthy`.

A one-shot migration service runs `alembic upgrade head` before the backend starts.

### 4.2 Automated Publishing to GHCR

Workflow: `.github/workflows/cd.yml`

On a push to main or a `v*` tag, the workflow:

1. Logs in to `ghcr.io` with the ephemeral `GITHUB_TOKEN`.
2. Builds backend and frontend with Buildx using the GitHub Actions layer cache.
3. Pushes with SBOM and provenance attestations.
4. Scans the published image with Trivy and fails on CRITICAL findings.
5. On tags or manual dispatch, deploys over SSH to a protected GitHub Environment (staging/production) and runs a health check.

### 4.3 Publishing to Docker Hub

Log in:

```bash
docker login
```

Build the backend and frontend images:

```bash
docker build -t <dockerhub-user>/siem-backend:1.0.0 ./backend
docker build -t <dockerhub-user>/siem-frontend:1.0.0 ./frontend
```

Push the images:

```bash
docker push <dockerhub-user>/siem-backend:1.0.0
docker push <dockerhub-user>/siem-frontend:1.0.0
```

Anyone can then run:

```bash
docker pull <dockerhub-user>/siem-backend:1.0.0
docker pull <dockerhub-user>/siem-frontend:1.0.0

export SIEM_BACKEND_IMAGE=<dockerhub-user>/siem-backend:1.0.0
export SIEM_FRONTEND_IMAGE=<dockerhub-user>/siem-frontend:1.0.0

docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --wait
```

Docker Hub pages:

- https://hub.docker.com/r/<dockerhub-user>/siem-backend
- https://hub.docker.com/r/<dockerhub-user>/siem-frontend

---

## 5. Performance and Metrics

The backend exports Prometheus metrics at `/metrics`.

Labels are bounded enums only, never users, IPs or raw text.

### Prometheus Metrics

| Metric | Meaning |
|---|---|
| `siem_http_requests_total{method,route,status}` | Request count |
| `siem_http_request_seconds{route}` | Latency histogram |
| `siem_events_accepted_total` | Accepted events |
| `siem_events_duplicate_total` | Duplicate events |
| `siem_events_rejected_total` | Rejected events |
| `siem_parse_failures_total` | Parser failures |
| `siem_alerts_created_total{rule,severity}` | Detection output |
| `siem_alerts_suppressed_total` | Suppressed alerts |
| `siem_detection_failures_total` | Detection errors |
| `siem_background_failures_total` | Background processing errors |
| `siem_notifications_total{channel,status}` | Email/Slack delivery |
| `siem_database_up` | Database health |
| `siem_opensearch_up` | OpenSearch health |
| `siem_collector_last_seen_age_seconds` | Collector liveness |

### Dashboards and Alerting

- Grafana "SIEM - Operations" is auto-provisioned from `deploy/grafana/`.
- Prometheus alert rules are in `deploy/prometheus/alerts.yml`.

### Resilience

- All containers restarted with data retained (verified).
- The backend exits cleanly in about 1 second on `docker compose stop`.

### Known Limits

- Single backend worker.
- Single-node OpenSearch without replicas.
- In-process rate limiter.
- In-process live buffer.

---

## 6. Testing and How We Tested It

### 6.1 Test Results

| Check | Tool / Command | Result |
|---|---|---|
| Backend lint/format | `ruff check .`, `ruff format --check .` | Pass |
| Backend tests | `pytest -q --cov=app` (against real OpenSearch 2.17.1) | 62 passed, 91% line coverage |
| DB migrations | `alembic upgrade head`, downgrade base, upgrade head, check (SQLite and PostgreSQL 16) | Pass |
| Frontend | ESLint, Prettier, tsc, Vitest, build | Pass, 21 tests |
| End-to-end smoke | `siem.ps1 smoke` on the live Compose stack | 13/13 checks |
| Browser test | Playwright/Chromium: login and every page | 0 console errors, 0 HTTP 5xx |
| Windows host checks | `Test-WindowsHost.ps1 -StackRunning` | Pass |
| Dependency scans | `pip-audit`, `npm audit` | 0 known vulnerabilities |
| Image scans | Trivy (HIGH/CRITICAL, fixable) | 0 backend / 0 frontend |
| Secret scan | gitleaks | No leaks |
| Backup/restore | Backup, change data, restore | PostgreSQL returned to backup state |
| Persistence | Restart backend, PostgreSQL, OpenSearch | Data retained |

### 6.2 What the Tests Cover

- **Detection (`test_detection.py`):** Each of the five rules fires on its positive fixture and not on negatives. The smoke run produces exactly SIEM-001 to SIEM-005.
- **Normalisation (`test_normalize.py`):** Windows, Linux, Nginx, Docker and JSON samples.
- **API (`test_api.py`):** Authentication, RBAC, rate limits, ingest validation, deduplication, alerts and incidents workflow, reports.
- **Notifications (`test_notify.py`):** Email delivered to a real in-process SMTP server (aiosmtpd); retries and failure handling; Slack via a mock transport.
- **Integration (`test_opensearch_integration.py`):** Real OpenSearch search and aggregations.
- **Migrations (`test_migrations.py`).**
- **Frontend (Vitest):** Live stream and polling fallback, permissions, alerts and incidents UI.

### 6.3 Test Data and Safety

Synthetic events are labelled in the UI and never seeded automatically.

The demo endpoint is refused when `SIEM_ENV=production`.

Fixtures use RFC 5737 documentation IPs, the harmless EICAR hash and a `.invalid` domain.

Nothing is executed or scanned.

### 6.4 Automated CI

Workflow: `.github/workflows/ci.yml`

- Backend lint, migrations and pytest against an OpenSearch service container, plus pip-audit.
- Frontend lint, format, typecheck, test, build and npm audit.
- Windows runner job (PSScriptAnalyzer and backend tests).
- Compose stack smoke test, including a persistence-across-restart check.
- Trivy image scan for both images, and a gitleaks secret scan.

### 6.5 Not Verified

- Real Slack webhook, real MaxMind GeoIP database, and the Windows Security log (needs an elevated shell).
- The production overlay has not been started with published images.
- The GitHub Actions workflows have not yet had a first run on GitHub.

---

## 7. Repository and Team Contributions

**Repository:** https://github.com/SnehaanKandaswamy/SIEM

### Team Contributions

| Member | Contribution |
|---|---|
| Karthik-24011103013 | BACKEND + DATABASE |
| Kanishk-24011103022 | DEVOPS + INFRASTRUCTURE |
| Snehaan-24011103060 | LOG PIPELINE + OPENSEARCH |
| Liitheshwar-24011103027 | DETECTION ENGINE + SECURITY |
| Dependabot (automated) | Weekly dependency update PRs for pip, npm, GitHub Actions and Docker. |
