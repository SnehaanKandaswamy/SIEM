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

- **Alert workflow** (acknowledge, resolve) and incidents (assign, notes, state machine, audit timeline).

- **Role-based access control** (viewer / analyst / admin) with Argon2 password hashing and JWT access/refresh tokens.

- **Investigation interface:** Overview dashboard, live event stream (SSE with polling fallback), OpenSearch log explorer, GeoIP attack map, MITRE ATT&CK view.

- **Reporting and notifications:** CSV and PDF reports; Email and Slack notifications; admin screens (users, rules, collectors, integrations, audit).

- **Monitoring:** Prometheus metrics and a provisioned Grafana dashboard.

### 1.2 Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, SQLAlchemy, Alembic |
| Frontend | React, TypeScript, Vite, Tailwind CSS, served by Nginx |
| Databases | PostgreSQL 16 (alerts, users, incidents), OpenSearch 2.17 (events) |
| Log collection | Fluent Bit 3.1, Windows PowerShell forwarder |
| Monitoring | Prometheus 2.54, Grafana |
| DevOps | Docker, Docker Compose, GitHub Actions (CI/CD), GHCR, Trivy, gitleaks, Dependabot |
| Demo hosting | Render (backend), Vercel (frontend) |

---

## 2. How It Works

1. **Collect.** Fluent Bit tails Docker container logs and Nginx logs. A PowerShell forwarder sends Windows Event Log records. Both POST to the backend ingest API using an API key.

2. **Normalise.** The backend parses Windows (4624/4625/4688), Linux auth/sudo/firewall, Nginx, Docker and generic JSON into one schema, with UTC timestamps and a deterministic `event_id` for de-duplication. It also adds GeoIP enrichment.

3. **Index.** Events are stored in OpenSearch using a versioned index template, with 30-day retention (ISM).

4. **Detect.** The detection engine evaluates the five rules over the events. Matches are correlated and suppressed so repeats merge into one alert. Each alert has a severity and MITRE mapping.

5. **Alert and notify.** Alerts are saved in PostgreSQL and sent by Email (SMTP) or Slack.

6. **Investigate.** Analysts use the React UI to triage alerts, open incidents, search logs, and view the attack map and MITRE coverage.

7. **Report and monitor.** CSV/PDF export. Prometheus scrapes `/metrics` and Grafana shows the operations dashboard.

**Container view:** frontend (Nginx) → backend (FastAPI) → postgres + opensearch. fluent-bit → backend. prometheus → backend; grafana → prometheus.

The data network (PostgreSQL, OpenSearch) is internal-only with no external route. Only the UI is published, and only on loopback (`127.0.0.1:8080`).

---

## 3. How Others Can Run It

### 3.1 Option A: Docker Compose from source (tested)

**Prerequisites:** Docker Desktop (WSL2 backend, Linux containers), about 8 GB RAM (16 GB recommended), 20 GB disk, `vm.max_map_count ≥ 262144`.

```powershell
git clone https://github.com/SnehaanKandaswamy/SIEM.git
cd SIEM
wsl -d docker-desktop sysctl -w vm.max_map_count=262144   # OpenSearch requirement
.\scripts\siem.ps1 doctor     # environment checks
.\scripts\siem.ps1 setup      # generates .env with random secrets, prints admin password
.\scripts\siem.ps1 up         # build + start + wait until every service is healthy
.\scripts\siem.ps1 demo       # load labelled synthetic events (all 5 detections fire)
.\scripts\siem.ps1 smoke      # 13 end-to-end checks
