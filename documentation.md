::: titlepage
**PROJECT DOCUMENTATION**

**SIEM Dashboard for DevOps**

Security Information and Event Management Platform

------------------------------------------------------------------------

**Project Team**

  ------------- -------------
  Karthik       24011103013
  Kanishk       24011103022
  Snehaan       24011103060
  Liitheshwar   24011103027
  ------------- -------------

GitHub Repository

[github.com/SnehaanKandaswamy/SIEM](https://github.com/SnehaanKandaswamy/SIEM)

2026-10-31
:::

# Application Overview

## What the Application Does

The project is a self-hosted Security Information and Event Management
(SIEM) platform. It collects logs from Windows, Linux, Nginx, and
Docker, normalises them into a single schema, indexes them, runs
detection rules, raises alerts, and provides security analysts with a
web dashboard for investigation and reporting.

The overall processing pipeline is:

::: center
**Collect $\rightarrow$ Normalise $\rightarrow$ Index $\rightarrow$
Detect $\rightarrow$ Alert $\rightarrow$ Investigate $\rightarrow$
Report**
:::

### Key Features

- **Detection Rules:** Five detection rules, mapped to MITRE ATT&CK
  where justified:

  - SIEM-001: Brute Force

  - SIEM-002: Multiple Failed Logins

  - SIEM-003: Port Scan

  - SIEM-004: Suspicious Command

  - SIEM-005: Malware Indicators

  Rules include correlation, suppression, and evidence.

- **Alert and Incident Workflow:** Alerts can be acknowledged and
  resolved. Incidents support assignment, notes, a state machine, and an
  audit timeline.

- **Role-Based Access Control:** Viewer, analyst, and admin roles, with
  Argon2 password hashing and JWT access/refresh tokens.

- **Investigation Dashboard:** Overview dashboard, live event stream
  using Server-Sent Events (SSE) with polling fallback, OpenSearch log
  explorer, GeoIP attack map, and MITRE ATT&CK view.

- **Reporting and Notifications:** CSV and PDF reports, Email and Slack
  notifications, and administrative screens for users, rules,
  collectors, integrations, and audit records.

- **Monitoring:** Prometheus metrics and a provisioned Grafana
  dashboard.

## Technology Stack

  **Layer**        **Technology**
  ---------------- -----------------------------------------------------------------------------------
  Backend          Python 3.12, FastAPI, SQLAlchemy, Alembic
  Frontend         React, TypeScript, Vite, Tailwind CSS, served by Nginx
  Databases        PostgreSQL 16 (alerts, users, incidents), OpenSearch 2.17 (events)
  Log Collection   Fluent Bit 3.1, Windows PowerShell forwarder
  Monitoring       Prometheus 2.54, Grafana
  DevOps           Docker, Docker Compose, GitHub Actions (CI/CD), GHCR, Trivy, gitleaks, Dependabot
  Demo Hosting     Render (backend), Vercel (frontend)

# System Architecture and Workflow

## How the System Works

The SIEM platform processes security events through the following
stages:

1.  **Collect.** Fluent Bit tails Docker container logs and Nginx logs.
    A PowerShell forwarder sends Windows Event Log records. Both send
    data to the backend ingest API using an API key.

2.  **Normalise.** The backend parses Windows event IDs 4624, 4625, and
    4688; Linux authentication, sudo, and firewall logs; Nginx logs;
    Docker logs; and generic JSON.

    Events are converted into one schema with UTC timestamps and a
    deterministic `event_id` for de-duplication. GeoIP enrichment is
    also added.

3.  **Index.** Events are stored in OpenSearch using a versioned index
    template, with 30-day retention configured through ISM.

4.  **Detect.** The detection engine evaluates the five rules against
    events. Matches are correlated and suppressed so repeated detections
    can be merged into one alert. Each alert includes a severity and
    MITRE mapping.

5.  **Alert and Notify.** Alerts are stored in PostgreSQL and delivered
    through Email (SMTP) or Slack.

6.  **Investigate.** Analysts use the React interface to triage alerts,
    open incidents, search logs, and view the attack map and MITRE
    coverage.

7.  **Report and Monitor.** Reports can be exported in CSV/PDF formats.
    Prometheus scrapes the `/metrics` endpoint, and Grafana displays the
    operations dashboard.

## Container Architecture

The container-level architecture consists of the following
relationships:

- Frontend (Nginx) communicates with the backend (FastAPI).

- The backend communicates with PostgreSQL and OpenSearch.

- Fluent Bit forwards collected logs to the backend.

- Prometheus collects metrics from the backend.

- Grafana uses Prometheus as its metrics source.

The data network containing PostgreSQL and OpenSearch is internal-only
and has no external route.

Only the UI is published, and it is bound to `127.0.0.1:8080`.

# Installation and Execution

## Option A: Docker Compose from Source

This is the tested source-based installation method.

### Prerequisites

- Docker Desktop with the WSL2 backend and Linux containers.

- Approximately 8 GB RAM; 16 GB is recommended.

- 20 GB of available disk space.

- `vm.max_map_count` greater than or equal to 262144.

### Setup and Execution

Clone the repository and enter the project directory:

    git clone https://github.com/SnehaanKandaswamy/SIEM.git
    cd SIEM

Set the OpenSearch virtual memory requirement:

    wsl -d docker-desktop sysctl -w vm.max_map_count=262144

Run the project setup and validation commands:

    .\scripts\siem.ps1 doctor
    .\scripts\siem.ps1 setup
    .\scripts\siem.ps1 up
    .\scripts\siem.ps1 demo
    .\scripts\siem.ps1 smoke

The commands perform environment checks, generate the environment file
with random secrets and print the admin password, build and start the
services, load labelled synthetic events, and run 13 end-to-end checks.

### Accessing the Services

- **SIEM UI:** <http://localhost:8080>

- **Default User:** `admin`

- **Password:** Printed by the setup command.

- **Grafana:** <http://localhost:3000>

- **Grafana Dashboard:** `SIEM - Operations`

To stop the services while retaining data:

    .\scripts\siem.ps1 down

To wipe all project data:

    .\scripts\siem.ps1 reset

### Plain Docker Compose on Linux/macOS

Create the environment file:

    cp .env.example .env

Set `POSTGRES_PASSWORD`, `SIEM_JWT_SECRET`, `SIEM_INGEST_API_KEYS`,
`SIEM_COLLECTOR_KEY`, and the admin password in the environment file.

Start the services:

    docker compose -f docker-compose.yml \
      -f docker-compose.dev.yml up -d --build --wait

## Option B: Run Published Images from GHCR

The CI/CD workflow publishes two images to GitHub Container Registry
(GHCR). Images are tagged as `sha-<7 chars>` for the main branch and
`vX.Y.Z` for releases. The `latest` tag is not used.

Pull the images:

    docker pull ghcr.io/snehaankandaswamy/siem-backend:<tag>
    docker pull ghcr.io/snehaankandaswamy/siem-frontend:<tag>

Set the image namespace and version:

    export SIEM_IMAGE_NAMESPACE=snehaankandaswamy/siem
    export SIEM_VERSION=<tag>

Start the production Compose configuration:

    docker compose -f docker-compose.yml \
      -f docker-compose.prod.yml up -d --wait

The production overlay enables the OpenSearch security plugin. The demo
TLS certificates must be replaced before real use.

## Option C: Linux Server Deployment

The deployment script can be used to deploy a selected image version:

    IMAGE_NS=snehaankandaswamy/siem \
      ./scripts/deploy.sh v1.0.0

Rollback can be performed by running the deployment script again with an
older image tag.

## Option D: Live Demo

The presentation demo uses the frontend hosted on Vercel and the backend
hosted on Render through `render.yaml`.

- The demo uses SQLite and an in-memory event store; data resets when
  the service restarts.

- Synthetic data can be loaded from **Admin $\rightarrow$ System
  $\rightarrow$ Load synthetic scenarios**.

- Backend URL: <https://siem-backend-li9r.onrender.com>

- Frontend URL: To be supplied by the project deployment.

# Docker and Image Publishing

## Dockerfiles and Container Hardening

- **Backend:** Uses a multi-stage build based on `python:3.12-slim`. It
  runs as a non-root user (UID 10001), has a health check on `/healthz`,
  and uses a single Uvicorn worker with graceful shutdown.

- **Frontend:** Uses a Vite build served by unprivileged Nginx. Nginx
  also proxies `/api` requests to the backend.

- **Compose Hardening:** The backend uses a read-only filesystem, drops
  all Linux capabilities, enables no-new-privileges, and uses an
  internal-only data network. Log rotation, health checks, and
  `depends_on: service_healthy` are configured.

- **Database Migrations:** A one-shot migration service runs
  `alembic upgrade head` before the backend starts.

## Automated Publishing to GHCR

The workflow is defined in `.github/workflows/cd.yml`.

On a push to the main branch or a `v*` tag, it performs the following
steps:

1.  Authenticates to `ghcr.io` using the ephemeral `GITHUB_TOKEN`.

2.  Builds backend and frontend images with Buildx using the GitHub
    Actions layer cache.

3.  Pushes the images with SBOM and provenance attestations.

4.  Scans the published images using Trivy and fails on CRITICAL
    findings.

5.  On tags or manual dispatch, deploys over SSH to a protected GitHub
    Environment (staging/production) and runs a health check.

## Publishing to Docker Hub

Log in to Docker Hub:

    docker login

Build the backend and frontend images:

    docker build -t <dockerhub-user>/siem-backend:1.0.0 ./backend
    docker build -t <dockerhub-user>/siem-frontend:1.0.0 ./frontend

Push both images:

    docker push <dockerhub-user>/siem-backend:1.0.0
    docker push <dockerhub-user>/siem-frontend:1.0.0

Other users can pull and run the published images:

    docker pull <dockerhub-user>/siem-backend:1.0.0
    docker pull <dockerhub-user>/siem-frontend:1.0.0

    export SIEM_BACKEND_IMAGE=<dockerhub-user>/siem-backend:1.0.0
    export SIEM_FRONTEND_IMAGE=<dockerhub-user>/siem-frontend:1.0.0

    docker compose -f docker-compose.yml \
      -f docker-compose.dev.yml up -d --wait

Docker Hub repository pages:

- [https://hub.docker.com/r/\<dockerhub-user\>/siem-backend](https://hub.docker.com/r/<dockerhub-user>/siem-backend){.uri}

- [https://hub.docker.com/r/\<dockerhub-user\>/siem-frontend](https://hub.docker.com/r/<dockerhub-user>/siem-frontend){.uri}

# Performance and Monitoring

## Prometheus Metrics

The backend exposes Prometheus metrics through the `/metrics` endpoint.

Metric labels use bounded enums only; they do not use users, IP
addresses, or raw text.

  **Metric**                                                            **Meaning**
  --------------------------------------------------------------------- -------------------------------
  `siem_http_requests_total{method,route,status}`                       Request count
  `siem_http_request_seconds{route}`                                    Latency histogram
  `siem_events_accepted_total`, `_duplicate_total`, `_rejected_total`   Ingest throughput and quality
  `siem_parse_failures_total`                                           Parser failures
  `siem_alerts_created_total{rule,severity}`                            Detection output
  `siem_alerts_suppressed_total`                                        Suppressed alerts
  `siem_detection_failures_total`                                       Detection errors
  `siem_background_failures_total`                                      Background processing errors
  `siem_notifications_total{channel,status}`                            Email/Slack delivery
  `siem_database_up`                                                    Database health
  `siem_opensearch_up`                                                  OpenSearch health
  `siem_collector_last_seen_age_seconds`                                Collector liveness

## Dashboards, Resilience, and Known Limits

- **Dashboards and Alerting:** Grafana's `SIEM - Operations` dashboard
  is auto-provisioned from `deploy/grafana/`. Prometheus alert rules are
  located in `deploy/prometheus/alerts.yml`.

- **Resilience:** All containers were restarted with data retained, and
  the backend exits cleanly in approximately one second when stopped
  using `docker compose stop`.

- **Known Limits:** The deployment uses a single backend worker,
  single-node OpenSearch without replicas, an in-process rate limiter,
  and an in-process live buffer.

# Testing and Validation

## Test Results

The following table summarises the reported validation results.

  **Check**             **Tool / Command**                                                                       **Result**
  --------------------- ---------------------------------------------------------------------------------------- -------------------------------------
  Backend lint/format   `ruff check .`, `ruff format --check .`                                                  Pass
  Backend tests         `pytest -q --cov=app` against real OpenSearch 2.17.1                                     62 passed, 91% line coverage
  DB migrations         `alembic upgrade head`, downgrade base, upgrade head, check (SQLite and PostgreSQL 16)   Pass
  Frontend              ESLint, Prettier, TypeScript compiler, Vitest, build                                     Pass, 21 tests
  End-to-end smoke      `siem.ps1 smoke` on the live Compose stack                                               13/13 checks
  Browser test          Playwright/Chromium: login and every page                                                0 console errors, 0 HTTP 5xx
  Windows host checks   `Test-WindowsHost.ps1 -StackRunning`                                                     Pass
  Dependency scans      `pip-audit`, `npm audit`                                                                 0 known vulnerabilities
  Image scans           Trivy (HIGH/CRITICAL, fixable)                                                           0 backend / 0 frontend
  Secret scan           gitleaks                                                                                 No leaks
  Backup/restore        Backup, change data, restore                                                             PostgreSQL returned to backup state
  Persistence           Restart backend, PostgreSQL, OpenSearch                                                  Data retained

## Test Coverage

- **Detection (`test_detection.py`):** Each of the five rules fires on
  its positive fixture and not on negative fixtures. The smoke run
  produces exactly SIEM-001 through SIEM-005.

- **Normalisation (`test_normalize.py`):** Tests Windows, Linux, Nginx,
  Docker, and JSON samples.

- **API (`test_api.py`):** Covers authentication, RBAC, rate limits,
  ingest validation, de-duplication, alert and incident workflows, and
  reports.

- **Notifications (`test_notify.py`):** Email delivery through a real
  in-process SMTP server (aiosmtpd), retries and failure handling, and
  Slack through a mock transport.

- **Integration (`test_opensearch_integration.py`):** Tests real
  OpenSearch search and aggregations.

- **Migrations (`test_migrations.py`):** Tests database migration
  behaviour.

- **Frontend (Vitest):** Tests the live stream and polling fallback,
  permissions, alerts, and incidents UI.

## Test Data and Safety

Synthetic events are labelled in the UI and are never seeded
automatically.

The demo endpoint is refused when `SIEM_ENV=production`.

Test fixtures use RFC 5737 documentation IP addresses, the harmless
EICAR hash, and a `.invalid` domain.

Nothing is executed or scanned.

## Automated Continuous Integration

The CI workflow is defined in `.github/workflows/ci.yml` and includes:

- Backend linting, migrations, and pytest against an OpenSearch service
  container, together with pip-audit.

- Frontend linting, formatting, type checking, tests, build, and npm
  audit.

- A Windows runner job using PSScriptAnalyzer and backend tests.

- A Compose stack smoke test, including a persistence-across-restart
  check.

- Trivy image scans for both images and a gitleaks secret scan.

## Tests Not Yet Verified

The following items were not verified at the time of the project
submission:

- A real Slack webhook, a real MaxMind GeoIP database, and the Windows
  Security log (which requires an elevated shell).

- The production overlay has not been started with published images.

- The GitHub Actions workflows have not yet had a first run on GitHub.

# Repository and Team Contributions

## Repository

The project source code is hosted at:

::: center
<https://github.com/SnehaanKandaswamy/SIEM>
:::

## Team Contributions

  **Member**                   **Contribution**
  ---------------------------- ---------------------------------------------------------------------------------
  Karthik -- 24011103013       Backend and Database
  Kanishk -- 24011103022       DevOps and Infrastructure
  Snehaan -- 24011103060       Log Pipeline and OpenSearch
  Liitheshwar -- 24011103027   Detection Engine and Security
  Dependabot (automated)       Weekly dependency update pull requests for pip, npm, GitHub Actions, and Docker

# Conclusion {#conclusion .unnumbered}

The SIEM Dashboard for DevOps provides a self-hosted platform for
collecting, normalising, indexing, and analysing security events from
multiple sources.

It combines event ingestion, detection rules, alert and incident
management, role-based access control, reporting, notifications, and
operational monitoring in one system.

The project includes Docker-based deployment, automated image
publishing, security scanning, CI checks, and validation across backend,
frontend, integration, and end-to-end workflows.

The documented limitations and unverified items identify areas that
remain for further validation and hardening.
