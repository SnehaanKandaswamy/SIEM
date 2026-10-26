# SIEM Dashboard for DevOps

A self-hosted Security Information and Event Management platform: collect → normalise → index → detect → alert →
investigate → report. FastAPI + PostgreSQL + OpenSearch + Fluent Bit behind a React/TypeScript dashboard, with
Prometheus/Grafana monitoring, GitHub Actions CI/CD and a Windows-first workflow (Docker Desktop + WSL2 + PowerShell).

* Five executable detections (brute force, multiple failed logins, port scan, suspicious command, malware indicators)
  with correlation, suppression, MITRE ATT&CK mapping (only where justified) and evidence.
* Alerts → incidents (assign, notes, state machine, audit timeline), role-based access (viewer / analyst / admin).
* Overview dashboard, live event stream (SSE + polling fallback), OpenSearch log explorer, GeoIP map, MITRE view,
  CSV/PDF reports, Email/Slack notifications, administration screens.
* Everything in this repo is documented in [`docs/`](docs/): [architecture](docs/ARCHITECTURE.md),
  [DevOps/CI-CD](docs/DEVOPS.md), [deployment & backup](docs/DEPLOYMENT.md), [security](docs/SECURITY.md),
  [API](docs/API.md), [troubleshooting](docs/TROUBLESHOOTING.md), [traceability](docs/FEATURE-TRACEABILITY.md).
  Honest status of every item: [`TASKS.md`](TASKS.md).

## Quick start (Windows 11 + Docker Desktop, PowerShell)

Prerequisites: Docker Desktop with the WSL2 backend (Linux containers), ~8 GB RAM (16 GB recommended), 20 GB disk,
`vm.max_map_count ≥ 262144` in the WSL2 VM ([details](docs/DEPLOYMENT.md#1-windows-11-prerequisites)).

```powershell
git clone <this repo> ; cd SIEM
.\scripts\siem.ps1 doctor      # environment checks (daemon, RAM, disk, vm.max_map_count, ports)
.\scripts\siem.ps1 setup       # writes .env with random secrets; prints the admin password
.\scripts\siem.ps1 up          # build + start + wait until every service is healthy
.\scripts\siem.ps1 demo        # load labelled synthetic events (all five detections fire)
.\scripts\siem.ps1 smoke       # 13 end-to-end checks
```

* UI: <http://localhost:8080> (user `admin`, password from `setup`)
* Grafana: <http://localhost:3000> (`admin` / `GRAFANA_ADMIN_PASSWORD` in `.env`) → SIEM → *SIEM - Operations*
* Stop (keeps data): `.\scripts\siem.ps1 down` · logs: `.\scripts\siem.ps1 logs backend` · wipe everything: `.\scripts\siem.ps1 reset`

If PowerShell blocks the script: `powershell -ExecutionPolicy Bypass -File .\scripts\siem.ps1 doctor`.
WSL2 workflow, Windows event collection, production deployment, backup/restore: [DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Developing without Docker

```powershell
# backend (Python 3.12) — uses an in-memory event store and SQLite when SIEM_OPENSEARCH_URL / DATABASE_URL are unset
cd backend
python -m venv .venv ; .\.venv\Scripts\python -m pip install -r requirements-dev.txt
$env:SIEM_JWT_SECRET = -join ((48..122) | Get-Random -Count 48 | % { [char]$_ })
$env:SIEM_BOOTSTRAP_ADMIN_USERNAME = 'admin' ; $env:SIEM_BOOTSTRAP_ADMIN_PASSWORD = 'change-me-please-12'
$env:SIEM_INGEST_API_KEYS = 'dev-key' ; $env:SIEM_ALLOW_DEMO_ENDPOINTS = 'true'
.\.venv\Scripts\python -m uvicorn app.main:app --reload --port 8000
# frontend (Node 22) in another terminal: proxies /api to :8000
cd frontend ; npm ci ; npm run dev        # http://localhost:5173
```

## Tests and checks

```powershell
.\scripts\siem.ps1 test                    # everything below
cd backend  ; .\.venv\Scripts\python -m ruff check . ; .\.venv\Scripts\python -m ruff format --check . ; .\.venv\Scripts\python -m pytest -q
$env:SIEM_TEST_OPENSEARCH_URL='http://127.0.0.1:9200'; .\.venv\Scripts\python -m pytest -q   # + real OpenSearch integration tests
cd frontend ; npm run lint ; npm run format ; npm run typecheck ; npm test ; npm run build
.\scripts\windows\Test-WindowsHost.ps1 -StackRunning                                         # Windows/Docker Desktop checks
```

## Repository layout

```
backend/            FastAPI app (app/), Alembic migrations, pytest suite, Dockerfile
  app/ingest/       normalisation + GeoIP + pipeline        app/detection/   rules + engine
  app/store.py      OpenSearch / in-memory event store       app/routers/     REST + SSE endpoints
  app/services/     Email / Slack adapters                   app/demo.py      deterministic synthetic generator
frontend/           React + TS + Vite + Tailwind app, Vitest tests, Nginx image
deploy/             Fluent Bit, Prometheus (+alert rules), Grafana provisioning + dashboard, GeoIP demo mapping
scripts/            siem.ps1 (entry point), smoke/backup/restore, windows/ (forwarder, installer, host checks), deploy.sh
.github/workflows/  ci.yml, cd.yml            docker-compose{,.dev,.prod}.yml        .env.example
docs/               ARCHITECTURE, DEVOPS, DEPLOYMENT, SECURITY, API, TROUBLESHOOTING, FEATURE-TRACEABILITY
```

## Safety notes

Synthetic records are labelled in the UI and never seeded automatically; the demo endpoint is refused when
`SIEM_ENV=production`. Detection test fixtures use documentation IP ranges (RFC 5737), the harmless EICAR test hash and
a `.invalid` domain — nothing is executed, scanned or downloaded. No secrets are committed; `.env` is git-ignored.
