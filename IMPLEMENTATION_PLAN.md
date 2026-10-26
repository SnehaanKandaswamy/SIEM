# Implementation plan

> The repository was empty and `docs/SIEM-Project-Proposal.pdf` does **not exist**, so requirements were taken from the
> project brief (build prompt) section by section. `docs/FEATURE-TRACEABILITY.md` maps each requirement to code, endpoints and tests.

## Architecture (summary — details in `docs/ARCHITECTURE.md`)

Sources (Windows host forwarder, Fluent Bit for Docker/Nginx/Linux, synthetic generator) → `POST /api/ingest` (key auth, limits)
→ normalise/enrich → OpenSearch (events) → detection engine → PostgreSQL (alerts/incidents/…) → React UI, notifications, reports.
Prometheus scrapes the backend and Fluent Bit; Grafana visualises. Compose runs everything on Docker Desktop/WSL2.

## Stages and acceptance criteria

| # | Stage | Acceptance (all executed unless TASKS.md says otherwise) |
|---|---|---|
| 1 | Foundation: repo layout, Compose (+dev/prod), PostgreSQL + OpenSearch health checks, lint/test infrastructure | `docker compose config` valid; services healthy; ruff/eslint/pytest/vitest wired |
| 2 | Backend + auth: models, Alembic, JWT/RBAC/audit, ingestion, normalisation, OpenSearch store | migrations up/down/check; RBAC matrix test; ingest → OpenSearch search works on a real cluster |
| 3 | Detection + incidents: 5 rules, correlation/suppression, alerts, incidents, notifications | positive+negative fixture per rule; suppression test; incident state machine test; SMTP test against a real server |
| 4 | Frontend: all pages on real APIs, live stream, explorer, GeoIP, MITRE, reports, admin | 21 Vitest tests; headless-browser walk of every page with zero console/5xx errors |
| 5 | DevOps: production images, CI, GHCR CD, deploy+rollback, Prometheus/Grafana, backup/restore | images build, non-root, Trivy clean; smoke passes; backup→mutate→restore verified; workflows reviewed (not run) |
| 6 | Integration + release: smoke, persistence, shutdown, Windows checks, docs, traceability | `scripts\siem.ps1 smoke` 13/13; Windows host checks pass; TASKS.md states what is **not** verified |

## Dependencies

Docker Desktop (WSL2), Python 3.12, Node 22, PostgreSQL 16, OpenSearch 2.17, Fluent Bit 3.1, Prometheus 2.54, Grafana 11.2.
Versions and rationale: `docs/DEVOPS.md`. Optional external services (SMTP, Slack, GeoLite2, GHCR, a deploy target) are
abstracted and documented; none is required for local use.

## Key design decisions

1. **Two stores** — OpenSearch for events, PostgreSQL for relational state (no event duplication).
2. **Rules evaluate against the store** (windows fetched from OpenSearch) rather than keeping per-process state, so they are
   restart-safe and replay-safe; correlation state lives in PostgreSQL alerts (suppression by key + window).
3. **Idempotent ingestion** via deterministic `event_id` + OpenSearch `create` (retries are harmless).
4. **Honest telemetry handling** — rules only fire on fields that exist; no invented coordinates, no MITRE mapping without
   justification; prerequisites are documented.
5. **Windows collection runs on the host** (Linux containers can't read the Windows Security log) via a dependency-free
   PowerShell forwarder with bookmarks and retries; Fluent Bit covers Docker/Nginx/Linux.
6. **Single backend worker** (in-process live buffer and rate limiters) — documented scaling limit.
