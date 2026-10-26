# Task status (what is actually verified)

Legend: ✅ implemented **and verified** (how) · 🟡 implemented, **not** verified in this environment · ❌ not done

Verification environment: Windows 11 Home (build 26200), Docker Desktop 4.96 (Engine 29.9.2, Compose 5.6, WSL2), Python 3.12.10, Node 24 (images use Node 22).
No Git remote exists, so nothing has run on GitHub.

## Test results (final run)

| Check | Command | Result |
|---|---|---|
| Backend lint/format | `ruff check .` / `ruff format --check .` | pass |
| Backend tests | `pytest -q --cov=app` (with `SIEM_TEST_OPENSEARCH_URL` → real OpenSearch 2.17.1) | **62 passed**, 0 skipped, 91 % line coverage (without OpenSearch: 60 passed, 2 skipped) |
| Migrations | `alembic upgrade head / downgrade base / upgrade head / check` (SQLite) + the `migrate` service on PostgreSQL 16 in Compose | pass |
| Frontend | `npm run lint` / `format` / `typecheck` / `test` / `build` | pass; **21 tests passed** |
| Stack smoke | `.\scripts\siem.ps1 smoke` | **13/13 checks passed** on the Compose stack |
| Windows host | `.\scripts\windows\Test-WindowsHost.ps1 -StackRunning` | all checks pass |
| UI in a real browser | Playwright/Chromium: login + every page + alert detail | 0 console errors, 0 HTTP 5xx |
| Dependency scans | `pip-audit -r requirements.txt`; `npm audit` | **0 known vulnerabilities** both |
| Image scans | Trivy 0.57.1 `--severity HIGH,CRITICAL --ignore-unfixed` on `siem-backend:local`, `siem-frontend:local` | **0 / 0** (frontend needed `apk upgrade`, added to its Dockerfile) |
| Secret scan | gitleaks 8.21.2 on the working tree (excl. `.env`, `node_modules`, `.venv`) | no leaks (one false positive allow-listed with justification in `.gitleaks.toml`) |
| Filesystem/config scan | Trivy fs `vuln,secret,misconfig` HIGH/CRITICAL | no findings |

## Feature status

| Area | Status | Evidence / notes |
|---|---|---|
| Ingestion API (auth, limits, rate limit, validation, dedupe, diagnostics, metrics) | ✅ | `tests/test_api.py`; smoke; Fluent Bit + forwarder delivered to the live API |
| Normalisation: Windows, Linux auth/sudo/firewall, Nginx, Docker, JSON | ✅ | `tests/test_normalize.py` (12), live Nginx/Docker/Windows-Application events indexed |
| Windows Security log events 4624/4625/4688 on a live host | 🟡 | Forwarder verified against the real **Application** log; Security needs an elevated shell/auditing policy not available here. Parser covered by fixtures incl. positional `StringInserts` |
| Fluent Bit `winevtlog` input / Linux-host Fluent Bit config | 🟡 | config + parser support provided; not run |
| OpenSearch index template (versioned), mapping, ISM retention | ✅ template/search/aggregations on real cluster · 🟡 ISM deletion after 30 days not observed (time) |
| Five detection rules (+ negatives) | ✅ | `tests/test_detection.py`; smoke produces exactly SIEM-001..005 |
| Correlation, suppression, severity ranking, rule config validation | ✅ | tests |
| MITRE mapping (T1110, T1046, T1059; SIEM-005 intentionally unmapped) | ✅ | `/api/mitre` test + UI |
| Alerts workflow (filter/sort/paginate/ack/resolve) | ✅ | API tests + Vitest |
| Incidents (create from alerts, assign, notes, transitions, history) | ✅ | API test + Vitest |
| Auth: Argon2, JWT access+refresh, RBAC, login rate limit, audit, bootstrap | ✅ | tests; live login |
| Notifications: Email | ✅ | delivered to an in-process real SMTP server (`aiosmtpd`); retries/dedupe/failure tests |
| Notifications: Slack | 🟡 | adapter + HTTP error handling tested with a mock transport; **no real Slack webhook** was available |
| Reports CSV/PDF | ✅ | tests (valid `%PDF-`, CSV neutralisation) + smoke download |
| Live stream (SSE + polling fallback) | ✅ | Vitest (stream, fallback); verified through Nginx with curl |
| Log explorer (OpenSearch full-text) | ✅ | real-cluster test incl. malformed query strings |
| GeoIP | ✅ private/unknown/static mapping · 🟡 real MaxMind database not tested (not bundled; licence) |
| Overview dashboard with live data | ✅ | tests + screenshot |
| Admin UI (users, rules, collectors, integrations, audit, system) | ✅ Vitest covers permissions; pages exercised in browser · 🟡 individual admin forms were not click-tested in the browser |
| Prometheus metrics + Grafana dashboard + alert rules | ✅ scrape + dashboard provisioned (smoke) · 🟡 alert rules are loaded but no alert was fired; no Alertmanager |
| Compose stack (health checks, non-root, read-only backend, internal network, loopback ports) | ✅ | started on Docker Desktop |
| Persistence / restart / graceful shutdown | ✅ | restart of backend+postgres+opensearch kept data; backend `stop` ≈1 s exit 0 |
| Backup + restore (PostgreSQL + OpenSearch) | ✅ | backup → mutate → restore returned PostgreSQL to the backup state and removed post-backup events |
| `docker-compose.prod.yml` (OpenSearch security on, GHCR images) | 🟡 | `config` renders; never started (needs published images and replaced demo certs) |
| GitHub Actions CI (`ci.yml`) | 🟡 | every command was run locally; the workflow itself has not run |
| GitHub Actions CD / GHCR publish / `deploy.sh` / rollback | 🟡 | written and reviewed; **no registry, remote or deploy target** — not executed |
| Windows CI runner job | 🟡 | not executed on GitHub |
| Documentation set | ✅ | README, ARCHITECTURE, DEVOPS, DEPLOYMENT, SECURITY, API, TROUBLESHOOTING, TRACEABILITY |

## Known limitations / remaining work

* Single backend worker (in-process live buffer + rate limiters); horizontal scaling needs Redis or similar.
* Single-node OpenSearch without replicas; production overlay uses the image's *demo* TLS certificates — replace them.
* Tokens live in `sessionStorage` (see SECURITY.md for the trade-off); no refresh-token revocation list.
* The Attack map draws a lat/lon grid, not a basemap (deliberately no third-party tiles).
* Alerts reference events by ID; once indices age out (30 days) the evidence list is empty (alert evidence summary remains).
* `siem.ps1 smoke` expects the dev overlay (demo generator inside the backend container).
* Vitest/Playwright tests cover critical paths but not every admin form; no accessibility audit was done.
* CI/CD, GHCR, deployment, rollback and the production overlay still need a first real run (expect minor fixes).
