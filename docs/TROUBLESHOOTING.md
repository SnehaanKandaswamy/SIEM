# Troubleshooting

Start with `.\scripts\siem.ps1 doctor` and `.\scripts\siem.ps1 status`, then `.\scripts\siem.ps1 logs <service>`.

| Symptom | Cause / fix |
|---|---|
| `doctor`: *Docker daemon NOT reachable* | Start Docker Desktop and wait until the whale says "Engine running". `docker` is not on PATH in a shell opened before installation: open a new terminal |
| OpenSearch container restarts, log says `max virtual memory areas vm.max_map_count [65530] is too low` | `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`; persist via `.wslconfig` (DEPLOYMENT.md §1) |
| OpenSearch killed / `exit 137` | Not enough memory. Lower `OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m` in `.env` and/or raise WSL2 memory in `.wslconfig` |
| `up` waits then reports *unhealthy* | `siem.ps1 status` → find the unhealthy service → `siem.ps1 logs <svc>`. First start pulls ≈4 GB; the 600 s `--wait-timeout` can be re-run safely |
| Port 8080/3000 already in use | Change `SIEM_HTTP_PORT` / `GRAFANA_PORT` in `.env` (and `SIEM_CORS_ORIGINS` if you use another origin) then `siem.ps1 up` |
| `variable is not set` from Compose | `.env` is missing or incomplete → `siem.ps1 setup` (never overwrites an existing file) |
| Backend exits: *SIEM_JWT_SECRET must be set* | `.env` secret empty or <32 chars |
| Cannot log in | Use the bootstrap credentials from `.env`. The bootstrap only runs when **no admin exists**; to reset a lost admin password, set `PATCH /api/users/{id}` from another admin, or `docker compose exec postgres psql -U siem -c "delete from users where username='admin'"` and restart the backend with the bootstrap variables set. 10 failed logins/min per IP are rate-limited (429) |
| Login works but pages show *401* repeatedly | Clock skew or expired refresh token → sign out/in; in a VM make sure the time is synced |
| Windows: scripts are blocked | `powershell -ExecutionPolicy Bypass -File .\scripts\siem.ps1 …` or `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| No Docker/Nginx events appear | `siem.ps1 logs fluent-bit` — look for `HTTP status=200` lines. Status 401 → `SIEM_COLLECTOR_KEY` is not listed in `SIEM_INGEST_API_KEYS`. Status 503 → OpenSearch is down; Fluent Bit buffers and retries. The Nginx log files are `siem-access.log`/`siem-error.log` on the `nginxlogs` volume |
| Windows forwarder: *Access denied reading 'Security'* | Run an elevated PowerShell (or add the account to *Event Log Readers*) |
| Windows forwarder: no 4625/4688 events | Auditing is not enabled — see DEPLOYMENT.md §3. 4688 `CommandLine` stays empty without the GPO setting |
| Forwarder keeps retrying | Wrong `-ApiUrl`/key (401) or API down; it never advances its bookmark on failure. Reset with `Remove-Item $env:ProgramData\SiemCollector\*.recordid` (re-sends the last 5 min) |
| Alerts don't fire for port scans | Needs connection telemetry (`SRC= DST= DPT=` kernel log lines or Windows 5156/5157). Check Log explorer for `category=network` events |
| Alerts don't fire for suspicious commands | Events need `command_line` (Sysmon 1 / 4688 with command-line auditing / sudo). Check an event's detail panel |
| Search returns nothing right after ingest | OpenSearch refreshes about every second; retry. The explorer defaults to the *last 24 hours* — widen the range |
| Search says *request was rejected* | Invalid `src_ip`, sort or filter value (HTTP 400). Free-text syntax errors never fail (they are treated leniently) |
| Attack map is empty | Expected unless a GeoIP database is configured (SECURITY.md); private/reserved IPs are never located. The dev overlay enables only the labelled *synthetic* demo mapping |
| Live stream shows "Polling fallback" | The SSE connection failed twice (proxy/VPN buffering). Polling every few seconds is the documented fallback; check that no proxy buffers `text/event-stream` |
| Slack/email not arriving | Admin → Integrations shows whether each channel is configured; use **Send test**. Delivery failures (with error class) are in `notification_deliveries` and `siem_notifications_total{status="failed"}`. Severity thresholds: email ≥ high, Slack ≥ medium |
| Grafana panels empty | Prometheus target down (*Status → Targets* at <http://localhost:9090> with the dev overlay) or no traffic yet; some panels (`rate()`) need ≥2 scrapes |
| `restore` fails on OpenSearch | The snapshot path must be owned by UID 1000 — the script fixes ownership; check `docker compose logs opensearch` for `repository_exception` and that `path.repo=/snapshots` is set |
| Disk filling up | OpenSearch retention deletes indices after 30 days; check `docker system df`, Prometheus retention (15 d), and Docker log rotation (10 MB × 3 per container) |
| Need to start over | `.\scripts\siem.ps1 reset` (deletes **all** volumes after confirmation) |

## Diagnosing unhealthy dependencies

```powershell
Invoke-RestMethod http://localhost:8080/readyz                      # {"status":"ready","checks":{"database":"ok","search":"ok"}}
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec postgres pg_isready -U siem
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec opensearch curl -s localhost:9200/_cluster/health?pretty
docker compose -f docker-compose.yml -f docker-compose.dev.yml exec prometheus wget -qO- localhost:9090/api/v1/targets
```
`readyz` returns 503 with the failing check when PostgreSQL or the search backend is unreachable; the backend keeps serving
`/healthz` and recovers by itself when the dependency returns (connections are `pool_pre_ping`ed, the OpenSearch client retries).
