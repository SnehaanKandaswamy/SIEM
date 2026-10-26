# Deployment, operations, backup and recovery

## 1. Windows 11 prerequisites

| Requirement | Detail |
|---|---|
| Docker Desktop | 4.30+ with the **WSL2 backend** and **Linux containers** (tested with Docker Desktop 4.96 / Engine 29.9 / Compose 5.6) |
| Memory | 8 GB RAM minimum, 16 GB recommended. OpenSearch heap defaults to 1 GB (`OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`); on 8 GB hosts use `-Xms512m -Xmx512m` and give WSL2 ≥ 4 GB (`%UserProfile%\.wslconfig` → `[wsl2] memory=6GB`) |
| Disk | ≥ 20 GB free for images + volumes (the stack uses ≈ 4 GB of images) |
| Kernel setting | OpenSearch needs `vm.max_map_count ≥ 262144` inside the WSL2 VM |
| Ports | `8080` (UI) and `3000` (Grafana) on **127.0.0.1**; change with `SIEM_HTTP_PORT` / `GRAFANA_PORT` |
| PowerShell | Windows PowerShell 5.1 (built in) or PowerShell 7. If scripts are blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` or invoke with `powershell -ExecutionPolicy Bypass -File …` |

### `vm.max_map_count` on Docker Desktop / WSL2

```powershell
wsl -d docker-desktop sysctl -w vm.max_map_count=262144     # immediate, lost when the VM restarts
```

To make it permanent create/extend `%UserProfile%\.wslconfig`, then `wsl --shutdown` and restart Docker Desktop:

```ini
[wsl2]
kernelCommandLine = "sysctl.vm.max_map_count=262144"
memory=8GB
```

`.\scripts\siem.ps1 doctor` reports the current value, RAM, disk, daemon, and port conflicts.

### Working inside WSL2 instead of `C:\`

The stack works from a Windows path (this is what was tested: bind mounts are used only for read-only config files).
If you develop in a WSL2 distro, clone the repo **inside the Linux filesystem** (`~/siem`, not `/mnt/c/...`) for faster file
I/O and file watching, enable *Settings → Resources → WSL integration* for that distro, and run the same commands with
`pwsh scripts/siem.ps1 …` or plain `docker compose` (the Compose files are OS-neutral).

## 2. First start (PowerShell, from the repository root)

```powershell
.\scripts\siem.ps1 doctor          # checks Docker, RAM, disk, vm.max_map_count, ports
.\scripts\siem.ps1 setup           # creates .env with random secrets; prints the generated admin password
.\scripts\siem.ps1 up              # builds + starts + waits for every health check (first run ≈ 5–10 min)
.\scripts\siem.ps1 demo            # loads the labelled synthetic scenarios through the real ingestion API
.\scripts\siem.ps1 smoke           # 13 end-to-end checks (login, ingest, 5 rules, search, reports, Prometheus, Grafana)
```

Open <http://localhost:8080> and sign in as `admin` with the password from `setup` (also in `.env`).
Grafana: <http://localhost:3000> (`admin` / `GRAFANA_ADMIN_PASSWORD`), dashboard **SIEM → SIEM - Operations**.

Everyday commands: `.\scripts\siem.ps1 status | logs backend | down | migrate | test | backup | restore <name> | reset`.
`down` **never** removes volumes. `reset` deletes all data and requires typing `siem`.

Equivalent raw Compose commands:

```powershell
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build --wait
docker compose -f docker-compose.yml -f docker-compose.dev.yml run --rm migrate      # Alembic upgrade head
docker compose -f docker-compose.yml -f docker-compose.dev.yml down
```

Demo data is only available through `docker-compose.dev.yml` (`SIEM_ALLOW_DEMO_ENDPOINTS=true`); it is never seeded
automatically and the endpoint refuses to run when `SIEM_ENV=production`.

### Demo walk-through

1. `.\scripts\siem.ps1 demo` (or *Administration → System → Load synthetic scenarios*).
2. **Alerts** now shows five alerts (one per rule), tagged *synthetic*: brute force from `198.51.100.23`, multiple failed
   logins for `jdoe`, port scan from `198.51.100.77`, encoded PowerShell on `WIN-WS07`, EICAR-hash/test-domain indicators.
   The `negative_cases` and `normal_activity` scenarios deliberately produce **no** alert.
3. Open an alert → evidence + supporting events → **Create incident** → assign, add notes, move through
   `open → investigating → resolved → closed` (a resolution summary is required).
4. **Attack map** shows the two synthetic source ranges at their (demo-labelled) coordinates; **MITRE ATT&CK** shows T1110, T1046, T1059.
5. Re-run `demo` a minute later: the ongoing attacks update the same alerts (counters/last-seen) instead of creating new ones.
6. **Reports** → alerts/incidents/events as CSV or PDF.

## 3. Collectors

### Docker containers and Nginx (included)
Fluent Bit tails `/var/lib/docker/containers/*/*-json.log` (source `docker`) and the Nginx logs written by the frontend
container to the `nginxlogs` volume (source `nginx`). Backend and Fluent Bit use the `local` logging driver so their own
output is **not** collected (prevents an ingest → log → ingest feedback loop). Fluent Bit keeps a disk buffer and tail
offsets in the `fluentstate` volume, so restarts neither lose nor re-send data.

### Windows event logs (host-side)
Linux containers cannot read the Windows Security log, so collection runs **on the Windows host**:

```powershell
# one-off test of what would be sent (no network)
.\scripts\windows\Send-WindowsEvents.ps1 -LogName Application -Once -DryRun
# real forward, reads the key from the environment
$env:SIEM_INGEST_KEY = '<SIEM_COLLECTOR_KEY from .env>'
.\scripts\windows\Send-WindowsEvents.ps1 -ApiUrl http://localhost:8080 -LogName Security -EventIds 4624,4625,4688,4720 -Once
# permanent: scheduled task running as SYSTEM at startup (elevated PowerShell)
.\scripts\windows\Install-WindowsCollector.ps1 -ApiUrl http://<siem-host>:8080 -ApiKey '<key>'
```

* The **Security** log needs an elevated shell (or *Event Log Readers* membership).
* Enable auditing: `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`,
  `auditpol /set /subcategory:"Process Creation" /success:enable`, and set GPO *Administrative Templates → System → Audit
  Process Creation → Include command line in process creation events* (otherwise `command_line` is empty and SIEM-004 cannot
  fire on 4688). Sysmon event 1 (with hashes) is the better source for SIEM-004/005.
* Port-scan telemetry from Windows requires *Audit Filtering Platform Connection* (5156/5157) — very high volume.
* A bookmark (`%ProgramData%\SiemCollector\<log>.recordid`) makes restarts resume without gaps or duplicates; failed
  sends are retried 5× with back-off and the bookmark only advances after success.
* Fluent Bit's native `winevtlog` input also works: send to `/api/ingest` with `X-Source-Type: windows`; the parser accepts
  both `EventData` objects and positional `StringInserts` for events 4624/4625/4688/5156/5157. (Only the PowerShell
  forwarder has been exercised against a live host here; see TASKS.md.)
* To remove: `.\scripts\windows\Install-WindowsCollector.ps1 -Uninstall`.

### Linux hosts
Run Fluent Bit on the host with `deploy/fluent-bit/fluent-bit-linux-host.conf` (tails `/var/log/auth.log`/`secure` for
SSH/sudo and `/var/log/kern.log` for iptables `LOG` lines → `SIEM-001/002/003`). Example firewall rule to produce scan telemetry:
`iptables -A INPUT -p tcp --syn -j LOG --log-prefix "SIEM "`.

## 4. Configuration reference (`.env`)

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD`, `SIEM_JWT_SECRET`, `GRAFANA_ADMIN_PASSWORD` | generated by `setup`; required |
| `SIEM_INGEST_API_KEYS` | comma-separated accepted ingest keys; `SIEM_COLLECTOR_KEY` is the one Fluent Bit uses |
| `SIEM_BOOTSTRAP_ADMIN_USERNAME/PASSWORD/EMAIL` | one-time administrator creation |
| `SIEM_ENV` | `development` / `production` (production hides API docs and disables the demo loader) |
| `SIEM_HTTP_PORT`, `GRAFANA_PORT`, `SIEM_CORS_ORIGINS`, `SIEM_HOST_NAME` | exposure / labelling |
| `OPENSEARCH_JAVA_OPTS` | heap size |
| `SIEM_SMTP_HOST/PORT/USER/PASSWORD/FROM/STARTTLS`, `SIEM_NOTIFY_EMAIL_TO`, `SIEM_NOTIFY_EMAIL_MIN_SEVERITY` (default `high`) | email notifications |
| `SIEM_SLACK_WEBHOOK_URL`, `SIEM_NOTIFY_SLACK_MIN_SEVERITY` (default `medium`) | Slack notifications |
| `SIEM_GEOIP_DB_PATH` / `SIEM_GEOIP_STATIC_PATH` | GeoIP sources (see SECURITY.md) |
| `SIEM_IMAGE_NAMESPACE`, `SIEM_VERSION`, `OPENSEARCH_ADMIN_PASSWORD` | production overlay only |
| `SIEM_LOGIN_RATE_PER_MINUTE`, `SIEM_INGEST_RATE_PER_MINUTE`, `SIEM_ACCESS_TOKEN_MINUTES`, `SIEM_NOTIFY_MAX_ATTEMPTS`, `SIEM_INGEST_MAX_BATCH`, `SIEM_INGEST_MAX_BODY_BYTES` | tuning |

Local development vs production authentication: in development the generated bootstrap admin is stored in `.env` for
convenience; in production set a strong unique password, remove the bootstrap variables after first login, set
`SIEM_ENV=production`, restrict `SIEM_CORS_ORIGINS` to your real origin, front the UI with TLS, and use a secret manager or
protected CI secrets rather than a world-readable `.env` (`chmod 600`).

## 5. Production deployment (Linux server with Docker)

Images are built and published by the CD workflow (see DEVOPS.md). On the server (`/opt/siem`): copy the repo's compose files,
`deploy/` folder and `scripts/deploy.sh`, create `.env` once with production values (including `SIEM_ENV=production`,
`SIEM_IMAGE_NAMESPACE`, `OPENSEARCH_ADMIN_PASSWORD`, `SIEM_COLLECTOR_KEY`), then:

```bash
echo "$GHCR_USER\n$GHCR_TOKEN" | IMAGE_NS=<owner>/<repo> ./deploy.sh sha-abc1234     # or v1.2.0
```

`deploy.sh` refuses `latest`, pulls the pinned images, runs migrations (the `migrate` one-shot service), starts the stack,
polls `/readyz`, records the version in `.deployed_version`, and **automatically rolls back** to the previous version if the new
one is not healthy within 300 s. The same command with an older version is the manual rollback.
OpenSearch security is enabled by `docker-compose.prod.yml`; replace the demo TLS certificates for a real deployment.

## 6. Monitoring

* Prometheus (internal) scrapes `backend:8000/metrics` and `fluent-bit:2020`. Rules in `deploy/prometheus/alerts.yml`
  (backend down, dependency down, 5xx rate, parse-failure spike, detection/background failures, silent collectors, Fluent Bit
  drops). Add Alertmanager to route them; the stack only evaluates them.
* Grafana dashboard *SIEM - Operations* is provisioned from `deploy/grafana/dashboards/`.
* Quick checks: `GET /readyz`, `docker compose ps`, Admin → Collectors, Prometheus *Status → Targets*
  (dev overlay: <http://localhost:9090>).

## 7. Backup and recovery

> A Docker volume is **not** a backup. `scripts\backup.ps1` stages dumps in the `backups` volume and **copies them to
> `.\backups-local\<timestamp>\` on the host**; copy that folder off the machine (and encrypt it) to have a real backup.

```powershell
.\scripts\siem.ps1 backup                       # pg_dump -Fc + OpenSearch fs snapshot of siem-events-*
.\scripts\siem.ps1 restore 20261022T054635Z     # asks for confirmation; stops writers, restores, restarts
```

What each part does: PostgreSQL `pg_dump -Fc` (users, rules, alerts, incidents, audit…) → `pg_restore --clean --if-exists`;
OpenSearch snapshot repository `siem_fs` at `/snapshots/os` (`path.repo`), restore deletes `siem-events-*` and restores from the snapshot.

### Recovery verification
Tested on Windows 11 / Docker Desktop: before backup the instance had 5 alerts and 0 incidents; afterwards one incident and two
events were created; after `restore`, PostgreSQL returned to 5 alerts / 0 incidents and the post-backup events were gone
(search for them returned 0) while collection resumed. To verify your own restore: note `GET /api/dashboard/overview` →
`events_total`, `/api/alerts?size=1` → `total`, `/api/incidents` → `total` before backup; after restore compare (event counts
keep growing from live collection), search for a marker event you created after the backup (must be absent), run
`.\scripts\siem.ps1 smoke`, and check `/readyz`.

### Retention and lifecycle
* Events: daily indices `siem-events-YYYY.MM.DD`; ISM policy `siem-retention` deletes indices after **30 days**
  (`RETENTION_DAYS` in `store.py`). The index template is versioned (`TEMPLATE_VERSION`) and only rewritten when the version
  changes; nothing is ever re-indexed at start-up.
* Prometheus keeps 15 days. Alerts/incidents/audit in PostgreSQL are kept until you delete them.
* Interrupted ingestion: Fluent Bit buffers to disk and retries; the PowerShell forwarder resumes from its bookmark; duplicates
  from retries are ignored by the deterministic `event_id`.
* Service restarts: all state is on named volumes (`pgdata`, `osdata`, …). Tested: restarting `backend`, `postgres` and
  `opensearch` kept all alerts/events; `docker compose stop backend` exits cleanly (code 0, ≈1 s) via graceful shutdown.

## 8. Resource recommendations

| Service | Memory (typical) | Notes |
|---|---|---|
| OpenSearch | 1.5–2 GB (1 GB heap) | the dominant consumer; scale heap with ingest volume, keep ≤50 % of RAM |
| PostgreSQL | 150–300 MB | |
| Backend | 150–250 MB | single worker |
| Fluent Bit / Nginx / Prometheus / Grafana | <100 / <20 / 150 / 150 MB | |
Single-node OpenSearch, no replicas: suitable for lab/small-team use (≈ hundreds of events/s). Larger volumes need a multi-node
cluster and horizontal backend scaling (see the single-worker note in ARCHITECTURE.md).
