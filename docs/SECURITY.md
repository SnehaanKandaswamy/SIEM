# Security

## Authentication and authorisation

| Control | Implementation |
|---|---|
| Passwords | Argon2id (`argon2-cffi` defaults); login timing equalised for unknown users with a dummy hash |
| Tokens | HS256 JWT. Access token 30 min (`SIEM_ACCESS_TOKEN_MINUTES`), refresh token 7 days. Token `typ` is checked so a refresh token can't be used as an access token and vice versa |
| Secret | `SIEM_JWT_SECRET` (≥32 chars) is mandatory — the app refuses to start without it. Nothing is defaulted or committed |
| Roles | `viewer` (read), `analyst` (+ acknowledge/resolve alerts, incidents, notes, reports, diagnostics), `admin` (+ users, rules, audit, integrations, settings, demo loader) |
| Enforcement | FastAPI dependencies on **every** router; the user's role/active flag is re-read from PostgreSQL on each request, so demotion/disable applies immediately. The React app only hides controls |
| Bootstrap | No default account exists. An admin is created at start-up only if `SIEM_BOOTSTRAP_ADMIN_USERNAME/PASSWORD` are set and no admin exists (password ≥ 12 chars). `scripts\siem.ps1 setup` generates a random one. Remove the bootstrap variables from `.env` after the first login if you wish |
| Rate limits | Login: 10/min per client IP (`SIEM_LOGIN_RATE_PER_MINUTE`). Ingest: 600/min per key. In-process (single replica) |
| Audit | Logins (success/failure/rate-limited), user create/update, alert ack/resolve, incident create/update/notes, rule changes, report exports, notification tests, demo loads → `audit_logs` (admin UI + API) |
| IDOR | Resources are single-tenant and role-gated; identifiers are integers validated against the DB, event IDs are validated as alphanumeric hashes |

## Input handling

* **SQL injection** — SQLAlchemy ORM with bound parameters only; sort fields are whitelisted dictionaries.
* **OpenSearch injection** — user text goes only into a `simple_query_string` clause (never parsed as Query DSL, never
  throws on bad syntax); filters are `term(s)`/`range` built from validated values; sort fields whitelisted.
* **XSS** — React escapes all text; there is no `dangerouslySetInnerHTML`. Untrusted log text is rendered only as text
  nodes (tests assert a hostile `<img onerror>` message creates no element). Nginx sends a strict CSP
  (`default-src 'self'`, no inline scripts).
* **CSV injection** — cells beginning with `= + - @ TAB CR` are prefixed with `'`.
* **Notification injection** — control characters stripped, `<`/`>` neutralised, subjects single-line.
* **Regex DoS** — detection patterns are length-limited (300) and validated on save; they run against ≤2 048 chars.
  Admins are trusted, but note that a pathological regex can still be slow: review custom patterns.
* **Request limits** — 5 MB body, 5 000 records/request (processed in slices), parse errors tracked.
* **CORS** — explicit allow-list (`SIEM_CORS_ORIGINS`), no credentials, limited methods/headers.
* **Headers** — `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API
  responses; Swagger/OpenAPI disabled when `SIEM_ENV=production` and blocked at the proxy.

## Token storage trade-off

The SPA keeps tokens in `sessionStorage` (cleared when the tab closes) and sends them in the `Authorization` header.
This avoids CSRF, but any XSS would expose them; the CSP + no-HTML-injection rules above are the mitigation. For a
higher bar, move to `HttpOnly; SameSite=Strict` cookies with CSRF tokens behind the same origin.

## Network exposure

Only the web UI (`127.0.0.1:8080`) and Grafana (`127.0.0.1:3000`) are published, and only on loopback. PostgreSQL and
OpenSearch live on an `internal: true` Docker network with no host ports (the dev overlay publishes 5432/9200/9090/8000
**on loopback only**, for debugging). `/metrics` is not proxied by Nginx. To expose the UI to a LAN put a TLS-terminating
reverse proxy in front (the stack serves plain HTTP) and change the port binding deliberately.

Container hardening: backend runs as UID 10001, read-only root FS, all capabilities dropped, `no-new-privileges`;
Nginx is `nginx-unprivileged` (UID 101). Fluent Bit runs as root **only** because it must read
`/var/lib/docker/containers`; it mounts everything read-only.

### OpenSearch security

The base Compose file runs OpenSearch **without** its security plugin because it is reachable only from the internal
network. `docker-compose.prod.yml` turns the plugin on (TLS with the image's *demo* certificates + admin password) and the
backend connects with `https` + credentials. The demo certificates are self-signed and shared by every install of the same
image: **replace them with your own CA before treating this as a hardened deployment.** The production overlay has not been
executed in this repository's test environment (see TASKS.md).

## Secrets

* Only `.env.example` (placeholders) is committed; `.env` is git-ignored and `siem.ps1 setup` generates random values.
* CI: GitHub Secrets for deploy credentials; the CD workflow passes them via environment variables / stdin, never on
  command lines. GHCR pushes use the ephemeral `GITHUB_TOKEN`.
* The Slack webhook URL and SMTP password are only read from the environment; the API never returns them, and the
  `notification_deliveries.destination` column stores `slack-webhook`, not the URL.

## Vulnerability scanning and handling policy

| Scanner | Where | Policy |
|---|---|---|
| `pip-audit` | CI `backend` job | fail on any known vulnerability in `requirements.txt` |
| `npm audit --audit-level=high` | CI `frontend` job | fail on high/critical |
| Trivy (images) | CI `images` job + CD | fail on fixable HIGH/CRITICAL (`ignore-unfixed`) |
| Trivy (fs/config/secret) | CI `filesystem-scan` | fail on HIGH/CRITICAL |
| Gitleaks | CI `secrets` job | fail on any finding |
| Dependabot | weekly | PRs for pip, npm, Actions, Docker |

Findings: fix or upgrade within 7 days for CRITICAL and 30 days for HIGH. If a fix is unavailable or not exploitable,
add the ID to `.trivyignore` **with a justification and a review date**; the file is reviewed at every release.
Latest local scan results are recorded in `TASKS.md`.

## GeoIP data, licensing and privacy

The repository ships **no** GeoIP database. To place public IPs on the map, download MaxMind **GeoLite2-City**
(free licence key and EULA acceptance required; it must be refreshed regularly and may not be redistributed), mount it
into the backend container and set `SIEM_GEOIP_DB_PATH`. Without it, public IPs are stored as
`{"scope":"public","located":false}`. Private, loopback, link-local, reserved and documentation ranges are never
located. `backend/app/geoip_demo.json` maps the RFC 5737 documentation addresses used by the demo generator to clearly
labelled *synthetic* coordinates, for demos only, via `SIEM_GEOIP_STATIC_PATH` (enabled by the dev overlay and the Render
demo blueprint, never in production).
IP addresses can be personal data (GDPR/UK GDPR): geolocation is city-level approximate, events are retained 30 days by the
ISM policy, and the map does not call any external service (no tiles).

## Sensitive data in events

`raw` is truncated to 4 KiB and kept for investigation. Command lines and usernames are stored as sent; **do not forward
logs that contain secrets** (for example process command lines with passwords). Add redaction in the collector
(Fluent Bit `modify`/`lua` filters) if your telemetry can contain credentials. Metrics never use users, IPs or raw text
as label values.
