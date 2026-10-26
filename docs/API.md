# API reference

Interactive OpenAPI docs: `http://localhost:8000/api/docs` (dev overlay only; disabled when `SIEM_ENV=production`).
All JSON. Auth: `Authorization: Bearer <access_token>` unless noted. Roles: **V**iewer, **A**nalyst, **Ad**min.
Errors: `{"detail": "..."}` with 400/401/403/404/409/413/422/429/503.

## Auth and users
| Method & path | Role | Notes |
|---|---|---|
| `POST /api/auth/login` | – | `{username,password}` → `{access_token,refresh_token,role,username}`; rate limited |
| `POST /api/auth/refresh` | – | `{refresh_token}` → new token pair |
| `GET /api/auth/me` | V | |
| `GET/POST /api/users`, `PATCH /api/users/{id}` | Ad | create (password ≥12), change role / active / password; cannot demote self |

## Ingestion
`POST /api/ingest` — header `X-Ingest-Key: <key from SIEM_INGEST_API_KEYS>`; optional `X-Collector`, `X-Source-Type`, `X-Source-Host`.
Body: either `{"source_type":"auto|windows|linux|nginx|docker|json","host":"h","synthetic":false,"records":[...]}` or a bare JSON
array (Fluent Bit `Format json`). Records are objects or raw log-line strings. Limits: 5 MB, 5 000 records.
Response: `{received,accepted,indexed,duplicates,rejected,alerts_created,errors:[{index,error,snippet}]}`.
`503` means storage is unavailable — the client should retry. `GET /api/ingest/diagnostics` (A) lists recent parse failures.

## Events and dashboard
| Path | Role | Notes |
|---|---|---|
| `GET /api/events/search` | V | `q` (≤500 chars, full-text), `start`,`end`,`host`*,`source_type`*,`severity`*,`category`*,`action`*,`outcome`*,`src_ip`,`user`,`synthetic`,`page`,`size`(≤200),`sort`(`@timestamp,severity,host,source_type`),`order` (*repeatable) |
| `GET /api/events/{event_id}` | V | |
| `GET /api/events/stream` | V | `text/event-stream`; `data:` frames contain an event + `seq` |
| `GET /api/events/recent?after=<seq>` | V | polling fallback |
| `GET /api/dashboard/overview?minutes=60` | V | totals, rate, timeline, alerts by severity, detections by rule, incident counts, top IPs/hosts, collectors, backend health |
| `GET /api/dashboard/geo` | V | located suspicious sources + count of unlocated events |

## Alerts, rules, MITRE
| Path | Role | Notes |
|---|---|---|
| `GET /api/alerts` | V | `severity*,status*,rule_id*,source,host,start,end,synthetic,page,size,sort(last_seen,first_seen,severity,event_count,status,id),order` |
| `GET /api/alerts/{id}` | V | alert + evidence + supporting events |
| `POST /api/alerts/{id}/acknowledge` · `/resolve` | A | 409 on invalid transition |
| `GET /api/rules` | V | |
| `PATCH /api/rules/{rule_id}` | Ad | `{enabled?,severity?,config?}`; config validated (types, ranges, regex) |
| `GET /api/mitre` | V | techniques with alert counts, rules, official URLs; `unmapped_rules` |

## Incidents
`GET /api/incidents?status*&assignee_id&page&size` (V) · `POST /api/incidents {title,alert_ids[,assignee_id]}` (A) ·
`GET /api/incidents/{id}` (V: alerts, notes, history, related events) · `PATCH /api/incidents/{id} {status?,assignee_id?,resolution_summary?}` (A) ·
`POST /api/incidents/{id}/notes {body}` (A) · `POST /api/incidents/{id}/alerts {alert_ids}` (A).
Transitions: `open → investigating|closed`, `investigating → resolved|open`, `resolved → closed|investigating`, `closed` is terminal.
Resolving or closing requires a non-empty `resolution_summary`. Assignees must be active analysts/admins.

## Reports (A)
`GET /api/reports/alerts?format=csv|pdf&severity*&status*&rule_id*&start&end` ·
`GET /api/reports/incidents?format=&status*` · `GET /api/reports/events?format=&q&start&end&severity*&host*`.
Max 5 000 rows; every export is audited; `Content-Disposition: attachment`.

## Admin (Ad)
`GET /api/admin/audit?action&actor&page&size` · `GET /api/admin/collectors` · `GET /api/admin/integrations` ·
`POST /api/admin/integrations/test?channel=email|slack` · `GET /api/admin/settings` ·
`POST /api/demo/ingest?scenario=all|bruteforce_ssh|failed_logins_windows|port_scan|suspicious_command|malware_indicator|negative_cases|normal_activity`
(403 unless `SIEM_ALLOW_DEMO_ENDPOINTS=true` and `SIEM_ENV != production`).

## Operations (no auth, internal)
`GET /healthz` (liveness) · `GET /readyz` (PostgreSQL + search; 503 when degraded) · `GET /metrics` (Prometheus; **not** proxied by Nginx).
Nginx additionally exposes `/healthz` and `/readyz` (status only) and `/nginx-health`.

## Prometheus metrics
`siem_http_requests_total{method,route,status}`, `siem_http_request_seconds{route}`, `siem_events_accepted_total{source_type}`,
`siem_events_duplicate_total`, `siem_events_rejected_total{reason}`, `siem_parse_failures_total{source_type}`,
`siem_alerts_created_total{rule,severity}`, `siem_alerts_suppressed_total{rule}`, `siem_detection_failures_total{rule}`,
`siem_background_failures_total{task}`, `siem_notifications_total{channel,status}`, `siem_database_up`, `siem_opensearch_up`,
`siem_collector_last_seen_age_seconds`. Route labels use the *templated* path (bounded cardinality).
