"""Prometheus metrics. Labels are bounded enums only (never users, IPs or raw text)."""

from prometheus_client import Counter, Gauge, Histogram

HTTP_REQUESTS = Counter("siem_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram("siem_http_request_seconds", "HTTP latency", ["route"])
EVENTS_ACCEPTED = Counter("siem_events_accepted_total", "Events accepted and indexed", ["source_type"])
EVENTS_DUPLICATE = Counter("siem_events_duplicate_total", "Duplicate events skipped")
EVENTS_REJECTED = Counter("siem_events_rejected_total", "Records rejected", ["reason"])
PARSE_FAILURES = Counter("siem_parse_failures_total", "Records that failed parsing", ["source_type"])
ALERTS_CREATED = Counter("siem_alerts_created_total", "Alerts created", ["rule", "severity"])
ALERTS_SUPPRESSED = Counter("siem_alerts_suppressed_total", "Findings merged into existing alerts", ["rule"])
DETECTION_FAILURES = Counter("siem_detection_failures_total", "Detection rule failures", ["rule"])
BACKGROUND_FAILURES = Counter("siem_background_failures_total", "Background task failures", ["task"])
NOTIFICATIONS = Counter("siem_notifications_total", "Notification deliveries", ["channel", "status"])
DB_UP = Gauge("siem_database_up", "1 if PostgreSQL reachable")
SEARCH_UP = Gauge("siem_opensearch_up", "1 if OpenSearch reachable")
COLLECTOR_AGE = Gauge("siem_collector_last_seen_age_seconds", "Seconds since any collector sent data")
