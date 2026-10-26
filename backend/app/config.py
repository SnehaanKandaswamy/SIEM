"""Application settings, loaded from environment variables (see .env.example)."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIEM_", env_file=".env", extra="ignore")

    env: str = "development"
    database_url: str = "sqlite+pysqlite:///./siem-dev.db"
    opensearch_url: str = ""  # empty -> in-memory event store (development / tests only)
    opensearch_user: str = ""
    opensearch_password: str = ""
    opensearch_verify_certs: bool = False
    index_prefix: str = "siem-events"

    jwt_secret: str = ""  # required; no default so secrets are never committed
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_days: int = 7

    # Explicit administrator bootstrap: created at startup only if both are set and no admin exists.
    bootstrap_admin_username: str = ""
    bootstrap_admin_password: str = ""
    bootstrap_admin_email: str = "admin@example.invalid"

    # Ingestion credentials (comma separated). Compared in constant time.
    ingest_api_keys: str = ""
    ingest_max_batch: int = 5000  # records per request; processed in slices of 500
    ingest_max_body_bytes: int = 5_000_000
    ingest_rate_per_minute: int = 600
    login_rate_per_minute: int = 10

    cors_origins: str = "http://localhost:8080,http://localhost:5173"
    geoip_db_path: str = ""  # optional MaxMind GeoLite2-City .mmdb (not bundled; see docs/SECURITY.md)
    geoip_static_path: str = ""  # optional JSON {cidr: {lat, lon, country, city}} for offline demos

    smtp_host: str = ""
    smtp_port: int = 25
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "siem@example.invalid"
    smtp_starttls: bool = False
    notify_email_to: str = ""
    notify_email_min_severity: str = "high"
    slack_webhook_url: str = ""
    notify_slack_min_severity: str = "medium"
    notify_max_attempts: int = 3

    detections_enabled: bool = True
    allow_demo_endpoints: bool = False  # never enabled implicitly in production
    stream_buffer: int = 500

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def ingest_keys(self) -> list[str]:
        return [k.strip() for k in self.ingest_api_keys.split(",") if k.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
