"""Alembic migrations apply cleanly, roll back, and match the SQLAlchemy models (no un-migrated model changes)."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

BACKEND = Path(__file__).resolve().parent.parent


def _cfg(url: str, monkeypatch) -> Config:
    monkeypatch.setenv("SIEM_DATABASE_URL", url)
    from app.config import get_settings

    get_settings.cache_clear()
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    return cfg


def test_upgrade_downgrade_and_no_model_drift(tmp_path, monkeypatch):
    url = f"sqlite+pysqlite:///{tmp_path / 'mig.db'}"
    cfg = _cfg(url, monkeypatch)
    command.upgrade(cfg, "head")
    tables = set(inspect(create_engine(url)).get_table_names())
    assert {
        "users",
        "alerts",
        "incidents",
        "incident_notes",
        "incident_history",
        "audit_logs",
        "detection_rules",
        "notification_deliveries",
        "collectors",
        "app_settings",
        "incident_alerts",
    } <= tables
    command.check(cfg)  # raises if models differ from the migrated schema
    command.downgrade(cfg, "base")
    assert "alerts" not in set(inspect(create_engine(url)).get_table_names())
    command.upgrade(cfg, "head")
    from app.config import get_settings

    get_settings.cache_clear()
