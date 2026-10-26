import os

os.environ.update(
    {
        "SIEM_ENV": "test",
        "SIEM_DATABASE_URL": "sqlite+pysqlite://",
        "SIEM_JWT_SECRET": "unit-test-secret-unit-test-secret-1234",
        "SIEM_INGEST_API_KEYS": "test-ingest-key",
        "SIEM_BOOTSTRAP_ADMIN_USERNAME": "admin",
        "SIEM_BOOTSTRAP_ADMIN_PASSWORD": "Adm1n-Test-Password!",
        "SIEM_OPENSEARCH_URL": "",
        "SIEM_ALLOW_DEMO_ENDPOINTS": "true",
        "SIEM_NOTIFY_MAX_ATTEMPTS": "2",
    }
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db as dbmod  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.deps import state  # noqa: E402
from app.models import User  # noqa: E402
from app.security import hash_password, limiter  # noqa: E402
from app.store import MemoryStore  # noqa: E402


@pytest.fixture()
def client():
    get_settings.cache_clear()
    dbmod.init_engine("sqlite+pysqlite://")
    state.store = MemoryStore()
    state.recent.clear()
    state.parse_errors.clear()
    state.seq = 0
    limiter.reset()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def _login(c, user, pw):
    r = c.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture()
def admin_h(client):
    return _login(client, "admin", "Adm1n-Test-Password!")


@pytest.fixture()
def make_user(client):
    def make(name, role):
        with dbmod.session_factory()() as db:
            db.add(
                User(
                    username=name,
                    email=f"{name}@example.com",
                    password_hash=hash_password("Passw0rd-long-enough"),
                    role=role,
                )
            )
            db.commit()
        return _login(client, name, "Passw0rd-long-enough")

    return make


@pytest.fixture()
def analyst_h(make_user):
    return make_user("ana", "analyst")


@pytest.fixture()
def viewer_h(make_user):
    return make_user("vic", "viewer")


INGEST = {"X-Ingest-Key": "test-ingest-key"}
