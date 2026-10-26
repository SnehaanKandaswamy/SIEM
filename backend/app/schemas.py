from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

Severity = Literal["informational", "low", "medium", "high", "critical"]
Role = Literal["viewer", "analyst", "admin"]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: Role
    username: str


class RefreshIn(BaseModel):
    refresh_token: str


class UserOut(ORM):
    id: int
    username: str
    email: str
    role: Role
    is_active: bool
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    role: Role = "viewer"


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class IngestBatch(BaseModel):
    source_type: Literal["auto", "windows", "linux", "nginx", "docker", "json"] = "auto"
    host: str = Field(default="unknown", max_length=255)
    synthetic: bool = False
    records: list[dict[str, Any] | str] = Field(min_length=1)


class AlertOut(ORM):
    id: int
    rule_id: str
    title: str
    severity: Severity
    status: str
    source: str
    host: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    mitre: list
    synthetic: bool
    acknowledged_by: str | None
    resolved_by: str | None


class AlertDetail(AlertOut):
    evidence: dict
    event_ids: list
    correlation_key: str


class Page(BaseModel):
    total: int
    page: int
    size: int
    items: list[Any]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    alert_ids: list[int] = Field(min_length=1, max_length=100)
    assignee_id: int | None = None


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "closed"] | None = None
    assignee_id: int | None = None
    resolution_summary: str | None = Field(default=None, max_length=5000)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class LinkAlerts(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=100)


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    config: dict[str, Any] | None = None
