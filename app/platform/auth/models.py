"""User, API key, and audit log data models."""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class User(BaseModel):
    id: str
    provider: str  # "linuxdo" | "local"
    provider_user_id: int | None = None
    username: str
    name: str | None = None
    avatar_url: str | None = None
    trust_level: int | None = None
    is_active: bool = True
    banned_until: datetime | None = None
    rpm_limit: int | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_login_at: datetime | None = None


class UserApiKey(BaseModel):
    id: str
    user_id: str
    key_name: str
    key_prefix: str
    key_fingerprint: str
    hashed_key: str
    is_banned: bool = False
    last_used_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    revoked_at: datetime | None = None


@dataclass(slots=True)
class ApiKeyContext:
    auth_type: Literal["global_key", "user_key"]
    user_id: str | None
    key_id: str | None
    key_name: str | None
    is_global_key: bool


class AuditLog(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: str | None = None
    key_id: str | None = None
    auth_type: str = "global_key"  # "user_key" | "global_key"
    endpoint: str = ""
    method: str = "GET"
    model: str | None = None
    status_code: int = 0
    tokens_used: int = 0
    ip_address: str | None = None
    request_id: str | None = None
    error_code: str | None = None


class AuditLogQuery(BaseModel):
    user_id: str | None = None
    key_id: str | None = None
    endpoint: str | None = None
    model: str | None = None
    status_code: int | None = None
    ip_address: str | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    page: int = 1
    page_size: int = 50


class AuditLogPage(BaseModel):
    items: list[AuditLog]
    total: int
    page: int
    page_size: int
    total_pages: int


class UserCreate(BaseModel):
    username: str
    name: str | None = None
    avatar_url: str | None = None


class UserUpdate(BaseModel):
    username: str | None = None
    name: str | None = None
    avatar_url: str | None = None
    is_active: bool | None = None


class UserAdminUpdate(BaseModel):
    banned_until: datetime | None = None
    rpm_limit: int | None = None


class KeyCreate(BaseModel):
    key_name: str = "Default"


class KeyCreated(BaseModel):
    id: str
    key_name: str
    key_prefix: str
    raw_key: str
    created_at: datetime


class KeySummary(BaseModel):
    id: str
    key_name: str
    key_prefix: str
    is_banned: bool
    last_used_at: datetime | None
    created_at: datetime
    revoked_at: datetime | None


class KeyUpdate(BaseModel):
    key_name: str | None = None


class UserWithKeyCount(BaseModel):
    user: User
    key_count: int
