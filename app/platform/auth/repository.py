"""UserKeyRepository Protocol — storage contract for user/key/audit operations."""

from datetime import datetime
from typing import Protocol

from .models import (
    AuditLog,
    AuditLogPage,
    AuditLogQuery,
    User,
    UserApiKey,
    UserCreate,
    UserUpdate,
)


class UserKeyRepository(Protocol):
    """Storage contract shared by all user-key backends (SQL / Redis / local)."""

    async def initialize(self) -> None: ...

    # ── Users ──────────────────────────────────────────────────────────

    async def create_user(
        self,
        provider: str,
        username: str,
        *,
        provider_user_id: int | None = None,
        name: str | None = None,
        avatar_url: str | None = None,
        trust_level: int | None = None,
    ) -> User: ...

    async def get_user(self, user_id: str) -> User | None: ...

    async def get_user_by_provider(self, provider: str, provider_user_id: int) -> User | None: ...

    async def update_user(self, user_id: str, updates: UserUpdate) -> User | None: ...

    async def list_users(
        self,
        *,
        provider: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[User], int]: ...

    async def delete_user(self, user_id: str) -> bool: ...

    # ── API Keys ───────────────────────────────────────────────────────

    async def create_key(
        self,
        user_id: str,
        key_name: str,
        key_prefix: str,
        key_fingerprint: str,
        hashed_key: str,
    ) -> UserApiKey: ...

    async def get_key(self, key_id: str) -> UserApiKey | None: ...

    async def get_key_by_prefix(self, key_prefix: str) -> UserApiKey | None: ...

    async def get_key_by_fingerprint(self, fingerprint: str) -> UserApiKey | None: ...

    async def list_user_keys(self, user_id: str) -> list[UserApiKey]: ...

    async def list_all_keys(
        self,
        *,
        user_id: str | None = None,
        is_banned: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[UserApiKey], int]: ...

    async def count_user_keys(self, user_id: str) -> int: ...

    async def update_key(self, key_id: str, key_name: str | None = None, rpm_limit: int | None = None) -> UserApiKey | None: ...

    async def ban_key(self, key_id: str) -> bool: ...

    async def unban_key(self, key_id: str) -> bool: ...

    async def revoke_key(self, key_id: str) -> bool: ...

    async def record_key_usage(self, key_id: str, timestamp: datetime) -> None: ...

    # ── Audit Logs ─────────────────────────────────────────────────────

    async def write_audit_log(self, entry: AuditLog) -> None: ...

    async def query_audit_logs(self, query: AuditLogQuery) -> AuditLogPage: ...

    async def cleanup_audit_logs(self, before: datetime) -> int: ...

    # ── Lifecycle ──────────────────────────────────────────────────────

    async def close(self) -> None: ...
