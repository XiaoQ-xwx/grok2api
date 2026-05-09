"""Shared SQLAlchemy Core backend for user/key/audit storage (MySQL / PostgreSQL / SQLite)."""

import json
import ssl
import uuid
from datetime import datetime
from threading import Lock
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from ..models import (
    AuditLog,
    AuditLogPage,
    AuditLogQuery,
    User,
    UserApiKey,
    UserCreate,
    UserUpdate,
)
from ..repository import UserKeyRepository

_TBL_USERS = "users"
_TBL_KEYS = "user_api_keys"
_TBL_AUDIT = "audit_logs"
_TBL_META = "user_key_meta"

metadata = sa.MetaData()

users_table = sa.Table(
    _TBL_USERS,
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("provider", sa.String(32), nullable=False),
    sa.Column("provider_user_id", sa.BigInteger, nullable=True),
    sa.Column("username", sa.String(256), nullable=False),
    sa.Column("name", sa.String(256), nullable=True),
    sa.Column("avatar_url", sa.Text, nullable=True),
    sa.Column("trust_level", sa.Integer, nullable=True),
    sa.Column("is_active", sa.Boolean, nullable=False, default=True),
    sa.Column("banned_until", sa.DateTime, nullable=True),
    sa.Column("rpm_limit", sa.Integer, nullable=True),
    sa.Column("created_at", sa.DateTime, nullable=False),
    sa.Column("updated_at", sa.DateTime, nullable=False),
    sa.Column("last_login_at", sa.DateTime, nullable=True),
    sa.UniqueConstraint("provider", "provider_user_id", name="uq_users_provider"),
    sa.Index("idx_users_username", "username"),
    sa.Index("idx_users_provider", "provider", "provider_user_id"),
)

keys_table = sa.Table(
    _TBL_KEYS,
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("user_id", sa.String(36), nullable=False),
    sa.Column("key_name", sa.String(256), nullable=False),
    sa.Column("key_prefix", sa.String(16), nullable=False),
    sa.Column("key_fingerprint", sa.String(64), nullable=False),
    sa.Column("hashed_key", sa.String(128), nullable=False),
    sa.Column("rpm_limit", sa.Integer, nullable=True),
    sa.Column("is_banned", sa.Boolean, nullable=False, default=False),
    sa.Column("last_used_at", sa.DateTime, nullable=True),
    sa.Column("created_at", sa.DateTime, nullable=False),
    sa.Column("updated_at", sa.DateTime, nullable=False),
    sa.Column("revoked_at", sa.DateTime, nullable=True),
    sa.UniqueConstraint("key_fingerprint", name="uq_keys_fingerprint"),
    sa.Index("idx_keys_user_id", "user_id"),
    sa.Index("idx_keys_prefix", "key_prefix"),
    sa.Index("idx_keys_banned", "is_banned"),
)

audit_table = sa.Table(
    _TBL_AUDIT,
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("timestamp", sa.DateTime, nullable=False),
    sa.Column("user_id", sa.String(36), nullable=True),
    sa.Column("key_id", sa.String(36), nullable=True),
    sa.Column("auth_type", sa.String(32), nullable=False),
    sa.Column("endpoint", sa.String(512), nullable=False),
    sa.Column("method", sa.String(10), nullable=False),
    sa.Column("model", sa.String(128), nullable=True),
    sa.Column("status_code", sa.Integer, nullable=False),
    sa.Column("tokens_used", sa.Integer, nullable=False, default=0),
    sa.Column("ip_address", sa.String(64), nullable=True),
    sa.Column("request_id", sa.String(64), nullable=True),
    sa.Column("error_code", sa.String(64), nullable=True),
    sa.Index("idx_audit_timestamp", "timestamp"),
    sa.Index("idx_audit_user_id", "user_id", "timestamp"),
    sa.Index("idx_audit_key_id", "key_id", "timestamp"),
    sa.Index("idx_audit_endpoint", "endpoint", "timestamp"),
)

meta_table = sa.Table(
    _TBL_META,
    metadata,
    sa.Column("key", sa.String(128), primary_key=True),
    sa.Column("value", sa.Text, nullable=False),
)

_ENGINE_LOCK = Lock()
_ENGINE_CACHE: dict[str, AsyncEngine] = {}


def _engine_key(dialect: str, url: str) -> str:
    return f"{dialect}::{url}"


def _get_or_create_engine(dialect: str, url: str, connect_args: dict[str, Any] | None = None) -> AsyncEngine:
    key = _engine_key(dialect, url)
    with _ENGINE_LOCK:
        if key not in _ENGINE_CACHE:
            if dialect == "sqlite":
                _ENGINE_CACHE[key] = create_async_engine(
                    url, echo=False, connect_args={"check_same_thread": False}
                )
            else:
                kw: dict[str, Any] = {"echo": False, "pool_size": 10, "max_overflow": 20}
                if connect_args:
                    kw["connect_args"] = connect_args
                _ENGINE_CACHE[key] = create_async_engine(url, **kw)
        return _ENGINE_CACHE[key]


def _now() -> datetime:
    return datetime.utcnow()


def _uid() -> str:
    return uuid.uuid4().hex


def _row_to_user(row: Any) -> User:
    return User(
        id=row.id,
        provider=row.provider,
        provider_user_id=row.provider_user_id,
        username=row.username,
        name=row.name,
        avatar_url=row.avatar_url,
        trust_level=row.trust_level,
        is_active=row.is_active,
        banned_until=row.banned_until if hasattr(row, "banned_until") else None,
        rpm_limit=row.rpm_limit if hasattr(row, "rpm_limit") else None,
        created_at=row.created_at,
        updated_at=row.updated_at,
        last_login_at=row.last_login_at,
    )


def _row_to_key(row: Any) -> UserApiKey:
    return UserApiKey(
        id=row.id,
        user_id=row.user_id,
        key_name=row.key_name,
        key_prefix=row.key_prefix,
        key_fingerprint=row.key_fingerprint,
        hashed_key=row.hashed_key,
        is_banned=row.is_banned,
        last_used_at=row.last_used_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        revoked_at=row.revoked_at,
    )


def _row_to_audit(row: Any) -> AuditLog:
    return AuditLog(
        id=row.id,
        timestamp=row.timestamp,
        user_id=row.user_id,
        key_id=row.key_id,
        auth_type=row.auth_type,
        endpoint=row.endpoint,
        method=row.method,
        model=row.model,
        status_code=row.status_code,
        tokens_used=row.tokens_used,
        ip_address=row.ip_address,
        request_id=row.request_id,
        error_code=row.error_code,
    )


class SqlUserKeyRepository:
    """SQLAlchemy Core backend for UserKeyRepository (MySQL / PostgreSQL / SQLite)."""

    def __init__(self, engine: AsyncEngine, dialect: str):
        self._engine = engine
        self._dialect = dialect

    async def initialize(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        # Schema migration: add banned_until and rpm_limit columns if missing
        for col_sql in [
            "ALTER TABLE users ADD COLUMN banned_until DATETIME NULL",
            "ALTER TABLE users ADD COLUMN rpm_limit INTEGER NULL",
        ]:
            try:
                async with self._engine.begin() as conn:
                    await conn.execute(sa.text(col_sql))
            except Exception:
                pass

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
    ) -> User:
        user_id = _uid()
        now = _now()
        async with self._engine.begin() as conn:
            await conn.execute(
                users_table.insert().values(
                    id=user_id,
                    provider=provider,
                    provider_user_id=provider_user_id,
                    username=username,
                    name=name,
                    avatar_url=avatar_url,
                    trust_level=trust_level,
                    is_active=True,
                    created_at=now,
                    updated_at=now,
                )
            )
        return User(
            id=user_id,
            provider=provider,
            provider_user_id=provider_user_id,
            username=username,
            name=name,
            avatar_url=avatar_url,
            trust_level=trust_level,
            is_active=True,
            created_at=now,
            updated_at=now,
        )

    async def get_user(self, user_id: str) -> User | None:
        async with self._engine.connect() as conn:
            row = await conn.execute(
                users_table.select().where(users_table.c.id == user_id)
            )
            r = row.first()
            return _row_to_user(r) if r else None

    async def get_user_by_provider(self, provider: str, provider_user_id: int) -> User | None:
        async with self._engine.connect() as conn:
            row = await conn.execute(
                users_table.select().where(
                    sa.and_(
                        users_table.c.provider == provider,
                        users_table.c.provider_user_id == provider_user_id,
                    )
                )
            )
            r = row.first()
            return _row_to_user(r) if r else None

    async def update_user(self, user_id: str, updates: UserUpdate) -> User | None:
        values: dict[str, Any] = {"updated_at": _now()}
        if updates.username is not None:
            values["username"] = updates.username
        if updates.name is not None:
            values["name"] = updates.name
        if updates.avatar_url is not None:
            values["avatar_url"] = updates.avatar_url
        if updates.is_active is not None:
            values["is_active"] = updates.is_active
        async with self._engine.begin() as conn:
            result = await conn.execute(
                users_table.update()
                .where(users_table.c.id == user_id)
                .values(**values)
            )
            if result.rowcount == 0:
                return None
        return await self.get_user(user_id)

    async def list_users(
        self,
        *,
        provider: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[User], int]:
        conditions = []
        if provider is not None:
            conditions.append(users_table.c.provider == provider)
        if is_active is not None:
            conditions.append(users_table.c.is_active == is_active)
        if search:
            conditions.append(users_table.c.username.contains(search))

        async with self._engine.connect() as conn:
            base = users_table.select()
            if conditions:
                base = base.where(sa.and_(*conditions))

            count_q = sa.select(sa.func.count()).select_from(base.subquery())
            total = (await conn.execute(count_q)).scalar() or 0

            rows = await conn.execute(
                base.order_by(users_table.c.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            return [_row_to_user(r) for r in rows], total

    async def delete_user(self, user_id: str) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                users_table.update()
                .where(users_table.c.id == user_id)
                .values(is_active=False, updated_at=_now())
            )
            return result.rowcount > 0

    async def ban_user(self, user_id: str, banned_until: datetime) -> User | None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                users_table.update()
                .where(users_table.c.id == user_id)
                .values(banned_until=banned_until, updated_at=_now())
            )
            if result.rowcount == 0:
                return None
        return await self.get_user(user_id)

    async def unban_user(self, user_id: str) -> User | None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                users_table.update()
                .where(users_table.c.id == user_id)
                .values(banned_until=None, updated_at=_now())
            )
            if result.rowcount == 0:
                return None
        return await self.get_user(user_id)

    async def set_user_rpm(self, user_id: str, rpm_limit: int | None) -> User | None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                users_table.update()
                .where(users_table.c.id == user_id)
                .values(rpm_limit=rpm_limit, updated_at=_now())
            )
            if result.rowcount == 0:
                return None
        return await self.get_user(user_id)

    # ── API Keys ───────────────────────────────────────────────────────

    async def create_key(
        self,
        user_id: str,
        key_name: str,
        key_prefix: str,
        key_fingerprint: str,
        hashed_key: str,
    ) -> UserApiKey:
        key_id = _uid()
        now = _now()
        async with self._engine.begin() as conn:
            await conn.execute(
                keys_table.insert().values(
                    id=key_id,
                    user_id=user_id,
                    key_name=key_name,
                    key_prefix=key_prefix,
                    key_fingerprint=key_fingerprint,
                    hashed_key=hashed_key,
                    is_banned=False,
                    created_at=now,
                    updated_at=now,
                )
            )
        return UserApiKey(
            id=key_id,
            user_id=user_id,
            key_name=key_name,
            key_prefix=key_prefix,
            key_fingerprint=key_fingerprint,
            hashed_key=hashed_key,
            is_banned=False,
            created_at=now,
            updated_at=now,
        )

    async def get_key(self, key_id: str) -> UserApiKey | None:
        async with self._engine.connect() as conn:
            row = await conn.execute(keys_table.select().where(keys_table.c.id == key_id))
            r = row.first()
            return _row_to_key(r) if r else None

    async def get_key_by_prefix(self, key_prefix: str) -> UserApiKey | None:
        async with self._engine.connect() as conn:
            row = await conn.execute(
                keys_table.select().where(keys_table.c.key_prefix == key_prefix)
            )
            r = row.first()
            return _row_to_key(r) if r else None

    async def get_key_by_fingerprint(self, fingerprint: str) -> UserApiKey | None:
        async with self._engine.connect() as conn:
            row = await conn.execute(
                keys_table.select().where(keys_table.c.key_fingerprint == fingerprint)
            )
            r = row.first()
            return _row_to_key(r) if r else None

    async def list_user_keys(self, user_id: str) -> list[UserApiKey]:
        async with self._engine.connect() as conn:
            rows = await conn.execute(
                keys_table.select()
                .where(sa.and_(keys_table.c.user_id == user_id, keys_table.c.revoked_at.is_(None)))
                .order_by(keys_table.c.created_at.desc())
            )
            return [_row_to_key(r) for r in rows]

    async def list_all_keys(
        self,
        *,
        user_id: str | None = None,
        is_banned: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[UserApiKey], int]:
        conditions = [keys_table.c.revoked_at.is_(None)]
        if user_id is not None:
            conditions.append(keys_table.c.user_id == user_id)
        if is_banned is not None:
            conditions.append(keys_table.c.is_banned == is_banned)
        if search:
            conditions.append(keys_table.c.key_name.contains(search))

        async with self._engine.connect() as conn:
            base = keys_table.select().where(sa.and_(*conditions))
            count_q = sa.select(sa.func.count()).select_from(base.subquery())
            total = (await conn.execute(count_q)).scalar() or 0

            rows = await conn.execute(
                base.order_by(keys_table.c.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            return [_row_to_key(r) for r in rows], total

    async def count_user_keys(self, user_id: str) -> int:
        async with self._engine.connect() as conn:
            q = sa.select(sa.func.count()).where(
                sa.and_(
                    keys_table.c.user_id == user_id,
                    keys_table.c.revoked_at.is_(None),
                )
            )
            return (await conn.execute(q)).scalar() or 0

    async def update_key(self, key_id: str, key_name: str | None = None) -> UserApiKey | None:
        values: dict[str, Any] = {"updated_at": _now()}
        if key_name is not None:
            values["key_name"] = key_name
        async with self._engine.begin() as conn:
            result = await conn.execute(
                keys_table.update().where(keys_table.c.id == key_id).values(**values)
            )
            if result.rowcount == 0:
                return None
        return await self.get_key(key_id)

    async def ban_key(self, key_id: str) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                keys_table.update()
                .where(keys_table.c.id == key_id)
                .values(is_banned=True, updated_at=_now())
            )
            return result.rowcount > 0

    async def unban_key(self, key_id: str) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                keys_table.update()
                .where(keys_table.c.id == key_id)
                .values(is_banned=False, updated_at=_now())
            )
            return result.rowcount > 0

    async def revoke_key(self, key_id: str) -> bool:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                keys_table.update()
                .where(keys_table.c.id == key_id)
                .values(revoked_at=_now(), updated_at=_now())
            )
            return result.rowcount > 0

    async def record_key_usage(self, key_id: str, timestamp: datetime) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                keys_table.update()
                .where(keys_table.c.id == key_id)
                .values(last_used_at=timestamp, updated_at=timestamp)
            )

    # ── Audit Logs ─────────────────────────────────────────────────────

    async def write_audit_log(self, entry: AuditLog) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                audit_table.insert().values(
                    id=entry.id or _uid(),
                    timestamp=entry.timestamp,
                    user_id=entry.user_id,
                    key_id=entry.key_id,
                    auth_type=entry.auth_type,
                    endpoint=entry.endpoint,
                    method=entry.method,
                    model=entry.model,
                    status_code=entry.status_code,
                    tokens_used=entry.tokens_used,
                    ip_address=entry.ip_address,
                    request_id=entry.request_id,
                    error_code=entry.error_code,
                )
            )

    async def query_audit_logs(self, query: AuditLogQuery) -> AuditLogPage:
        conditions = []
        if query.user_id:
            conditions.append(audit_table.c.user_id == query.user_id)
        if query.key_id:
            conditions.append(audit_table.c.key_id == query.key_id)
        if query.endpoint:
            conditions.append(audit_table.c.endpoint == query.endpoint)
        if query.model:
            conditions.append(audit_table.c.model == query.model)
        if query.status_code is not None:
            conditions.append(audit_table.c.status_code == query.status_code)
        if query.ip_address:
            conditions.append(audit_table.c.ip_address.like(f"{query.ip_address}%"))
        if query.time_from:
            conditions.append(audit_table.c.timestamp >= query.time_from)
        if query.time_to:
            conditions.append(audit_table.c.timestamp <= query.time_to)

        async with self._engine.connect() as conn:
            base = audit_table.select()
            if conditions:
                base = base.where(sa.and_(*conditions))

            count_q = sa.select(sa.func.count()).select_from(base.subquery())
            total = (await conn.execute(count_q)).scalar() or 0

            rows = await conn.execute(
                base.order_by(audit_table.c.timestamp.desc())
                .offset((query.page - 1) * query.page_size)
                .limit(query.page_size)
            )
            items = [_row_to_audit(r) for r in rows]
            total_pages = max(1, (total + query.page_size - 1) // query.page_size)
            return AuditLogPage(
                items=items,
                total=total,
                page=query.page,
                page_size=query.page_size,
                total_pages=total_pages,
            )

    async def cleanup_audit_logs(self, before: datetime) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                audit_table.delete().where(audit_table.c.timestamp < before)
            )
            return result.rowcount

    async def close(self) -> None:
        await self._engine.dispose()


def create_mysql_engine(url: str) -> AsyncEngine:
    return _get_or_create_engine("mysql", url)


_PG_SSLMODE_ALIASES: dict[str, str] = {
    "disable": "disable",
    "allow": "allow",
    "prefer": "prefer",
    "require": "require",
    "verify-ca": "verify-ca",
    "verify-full": "verify-full",
}


def _build_pg_ssl_context(sslmode: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if sslmode == "disable":
        return ctx
    if sslmode == "require":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif sslmode == "verify-ca":
        ctx.check_hostname = False
    else:
        ctx.check_hostname = True
    return ctx


def _prepare_pgsql_url(url: str) -> tuple[str, dict[str, Any] | None]:
    """Normalize PostgreSQL URL scheme and extract sslmode → connect_args."""
    # Normalize scheme
    normalized = url
    if url.startswith("postgres://"):
        normalized = f"postgresql+asyncpg://{url[len('postgres://'):]}"
    elif url.startswith("postgresql://"):
        normalized = f"postgresql+asyncpg://{url[len('postgresql://'):]}"
    elif url.startswith("pgsql://"):
        normalized = f"postgresql+asyncpg://{url[len('pgsql://'):]}"

    # Extract sslmode from query params (asyncpg does not accept sslmode)
    if "://" not in normalized:
        return normalized, None

    parsed = urlparse(normalized)
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    sslmode: str | None = None
    filtered: list[tuple[str, str]] = []
    for key, value in query_items:
        if key.lower() == "sslmode":
            if not sslmode:
                sslmode = value.strip().lower()
            continue
        filtered.append((key, value))

    cleaned_url = urlunparse(parsed._replace(query=urlencode(filtered, doseq=True)))
    if not sslmode:
        return cleaned_url, None

    canonical = _PG_SSLMODE_ALIASES.get(sslmode)
    if not canonical:
        raise ValueError(f"Unsupported PostgreSQL sslmode: {sslmode!r}")
    if canonical == "disable":
        return cleaned_url, None

    return cleaned_url, {"ssl": _build_pg_ssl_context(canonical)}


def create_pgsql_engine(url: str) -> AsyncEngine:
    cleaned_url, connect_args = _prepare_pgsql_url(url)
    return _get_or_create_engine("postgresql", cleaned_url, connect_args)
