"""UserKeyRepository factory — selects the backend from ACCOUNT_STORAGE env."""

import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from app.platform.paths import data_path

from ..repository import UserKeyRepository

_SUPPORTED_BACKENDS = {"local", "redis", "mysql", "postgresql"}


def create_user_key_repository() -> UserKeyRepository:
    backend = get_key_repository_backend()

    if backend == "local":
        return _make_local()
    if backend == "redis":
        return _make_redis()
    if backend == "mysql":
        return _make_sql("mysql")
    if backend == "postgresql":
        return _make_sql("postgresql")

    raise ValueError(f"Unknown user-key storage backend: {backend!r}")


def get_key_repository_backend() -> str:
    backend = _get_env("ACCOUNT_STORAGE", "local").lower()
    if backend not in _SUPPORTED_BACKENDS:
        raise ValueError(f"Unknown account storage backend: {backend!r}")
    return backend


def describe_key_repository_target() -> tuple[str, str]:
    backend = get_key_repository_backend()
    if backend == "local":
        return "local", str(_resolve_local_db_path())
    if backend == "redis":
        return "redis", _redact_url(_get_required_env("ACCOUNT_REDIS_URL"))
    if backend == "mysql":
        return "mysql", _redact_url(_get_env("ACCOUNT_MYSQL_URL"))
    if backend == "postgresql":
        return "postgresql", _redact_url(_get_env("ACCOUNT_POSTGRESQL_URL"))
    return backend, "<unknown>"


def _get_env(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    return value or default


def _get_required_env(name: str) -> str:
    value = _get_env(name)
    if not value:
        raise ValueError(f"Missing required env: {name}")
    return value


def _resolve_local_db_path() -> Path:
    path_str = _get_env("USER_KEY_LOCAL_PATH", str(data_path("user_keys.db")))
    db_path = Path(path_str)
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parents[5] / db_path
    return db_path


def _redact_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return "<empty>"
    try:
        parts = urlsplit(raw)
    except Exception:
        return raw
    if not parts.scheme:
        return raw
    hostname = parts.hostname or ""
    if parts.port:
        hostname = f"{hostname}:{parts.port}"
    if parts.username:
        auth = f"{parts.username}:***@"
    elif parts.password:
        auth = "***@"
    else:
        auth = ""
    return urlunsplit((parts.scheme, f"{auth}{hostname}", parts.path, parts.query, parts.fragment))


def _make_local() -> UserKeyRepository:
    from .local import LocalUserKeyRepository
    return LocalUserKeyRepository(_resolve_local_db_path())


def _make_redis() -> UserKeyRepository:
    from redis.asyncio import Redis
    from .redis import RedisUserKeyRepository

    url = _get_required_env("ACCOUNT_REDIS_URL")
    r = Redis.from_url(url, decode_responses=False)
    return RedisUserKeyRepository(r)


def _make_sql(dialect: str) -> UserKeyRepository:
    from .sql import SqlUserKeyRepository, create_mysql_engine, create_pgsql_engine

    if dialect == "mysql":
        url = _get_env("ACCOUNT_MYSQL_URL")
        engine = create_mysql_engine(url)
    else:
        url = _get_env("ACCOUNT_POSTGRESQL_URL")
        engine = create_pgsql_engine(url)
    return SqlUserKeyRepository(engine, dialect=dialect)
