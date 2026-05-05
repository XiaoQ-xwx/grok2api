"""Local SQLite backend — thin wrapper over SQL backend with SQLite-specific init."""

from pathlib import Path

from .sql import SqlUserKeyRepository, _get_or_create_engine


class LocalUserKeyRepository(SqlUserKeyRepository):
    """SQLite-backed UserKeyRepository (single-process / low-traffic deployments)."""

    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        url = f"sqlite+aiosqlite:///{db_path.as_posix()}"
        engine = _get_or_create_engine("sqlite", url)
        super().__init__(engine, dialect="sqlite")
