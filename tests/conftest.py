"""Shared test fixtures for grok2api testing."""

import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from app.platform.auth.keygen import generate_api_key
from app.platform.auth.models import ApiKeyContext

os.environ.setdefault("GROK_API_KEY_SECRET", "test-secret-key-for-pytest")
os.environ.setdefault("ACCOUNT_STORAGE", "local")


# ---------------------------------------------------------------------------
# Core fixtures (repo, user, key)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def repo():
    """Create a temporary SQLite-backed UserKeyRepository."""
    from app.platform.auth.backends.local import LocalUserKeyRepository

    td = tempfile.mkdtemp()
    try:
        db_path = Path(td) / "test.db"
        r = LocalUserKeyRepository(db_path)
        await r.initialize()
        yield r
        await r.close()
    finally:
        import shutil
        import time

        for _ in range(10):
            try:
                shutil.rmtree(td)
                break
            except PermissionError:
                time.sleep(0.05)


@pytest_asyncio.fixture
async def user(repo):
    """Create a test local user."""
    return await repo.create_user(
        provider="local",
        username="testuser",
        name="Test User",
        avatar_url="https://example.com/avatar.png",
    )


@pytest_asyncio.fixture
async def linuxdo_user(repo):
    """Create a test LinuxDo user."""
    return await repo.create_user(
        provider="linuxdo",
        username="linuxdo_user",
        provider_user_id=12345,
        name="LinuxDo User",
        avatar_url="https://linux.do/avatar.png",
        trust_level=3,
    )


@pytest_asyncio.fixture
async def api_key(repo, user):
    """Create a test API key. Returns (key_record, raw_key)."""
    raw, prefix, fingerprint, hashed = generate_api_key()
    key_record = await repo.create_key(
        user_id=user.id,
        key_name="test-key",
        key_prefix=prefix,
        key_fingerprint=fingerprint,
        hashed_key=hashed,
    )
    return key_record, raw


# ---------------------------------------------------------------------------
# Config patching
# ---------------------------------------------------------------------------


@pytest.fixture
def config_values():
    """Temporarily patch config values via a dict-backed override.

    Usage: ``config_values["some.key"] = value``
    """
    from app.platform.config import snapshot as config_snapshot

    store: dict[str, Any] = {}

    original = config_snapshot.get_config

    def _get_config(key: str, default: Any = None) -> Any:
        if key in store:
            return store[key]
        return original(key, default)

    with patch.object(config_snapshot, "get_config", _get_config):
        yield store


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------


@pytest.fixture
def admin_headers() -> dict[str, str]:
    """Authorization headers for admin endpoints (default key: grok2api)."""
    return {"Authorization": "Bearer grok2api"}


# ---------------------------------------------------------------------------
# FastAPI test app and async client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def app_with_repo(repo):
    """Create a FastAPI test app with admin routes and a /v1/audit-probe endpoint."""
    from app.platform.auth.middleware import verify_api_key
    from app.platform.auth.audit import AuditMiddleware

    app = FastAPI()

    # Attach repo to app state (used by admin endpoints)
    app.state.user_key_repo = repo

    # Mount the admin API router (handles /admin/api/*)
    from app.products.web.admin import router as admin_router

    app.include_router(admin_router)

    # Mount verify-password routes directly
    from app.products.web.router import admin_verify_password_page, admin_verify_password_submit

    @app.get("/admin/verify-password", include_in_schema=False)
    async def _verify_password_page():
        return await admin_verify_password_page()

    @app.post("/admin/verify-password", include_in_schema=False)
    async def _verify_password_submit(request: Request):
        return await admin_verify_password_submit(request)

    # A simple /v1/* endpoint guarded by verify_api_key for audit/IP/rate-limit tests
    from fastapi import Depends

    @app.get("/v1/audit-probe")
    async def audit_probe(
        request: Request,
        _ctx: ApiKeyContext = Depends(verify_api_key),
    ):
        return {"status": "ok"}

    # Add audit middleware (fire-and-forget for /v1/* paths)
    app.add_middleware(AuditMiddleware, get_repo=lambda: repo, enabled=True)

    return app


@pytest_asyncio.fixture
async def client(app_with_repo):
    """An async httpx client bound to the test app."""
    transport = ASGITransport(app=app_with_repo)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
