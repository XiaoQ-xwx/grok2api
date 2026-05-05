"""Shared test fixtures for Phase 11 testing."""

import os
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.platform.auth.backends.local import LocalUserKeyRepository
from app.platform.auth.keygen import generate_api_key, verify_api_key_hash
from app.platform.auth.models import User, UserApiKey, AuditLog, ApiKeyContext
from app.platform.auth.repository import UserKeyRepository

os.environ.setdefault("GROK_API_KEY_SECRET", "test-secret-key-for-pytest")
os.environ.setdefault("ACCOUNT_STORAGE", "local")


@pytest_asyncio.fixture
async def repo():
    """Create a temporary SQLite-backed UserKeyRepository."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test.db"
        r = LocalUserKeyRepository(db_path)
        await r.initialize()
        yield r
        await r.close()


@pytest_asyncio.fixture
async def user(repo):
    """Create a test user via the repo."""
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
    """Create a test API key."""
    raw, prefix, fingerprint, hashed = generate_api_key()
    return await repo.create_key(
        user_id=user.id,
        key_name="test-key",
        key_prefix=prefix,
        key_fingerprint=fingerprint,
        hashed_key=hashed,
    ), raw


@pytest.fixture
def app_with_repo(repo):
    """Create a FastAPI test app with user_key_repo on app.state."""
    app = FastAPI()

    @app.on_event("startup")
    async def startup():
        pass

    app.state.user_key_repo = repo
    return app


@pytest.fixture
def client(app_with_repo):
    """Create a TestClient for the FastAPI app."""
    return TestClient(app_with_repo)
