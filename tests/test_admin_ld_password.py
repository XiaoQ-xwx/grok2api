"""Tests for LinuxDo password verification, token management, and OAuth flow."""

import time
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from httpx import AsyncClient

from app.platform.auth import linuxdo
from app.platform.auth.linuxdo import (
    LinuxDoUser,
    hash_access_password,
    issue_pending_token,
    issue_token,
    PENDING_PREFIX,
    PENDING_TTL,
    TOKEN_PREFIX,
    upsert_linuxdo_user,
    verify_access_password,
    verify_pending_token,
    verify_state,
    verify_token,
)
from app.platform.auth.models import User, UserUpdate


# ---------------------------------------------------------------------------
# Password hashing / verification
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_hash_and_verify_correct_password(self) -> None:
        hashed = hash_access_password("open-sesame")
        assert verify_access_password("open-sesame", hashed) is True

    def test_verify_wrong_password(self) -> None:
        hashed = hash_access_password("open-sesame")
        assert verify_access_password("wrong", hashed) is False

    def test_hash_is_different_each_time(self) -> None:
        h1 = hash_access_password("open-sesame")
        h2 = hash_access_password("open-sesame")
        assert h1 != h2
        assert verify_access_password("open-sesame", h1) is True
        assert verify_access_password("open-sesame", h2) is True

    def test_verify_with_empty_string(self) -> None:
        hashed = hash_access_password("open-sesame")
        assert verify_access_password("", hashed) is False

    def test_verify_with_invalid_hash(self) -> None:
        assert verify_access_password("any", "not-a-valid-bcrypt-hash") is False

    def test_verify_with_corrupted_bcrypt_prefix(self) -> None:
        hashed = hash_access_password("open-sesame")
        corrupted = hashed[1:] if len(hashed) > 1 else "x"
        assert verify_access_password("open-sesame", corrupted) is False


# ---------------------------------------------------------------------------
# OAuth state (CSRF)
# ---------------------------------------------------------------------------


class TestOAuthState:
    def test_generate_and_verify_valid_state(self) -> None:
        state = linuxdo.generate_state()
        assert verify_state(state) is True

    def test_verify_tampered_payload(self) -> None:
        state = linuxdo.generate_state()
        payload, sig = state.rsplit(".", 1)
        tampered = f"{payload}.{'0' * 64}"
        assert verify_state(tampered) is False

    def test_verify_tampered_data(self) -> None:
        state = linuxdo.generate_state()
        payload, sig = state.rsplit(".", 1)
        import base64, json

        decoded = json.loads(base64.urlsafe_b64decode(payload + "==="))
        decoded["exp"] = int(time.time()) + 6000
        new_payload = (
            base64.urlsafe_b64encode(
                json.dumps(decoded, separators=(",", ":")).encode()
            )
            .decode()
            .rstrip("=")
        )
        tampered = f"{new_payload}.{sig}"
        assert verify_state(tampered) is False

    def test_verify_garbage_input(self) -> None:
        assert verify_state("garbage") is False
        assert verify_state("") is False

    def test_verify_expired_state(self, monkeypatch) -> None:
        state = linuxdo.generate_state()
        monkeypatch.setattr(time, "time", lambda: time.time() + 1200)
        assert verify_state(state) is False


# ---------------------------------------------------------------------------
# Session token (issue / verify)
# ---------------------------------------------------------------------------


class TestSessionToken:
    def test_issue_and_verify_valid_token(self) -> None:
        user = LinuxDoUser(
            id=42, username="testuser", name="Test User", avatar_url="https://a.com/p.png", trust_level=2
        )
        token = issue_token(user)
        verified = verify_token(token)
        assert verified is not None
        assert verified.id == 42
        # issue_token stores name as fallback for username (payload has "name" not "un")
        assert verified.username == "Test User"
        assert verified.name == "Test User"
        assert verified.avatar_url == "https://a.com/p.png"
        assert verified.trust_level == 2

    def test_verify_tampered_token(self) -> None:
        user = LinuxDoUser(id=42, username="test", name="Test", avatar_url="")
        token = issue_token(user)
        tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
        assert verify_token(tampered) is None

    def test_verify_token_without_prefix(self) -> None:
        assert verify_token("not-ld-token") is None

    def test_verify_expired_token_ignored(self) -> None:
        """Session tokens don't expire on their own; only version invalidation matters."""
        user = LinuxDoUser(id=42, username="test", name="Test", avatar_url="")
        token = issue_token(user)
        verified = verify_token(token)
        assert verified is not None


# ---------------------------------------------------------------------------
# Pending token (password verification flow)
# ---------------------------------------------------------------------------


class TestPendingToken:
    def test_issue_and_verify_valid_pending(self) -> None:
        pending = issue_pending_token("user-123")
        data = verify_pending_token(pending)
        assert data is not None
        assert data["uid"] == "user-123"
        assert data["purpose"] == "ld_password_pending"

    def test_verify_without_prefix(self) -> None:
        assert verify_pending_token("not-pending") is None

    def test_verify_tampered(self) -> None:
        pending = issue_pending_token("user-456")
        tampered = pending[:-4] + "dead"
        assert verify_pending_token(tampered) is None

    def test_verify_expired(self, monkeypatch) -> None:
        pending = issue_pending_token("user-789")
        monkeypatch.setattr(time, "time", lambda: time.time() + PENDING_TTL + 10)
        assert verify_pending_token(pending) is None

    def test_issue_with_custom_nonce(self) -> None:
        pending = issue_pending_token("user-custom", nonce="my-nonce-123")
        data = verify_pending_token(pending)
        assert data is not None
        assert data["nonce"] == "my-nonce-123"


# ---------------------------------------------------------------------------
# upsert_linuxdo_user
# ---------------------------------------------------------------------------


class TestUpsertLinuxdoUser:
    @pytest.mark.asyncio
    async def test_create_new_user(self, repo) -> None:
        ld = LinuxDoUser(
            id=9999, username="new-ld", name="New LD", avatar_url="https://ld.avatar/p.png", trust_level=2
        )
        result = await upsert_linuxdo_user(ld, repo=repo)
        assert result is not None
        assert result.provider == "linuxdo"
        assert result.provider_user_id == 9999
        assert result.username == "new-ld"
        assert result.name == "New LD"
        assert result.trust_level == 2

    @pytest.mark.asyncio
    async def test_update_existing_user(self, repo, linuxdo_user) -> None:
        ld = LinuxDoUser(
            id=linuxdo_user.provider_user_id,
            username="updated-ld",
            name="Updated Name",
            avatar_url="https://new.avatar/p.png",
            trust_level=4,
        )
        result = await upsert_linuxdo_user(ld, repo=repo)
        assert result is not None
        assert result.id == linuxdo_user.id
        assert result.username == "updated-ld"
        assert result.name == "Updated Name"
        assert result.avatar_url == "https://new.avatar/p.png"

    @pytest.mark.asyncio
    async def test_missing_repo_returns_none(self) -> None:
        ld = LinuxDoUser(id=1, username="x", name="X", avatar_url="")
        result = await upsert_linuxdo_user(ld, repo=None)
        assert result is None


# ---------------------------------------------------------------------------
# Admin verify-password endpoint (integration)
# ---------------------------------------------------------------------------


class TestAdminVerifyPasswordEndpoint:
    @pytest.mark.asyncio
    async def test_verify_password_redirects_with_session_token(
        self, client: AsyncClient, config_values, linuxdo_user
    ) -> None:
        config_values["auth.linuxdo.access_password_enabled"] = True
        config_values["auth.linuxdo.access_password_hash"] = hash_access_password("open-sesame")
        pending = issue_pending_token(str(linuxdo_user.provider_user_id))

        response = await client.post(
            "/admin/verify-password",
            data={"token": pending, "password": "open-sesame"},
            follow_redirects=False,
        )

        assert response.status_code == 307
        location = response.headers["location"]
        assert "/webui/login" in location
        assert "oauth_token=" in location

    @pytest.mark.asyncio
    async def test_verify_password_rejects_wrong_password(
        self, client: AsyncClient, config_values, linuxdo_user
    ) -> None:
        config_values["auth.linuxdo.access_password_hash"] = hash_access_password("open-sesame")
        pending = issue_pending_token(str(linuxdo_user.provider_user_id))

        response = await client.post(
            "/admin/verify-password",
            data={"token": pending, "password": "wrong"},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_verify_password_rejects_invalid_pending_token(
        self, client: AsyncClient, config_values
    ) -> None:
        config_values["auth.linuxdo.access_password_hash"] = hash_access_password("open-sesame")

        response = await client.post(
            "/admin/verify-password",
            data={"token": "ld_pending:invalid", "password": "open-sesame"},
        )

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_verify_password_page_serves_html(self, client: AsyncClient) -> None:
        response = await client.get("/admin/verify-password")
        assert response.status_code == 200
        assert "访问验证" in response.text
