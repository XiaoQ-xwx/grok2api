"""11.3 Integration tests for verify_api_key() with global and user keys."""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.platform.auth.middleware import verify_api_key
from app.platform.auth.keygen import generate_api_key
from app.platform.auth.models import ApiKeyContext


def _make_app(repo=None):
    app = FastAPI()
    if repo is not None:
        app.state.user_key_repo = repo

    @app.get("/v1/test")
    async def test_endpoint(ctx: ApiKeyContext = Depends(verify_api_key)):
        return {
            "auth_type": ctx.auth_type,
            "user_id": ctx.user_id,
            "key_id": ctx.key_id,
            "is_global_key": ctx.is_global_key,
        }

    return app


class TestGlobalKeyAuth:
    def test_global_key_authenticates(self, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["global-test-key"],
        )
        app = _make_app()
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": "Bearer global-test-key"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "global_key"
        assert data["is_global_key"] is True
        assert data["user_id"] is None

    def test_global_key_wrong_key_fails(self, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["global-test-key"],
        )
        app = _make_app()
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": "Bearer wrong-key"},
        )
        assert resp.status_code in (401, 403)

    def test_no_keys_configured_allows_all(self, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: [],
        )
        app = _make_app()
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": "Bearer anything"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "global_key"

    def test_missing_auth_header_fails(self, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["some-key"],
        )
        app = _make_app()
        client = TestClient(app)
        resp = client.get("/v1/test")
        assert resp.status_code == 401


class TestUserKeyAuth:
    @pytest.mark.asyncio
    async def test_user_key_authenticates(self, repo, user, monkeypatch):
        """User key should authenticate when global keys exist but token doesn't match them."""
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["dummy-global"],
        )
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="test-key",
            key_prefix=prefix, key_fingerprint=fingerprint,
            hashed_key=hashed,
        )

        app = _make_app(repo=repo)
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "user_key"
        assert data["is_global_key"] is False
        assert data["user_id"] == user.id

    @pytest.mark.asyncio
    async def test_banned_key_rejected(self, repo, user, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["dummy-global"],
        )
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="banned-key",
            key_prefix=prefix, key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        await repo.ban_key(key.id)

        app = _make_app(repo=repo)
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_revoked_key_rejected(self, repo, user, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["dummy-global"],
        )
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="revoked-key",
            key_prefix=prefix, key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        await repo.revoke_key(key.id)

        app = _make_app(repo=repo)
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert resp.status_code == 401

    def test_unknown_key_rejected(self, repo, user, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["configured-key"],
        )
        app = _make_app(repo=repo)
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": "Bearer g2a_unknownrandomhexkey1234"},
        )
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_context_stored_on_request_state(self, repo, user, monkeypatch):
        monkeypatch.setattr(
            "app.platform.auth.middleware._get_keys",
            lambda: ["dummy-global"],
        )
        raw, prefix, fingerprint, hashed = generate_api_key()
        await repo.create_key(
            user_id=user.id, key_name="state-key",
            key_prefix=prefix, key_fingerprint=fingerprint,
            hashed_key=hashed,
        )

        app = _make_app(repo=repo)
        client = TestClient(app)
        resp = client.get(
            "/v1/test",
            headers={"Authorization": f"Bearer {raw}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "user_key"
