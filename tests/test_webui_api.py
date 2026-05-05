"""11.5 Integration tests for user self-service API endpoints."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.platform.auth.keygen import generate_api_key
from app.platform.auth.middleware import verify_webui_key, get_webui_user


def _make_webui_app(repo, user=None):
    app = FastAPI()
    app.state.user_key_repo = repo

    async def _skip_auth():
        return None

    app.dependency_overrides[verify_webui_key] = _skip_auth

    if user is not None:
        async def _return_user():
            return user
        app.dependency_overrides[get_webui_user] = _return_user

    from app.products.web.webui.keys import router as keys_router
    from app.products.web.webui.profile import router as profile_router
    app.include_router(keys_router)
    app.include_router(profile_router)

    return app


class TestProfileEndpoint:
    def test_get_profile_requires_user(self, repo):
        app = _make_webui_app(repo, user=None)
        client = TestClient(app)
        resp = client.get("/webui/api/me/profile")
        assert resp.status_code == 404

    def test_get_profile_returns_user_data(self, repo, user):
        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.get("/webui/api/me/profile")
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == user.username
        assert data["id"] == user.id


class TestKeysListEndpoint:
    def test_list_keys_requires_user(self, repo):
        app = _make_webui_app(repo, user=None)
        client = TestClient(app)
        resp = client.get("/webui/api/me/keys")
        assert resp.status_code == 404

    def test_list_keys_empty(self, repo, user):
        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.get("/webui/api/me/keys")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_list_keys_with_keys(self, repo, user):
        for i in range(3):
            raw, prefix, fingerprint, hashed = generate_api_key()
            await repo.create_key(
                user_id=user.id, key_name=f"key-{i}",
                key_prefix=prefix, key_fingerprint=fingerprint,
                hashed_key=hashed,
            )

        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.get("/webui/api/me/keys")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        for k in data:
            assert "raw_key" not in k
            assert "key_prefix" in k
            assert "key_name" in k


class TestKeyCreateEndpoint:
    def test_create_key_requires_user(self, repo):
        app = _make_webui_app(repo, user=None)
        client = TestClient(app)
        resp = client.post("/webui/api/me/keys", json={"key_name": "test"})
        assert resp.status_code == 404

    def test_create_key_returns_raw_key_once(self, repo, user):
        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.post("/webui/api/me/keys", json={"key_name": "my-key"})
        assert resp.status_code == 201
        data = resp.json()
        assert "raw_key" in data
        assert data["raw_key"].startswith("g2a_")
        assert data["key_name"] == "my-key"

    def test_create_key_default_name(self, repo, user):
        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.post("/webui/api/me/keys", json={})
        assert resp.status_code == 201
        assert resp.json()["key_name"] == "Default"

    def test_create_key_increments_count(self, repo, user):
        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.post("/webui/api/me/keys", json={"key_name": "k1"})
        assert resp.status_code == 201

        list_resp = client.get("/webui/api/me/keys")
        assert len(list_resp.json()) == 1

    @pytest.mark.asyncio
    async def test_max_keys_limit(self, repo, user, monkeypatch):
        monkeypatch.setattr(
            "app.products.web.webui.keys.get_config",
            lambda key, default: 3,
        )
        for i in range(3):
            raw, prefix, fp, hashed = generate_api_key()
            await repo.create_key(
                user_id=user.id, key_name=f"fill-{i}",
                key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
            )

        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.post("/webui/api/me/keys", json={"key_name": "overflow"})
        assert resp.status_code == 400
        assert "Maximum" in resp.json()["detail"]


class TestKeyDeleteEndpoint:
    @pytest.mark.asyncio
    async def test_delete_own_key(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="to-delete",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.delete(f"/webui/api/me/keys/{key.id}")
        assert resp.status_code == 200
        assert "revoked" in resp.json()["detail"].lower()

    def test_delete_nonexistent_key(self, repo, user):
        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.delete("/webui/api/me/keys/nonexistent")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cannot_delete_other_user_key(self, repo, user):
        other = await repo.create_user(provider="local", username="other")
        raw, prefix, fp, hashed = generate_api_key()
        other_key = await repo.create_key(
            user_id=other.id, key_name="other-key",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.delete(f"/webui/api/me/keys/{other_key.id}")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_already_revoked_key(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="revoked-already",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )
        await repo.revoke_key(key.id)

        app = _make_webui_app(repo, user=user)
        client = TestClient(app)
        resp = client.delete(f"/webui/api/me/keys/{key.id}")
        assert resp.status_code == 404

    def test_delete_requires_user(self, repo):
        app = _make_webui_app(repo, user=None)
        client = TestClient(app)
        resp = client.delete("/webui/api/me/keys/some-id")
        assert resp.status_code == 404
