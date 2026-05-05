"""11.6 Integration tests for admin management API endpoints."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.platform.auth.keygen import generate_api_key
from app.platform.auth.middleware import verify_admin_key


def _make_admin_app(repo):
    app = FastAPI()
    app.state.user_key_repo = repo

    async def _skip_auth():
        return None

    app.dependency_overrides[verify_admin_key] = _skip_auth

    from app.products.web.admin.users import router as users_router
    from app.products.web.admin.keys import router as keys_router
    from app.products.web.admin.audit import router as audit_router
    app.include_router(users_router, prefix="/admin/api")
    app.include_router(keys_router, prefix="/admin/api")
    app.include_router(audit_router, prefix="/admin/api")

    return app


class TestAdminUsersEndpoint:
    def test_list_users(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/users")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert "items" in data

    def test_list_users_with_filters(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/users?provider=local")
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["user"]["provider"] == "local"

    def test_list_users_pagination(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/users?page=1&page_size=1")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 1
        assert data["page"] == 1
        assert data["page_size"] == 1

    def test_get_user_detail(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get(f"/admin/api/users/{user.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user"]["id"] == user.id
        assert "keys" in data
        assert "key_count" in data

    def test_get_user_not_found(self, repo):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/users/nonexistent")
        assert resp.status_code == 404

    def test_create_user(self, repo):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.post(
            "/admin/api/users",
            json={"username": "admin-created", "name": "Admin Created"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["username"] == "admin-created"
        assert data["provider"] == "local"

    def test_update_user(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.patch(
            f"/admin/api/users/{user.id}",
            json={"name": "Updated Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Name"

    def test_update_user_not_found(self, repo):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.patch("/admin/api/users/nonexistent", json={"name": "X"})
        assert resp.status_code == 404


class TestAdminKeysEndpoint:
    @pytest.mark.asyncio
    async def test_list_keys(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        await repo.create_key(
            user_id=user.id, key_name="admin-key",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/keys")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_list_keys_filter_banned(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/keys?is_banned=true")
        assert resp.status_code == 200

    def test_create_key_for_user(self, repo, user):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.post(
            f"/admin/api/users/{user.id}/keys",
            json={"key_name": "admin-created-key"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "raw_key" in data
        assert data["key_name"] == "admin-created-key"

    def test_create_key_for_nonexistent_user(self, repo):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.post(
            "/admin/api/users/nonexistent/keys",
            json={"key_name": "ghost"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_key(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="old-name",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.patch(
            f"/admin/api/keys/{key.id}",
            json={"key_name": "new-name", "rpm_limit": 30},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key_name"] == "new-name"
        assert data["rpm_limit"] == 30

    def test_update_nonexistent_key(self, repo):
        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.patch("/admin/api/keys/nonexistent", json={"key_name": "x"})
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_ban_key(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="ban-me",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.post(f"/admin/api/keys/{key.id}/ban")
        assert resp.status_code == 200
        assert "banned" in resp.json()["detail"].lower()

        # Verify banned
        fetched = client.get(f"/admin/api/users/{user.id}")
        keys = fetched.json()["keys"]
        target = [k for k in keys if k["id"] == key.id][0]
        assert target["is_banned"] is True

    @pytest.mark.asyncio
    async def test_unban_key(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="unban-me",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )
        await repo.ban_key(key.id)

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.post(f"/admin/api/keys/{key.id}/unban")
        assert resp.status_code == 200
        assert "unbanned" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_delete_key(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="delete-me",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.delete(f"/admin/api/keys/{key.id}")
        assert resp.status_code == 200


class TestAdminAuditEndpoint:
    @pytest.mark.asyncio
    async def test_query_audit_logs(self, repo, user):
        from datetime import datetime
        from app.platform.auth.models import AuditLog

        await repo.write_audit_log(AuditLog(
            id="admin-audit-1", timestamp=datetime.utcnow(),
            user_id=user.id, auth_type="user_key",
            endpoint="/v1/chat/completions", method="POST", status_code=200,
        ))

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/audit-logs")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_query_audit_logs_with_filters(self, repo, user):
        from datetime import datetime
        from app.platform.auth.models import AuditLog

        for i in range(3):
            await repo.write_audit_log(AuditLog(
                id=f"filter-{i}", timestamp=datetime.utcnow(),
                user_id=user.id, auth_type="user_key",
                endpoint="/v1/test", method="GET", status_code=200,
            ))

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get(f"/admin/api/audit-logs?user_id={user.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    @pytest.mark.asyncio
    async def test_query_audit_logs_pagination(self, repo, user):
        from datetime import datetime
        from app.platform.auth.models import AuditLog

        for i in range(10):
            await repo.write_audit_log(AuditLog(
                id=f"pag-{i}", timestamp=datetime.utcnow(),
                user_id=user.id, auth_type="user_key",
                endpoint="/v1/test", method="GET", status_code=200,
            ))

        app = _make_admin_app(repo)
        client = TestClient(app)
        resp = client.get("/admin/api/audit-logs?page=1&page_size=3")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) <= 3
        assert data["total_pages"] >= 3
