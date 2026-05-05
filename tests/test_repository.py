"""11.2 Unit tests for UserKeyRepository backend CRUD operations."""

import pytest
import pytest_asyncio

from app.platform.auth.keygen import generate_api_key
from app.platform.auth.models import AuditLog, AuditLogQuery, UserUpdate


class TestUserCRUD:
    @pytest.mark.asyncio
    async def test_create_user(self, repo):
        user = await repo.create_user(
            provider="local",
            username="alice",
            name="Alice",
        )
        assert user.id is not None
        assert user.provider == "local"
        assert user.username == "alice"
        assert user.name == "Alice"
        assert user.is_active is True
        assert user.created_at is not None
        assert user.updated_at is not None

    @pytest.mark.asyncio
    async def test_get_user(self, repo, user):
        fetched = await repo.get_user(user.id)
        assert fetched is not None
        assert fetched.id == user.id
        assert fetched.username == user.username

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, repo):
        result = await repo.get_user("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_by_provider(self, repo, linuxdo_user):
        fetched = await repo.get_user_by_provider("linuxdo", 12345)
        assert fetched is not None
        assert fetched.id == linuxdo_user.id
        assert fetched.trust_level == 3

    @pytest.mark.asyncio
    async def test_get_user_by_provider_not_found(self, repo):
        result = await repo.get_user_by_provider("linuxdo", 99999)
        assert result is None

    @pytest.mark.asyncio
    async def test_update_user(self, repo, user):
        updated = await repo.update_user(user.id, UserUpdate(name="New Name"))
        assert updated is not None
        assert updated.name == "New Name"

    @pytest.mark.asyncio
    async def test_update_nonexistent_user(self, repo):
        result = await repo.update_user("nonexistent", UserUpdate(name="X"))
        assert result is None

    @pytest.mark.asyncio
    async def test_list_users(self, repo, user, linuxdo_user):
        users, total = await repo.list_users()
        assert total >= 2
        ids = [u.id for u in users]
        assert user.id in ids
        assert linuxdo_user.id in ids

    @pytest.mark.asyncio
    async def test_list_users_filter_provider(self, repo, user, linuxdo_user):
        users, total = await repo.list_users(provider="linuxdo")
        assert all(u.provider == "linuxdo" for u in users)

    @pytest.mark.asyncio
    async def test_list_users_filter_search(self, repo, user, linuxdo_user):
        users, total = await repo.list_users(search="linuxdo")
        assert len(users) >= 1
        assert any("linuxdo" in u.username.lower() for u in users)

    @pytest.mark.asyncio
    async def test_list_users_pagination(self, repo, user, linuxdo_user):
        users, total = await repo.list_users(page=1, page_size=1)
        assert len(users) == 1

    @pytest.mark.asyncio
    async def test_delete_user_soft(self, repo, user):
        ok = await repo.delete_user(user.id)
        assert ok is True
        deleted = await repo.get_user(user.id)
        assert deleted is not None
        assert deleted.is_active is False

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user(self, repo):
        ok = await repo.delete_user("nonexistent")
        assert ok is False


class TestKeyCRUD:
    @pytest.mark.asyncio
    async def test_create_key(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="my-key",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        assert key.id is not None
        assert key.user_id == user.id
        assert key.key_name == "my-key"
        assert key.key_prefix == prefix
        assert key.is_banned is False
        assert key.revoked_at is None

    @pytest.mark.asyncio
    async def test_get_key(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        fetched = await repo.get_key(key.id)
        assert fetched is not None
        assert fetched.id == key.id

    @pytest.mark.asyncio
    async def test_get_key_not_found(self, repo):
        result = await repo.get_key("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_key_by_prefix(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        fetched = await repo.get_key_by_prefix(prefix)
        assert fetched is not None
        assert fetched.key_prefix == prefix

    @pytest.mark.asyncio
    async def test_get_key_by_fingerprint(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        fetched = await repo.get_key_by_fingerprint(fingerprint)
        assert fetched is not None

    @pytest.mark.asyncio
    async def test_fingerprint_unique_constraint(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        await repo.create_key(
            user_id=user.id,
            key_name="k1",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        # Second key with same fingerprint should fail
        with pytest.raises(Exception):
            await repo.create_key(
                user_id=user.id,
                key_name="k2",
                key_prefix=prefix,
                key_fingerprint=fingerprint,
                hashed_key=hashed,
            )

    @pytest.mark.asyncio
    async def test_list_user_keys(self, repo, user):
        for i in range(3):
            raw, prefix, fingerprint, hashed = generate_api_key()
            await repo.create_key(
                user_id=user.id,
                key_name=f"key-{i}",
                key_prefix=prefix,
                key_fingerprint=fingerprint,
                hashed_key=hashed,
            )
        keys = await repo.list_user_keys(user.id)
        assert len(keys) == 3

    @pytest.mark.asyncio
    async def test_list_user_keys_excludes_revoked(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="to-revoke",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        await repo.revoke_key(key.id)
        keys = await repo.list_user_keys(user.id)
        assert all(k.id != key.id for k in keys)

    @pytest.mark.asyncio
    async def test_count_user_keys(self, repo, user):
        assert await repo.count_user_keys(user.id) == 0
        raw, prefix, fingerprint, hashed = generate_api_key()
        await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        assert await repo.count_user_keys(user.id) == 1

    @pytest.mark.asyncio
    async def test_update_key_name(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="old-name",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        updated = await repo.update_key(key.id, key_name="new-name")
        assert updated is not None
        assert updated.key_name == "new-name"

    @pytest.mark.asyncio
    async def test_update_key_rpm(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        updated = await repo.update_key(key.id, rpm_limit=60)
        assert updated is not None
        assert updated.rpm_limit == 60

    @pytest.mark.asyncio
    async def test_update_nonexistent_key(self, repo):
        result = await repo.update_key("nonexistent", key_name="x")
        assert result is None

    @pytest.mark.asyncio
    async def test_ban_key(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        ok = await repo.ban_key(key.id)
        assert ok is True
        fetched = await repo.get_key(key.id)
        assert fetched.is_banned is True

    @pytest.mark.asyncio
    async def test_unban_key(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        await repo.ban_key(key.id)
        ok = await repo.unban_key(key.id)
        assert ok is True
        fetched = await repo.get_key(key.id)
        assert fetched.is_banned is False

    @pytest.mark.asyncio
    async def test_ban_nonexistent_key(self, repo):
        ok = await repo.ban_key("nonexistent")
        assert ok is False

    @pytest.mark.asyncio
    async def test_revoke_key(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        ok = await repo.revoke_key(key.id)
        assert ok is True
        fetched = await repo.get_key(key.id)
        assert fetched.revoked_at is not None

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_key(self, repo):
        ok = await repo.revoke_key("nonexistent")
        assert ok is False

    @pytest.mark.asyncio
    async def test_record_key_usage(self, repo, user):
        from datetime import datetime

        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="k",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        now = datetime.utcnow()
        await repo.record_key_usage(key.id, now)
        fetched = await repo.get_key(key.id)
        assert fetched.last_used_at is not None

    @pytest.mark.asyncio
    async def test_list_all_keys(self, repo, user):
        for i in range(3):
            raw, prefix, fingerprint, hashed = generate_api_key()
            await repo.create_key(
                user_id=user.id,
                key_name=f"ak-{i}",
                key_prefix=prefix,
                key_fingerprint=fingerprint,
                hashed_key=hashed,
            )
        keys, total = await repo.list_all_keys()
        assert total >= 3

    @pytest.mark.asyncio
    async def test_list_all_keys_filter_banned(self, repo, user):
        raw, prefix, fingerprint, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id,
            key_name="banned-key",
            key_prefix=prefix,
            key_fingerprint=fingerprint,
            hashed_key=hashed,
        )
        await repo.ban_key(key.id)
        keys, total = await repo.list_all_keys(is_banned=True)
        assert len(keys) >= 1
        assert all(k.is_banned for k in keys)


class TestAuditLogCRUD:
    @pytest.mark.asyncio
    async def test_write_and_query_audit_log(self, repo, user, api_key):
        from datetime import datetime

        key, raw = api_key
        entry = AuditLog(
            id="test-audit-1",
            timestamp=datetime.utcnow(),
            user_id=user.id,
            key_id=key.id,
            auth_type="user_key",
            endpoint="/v1/chat/completions",
            method="POST",
            model="grok-3",
            status_code=200,
        )
        await repo.write_audit_log(entry)

        result = await repo.query_audit_logs(AuditLogQuery(page=1, page_size=10))
        assert result.total >= 1

    @pytest.mark.asyncio
    async def test_query_audit_logs_filter_user(self, repo, user):
        from datetime import datetime

        entry = AuditLog(
            id="filter-test",
            timestamp=datetime.utcnow(),
            user_id=user.id,
            key_id=None,
            auth_type="user_key",
            endpoint="/v1/test",
            method="GET",
            status_code=200,
        )
        await repo.write_audit_log(entry)

        result = await repo.query_audit_logs(
            AuditLogQuery(user_id=user.id, page=1, page_size=10)
        )
        assert result.total >= 1
        assert all(e.user_id == user.id for e in result.items)

    @pytest.mark.asyncio
    async def test_query_audit_logs_filter_endpoint(self, repo, user):
        from datetime import datetime

        entry = AuditLog(
            id="ep-filter",
            timestamp=datetime.utcnow(),
            user_id=user.id,
            key_id=None,
            auth_type="user_key",
            endpoint="/v1/images/generate",
            method="POST",
            status_code=200,
        )
        await repo.write_audit_log(entry)

        result = await repo.query_audit_logs(
            AuditLogQuery(endpoint="/v1/images/generate", page=1, page_size=10)
        )
        assert result.total >= 1
        for e in result.items:
            assert e.endpoint == "/v1/images/generate"

    @pytest.mark.asyncio
    async def test_query_audit_logs_pagination(self, repo, user):
        from datetime import datetime

        for i in range(5):
            await repo.write_audit_log(
                AuditLog(
                    id=f"page-test-{i}",
                    timestamp=datetime.utcnow(),
                    user_id=user.id,
                    auth_type="user_key",
                    endpoint="/v1/test",
                    method="GET",
                    status_code=200,
                )
            )
        result = await repo.query_audit_logs(
            AuditLogQuery(page=2, page_size=2)
        )
        assert result.page == 2
        assert result.page_size == 2
        assert len(result.items) <= 2

    @pytest.mark.asyncio
    async def test_cleanup_audit_logs(self, repo, user):
        from datetime import datetime, timedelta

        old = datetime.utcnow() - timedelta(days=60)
        await repo.write_audit_log(
            AuditLog(
                id="old-log",
                timestamp=old,
                user_id=user.id,
                auth_type="user_key",
                endpoint="/v1/test",
                method="GET",
                status_code=200,
            )
        )
        cutoff = datetime.utcnow() - timedelta(days=30)
        deleted = await repo.cleanup_audit_logs(cutoff)
        assert deleted >= 1

        result = await repo.query_audit_logs(AuditLogQuery(page=1, page_size=10))
        assert all(
            e.id != "old-log" for e in result.items
        ), "Old audit log should be cleaned up"
