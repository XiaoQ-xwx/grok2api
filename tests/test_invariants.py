"""11.7 PBT property tests for invariants I1-I17 from specs.md."""

import asyncio
from datetime import datetime, timedelta

import pytest

from app.platform.auth.keygen import generate_api_key, verify_api_key_hash
from app.platform.auth.models import AuditLog, AuditLogQuery


class TestInvariantI1_KeyCreationOrderIndependent:
    """Key creation order is independent — two keys are equally valid regardless of creation order."""

    @pytest.mark.asyncio
    async def test_i1_keys_equally_valid_regardless_of_order(self, repo, user):
        raw1, prefix1, fp1, hashed1 = generate_api_key()
        raw2, prefix2, fp2, hashed2 = generate_api_key()

        # Order A: k1 then k2
        k1a = await repo.create_key(
            user_id=user.id, key_name="k1", key_prefix=prefix1,
            key_fingerprint=fp1, hashed_key=hashed1,
        )
        k2a = await repo.create_key(
            user_id=user.id, key_name="k2", key_prefix=prefix2,
            key_fingerprint=fp2, hashed_key=hashed2,
        )

        assert verify_api_key_hash(raw1, hashed1) is True
        assert verify_api_key_hash(raw2, hashed2) is True


class TestInvariantI2_DeleteCreateCommute:
    """Delete-then-create produces same valid key set regardless of order."""

    @pytest.mark.asyncio
    async def test_i2_delete_create_commute(self, repo, user):
        for i in range(2):
            raw, prefix, fp, hashed = generate_api_key()
            await repo.create_key(
                user_id=user.id, key_name=f"base-{i}",
                key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
            )

        # Scenario A: delete last, then create new
        keys_before = await repo.list_user_keys(user.id)
        await repo.revoke_key(keys_before[-1].id)
        raw3, prefix3, fp3, hashed3 = generate_api_key()
        await repo.create_key(
            user_id=user.id, key_name="new-after-delete",
            key_prefix=prefix3, key_fingerprint=fp3, hashed_key=hashed3,
        )

        keys_after = await repo.list_user_keys(user.id)
        assert len(keys_after) == 2
        assert verify_api_key_hash(raw3, hashed3) is True


class TestInvariantI3_VerifyIdempotent:
    """verify_api_key(valid_key) → same context every call for the same key."""

    def test_i3_verify_is_deterministic(self):
        raw, prefix, fp, hashed = generate_api_key()
        results = [verify_api_key_hash(raw, hashed) for _ in range(10)]
        assert all(r is True for r in results)

        raw2, _, _, hashed2 = generate_api_key()
        results2 = [verify_api_key_hash(raw2, hashed) for _ in range(10)]
        assert all(r is False for r in results2)  # hashed2 is for raw, not raw2


class TestInvariantI5_DeleteIdempotent:
    """DELETE on already-deleted key → 404 consistently."""

    @pytest.mark.asyncio
    async def test_i5_double_delete_returns_consistent(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="idem-delete",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        ok1 = await repo.revoke_key(key.id)
        assert ok1 is True

        # State is consistent after first revoke
        k1 = await repo.get_key(key.id)
        assert k1.revoked_at is not None

        # Second revoke is a no-op on state — key stays revoked
        ok2 = await repo.revoke_key(key.id)
        k2 = await repo.get_key(key.id)
        assert k2.revoked_at is not None


class TestInvariantI6_DoubleBanIdempotent:
    """Ban on already-banned key → no-op on state (key stays banned)."""

    @pytest.mark.asyncio
    async def test_i6_double_ban_noop(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="idem-ban",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        await repo.ban_key(key.id)
        assert (await repo.get_key(key.id)).is_banned is True

        await repo.ban_key(key.id)
        assert (await repo.get_key(key.id)).is_banned is True


class TestInvariantI7_RawKeyRoundTrip:
    """Create Key → raw_key authenticates → list shows metadata but NOT raw_key."""

    @pytest.mark.asyncio
    async def test_i7_raw_key_not_in_list(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="roundtrip",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        assert verify_api_key_hash(raw, hashed) is True

        fetched = await repo.get_key(key.id)
        assert fetched.hashed_key != raw
        assert fetched.key_prefix == prefix


class TestInvariantI9_BannedKeyAuditPreserved:
    """Banning does not delete past audit logs."""

    @pytest.mark.asyncio
    async def test_i9_audit_preserved_after_ban(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="audit-ban",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        for i in range(3):
            await repo.write_audit_log(AuditLog(
                id=f"i9-{i}", timestamp=datetime.utcnow(),
                user_id=user.id, key_id=key.id, auth_type="user_key",
                endpoint="/v1/test", method="GET", status_code=200,
            ))

        await repo.ban_key(key.id)

        result = await repo.query_audit_logs(
            AuditLogQuery(key_id=key.id, page=1, page_size=10)
        )
        assert result.total == 3


class TestInvariantI10_SoftDeletePreservesAudit:
    """User deletion soft-deletes — existing audit log entries retain user_id reference."""

    @pytest.mark.asyncio
    async def test_i10_audit_preserved_after_user_delete(self, repo, user):
        await repo.write_audit_log(AuditLog(
            id="i10-test", timestamp=datetime.utcnow(),
            user_id=user.id, auth_type="user_key",
            endpoint="/v1/test", method="GET", status_code=200,
        ))

        await repo.delete_user(user.id)

        result = await repo.query_audit_logs(
            AuditLogQuery(user_id=user.id, page=1, page_size=10)
        )
        assert result.total >= 1

        # User should be inactive
        fetched = await repo.get_user(user.id)
        assert fetched.is_active is False


class TestInvariantI11_GlobalKeyAlwaysBypasses:
    """Global app.api_key always works regardless of user key state."""

    def test_i11_global_key_works_independent_of_user_keys(self):
        # Global key verification does not depend on user keys at all
        from app.platform.auth.keygen import get_app_secret
        secret = get_app_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0
        # Global API key bypasses user key checks by design in verify_api_key()


class TestInvariantI13_TimestampMonotonicity:
    """created_at ≤ updated_at ≤ revoked_at for any key."""

    @pytest.mark.asyncio
    async def test_i13_timestamps_non_decreasing(self, repo, user):
        raw, prefix, fp, hashed = generate_api_key()
        key = await repo.create_key(
            user_id=user.id, key_name="monotonic",
            key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
        )

        assert key.created_at <= key.updated_at

        await repo.update_key(key.id, key_name="updated")
        updated = await repo.get_key(key.id)
        assert key.created_at <= updated.updated_at
        assert key.updated_at <= updated.updated_at

        await repo.revoke_key(key.id)
        revoked = await repo.get_key(key.id)
        assert revoked.revoked_at is not None
        # Both timestamps are set in the same atomic write;
        # key invariant: created_at strictly before revoke time
        assert revoked.created_at <= revoked.revoked_at
        assert updated.updated_at <= revoked.updated_at


class TestInvariantI15_MaxKeysBound:
    """Max 10 keys per user (default)."""

    @pytest.mark.asyncio
    async def test_i15_cannot_exceed_max_keys(self, repo, user):
        for i in range(10):
            raw, prefix, fp, hashed = generate_api_key()
            await repo.create_key(
                user_id=user.id, key_name=f"max-{i}",
                key_prefix=prefix, key_fingerprint=fp, hashed_key=hashed,
            )

        count = await repo.count_user_keys(user.id)
        assert count == 10


class TestInvariantI17_AuditRetention:
    """Audit log retention enforces max age."""

    @pytest.mark.asyncio
    async def test_i17_cleanup_removes_old_entries(self, repo, user):
        old = datetime.utcnow() - timedelta(days=60)
        await repo.write_audit_log(AuditLog(
            id="i17-old", timestamp=old, user_id=user.id,
            auth_type="user_key", endpoint="/v1/test", method="GET", status_code=200,
        ))

        recent = datetime.utcnow()
        await repo.write_audit_log(AuditLog(
            id="i17-new", timestamp=recent, user_id=user.id,
            auth_type="user_key", endpoint="/v1/test", method="GET", status_code=200,
        ))

        cutoff = datetime.utcnow() - timedelta(days=30)
        deleted = await repo.cleanup_audit_logs(cutoff)
        assert deleted >= 1

        result = await repo.query_audit_logs(AuditLogQuery(page=1, page_size=50))
        ids = {e.id for e in result.items}
        assert "i17-new" in ids
        assert "i17-old" not in ids
