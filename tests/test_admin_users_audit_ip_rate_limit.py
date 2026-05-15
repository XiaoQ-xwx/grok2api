"""Tests for admin user management, audit logs, IP tracking, and rate limiting."""

import asyncio
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest
import pytest_asyncio
from httpx import AsyncClient
from starlette.requests import Request

from app.platform.auth import rate_limit as rate_limit_module
from app.platform.auth.middleware import _get_client_ip
from app.platform.auth.models import AuditLog, AuditLogQuery, UserUpdate
from app.platform.auth.rate_limit import RedisSlidingWindowLimiter, get_effective_rpm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ids(payload: dict[str, Any]) -> set[str]:
    items = payload["items"]
    if items and "user" in items[0]:
        return {item["user"]["id"] for item in items}
    return {item["id"] for item in items}


# ---------------------------------------------------------------------------
# Stub / in-memory test doubles for rate limiting
# ---------------------------------------------------------------------------


class StubLimiter:
    def __init__(self, *, allowed: bool = True, error: Exception | None = None) -> None:
        self._r = object()
        self.allowed = allowed
        self.error = error
        self.calls: list[tuple[str, int, int]] = []

    async def check(self, bucket: str, limit: int, window_ms: int = 60_000) -> bool:
        self.calls.append((bucket, limit, window_ms))
        if self.error is not None:
            raise self.error
        return self.allowed


class InMemoryRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], list[Any]]] = []
        self.storage: dict[str, list[tuple[int, str]]] = {}

    def register_script(self, script: str):
        assert "ZREMRANGEBYSCORE" in script

        async def run(*, keys: list[str], args: list[Any]) -> int:
            self.calls.append((keys, args))
            key = keys[0]
            limit = int(args[0])
            now_ms = int(args[1])
            window_ms = int(args[2])
            request_id = str(args[3])
            entries = [
                entry
                for entry in self.storage.get(key, [])
                if entry[0] > now_ms - window_ms
            ]
            if len(entries) >= limit:
                self.storage[key] = entries
                return 0
            entries.append((now_ms, request_id))
            self.storage[key] = entries
            return 1

        return run


class FailingRedis:
    def register_script(self, script: str):
        async def run(*, keys: list[str], args: list[Any]) -> int:
            raise RuntimeError("redis unavailable")

        return run


# ---------------------------------------------------------------------------
# Audit seed fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def audit_seed(repo, user, linuxdo_user, api_key):
    key_record, _raw_key = api_key
    base = datetime(2026, 1, 1, 12, 0, 0)
    logs = [
        AuditLog(
            id="audit-chat-ok",
            timestamp=base,
            user_id=user.id,
            key_id=key_record.id,
            auth_type="user_key",
            endpoint="/v1/chat/completions",
            method="POST",
            model="grok-3",
            status_code=200,
            tokens_used=25,
            ip_address="192.168.1.100",
            user_name="Stored Name",
        ),
        AuditLog(
            id="audit-chat-rate-limited",
            timestamp=base + timedelta(hours=1),
            user_id=user.id,
            key_id=key_record.id,
            auth_type="user_key",
            endpoint="/v1/chat/completions",
            method="POST",
            model="grok-3",
            status_code=429,
            tokens_used=0,
            ip_address="192.168.1.101",
        ),
        AuditLog(
            id="audit-image-ok",
            timestamp=base + timedelta(hours=2),
            user_id=linuxdo_user.id,
            key_id=None,
            auth_type="global_key",
            endpoint="/v1/images/generations",
            method="POST",
            model="grok-imagine",
            status_code=200,
            tokens_used=0,
            ip_address="10.0.0.5",
        ),
        AuditLog(
            id="audit-models-ok",
            timestamp=base + timedelta(hours=3),
            user_id=None,
            key_id=None,
            auth_type="global_key",
            endpoint="/v1/models",
            method="GET",
            model=None,
            status_code=200,
            tokens_used=0,
            ip_address=None,
        ),
    ]
    for log in logs:
        await repo.write_audit_log(log)
    return logs


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------


class TestAdminAuth:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "headers,query,expected_status",
        [
            pytest.param({"Authorization": "Bearer grok2api"}, "", 200, id="valid_bearer"),
            pytest.param({}, "?app_key=grok2api", 200, id="valid_query_param"),
            pytest.param({"Authorization": "Bearer wrong"}, "", 401, id="wrong_key"),
            pytest.param({}, "", 401, id="missing_key"),
        ],
    )
    async def test_admin_endpoints_require_admin_key(
        self,
        client: AsyncClient,
        headers: dict[str, str],
        query: str,
        expected_status: int,
    ) -> None:
        response = await client.get(f"/admin/api/users{query}", headers=headers)
        assert response.status_code == expected_status


# ---------------------------------------------------------------------------
# Admin user management
# ---------------------------------------------------------------------------


class TestAdminUserManagement:
    @pytest.mark.asyncio
    async def test_list_users_filters_and_pagination(
        self, client: AsyncClient, admin_headers, repo, user, linuxdo_user
    ) -> None:
        alpha = await repo.create_user(provider="local", username="alpha-admin", name="Alpha Admin")
        beta = await repo.create_user(provider="local", username="beta-disabled", name="Beta Disabled")
        await repo.update_user(beta.id, UserUpdate(is_active=False))

        # provider + search + is_active filter
        r = await client.get(
            "/admin/api/users",
            headers=admin_headers,
            params={"provider": "local", "search": "alpha", "is_active": "true"},
        )
        body = r.json()
        assert r.status_code == 200
        assert body["total"] == 1
        assert body["items"][0]["user"]["id"] == alpha.id

        # is_active filter
        inactive = await client.get(
            "/admin/api/users", headers=admin_headers, params={"is_active": "false"}
        )
        assert inactive.status_code == 200
        assert _ids(inactive.json()) == {beta.id}

        # provider filter
        ld_resp = await client.get(
            "/admin/api/users", headers=admin_headers, params={"provider": "linuxdo"}
        )
        assert ld_resp.status_code == 200
        assert _ids(ld_resp.json()) == {linuxdo_user.id}

        # pagination metadata
        paged = await client.get(
            "/admin/api/users", headers=admin_headers, params={"page": 1, "page_size": 2}
        )
        pb = paged.json()
        assert paged.status_code == 200
        assert pb["total"] == 4
        assert pb["page"] == 1
        assert pb["page_size"] == 2
        assert pb["total_pages"] == 2
        assert len(pb["items"]) == 2

    @pytest.mark.asyncio
    async def test_get_user_returns_keys(self, client: AsyncClient, admin_headers, user, api_key) -> None:
        key_record, _raw_key = api_key
        r = await client.get(f"/admin/api/users/{user.id}", headers=admin_headers)
        body = r.json()
        assert r.status_code == 200
        assert body["user"]["id"] == user.id
        assert body["key_count"] == 1
        assert body["keys"][0]["id"] == key_record.id
        assert "raw_key" not in body["keys"][0]

    @pytest.mark.asyncio
    async def test_create_and_update_user(self, client: AsyncClient, admin_headers) -> None:
        # Create
        created = await client.post(
            "/admin/api/users",
            headers=admin_headers,
            json={"username": "new-local", "name": "New Local", "avatar_url": "https://example.test/new.png"},
        )
        cb = created.json()
        assert created.status_code == 201
        assert cb["provider"] == "local"
        assert cb["username"] == "new-local"
        assert cb["is_active"] is True
        assert cb["banned_until"] is None

        # Update
        updated = await client.patch(
            f"/admin/api/users/{cb['id']}",
            headers=admin_headers,
            json={"username": "updated-local", "name": "Updated Local", "is_active": False},
        )
        ub = updated.json()
        assert updated.status_code == 200
        assert ub["username"] == "updated-local"
        assert ub["is_active"] is False

    @pytest.mark.asyncio
    async def test_create_user_missing_username_returns_422(self, client: AsyncClient, admin_headers) -> None:
        r = await client.post("/admin/api/users", headers=admin_headers, json={"name": "Missing Username"})
        assert r.status_code == 422

    @pytest.mark.asyncio
    async def test_update_missing_user_returns_404(self, client: AsyncClient, admin_headers) -> None:
        r = await client.patch("/admin/api/users/missing-user", headers=admin_headers, json={"name": "Nobody"})
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_get_missing_user_returns_404(self, client: AsyncClient, admin_headers) -> None:
        r = await client.get("/admin/api/users/missing-user", headers=admin_headers)
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_ban_unban_user(self, client: AsyncClient, admin_headers, user) -> None:
        # Ban with duration
        timed = await client.post(
            f"/admin/api/users/{user.id}/ban",
            headers=admin_headers,
            json={"duration_seconds": 120},
        )
        assert timed.status_code == 200
        assert timed.json()["banned_until"] is not None

        # Ban permanently (no duration / 0)
        permanent = await client.post(
            f"/admin/api/users/{user.id}/ban",
            headers=admin_headers,
            json={"duration_seconds": None},
        )
        assert permanent.status_code == 200

        # Unban
        unbanned = await client.post(f"/admin/api/users/{user.id}/unban", headers=admin_headers)
        assert unbanned.status_code == 200
        assert unbanned.json()["banned_until"] is None

        # Double unban is idempotent
        double = await client.post(f"/admin/api/users/{user.id}/unban", headers=admin_headers)
        assert double.status_code == 200
        assert double.json()["banned_until"] is None

    @pytest.mark.asyncio
    async def test_ban_missing_user_returns_404(self, client: AsyncClient, admin_headers) -> None:
        r = await client.post(
            "/admin/api/users/missing-user/ban",
            headers=admin_headers,
            json={"duration_seconds": 60},
        )
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_set_and_clear_user_rpm(self, client: AsyncClient, admin_headers, user) -> None:
        r = await client.patch(
            f"/admin/api/users/{user.id}/rpm",
            headers=admin_headers,
            json={"rpm_limit": 60},
        )
        assert r.status_code == 200
        assert r.json()["rpm_limit"] == 60

        r2 = await client.patch(
            f"/admin/api/users/{user.id}/rpm",
            headers=admin_headers,
            json={"rpm_limit": None},
        )
        assert r2.status_code == 200
        assert r2.json()["rpm_limit"] is None

    @pytest.mark.asyncio
    async def test_rpm_missing_user_returns_404(self, client: AsyncClient, admin_headers) -> None:
        r = await client.patch(
            "/admin/api/users/missing-user/rpm",
            headers=admin_headers,
            json={"rpm_limit": 10},
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Admin audit log querying
# ---------------------------------------------------------------------------


class TestAdminAuditLogQuerying:
    @pytest.mark.asyncio
    async def test_query_audit_logs_filters_individually(
        self, client: AsyncClient, admin_headers, audit_seed, user, linuxdo_user, api_key
    ) -> None:
        key_record, _raw_key = api_key
        cases: list[tuple[dict[str, Any], set[str]]] = [
            ({"user_id": user.id}, {"audit-chat-ok", "audit-chat-rate-limited"}),
            ({"user_id": linuxdo_user.id}, {"audit-image-ok"}),
            ({"key_id": key_record.id}, {"audit-chat-ok", "audit-chat-rate-limited"}),
            ({"endpoint": "/v1/chat/completions"}, {"audit-chat-ok", "audit-chat-rate-limited"}),
            ({"model": "grok-imagine"}, {"audit-image-ok"}),
            ({"status_code": 429}, {"audit-chat-rate-limited"}),
            ({"ip_address": "192.168.1.100"}, {"audit-chat-ok"}),
            ({"ip_address": "192.168.1.10"}, {"audit-chat-ok", "audit-chat-rate-limited"}),
            ({"user_id": user.id, "ip_address": "192.168"}, {"audit-chat-ok", "audit-chat-rate-limited"}),
            ({"ip_address": "203.0.113"}, set()),
        ]
        for params, expected_ids in cases:
            r = await client.get("/admin/api/audit-logs", headers=admin_headers, params=params)
            assert r.status_code == 200, f"failed for params={params}"
            assert _ids(r.json()) == expected_ids, f"mismatch for params={params}"
            assert r.json()["total"] == len(expected_ids)

    @pytest.mark.asyncio
    async def test_query_audit_logs_time_filters_and_pagination(
        self, client: AsyncClient, admin_headers, audit_seed
    ) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0)

        # Pagination
        paged = await client.get(
            "/admin/api/audit-logs", headers=admin_headers, params={"page": 1, "page_size": 2}
        )
        pb = paged.json()
        assert paged.status_code == 200
        assert pb["total"] == 4
        assert pb["total_pages"] == 2
        assert [item["id"] for item in pb["items"]] == ["audit-models-ok", "audit-image-ok"]

        # time_from
        r1 = await client.get(
            "/admin/api/audit-logs",
            headers=admin_headers,
            params={"time_from": (base + timedelta(minutes=90)).isoformat()},
        )
        assert r1.status_code == 200
        assert _ids(r1.json()) == {"audit-image-ok", "audit-models-ok"}

        # time_to
        r2 = await client.get(
            "/admin/api/audit-logs",
            headers=admin_headers,
            params={"time_to": (base + timedelta(minutes=30)).isoformat()},
        )
        assert r2.status_code == 200
        assert _ids(r2.json()) == {"audit-chat-ok"}

        # time window
        r3 = await client.get(
            "/admin/api/audit-logs",
            headers=admin_headers,
            params={
                "time_from": (base + timedelta(minutes=30)).isoformat(),
                "time_to": (base + timedelta(minutes=90)).isoformat(),
            },
        )
        assert r3.status_code == 200
        assert _ids(r3.json()) == {"audit-chat-rate-limited"}

    @pytest.mark.asyncio
    async def test_query_audit_logs_empty_ip_param_no_filter(self, client: AsyncClient, admin_headers, audit_seed) -> None:
        r = await client.get("/admin/api/audit-logs", headers=admin_headers, params={"ip_address": ""})
        assert r.status_code == 200
        assert r.json()["total"] == 4

    @pytest.mark.asyncio
    async def test_query_audit_logs_returns_beijing_time_and_user_names(
        self, client: AsyncClient, admin_headers, audit_seed, user, linuxdo_user
    ) -> None:
        r = await client.get("/admin/api/audit-logs", headers=admin_headers)
        body = r.json()
        assert r.status_code == 200

        by_id = {item["id"]: item for item in body["items"]}
        assert by_id["audit-chat-ok"]["user_name"] == "Stored Name"
        assert by_id["audit-image-ok"]["user_name"] == (linuxdo_user.name or linuxdo_user.username)
        ts = datetime.fromisoformat(by_id["audit-chat-ok"]["timestamp"])
        assert ts.utcoffset() == ZoneInfo("Asia/Shanghai").utcoffset(ts)
        assert ts.hour == 20

    @pytest.mark.asyncio
    @pytest.mark.parametrize("param_name", ["time_from", "time_to"])
    async def test_query_audit_logs_rejects_bad_iso_time(
        self, client: AsyncClient, admin_headers, param_name: str
    ) -> None:
        r = await client.get(
            "/admin/api/audit-logs",
            headers=admin_headers,
            params={param_name: "not-a-time"},
        )
        assert r.status_code == 400


# ---------------------------------------------------------------------------
# IP tracking
# ---------------------------------------------------------------------------


class TestIpTracking:
    @pytest.mark.parametrize(
        "headers,client_addr,expected",
        [
            pytest.param(
                [("x-forwarded-for", b"198.51.100.1, 10.0.0.1")],
                ("203.0.113.9", 12345),
                "198.51.100.1",
                id="forwarded_first",
            ),
            pytest.param(
                [("x-forwarded-for", b" 198.51.100.2 ")],
                ("203.0.113.9", 12345),
                "198.51.100.2",
                id="forwarded_single",
            ),
            pytest.param([], ("203.0.113.9", 12345), "203.0.113.9", id="client_host"),
            pytest.param(
                [("x-forwarded-for", b"")], ("203.0.113.10", 12345), "203.0.113.10", id="forwarded_empty"
            ),
            pytest.param([], None, "unknown", id="no_client"),
        ],
    )
    def test_get_client_ip(
        self,
        headers: list[tuple[str, bytes]],
        client_addr: tuple[str, int] | None,
        expected: str,
    ) -> None:
        scope: dict[str, Any] = {
            "type": "http",
            "method": "GET",
            "path": "/v1/audit-probe",
            "headers": [(n.encode(), v) if isinstance(v, bytes) else (n.encode(), v.encode()) for n, v in headers],
            "client": client_addr,
            "server": ("testserver", 80),
            "scheme": "http",
        }
        request = Request(scope)
        assert _get_client_ip(request) == expected

    @pytest.mark.asyncio
    async def test_audit_middleware_records_forwarded_ip(
        self, client: AsyncClient, repo, config_values, api_key
    ) -> None:
        key_record, raw_key = api_key
        config_values["app.api_key"] = raw_key

        response = await client.get(
            "/v1/audit-probe",
            headers={
                "Authorization": f"Bearer {raw_key}",
                "X-Forwarded-For": "198.51.100.44, 10.0.0.1",
            },
        )
        assert response.status_code == 200

        # Wait for fire-and-forget audit write
        result = None
        for _ in range(30):
            result = await repo.query_audit_logs(
                AuditLogQuery(endpoint="/v1/audit-probe", page=1, page_size=10)
            )
            if result.total:
                break
            await asyncio.sleep(0.02)

        assert result is not None
        assert result.total >= 1
        entry = result.items[0]
        assert entry.ip_address == "198.51.100.44"


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimiting:
    def test_get_effective_rpm_precedence(self, config_values) -> None:
        assert get_effective_rpm(user_rpm=100, global_rpm=20) == 100
        assert get_effective_rpm(user_rpm=None, global_rpm=20) == 20
        assert get_effective_rpm(user_rpm=0, global_rpm=20) == 20
        assert get_effective_rpm(user_rpm=None, global_rpm=0) == 0
        config_values["rate_limit.global_rpm"] = 33
        assert get_effective_rpm(user_rpm=None) == 33

    @pytest.mark.asyncio
    async def test_sliding_window_allows_until_limit_and_slides(self, monkeypatch) -> None:
        current = {"value": 1_700_000_000.000}
        redis = InMemoryRedis()
        limiter = RedisSlidingWindowLimiter(redis)
        monkeypatch.setattr(rate_limit_module.time, "time", lambda: current["value"])

        assert await limiter.check("user-1", limit=2, window_ms=1_000) is True
        assert await limiter.check("user-1", limit=2, window_ms=1_000) is True
        assert await limiter.check("user-1", limit=2, window_ms=1_000) is False
        current["value"] += 1.001
        assert await limiter.check("user-1", limit=2, window_ms=1_000) is True

    @pytest.mark.asyncio
    async def test_sliding_window_skips_non_positive_limits(self) -> None:
        class ExplodingRedis:
            def register_script(self, script: str):
                raise AssertionError("script should not be loaded")

        limiter = RedisSlidingWindowLimiter(ExplodingRedis())
        assert await limiter.check("user-1", limit=0) is True
        assert await limiter.check("user-1", limit=-1) is True

    @pytest.mark.asyncio
    async def test_sliding_window_propagates_redis_errors(self) -> None:
        limiter = RedisSlidingWindowLimiter(FailingRedis())
        with pytest.raises(RuntimeError, match="redis unavailable"):
            await limiter.check("user-1", limit=1)

    @pytest.mark.asyncio
    async def test_rate_limited_request_returns_429_with_ip_bucket(
        self, client: AsyncClient, app_with_repo, monkeypatch
    ) -> None:
        from app.platform.auth import middleware as mw_mod
        from app.platform.auth import rate_limit as rl_mod

        limiter = StubLimiter(allowed=False)
        app_with_repo.state.rate_limiter = limiter

        # _get_keys returns our test key → global-key path → _check_rpm is called
        monkeypatch.setattr(mw_mod, "_get_keys", lambda: ["global-secret"])
        # _check_rpm calls get_effective_rpm (local import from rate_limit)
        monkeypatch.setattr(rl_mod, "get_effective_rpm", lambda *a, **kw: 1)

        response = await client.get(
            "/v1/audit-probe",
            headers={
                "Authorization": "Bearer global-secret",
                "X-Forwarded-For": "203.0.113.7, 10.0.0.1",
            },
        )
        assert response.status_code == 429

    @pytest.mark.asyncio
    async def test_rate_limit_redis_error_returns_503(
        self, client: AsyncClient, app_with_repo, monkeypatch
    ) -> None:
        from app.platform.auth import middleware as mw_mod
        from app.platform.auth import rate_limit as rl_mod

        app_with_repo.state.rate_limiter = StubLimiter(error=RuntimeError("redis down"))

        monkeypatch.setattr(mw_mod, "_get_keys", lambda: ["global-secret"])
        monkeypatch.setattr(rl_mod, "get_effective_rpm", lambda *a, **kw: 1)

        response = await client.get(
            "/v1/audit-probe",
            headers={"Authorization": "Bearer global-secret"},
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "Rate limit service unavailable"

    @pytest.mark.asyncio
    async def test_unlimited_rpm_skips_limiter(
        self, client: AsyncClient, app_with_repo, monkeypatch
    ) -> None:
        from app.platform.auth import middleware as mw_mod
        from app.platform.auth import rate_limit as rl_mod

        limiter = StubLimiter(allowed=False)
        app_with_repo.state.rate_limiter = limiter

        monkeypatch.setattr(mw_mod, "_get_keys", lambda: ["global-secret"])
        monkeypatch.setattr(rl_mod, "get_effective_rpm", lambda *a, **kw: 0)

        response = await client.get(
            "/v1/audit-probe",
            headers={"Authorization": "Bearer global-secret"},
        )
        assert response.status_code == 200
        assert limiter.calls == []
