"""Redis backend for UserKeyRepository with hash + sorted-set layout."""

import uuid
from datetime import datetime, timezone

from redis.asyncio import Redis

from ..models import (
    AuditLog,
    AuditLogPage,
    AuditLogQuery,
    User,
    UserApiKey,
    UserUpdate,
)
from ..repository import UserKeyRepository

_USER_PREFIX = "uk:user"
_KEY_PREFIX = "uk:apikey"
_AUDIT_PREFIX = "uk:audit"

_SET_USERS_ALL = "uk:users:all"
_SET_AUDIT_BY_TIME = "uk:audit:by_time"
_SET_USER_KEYS = "uk:user:%s:keys"
_SET_PROVIDER_MAP = "uk:provider:%s:%s"
_SET_FINGERPRINT_MAP = "uk:fingerprint:%s"


def _uid() -> str:
    return uuid.uuid4().hex


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _user_key(user_id: str) -> str:
    return f"{_USER_PREFIX}:{user_id}"


def _key_key(key_id: str) -> str:
    return f"{_KEY_PREFIX}:{key_id}"


def _audit_key(audit_id: str) -> str:
    return f"{_AUDIT_PREFIX}:{audit_id}"


def _user_from_hash(data: dict) -> User:
    banned = data.get(b"banned_until", b"").decode()
    rpm_raw = data.get(b"rpm_limit", b"")
    return User(
        id=data.get(b"id", b"").decode(),
        provider=data.get(b"provider", b"").decode(),
        provider_user_id=int(data[b"provider_user_id"]) if data.get(b"provider_user_id") else None,
        username=data.get(b"username", b"").decode(),
        name=data.get(b"name", b"").decode() or None,
        avatar_url=data.get(b"avatar_url", b"").decode() or None,
        trust_level=int(data[b"trust_level"]) if data.get(b"trust_level") else None,
        is_active=data.get(b"is_active", b"1") == b"1",
        banned_until=_parse_dt(banned) if banned else None,
        rpm_limit=int(rpm_raw) if rpm_raw and rpm_raw != b"" else None,
        created_at=_parse_dt(data.get(b"created_at", b"").decode()) or datetime.utcnow(),
        updated_at=_parse_dt(data.get(b"updated_at", b"").decode()) or datetime.utcnow(),
        last_login_at=_parse_dt(data.get(b"last_login_at", b"").decode()) if data.get(b"last_login_at") else None,
    )


def _key_from_hash(data: dict) -> UserApiKey:
    return UserApiKey(
        id=data.get(b"id", b"").decode(),
        user_id=data.get(b"user_id", b"").decode(),
        key_name=data.get(b"key_name", b"").decode(),
        key_prefix=data.get(b"key_prefix", b"").decode(),
        key_fingerprint=data.get(b"key_fingerprint", b"").decode(),
        hashed_key=data.get(b"hashed_key", b"").decode(),
        is_banned=data.get(b"is_banned", b"0") == b"1",
        last_used_at=_parse_dt(data.get(b"last_used_at", b"").decode()) if data.get(b"last_used_at") else None,
        created_at=_parse_dt(data.get(b"created_at", b"").decode()) or datetime.utcnow(),
        updated_at=_parse_dt(data.get(b"updated_at", b"").decode()) or datetime.utcnow(),
        revoked_at=_parse_dt(data.get(b"revoked_at", b"").decode()) if data.get(b"revoked_at") else None,
    )


def _audit_from_hash(data: dict) -> AuditLog:
    return AuditLog(
        id=data.get(b"id", b"").decode(),
        timestamp=_parse_dt(data.get(b"timestamp", b"").decode()) or datetime.utcnow(),
        user_id=data.get(b"user_id", b"").decode() or None,
        key_id=data.get(b"key_id", b"").decode() or None,
        auth_type=data.get(b"auth_type", b"").decode(),
        endpoint=data.get(b"endpoint", b"").decode(),
        method=data.get(b"method", b"").decode(),
        model=data.get(b"model", b"").decode() or None,
        status_code=int(data.get(b"status_code", 0)),
        tokens_used=int(data.get(b"tokens_used", 0)),
        ip_address=data.get(b"ip_address", b"").decode() or None,
        request_id=data.get(b"request_id", b"").decode() or None,
        error_code=data.get(b"error_code", b"").decode() or None,
    )


class RedisUserKeyRepository:
    """Redis backend implementing UserKeyRepository."""

    def __init__(self, redis: Redis):
        self._r = redis

    async def initialize(self) -> None:
        pass

    # ── Users ──────────────────────────────────────────────────────────

    async def create_user(
        self,
        provider: str,
        username: str,
        *,
        provider_user_id: int | None = None,
        name: str | None = None,
        avatar_url: str | None = None,
        trust_level: int | None = None,
    ) -> User:
        user_id = _uid()
        now = _now()
        data = {
            "id": user_id,
            "provider": provider,
            "provider_user_id": str(provider_user_id) if provider_user_id is not None else "",
            "username": username,
            "name": name or "",
            "avatar_url": avatar_url or "",
            "trust_level": str(trust_level) if trust_level is not None else "",
            "is_active": "1",
            "created_at": now,
            "updated_at": now,
            "last_login_at": "",
        }
        pipe = self._r.pipeline()
        pipe.hset(_user_key(user_id), mapping={k: v for k, v in data.items() if v})
        pipe.sadd(_SET_USERS_ALL, user_id)
        if provider_user_id is not None:
            pipe.set(_SET_PROVIDER_MAP % (provider, provider_user_id), user_id)
        await pipe.execute()
        return User(
            id=user_id, provider=provider, provider_user_id=provider_user_id,
            username=username, name=name, avatar_url=avatar_url,
            trust_level=trust_level, is_active=True,
            created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
        )

    async def get_user(self, user_id: str) -> User | None:
        data = await self._r.hgetall(_user_key(user_id))
        return _user_from_hash(data) if data else None

    async def get_user_by_provider(self, provider: str, provider_user_id: int) -> User | None:
        uid = await self._r.get(_SET_PROVIDER_MAP % (provider, provider_user_id))
        if not uid:
            return None
        return await self.get_user(uid.decode())

    async def update_user(self, user_id: str, updates: UserUpdate) -> User | None:
        existing = await self.get_user(user_id)
        if not existing:
            return None
        mapping = {"updated_at": _now()}
        if updates.username is not None:
            mapping["username"] = updates.username
        if updates.name is not None:
            mapping["name"] = updates.name
        if updates.avatar_url is not None:
            mapping["avatar_url"] = updates.avatar_url
        if updates.is_active is not None:
            mapping["is_active"] = "1" if updates.is_active else "0"
        await self._r.hset(_user_key(user_id), mapping=mapping)
        return await self.get_user(user_id)

    async def list_users(
        self,
        *,
        provider: str | None = None,
        is_active: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[User], int]:
        all_ids = await self._r.smembers(_SET_USERS_ALL)
        users = []
        for uid in all_ids:
            u = await self.get_user(uid.decode())
            if not u:
                continue
            if provider is not None and u.provider != provider:
                continue
            if is_active is not None and u.is_active != is_active:
                continue
            if search and search.lower() not in u.username.lower():
                continue
            users.append(u)

        users.sort(key=lambda x: x.created_at, reverse=True)
        total = len(users)
        start = (page - 1) * page_size
        return users[start:start + page_size], total

    async def delete_user(self, user_id: str) -> bool:
        exists = await self._r.exists(_user_key(user_id))
        if not exists:
            return False
        await self._r.hset(_user_key(user_id), "is_active", "0")
        await self._r.hset(_user_key(user_id), "updated_at", _now())
        return True

    async def ban_user(self, user_id: str, banned_until: datetime) -> User | None:
        exists = await self._r.exists(_user_key(user_id))
        if not exists:
            return None
        mapping = {
            "banned_until": banned_until.isoformat(),
            "updated_at": _now(),
        }
        await self._r.hset(_user_key(user_id), mapping=mapping)
        return await self.get_user(user_id)

    async def unban_user(self, user_id: str) -> User | None:
        exists = await self._r.exists(_user_key(user_id))
        if not exists:
            return None
        mapping = {"banned_until": "", "updated_at": _now()}
        await self._r.hset(_user_key(user_id), mapping=mapping)
        return await self.get_user(user_id)

    async def set_user_rpm(self, user_id: str, rpm_limit: int | None) -> User | None:
        exists = await self._r.exists(_user_key(user_id))
        if not exists:
            return None
        mapping = {
            "rpm_limit": str(rpm_limit) if rpm_limit is not None else "",
            "updated_at": _now(),
        }
        await self._r.hset(_user_key(user_id), mapping=mapping)
        return await self.get_user(user_id)

    # ── API Keys ───────────────────────────────────────────────────────

    async def create_key(
        self,
        user_id: str,
        key_name: str,
        key_prefix: str,
        key_fingerprint: str,
        hashed_key: str,
    ) -> UserApiKey:
        key_id = _uid()
        now = _now()
        data = {
            "id": key_id, "user_id": user_id, "key_name": key_name,
            "key_prefix": key_prefix, "key_fingerprint": key_fingerprint,
            "hashed_key": hashed_key, "is_banned": "0",
            "last_used_at": "", "created_at": now, "updated_at": now, "revoked_at": "",
        }
        pipe = self._r.pipeline()
        pipe.hset(_key_key(key_id), mapping={k: v for k, v in data.items() if v})
        pipe.sadd(_SET_USER_KEYS % user_id, key_id)
        pipe.set(_SET_FINGERPRINT_MAP % key_fingerprint, key_id)
        await pipe.execute()
        return UserApiKey(
            id=key_id, user_id=user_id, key_name=key_name, key_prefix=key_prefix,
            key_fingerprint=key_fingerprint, hashed_key=hashed_key,
            is_banned=False, created_at=datetime.utcnow(), updated_at=datetime.utcnow(),
        )

    async def get_key(self, key_id: str) -> UserApiKey | None:
        data = await self._r.hgetall(_key_key(key_id))
        return _key_from_hash(data) if data else None

    async def get_key_by_prefix(self, key_prefix: str) -> UserApiKey | None:
        # Scan all keys for prefix match (Redis doesn't have prefix index)
        # In practice, the hash uses full key_id, so we iterate user key sets
        # For efficiency, we scan the fingerprint index which contains all key IDs
        # Actually, we need to iterate. Let's keep it simple but add a note.
        # Better approach: maintain a prefix → key_id mapping
        prefix_map_key = f"uk:prefix:{key_prefix}"
        kid = await self._r.get(prefix_map_key)
        if not kid:
            return None
        return await self.get_key(kid.decode())

    async def get_key_by_fingerprint(self, fingerprint: str) -> UserApiKey | None:
        kid = await self._r.get(_SET_FINGERPRINT_MAP % fingerprint)
        if not kid:
            return None
        return await self.get_key(kid.decode())

    async def list_user_keys(self, user_id: str) -> list[UserApiKey]:
        key_ids = await self._r.smembers(_SET_USER_KEYS % user_id)
        keys = []
        for kid in key_ids:
            k = await self.get_key(kid.decode())
            if k and k.revoked_at is None:
                keys.append(k)
        keys.sort(key=lambda x: x.created_at, reverse=True)
        return keys

    async def list_all_keys(
        self,
        *,
        user_id: str | None = None,
        is_banned: bool | None = None,
        search: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[UserApiKey], int]:
        if user_id:
            key_ids = await self._r.smembers(_SET_USER_KEYS % user_id)
        else:
            # Scan all users' keys
            all_users = await self._r.smembers(_SET_USERS_ALL)
            key_ids = set()
            for uid in all_users:
                kids = await self._r.smembers(_SET_USER_KEYS % uid.decode())
                key_ids.update(kids)

        keys = []
        for kid in key_ids:
            k = await self.get_key(kid.decode())
            if not k or k.revoked_at is not None:
                continue
            if is_banned is not None and k.is_banned != is_banned:
                continue
            if search and search.lower() not in k.key_name.lower():
                continue
            keys.append(k)

        keys.sort(key=lambda x: x.created_at, reverse=True)
        total = len(keys)
        start = (page - 1) * page_size
        return keys[start:start + page_size], total

    async def count_user_keys(self, user_id: str) -> int:
        keys = await self.list_user_keys(user_id)
        return len(keys)

    async def update_key(self, key_id: str, key_name: str | None = None) -> UserApiKey | None:
        existing = await self.get_key(key_id)
        if not existing:
            return None
        mapping = {"updated_at": _now()}
        if key_name is not None:
            mapping["key_name"] = key_name
        await self._r.hset(_key_key(key_id), mapping=mapping)
        return await self.get_key(key_id)

    async def ban_key(self, key_id: str) -> bool:
        exists = await self._r.exists(_key_key(key_id))
        if not exists:
            return False
        await self._r.hset(_key_key(key_id), mapping={"is_banned": "1", "updated_at": _now()})
        return True

    async def unban_key(self, key_id: str) -> bool:
        exists = await self._r.exists(_key_key(key_id))
        if not exists:
            return False
        await self._r.hset(_key_key(key_id), mapping={"is_banned": "0", "updated_at": _now()})
        return True

    async def revoke_key(self, key_id: str) -> bool:
        exists = await self._r.exists(_key_key(key_id))
        if not exists:
            return False
        now = _now()
        await self._r.hset(_key_key(key_id), mapping={"revoked_at": now, "updated_at": now})
        return True

    async def record_key_usage(self, key_id: str, timestamp: datetime) -> None:
        ts = timestamp.isoformat()
        await self._r.hset(_key_key(key_id), mapping={"last_used_at": ts, "updated_at": ts})

    # ── Audit Logs ─────────────────────────────────────────────────────

    async def write_audit_log(self, entry: AuditLog) -> None:
        audit_id = entry.id or _uid()
        now = entry.timestamp.isoformat()
        data = {
            "id": audit_id, "timestamp": now,
            "user_id": entry.user_id or "", "key_id": entry.key_id or "",
            "auth_type": entry.auth_type, "endpoint": entry.endpoint,
            "method": entry.method, "model": entry.model or "",
            "status_code": str(entry.status_code), "tokens_used": str(entry.tokens_used),
            "ip_address": entry.ip_address or "", "request_id": entry.request_id or "",
            "error_code": entry.error_code or "",
        }
        pipe = self._r.pipeline()
        pipe.hset(_audit_key(audit_id), mapping={k: v for k, v in data.items() if v})
        pipe.zadd(_SET_AUDIT_BY_TIME, {audit_id: entry.timestamp.timestamp()})
        await pipe.execute()

    async def query_audit_logs(self, query: AuditLogQuery) -> AuditLogPage:
        # Get all audit IDs sorted by time
        all_ids = await self._r.zrevrange(_SET_AUDIT_BY_TIME, 0, -1)
        items = []
        for aid in all_ids:
            data = await self._r.hgetall(_audit_key(aid.decode()))
            if not data:
                continue
            entry = _audit_from_hash(data)

            if query.user_id and entry.user_id != query.user_id:
                continue
            if query.key_id and entry.key_id != query.key_id:
                continue
            if query.endpoint and entry.endpoint != query.endpoint:
                continue
            if query.model and entry.model != query.model:
                continue
            if query.status_code is not None and entry.status_code != query.status_code:
                continue
            if query.ip_address:
                if not entry.ip_address or not entry.ip_address.startswith(query.ip_address):
                    continue
            if query.time_from and entry.timestamp < query.time_from:
                continue
            if query.time_to and entry.timestamp > query.time_to:
                continue
            items.append(entry)

        total = len(items)
        total_pages = max(1, (total + query.page_size - 1) // query.page_size)
        start = (query.page - 1) * query.page_size
        return AuditLogPage(
            items=items[start:start + query.page_size],
            total=total, page=query.page, page_size=query.page_size,
            total_pages=total_pages,
        )

    async def cleanup_audit_logs(self, before: datetime) -> int:
        cutoff = before.timestamp()
        old_ids = await self._r.zrangebyscore(_SET_AUDIT_BY_TIME, "-inf", cutoff)
        count = 0
        if old_ids:
            pipe = self._r.pipeline()
            for aid in old_ids:
                pipe.delete(_audit_key(aid.decode()))
            pipe.zremrangebyscore(_SET_AUDIT_BY_TIME, "-inf", cutoff)
            results = await pipe.execute()
            count = len(old_ids)
        return count

    async def close(self) -> None:
        await self._r.close()
