"""Redis sliding-window rate limiter for API RPM enforcement."""

import secrets
import time

from app.platform.logging.logger import logger

_LUA_CHECK = """
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local now_ms = tonumber(ARGV[2])
local window_ms = tonumber(ARGV[3])
local request_id = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)
local count = redis.call('ZCARD', key)
if count >= limit then
    return 0
end
redis.call('ZADD', key, now_ms, request_id)
redis.call('PEXPIRE', key, window_ms + 1000)
return 1
"""


class RedisSlidingWindowLimiter:
    """Sliding-window rate limiter backed by Redis Lua scripting."""

    def __init__(self, redis):
        self._r = redis
        self._script = None

    async def _load_script(self):
        if self._script is None:
            self._script = self._r.register_script(_LUA_CHECK)

    async def check(self, bucket: str, limit: int, window_ms: int = 60_000) -> bool:
        """Return True if request is allowed, False if limit exceeded."""
        if limit <= 0:
            return True
        await self._load_script()
        now_ms = int(time.time() * 1000)
        request_id = secrets.token_hex(8)
        try:
            result = await self._script(
                keys=[f"rate_limit:{bucket}"],
                args=[limit, now_ms, window_ms, request_id],
            )
            return result == 1
        except Exception as exc:
            logger.error("rate limiter redis error: bucket={} error={}", bucket, exc)
            raise


def get_effective_rpm(user_rpm: int | None, global_rpm: int | None = None) -> int:
    """Compute effective RPM: user > global > 0 (unlimited)."""
    from app.platform.config.snapshot import get_config

    if user_rpm is not None and user_rpm > 0:
        return user_rpm
    if global_rpm is None:
        global_rpm = get_config("rate_limit.global_rpm", 0)
    if global_rpm is not None and global_rpm > 0:
        return int(global_rpm)
    return 0
