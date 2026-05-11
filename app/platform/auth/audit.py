"""ASGI audit middleware — fire-and-forget async log writing for /v1/* requests."""

import asyncio
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .models import ApiKeyContext, AuditLog


class AuditMiddleware:
    """Captures request/response metadata and writes audit logs asynchronously.

    Attaches to the ASGI pipeline. After each response, if the request path
    starts with ``/v1/``, an AuditLog entry is written via fire-and-forget.
    """

    def __init__(self, app: ASGIApp, *, get_repo, enabled: bool = True):
        self.app = app
        self._get_repo = get_repo
        self._enabled = enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self._enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not path.startswith("/v1/"):
            await self.app(scope, receive, send)
            return

        captured_status: int = 0

        async def wrapped_send(message: Message) -> None:
            nonlocal captured_status
            if message["type"] == "http.response.start":
                captured_status = message.get("status", 0)
            await send(message)

        try:
            await self.app(scope, receive, wrapped_send)
        finally:
            entry = self._build_entry(scope, captured_status)
            if entry is not None:
                asyncio.ensure_future(self._write_log(entry))

    def _build_entry(self, scope: Scope, status_code: int) -> AuditLog | None:
        ctx: ApiKeyContext | None = scope.get("state", {}).get("api_key_context")
        if ctx is None:
            ctx = ApiKeyContext(
                auth_type="global_key",
                user_id=None,
                key_id=None,
                key_name=None,
                is_global_key=True,
            )

        # Extract client IP
        forwarded = scope.get("headers", [])
        ip = None
        for name, value in forwarded:
            if name == b"x-forwarded-for":
                ip = value.decode().split(",")[0].strip()
                break
        if not ip:
            client = scope.get("client")
            if client:
                ip = client[0]

        path = scope.get("path", "")
        endpoint = path.split("?")[0].rstrip("/")

        # Try to extract model from path
        model = None

        return AuditLog(
            id=uuid.uuid4().hex,
            timestamp=datetime.now(ZoneInfo("Asia/Shanghai")),
            user_id=ctx.user_id,
            key_id=ctx.key_id,
            auth_type=ctx.auth_type,
            endpoint=endpoint,
            method=scope.get("method", "GET"),
            model=model,
            status_code=status_code,
            ip_address=ip,
            request_id=None,
            user_name=ctx.user_name,
        )

    async def _write_log(self, entry: AuditLog) -> None:
        try:
            repo = self._get_repo()
            if repo is not None:
                await repo.write_audit_log(entry)
        except Exception:
            pass
