"""API-key authentication dependencies for FastAPI routes."""

import hmac

from fastapi import Header, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.platform.config.snapshot import get_config
from app.platform.logging.logger import logger

from .models import ApiKeyContext

_security = HTTPBearer(auto_error=False, scheme_name="API Key")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_keys() -> list[str]:
    raw = get_config("app.api_key", "")
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(k).strip() for k in raw if str(k).strip()]
    return [k.strip() for k in str(raw).split(",") if k.strip()]


def get_admin_key() -> str:
    """Return configured ``app.app_key`` (admin password)."""
    return str(get_config("app.app_key", "grok2api") or "")


def get_webui_key() -> str:
    """Return configured ``app.webui_key`` (webui access key)."""
    return str(get_config("app.webui_key", "") or "")


def is_webui_enabled() -> bool:
    """Whether the webui entry is enabled."""
    val = get_config("app.webui_enabled", False)
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes", "on"}
    return bool(val)


def _extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token


def _get_user_key_repo(request: Request):
    """Resolve UserKeyRepository from app state (lazy — may be None before init)."""
    return getattr(request.app.state, "user_key_repo", None)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

async def verify_api_key(
    request: Request,
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="x-api-key"),
) -> ApiKeyContext:
    """Validate Bearer token against configured ``api_key`` or user API keys.

    Accepts either ``Authorization: Bearer <key>`` (OpenAI / grok2api style)
    or ``X-API-Key: <key>`` (official Anthropic SDK style).

    Returns an ``ApiKeyContext`` describing the authenticated principal.
    Existing callers that ignore the return value continue to work unchanged.
    """
    token = _extract_bearer(authorization) or x_api_key or None

    # 1) Global app.api_key(s)
    allowed_keys = _get_keys()
    if allowed_keys and token is not None:
        if any(hmac.compare_digest(token, k) for k in allowed_keys):
            ctx = ApiKeyContext(
                auth_type="global_key",
                user_id=None,
                key_id=None,
                key_name=None,
                rpm_limit=None,
                is_global_key=True,
            )
            request.state.api_key_context = ctx
            return ctx

    # 2) No keys configured at all — allow all traffic
    if not allowed_keys:
        ctx = ApiKeyContext(
            auth_type="global_key",
            user_id=None,
            key_id=None,
            key_name=None,
            rpm_limit=None,
            is_global_key=True,
        )
        request.state.api_key_context = ctx
        return ctx

    # 3) User API key lookup
    if token is not None:
        repo = _get_user_key_repo(request)
        if repo is not None and len(token) >= 10:
            prefix = token[:10]
            try:
                key_record = await repo.get_key_by_prefix(prefix)
            except Exception:
                key_record = None

            if key_record is not None:
                if key_record.is_banned:
                    raise HTTPException(status.HTTP_403_FORBIDDEN, "API key has been banned.")
                if key_record.revoked_at is not None:
                    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "API key has been revoked.")

                from .keygen import verify_api_key_hash
                if verify_api_key_hash(token, key_record.hashed_key):
                    from datetime import datetime
                    try:
                        await repo.record_key_usage(key_record.id, datetime.utcnow())
                    except Exception:
                        pass

                    ctx = ApiKeyContext(
                        auth_type="user_key",
                        user_id=key_record.user_id,
                        key_id=key_record.id,
                        key_name=key_record.key_name,
                        rpm_limit=key_record.rpm_limit,
                        is_global_key=False,
                    )
                    # Store context on request.state for audit middleware
                    request.state.api_key_context = ctx
                    return ctx

    # 4) No valid token
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid Authorization header.")
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid API key.")


async def verify_admin_key(
    authorization: str | None = Header(default=None),
    app_key: str | None = Query(default=None),
) -> None:
    """Validate Bearer token against ``app.app_key`` (admin access).

    Accepts either ``Authorization: Bearer <key>`` header or ``?app_key=<key>``
    query parameter (the latter is needed for EventSource which cannot send headers).
    """
    key = get_admin_key()
    if not key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Admin key is not configured.")

    token = _extract_bearer(authorization) or app_key
    if token is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing authentication token.")

    if not hmac.compare_digest(token, key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token.")


async def verify_webui_key(
    authorization: str | None = Header(default=None),
) -> None:
    """Validate Bearer token for webui endpoints.

    Accepts the configured ``webui_key``, or a LinuxDo OAuth session token
    issued by ``app.platform.auth.linuxdo.issue_token``.
    """
    webui_key = get_webui_key()

    token = _extract_bearer(authorization)
    if token is None:
        if not webui_key and is_webui_enabled():
            return
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing authentication token.")

    # 1) Static webui_key
    if webui_key and hmac.compare_digest(token, webui_key):
        return

    # 2) LinuxDo OAuth token
    from app.platform.auth.linuxdo import verify_token
    if verify_token(token):
        return

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid authentication token.")


async def get_webui_user(
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Extract the current user from a WebUI session token.

    Returns the local ``User`` record when the request carries a valid
    LinuxDo OAuth token whose principal has been persisted.  Returns
    ``None`` for static ``webui_key`` auth (where there is no user).
    """
    token = _extract_bearer(authorization)
    if not token:
        return None

    from app.platform.auth.linuxdo import verify_token
    ld_user = verify_token(token)
    if ld_user is None:
        return None

    repo = _get_user_key_repo(request)
    if repo is None:
        return None

    try:
        return await repo.get_user_by_provider("linuxdo", ld_user.id)
    except Exception:
        return None


__all__ = [
    "get_webui_user",
    "verify_api_key",
    "verify_admin_key",
    "verify_webui_key",
    "get_admin_key",
    "get_webui_key",
    "is_webui_enabled",
]
