"""Auth platform package — API keys, OAuth, and audit middleware."""

from .middleware import (
    get_admin_key,
    get_webui_key,
    is_webui_enabled,
    verify_admin_key,
    verify_api_key,
    verify_webui_key,
)
from .models import ApiKeyContext, AuditLog, KeyCreated, KeySummary, User, UserApiKey

__all__ = [
    "ApiKeyContext",
    "AuditLog",
    "KeyCreated",
    "KeySummary",
    "User",
    "UserApiKey",
    "get_admin_key",
    "get_webui_key",
    "is_webui_enabled",
    "verify_admin_key",
    "verify_api_key",
    "verify_webui_key",
]
