"""API key generation and HMAC verification utilities."""

import hashlib
import hmac
import os
import secrets

from app.platform.config.snapshot import get_config
from app.platform.logging.logger import logger

_KEY_PREFIX = "g2a_"


def get_app_secret() -> str:
    secret = os.getenv("GROK_API_KEY_SECRET", "").strip()
    if secret:
        return secret

    secret = str(get_config("app.api_key_secret", "") or "").strip()
    if secret:
        return secret

    secret = str(get_config("app.app_key", "") or "").strip()
    if secret:
        return secret

    secret = secrets.token_hex(32)
    logger.warning(
        "No API key secret configured — generated random secret. "
        "Previously issued user API keys will fail validation after restart. "
        "Set GROK_API_KEY_SECRET env or app.api_key_secret config for persistence."
    )
    return secret


def generate_api_key() -> tuple[str, str, str, str]:
    """Returns (raw_key, key_prefix, key_fingerprint, hashed_key)."""
    raw = _KEY_PREFIX + secrets.token_hex(32)
    prefix = raw[:10]
    fingerprint = hashlib.sha256(raw.encode()).hexdigest()[:16]
    hashed = _hash_key(raw)
    return raw, prefix, fingerprint, hashed


def verify_api_key_hash(raw_key: str, stored_hash: str) -> bool:
    return hmac.compare_digest(_hash_key(raw_key), stored_hash)


def _hash_key(raw_key: str) -> str:
    secret = get_app_secret()
    return hmac.new(secret.encode(), raw_key.encode(), hashlib.sha256).hexdigest()
