"""LinuxDo Connect OAuth 2.0 handler with HMAC-signed session tokens."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import NamedTuple
from urllib.parse import urlencode

import aiohttp

from app.platform.auth.middleware import get_admin_key
from app.platform.config.snapshot import get_config

AUTHORIZE_URL = "https://connect.linux.do/oauth2/authorize"
TOKEN_URL = "https://connect.linux.do/oauth2/token"
USER_URL = "https://connect.linux.do/api/user"
TOKEN_PREFIX = "ld:"


class LinuxDoUser(NamedTuple):
    id: int
    username: str
    name: str | None
    avatar_url: str | None


def _get_config(key: str, default: str = "") -> str:
    # env vars take precedence: GROK_LINUXDO_CLIENT_ID, GROK_LINUXDO_CLIENT_SECRET
    env_val = os.getenv(f"GROK_LINUXDO_{key.upper()}", "")
    if env_val:
        return env_val
    return str(get_config(f"auth.linuxdo.{key}", default) or default)


def is_linuxdo_enabled() -> bool:
    client_id = _get_config("client_id")
    client_secret = _get_config("client_secret")
    return bool(client_id and client_secret)


def _sign(payload: str) -> str:
    key = get_admin_key().encode()
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def _verify_sig(payload: str, signature: str) -> bool:
    return hmac.compare_digest(_sign(payload), signature)


def _b64encode(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")


def _b64decode(s: str) -> dict | None:
    s += "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    try:
        return json.loads(base64.urlsafe_b64decode(s))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OAuth state — signed, stateless CSRF protection
# ---------------------------------------------------------------------------

def generate_state() -> str:
    payload = _b64encode({"r": secrets.token_hex(16), "exp": int(time.time()) + 600})
    return f"{payload}.{_sign(payload)}"


def verify_state(state: str) -> bool:
    try:
        payload, sig = state.rsplit(".", 1)
        if not _verify_sig(payload, sig):
            return False
        data = _b64decode(payload)
        return data is not None and data.get("exp", 0) > time.time()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session token — signed, stateless auth for webui
# ---------------------------------------------------------------------------

def issue_token(user: LinuxDoUser) -> str:
    payload = _b64encode({
        "uid": user.id,
        "name": user.name or user.username,
        "av": user.avatar_url or "",
        "iat": int(time.time()),
    })
    return f"{TOKEN_PREFIX}{payload}.{_sign(payload)}"


def verify_token(token: str) -> LinuxDoUser | None:
    if not token.startswith(TOKEN_PREFIX):
        return None
    token = token[len(TOKEN_PREFIX):]
    try:
        payload, sig = token.rsplit(".", 1)
        if not _verify_sig(payload, sig):
            return None
        data = _b64decode(payload)
        if data is None:
            return None
        return LinuxDoUser(
            id=data["uid"],
            username=data.get("un", data["name"]),
            name=data.get("name"),
            avatar_url=data.get("av"),
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# OAuth HTTP
# ---------------------------------------------------------------------------

def get_authorize_url(redirect_uri: str) -> tuple[str, str]:
    state = generate_state()
    params = {
        "client_id": _get_config("client_id"),
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "user",
        "state": state,
    }
    return f"{AUTHORIZE_URL}?{urlencode(params)}", state


async def exchange_code(code: str, redirect_uri: str) -> str | None:
    payload = {
        "client_id": _get_config("client_id"),
        "client_secret": _get_config("client_secret"),
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(TOKEN_URL, data=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            return data.get("access_token")


async def fetch_user(access_token: str) -> LinuxDoUser | None:
    headers = {"Authorization": f"Bearer {access_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(USER_URL, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
            return LinuxDoUser(
                id=data.get("id", 0),
                username=data.get("username", ""),
                name=data.get("name"),
                avatar_url=data.get("avatar_url"),
            )
