"""User self-service API key management endpoints."""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.platform.auth.keygen import generate_api_key
from app.platform.auth.middleware import get_webui_user, verify_webui_key
from app.platform.auth.models import KeyCreated, KeySummary, User
from app.platform.config.snapshot import get_config

router = APIRouter(
    prefix="/webui/api/me",
    dependencies=[Depends(verify_webui_key)],
    tags=["WebUI - Keys"],
)

_MAX_KEYS = 10


def _get_repo(request: Request):
    return getattr(request.app.state, "user_key_repo", None)


@router.get("/keys")
async def list_my_keys(request: Request, user: User | None = Depends(get_webui_user)):
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Login via LinuxDo to manage API keys.")

    repo = _get_repo(request)
    if repo is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Key repository not available.")

    keys = await repo.list_user_keys(user.id)
    return [
        KeySummary(
            id=k.id,
            key_name=k.key_name,
            key_prefix=k.key_prefix,
            is_banned=k.is_banned,
            last_used_at=k.last_used_at,
            created_at=k.created_at,
            revoked_at=k.revoked_at,
        ).model_dump(mode="json")
        for k in keys
    ]


@router.post("/keys", status_code=201)
async def create_my_key(request: Request, body: dict, user: User | None = Depends(get_webui_user)):
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Login via LinuxDo to manage API keys.")

    repo = _get_repo(request)
    if repo is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Key repository not available.")

    max_keys = int(get_config("user.max_keys", _MAX_KEYS) or _MAX_KEYS)
    current_count = await repo.count_user_keys(user.id)
    if current_count >= max_keys:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Maximum of {max_keys} API keys reached.",
        )

    key_name = str(body.get("key_name", "Default")).strip() or "Default"
    raw_key, prefix, fingerprint, hashed = generate_api_key()

    key_record = await repo.create_key(
        user_id=user.id,
        key_name=key_name,
        key_prefix=prefix,
        key_fingerprint=fingerprint,
        hashed_key=hashed,
    )

    return KeyCreated(
        id=key_record.id,
        key_name=key_name,
        key_prefix=prefix,
        raw_key=raw_key,
        created_at=key_record.created_at,
    ).model_dump(mode="json")


@router.delete("/keys/{key_id}")
async def delete_my_key(request: Request, key_id: str, user: User | None = Depends(get_webui_user)):
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Login via LinuxDo to manage API keys.")

    repo = _get_repo(request)
    if repo is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Key repository not available.")

    key_record = await repo.get_key(key_id)
    if key_record is None or key_record.revoked_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found.")

    if key_record.user_id != user.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cannot access another user's key.")

    await repo.revoke_key(key_id)
    return {"detail": "Key revoked."}
