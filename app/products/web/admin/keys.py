"""Admin API key management endpoints."""

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.platform.auth.keygen import generate_api_key
from app.platform.auth.models import KeyCreated, KeyUpdate
from app.platform.config.snapshot import get_config

router = APIRouter(tags=["Admin - Keys"])


def _get_repo(request: Request):
    return getattr(request.app.state, "user_key_repo", None)


def _repo_required(repo):
    if repo is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "User key repository not available.")


@router.get("/keys")
async def list_keys(
    request: Request,
    user_id: str | None = Query(None),
    is_banned: bool | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    repo = _get_repo(request)
    _repo_required(repo)

    keys, total = await repo.list_all_keys(
        user_id=user_id, is_banned=is_banned, search=search,
        page=page, page_size=page_size,
    )
    return {
        "items": [k.model_dump(mode="json") for k in keys],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.post("/users/{user_id}/keys", status_code=201)
async def create_key_for_user(request: Request, user_id: str, body: dict):
    repo = _get_repo(request)
    _repo_required(repo)

    user = await repo.get_user(user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    key_name = str(body.get("key_name", "Default")).strip() or "Default"
    raw_key, prefix, fingerprint, hashed = generate_api_key()

    key_record = await repo.create_key(
        user_id=user_id,
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


@router.patch("/keys/{key_id}")
async def update_key(request: Request, key_id: str, body: KeyUpdate):
    repo = _get_repo(request)
    _repo_required(repo)

    key_record = await repo.update_key(
        key_id,
        key_name=body.key_name,
    )
    if not key_record:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found.")
    return key_record.model_dump(mode="json")


@router.post("/keys/{key_id}/ban")
async def ban_key(request: Request, key_id: str):
    repo = _get_repo(request)
    _repo_required(repo)

    ok = await repo.ban_key(key_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found.")
    return {"detail": "Key banned."}


@router.post("/keys/{key_id}/unban")
async def unban_key(request: Request, key_id: str):
    repo = _get_repo(request)
    _repo_required(repo)

    ok = await repo.unban_key(key_id)
    if not ok:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found.")
    return {"detail": "Key unbanned."}


@router.delete("/keys/{key_id}")
async def delete_key(request: Request, key_id: str):
    repo = _get_repo(request)
    _repo_required(repo)

    key_record = await repo.get_key(key_id)
    if key_record is None or key_record.revoked_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Key not found.")

    await repo.revoke_key(key_id)
    return {"detail": "Key revoked."}
