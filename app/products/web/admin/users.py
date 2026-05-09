"""Admin user management endpoints."""

from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Request, status
from pydantic import BaseModel

from app.platform.auth.models import UserCreate, UserUpdate

router = APIRouter(tags=["Admin - Users"])


class BanRequest(BaseModel):
    duration_seconds: int | None = None


class RpmRequest(BaseModel):
    rpm_limit: int | None = None


def _get_repo(request: Request):
    return getattr(request.app.state, "user_key_repo", None)


def _repo_required(repo):
    if repo is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "User key repository not available.")


@router.get("/users")
async def list_users(
    request: Request,
    provider: str | None = Query(None),
    is_active: bool | None = Query(None),
    search: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    repo = _get_repo(request)
    _repo_required(repo)

    users, total = await repo.list_users(
        provider=provider, is_active=is_active, search=search,
        page=page, page_size=page_size,
    )
    items = []
    for u in users:
        key_count = await repo.count_user_keys(u.id)
        items.append({
            "user": u.model_dump(mode="json"),
            "key_count": key_count,
        })
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@router.get("/users/{user_id}")
async def get_user(request: Request, user_id: str):
    repo = _get_repo(request)
    _repo_required(repo)

    user = await repo.get_user(user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")

    keys = await repo.list_user_keys(user_id)
    return {
        "user": user.model_dump(mode="json"),
        "keys": [k.model_dump(mode="json") for k in keys],
        "key_count": len(keys),
    }


@router.post("/users", status_code=201)
async def create_user(request: Request, body: UserCreate):
    repo = _get_repo(request)
    _repo_required(repo)

    user = await repo.create_user(
        provider="local",
        username=body.username,
        name=body.name,
        avatar_url=body.avatar_url,
    )
    return user.model_dump(mode="json")


@router.patch("/users/{user_id}")
async def update_user(request: Request, user_id: str, body: UserUpdate):
    repo = _get_repo(request)
    _repo_required(repo)

    user = await repo.update_user(user_id, body)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return user.model_dump(mode="json")


@router.post("/users/{user_id}/ban")
async def ban_user(request: Request, user_id: str, body: BanRequest):
    repo = _get_repo(request)
    _repo_required(repo)

    if body.duration_seconds and body.duration_seconds > 0:
        banned_until = datetime.utcnow() + timedelta(seconds=body.duration_seconds)
    else:
        banned_until = datetime(2099, 1, 1)

    user = await repo.ban_user(user_id, banned_until)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return user.model_dump(mode="json")


@router.post("/users/{user_id}/unban")
async def unban_user(request: Request, user_id: str):
    repo = _get_repo(request)
    _repo_required(repo)

    user = await repo.unban_user(user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return user.model_dump(mode="json")


@router.patch("/users/{user_id}/rpm")
async def set_user_rpm(request: Request, user_id: str, body: RpmRequest):
    repo = _get_repo(request)
    _repo_required(repo)

    user = await repo.set_user_rpm(user_id, body.rpm_limit)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return user.model_dump(mode="json")
