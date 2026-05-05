"""User self-service profile endpoint."""

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.platform.auth.middleware import get_webui_user, verify_webui_key
from app.platform.auth.models import User

router = APIRouter(
    prefix="/webui/api/me",
    dependencies=[Depends(verify_webui_key)],
    tags=["WebUI - Profile"],
)


@router.get("/profile")
async def get_my_profile(user: User | None = Depends(get_webui_user)):
    if user is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "User profile not available. Login via LinuxDo to access your profile.",
        )
    return {
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "avatar_url": user.avatar_url,
        "trust_level": user.trust_level,
        "provider": user.provider,
        "created_at": user.created_at.isoformat(),
    }
