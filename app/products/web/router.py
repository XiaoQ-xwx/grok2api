"""Web product — unified pages + API for the statics-based frontend."""

from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from app.platform.auth.linuxdo import (
    exchange_code,
    fetch_user,
    get_authorize_url,
    is_linuxdo_enabled,
    issue_token,
    upsert_linuxdo_user,
    verify_state,
)
from app.platform.auth.middleware import is_webui_enabled, verify_webui_key
from app.platform.meta import get_project_version
from app.platform.update_check import get_latest_release_info
from .static_html import serve_static_html
from .admin import router as admin_api_router
from .webui import router as webui_router

router = APIRouter()

# Mount admin API sub-router (/admin/api/*)
router.include_router(admin_api_router)
router.include_router(webui_router)

_DIR = Path(__file__).resolve().parents[2] / "statics"


def _serve(path: str) -> FileResponse:
    f = _DIR / path
    if not f.exists():
        raise HTTPException(404, "Page not found")
    return FileResponse(f)


def _serve_html(path: str):
    return serve_static_html(_DIR / path)


@router.get("/", include_in_schema=False)
async def root():
    return RedirectResponse("/admin")


# --- LinuxDo OAuth ---

@router.get("/webui/auth/linuxdo", include_in_schema=False)
async def linuxdo_login(request: Request):
    if not is_webui_enabled() or not is_linuxdo_enabled():
        raise HTTPException(404, "Not Found")
    redirect_uri = str(request.url_for("linuxdo_callback"))
    auth_url, _ = get_authorize_url(redirect_uri)
    return RedirectResponse(auth_url)


@router.get("/webui/auth/linuxdo/callback", include_in_schema=False)
async def linuxdo_callback(request: Request, code: str = Query(...), state: str = Query(...)):
    if not is_webui_enabled() or not is_linuxdo_enabled():
        raise HTTPException(404, "Not Found")
    if not verify_state(state):
        return HTMLResponse("<h3>OAuth 授权失败：state 校验不通过</h3>", status_code=400)

    redirect_uri = str(request.url_for("linuxdo_callback"))
    access_token = await exchange_code(code, redirect_uri)
    if not access_token:
        return HTMLResponse("<h3>OAuth 授权失败：无法获取 access_token</h3>", status_code=400)

    user = await fetch_user(access_token)
    if not user:
        return HTMLResponse("<h3>OAuth 授权失败：无法获取用户信息</h3>", status_code=400)

    user_key_repo = getattr(request.app.state, "user_key_repo", None)
    await upsert_linuxdo_user(user, repo=user_key_repo)

    token = issue_token(user)
    qs = urlencode({"oauth_token": token})
    return RedirectResponse(f"/webui/login?{qs}")


# --- Admin pages ---
@router.get("/admin", include_in_schema=False)
async def admin_root():
    return RedirectResponse("/admin/login")

@router.get("/admin/login", include_in_schema=False)
async def admin_login():
    return _serve_html("admin/login.html")

@router.get("/admin/account", include_in_schema=False)
async def admin_account():
    return _serve_html("admin/account.html")

@router.get("/admin/config", include_in_schema=False)
async def admin_config():
    return _serve_html("admin/config.html")

@router.get("/admin/cache", include_in_schema=False)
async def admin_cache():
    return _serve_html("admin/cache.html")


# --- WebUI ---
@router.get("/webui", include_in_schema=False)
async def webui_root():
    return RedirectResponse("/webui/login")

@router.get("/webui/login", include_in_schema=False)
async def webui_login():
    if not is_webui_enabled():
        raise HTTPException(404, "Not Found")
    return serve_static_html(_DIR / "webui/login.html", {
        "{{LINUXDO_ENABLED}}": "true" if is_linuxdo_enabled() else "false",
    })

@router.get("/webui/api/verify", dependencies=[Depends(verify_webui_key)], tags=["WebUI - System"])
async def webui_verify():
    return {"status": "ok"}


@router.get("/meta", include_in_schema=False)
async def app_meta():
    return {"version": get_project_version()}


@router.get("/meta/update", include_in_schema=False)
async def app_update_meta(force: bool = Query(False)):
    return await get_latest_release_info(force=force)
