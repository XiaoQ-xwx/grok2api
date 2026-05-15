"""Admin audit log query endpoint."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.platform.auth.models import AuditLogQuery

router = APIRouter(tags=["Admin - Audit"])
_BEIJING_TZ = ZoneInfo("Asia/Shanghai")


def _to_beijing_iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(_BEIJING_TZ).isoformat()


async def _display_user_name(repo, user_id: str | None) -> str | None:
    if not user_id:
        return None
    user = await repo.get_user(user_id)
    if user is None:
        return None
    return user.name or user.username


def _serialize_audit_log(item, user_name: str | None) -> dict:
    data = item.model_dump(mode="json")
    data["timestamp"] = _to_beijing_iso(item.timestamp)
    data["user_name"] = item.user_name or user_name
    return data


def _get_repo(request: Request):
    return getattr(request.app.state, "user_key_repo", None)


@router.get("/audit-logs")
async def query_audit_logs(
    request: Request,
    user_id: str | None = Query(None),
    key_id: str | None = Query(None),
    endpoint: str | None = Query(None),
    model: str | None = Query(None),
    status_code: int | None = Query(None),
    ip_address: str | None = Query(None),
    time_from: str | None = Query(None),
    time_to: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    repo = _get_repo(request)
    if repo is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "User key repository not available.")

    q = AuditLogQuery(
        user_id=user_id,
        key_id=key_id,
        endpoint=endpoint,
        model=model,
        status_code=status_code,
        ip_address=ip_address,
        page=page,
        page_size=page_size,
    )
    if time_from:
        try:
            q.time_from = datetime.fromisoformat(time_from)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid time_from format. Use ISO 8601.")
    if time_to:
        try:
            q.time_to = datetime.fromisoformat(time_to)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid time_to format. Use ISO 8601.")

    result = await repo.query_audit_logs(q)
    user_names: dict[str, str | None] = {}
    items = []
    for item in result.items:
        if item.user_id not in user_names:
            user_names[item.user_id] = await _display_user_name(repo, item.user_id)
        items.append(_serialize_audit_log(item, user_names[item.user_id]))
    return {
        "items": items,
        "total": result.total,
        "page": result.page,
        "page_size": result.page_size,
        "total_pages": result.total_pages,
    }
