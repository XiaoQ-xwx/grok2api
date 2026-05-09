"""Admin audit log query endpoint."""

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request, status

from app.platform.auth.models import AuditLogQuery

router = APIRouter(tags=["Admin - Audit"])


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
    return {
        "items": [item.model_dump(mode="json") for item in result.items],
        "total": result.total,
        "page": result.page,
        "page_size": result.page_size,
        "total_pages": result.total_pages,
    }
