"""Read the audit log (admins only). There is deliberately no endpoint to edit or delete it."""

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.models import AuditLog
from app.schemas import AuditOut
from app.security.deps import AdminUser, DbSession

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit_logs(
    _: AdminUser,
    db: DbSession,
    action: str | None = Query(None, max_length=100, description="Filter, e.g. auth.login.failed"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[AuditLog]:
    query = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        query = query.where(AuditLog.action == action)
    return list(db.scalars(query.limit(limit).offset(offset)))
