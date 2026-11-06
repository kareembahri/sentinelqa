"""Audit log: a permanent record of security-relevant actions.

record() only adds the row to the session. The caller decides when to commit,
so an audit entry is saved together with the change it describes.
"""

import uuid
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def record(
    db: Session,
    action: str,
    *,
    user_id: uuid.UUID | None = None,
    object_type: str | None = None,
    object_id: str | None = None,
    ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            object_type=object_type,
            object_id=object_id,
            ip=ip,
            details=details or {},
        )
    )
