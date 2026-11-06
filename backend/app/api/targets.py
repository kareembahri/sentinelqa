"""Scan targets: the websites SentinelQA is allowed to test.

Every URL passes through the target guard before it is stored.
"""

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from sqlalchemy import select

from app.audit import client_ip, record
from app.config import get_settings
from app.models import Role, Scan, Target, User
from app.schemas import TargetCreate, TargetOut, TargetUpdate
from app.security.deps import CSRF_DOC, AdminUser, DbSession, TesterUser, ViewerUser
from app.security.target_guard import TargetValidationError, validate_target

router = APIRouter(prefix="/targets", tags=["targets"])

LAB_REQUIRES_ADMIN = "Only administrators can mark a target as a lab target"


def _get_target(db: DbSession, target_id: uuid.UUID) -> Target:
    target = db.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")
    return target


def _deny_lab_change(db: DbSession, request: Request, actor: User) -> HTTPException:
    record(
        db,
        "authz.denied",
        user_id=actor.id,
        ip=client_ip(request),
        details={"method": request.method, "path": request.url.path, "reason": "lab_flag"},
    )
    db.commit()
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=LAB_REQUIRES_ADMIN)


@router.get("", response_model=list[TargetOut])
def list_targets(
    _: ViewerUser,
    db: DbSession,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[Target]:
    query = select(Target).order_by(Target.created_at.desc()).limit(limit).offset(offset)
    return list(db.scalars(query))


@router.post(
    "", response_model=TargetOut, status_code=status.HTTP_201_CREATED, dependencies=[CSRF_DOC]
)
def create_target(payload: TargetCreate, request: Request, actor: TesterUser, db: DbSession) -> Target:
    if payload.is_lab and actor.role != Role.ADMIN:
        raise _deny_lab_change(db, request, actor)

    try:
        validated = validate_target(payload.base_url, get_settings(), is_lab=payload.is_lab)
    except TargetValidationError as exc:
        record(
            db,
            "target.rejected",
            user_id=actor.id,
            ip=client_ip(request),
            details={"url": payload.base_url[:300], "reason": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None

    target = Target(
        name=payload.name,
        base_url=validated.base_url,
        host=validated.host,
        is_lab=payload.is_lab,
        scope={},
        created_by=actor.id,
    )
    db.add(target)
    db.flush()
    record(
        db,
        "target.created",
        user_id=actor.id,
        object_type="target",
        object_id=str(target.id),
        ip=client_ip(request),
        details={"base_url": target.base_url, "is_lab": target.is_lab, "addresses": list(validated.addresses)},
    )
    db.commit()
    return target


@router.get("/{target_id}", response_model=TargetOut)
def get_target(target_id: uuid.UUID, _: ViewerUser, db: DbSession) -> Target:
    return _get_target(db, target_id)


@router.patch("/{target_id}", response_model=TargetOut, dependencies=[CSRF_DOC])
def update_target(
    target_id: uuid.UUID, payload: TargetUpdate, request: Request, actor: TesterUser, db: DbSession
) -> Target:
    target = _get_target(db, target_id)
    changes: dict[str, Any] = {}

    if payload.is_lab is not None and payload.is_lab != target.is_lab:
        if actor.role != Role.ADMIN:
            raise _deny_lab_change(db, request, actor)
        if payload.is_lab:
            try:
                validate_target(target.base_url, get_settings(), is_lab=True)
            except TargetValidationError as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
        changes["is_lab"] = {"from": target.is_lab, "to": payload.is_lab}
        target.is_lab = payload.is_lab

    if payload.name is not None and payload.name != target.name:
        changes["name"] = {"from": target.name, "to": payload.name}
        target.name = payload.name

    if changes:
        record(
            db,
            "target.updated",
            user_id=actor.id,
            object_type="target",
            object_id=str(target.id),
            ip=client_ip(request),
            details=changes,
        )
    db.commit()
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CSRF_DOC])
def delete_target(target_id: uuid.UUID, request: Request, actor: AdminUser, db: DbSession) -> Response:
    target = _get_target(db, target_id)
    if db.scalar(select(Scan.id).where(Scan.target_id == target.id).limit(1)) is not None:
        # Scan history is evidence; it is never deleted as a side effect.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This target has scan history and cannot be deleted",
        )
    record(
        db,
        "target.deleted",
        user_id=actor.id,
        object_type="target",
        object_id=str(target.id),
        ip=client_ip(request),
        details={"base_url": target.base_url},
    )
    db.delete(target)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
