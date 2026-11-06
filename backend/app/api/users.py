"""User management (admins only)."""

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from app.audit import client_ip, record
from app.models import Role, User
from app.schemas import UserCreate, UserOut, UserUpdate
from app.security.deps import CSRF_DOC, AdminUser, DbSession
from app.security.passwords import hash_password

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(
    _: AdminUser,
    db: DbSession,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at).limit(limit).offset(offset)))


@router.post(
    "", response_model=UserOut, status_code=status.HTTP_201_CREATED, dependencies=[CSRF_DOC]
)
def create_user(payload: UserCreate, request: Request, admin: AdminUser, db: DbSession) -> User:
    email = str(payload.email).lower()
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="A user with this email already exists")

    user = User(email=email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.flush()  # assigns user.id
    record(
        db,
        "user.created",
        user_id=admin.id,
        object_type="user",
        object_id=str(user.id),
        ip=client_ip(request),
        details={"email": email, "role": payload.role.value},
    )
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut, dependencies=[CSRF_DOC])
def update_user(
    user_id: uuid.UUID, payload: UserUpdate, request: Request, admin: AdminUser, db: DbSession
) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    removes_own_admin = user.id == admin.id and (
        (payload.role is not None and payload.role != Role.ADMIN) or payload.is_active is False
    )
    if removes_own_admin:
        # Prevents an admin from accidentally locking everyone out of administration.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot remove your own admin access or deactivate yourself",
        )

    changes: dict[str, Any] = {}
    if payload.role is not None and payload.role != user.role:
        changes["role"] = {"from": user.role.value, "to": payload.role.value}
        user.role = payload.role
    if payload.is_active is not None and payload.is_active != user.is_active:
        changes["is_active"] = {"from": user.is_active, "to": payload.is_active}
        user.is_active = payload.is_active
    if payload.unlock:
        user.locked_until = None
        user.failed_logins = 0
        changes["unlocked"] = True

    if "role" in changes or "is_active" in changes:
        user.token_version += 1  # existing sessions must log in again with the new permissions

    if changes:
        record(
            db,
            "user.updated",
            user_id=admin.id,
            object_type="user",
            object_id=str(user.id),
            ip=client_ip(request),
            details=changes,
        )
    db.commit()
    return user
