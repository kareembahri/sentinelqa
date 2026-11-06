"""Request and response models.

Every request body is validated here before any code touches it:
types, lengths and allowed values. `extra="forbid"` rejects unknown fields,
so a client cannot sneak in something like {"role": "admin"} where it does
not belong (mass assignment).
"""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.models import Role

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128  # long enough for passphrases, short enough to stop hashing DoS

Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- auth


class LoginRequest(StrictModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class CsrfOut(BaseModel):
    csrf_token: str


# ---------------------------------------------------------------- users


class UserCreate(StrictModel):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    role: Role = Role.VIEWER


class UserUpdate(StrictModel):
    role: Role | None = None
    is_active: bool | None = None
    unlock: bool = False


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: Role
    is_active: bool
    locked_until: datetime | None
    created_at: datetime


# ---------------------------------------------------------------- targets


class TargetCreate(StrictModel):
    name: Name
    base_url: str = Field(min_length=1, max_length=2048, examples=["http://juice-shop:3000"])
    is_lab: bool = False


class TargetUpdate(StrictModel):
    name: Name | None = None
    is_lab: bool | None = None


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    base_url: str
    host: str
    is_lab: bool
    created_by: uuid.UUID
    created_at: datetime


# ---------------------------------------------------------------- audit


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: uuid.UUID | None
    action: str
    object_type: str | None
    object_id: str | None
    ip: str | None
    details: dict[str, Any]
    created_at: datetime
