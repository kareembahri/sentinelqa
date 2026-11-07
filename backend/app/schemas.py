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

from app.models import LinkResult, Role, ScanStatus, ScanType

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


# ---------------------------------------------------------------- scans

DEFAULT_EXCLUDE_PATTERNS = ["logout", "signout", "sign-out", "delete"]

ExcludePattern = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]


class CrawlOptions(StrictModel):
    """Limits for a crawl. The upper bounds are enforced server-side and cannot be raised by clients."""

    max_pages: int = Field(50, ge=1, le=500, description="Pages to fetch and analyse")
    max_depth: int = Field(3, ge=0, le=10, description="Clicks away from the start page")
    max_duration_s: int = Field(300, ge=10, le=1800, description="Hard time limit for the whole scan")
    timeout_s: int = Field(10, ge=1, le=30, description="Timeout for a single request")
    delay_ms: int = Field(100, ge=0, le=5000, description="Pause between requests")
    max_links: int = Field(500, ge=1, le=2000, description="Extra link targets to check")
    use_robots: bool = Field(True, description="Use robots.txt and sitemaps to discover pages")
    exclude_patterns: list[ExcludePattern] = Field(
        default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS),
        max_length=20,
        description="URLs containing any of these texts are never requested",
    )


class ScanCreate(StrictModel):
    target_id: uuid.UUID
    type: ScanType = ScanType.CRAWL
    options: CrawlOptions = Field(default_factory=CrawlOptions)


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_id: uuid.UUID
    started_by: uuid.UUID
    type: ScanType
    status: ScanStatus
    progress_pct: int
    config: dict[str, Any]
    error_message: str | None
    notes: list[str] | None
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanSummary(BaseModel):
    pages: int
    http_error_pages: int
    avg_response_ms: int | None
    max_response_ms: int | None
    links_total: int
    links_by_result: dict[str, int]
    accessibility_issues: int


class ScanDetail(ScanOut):
    summary: ScanSummary


class PageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    url: str
    status_code: int | None
    response_ms: int | None
    depth: int
    title: str | None
    meta: dict[str, Any]
    a11y_issues: list[Any]


class LinkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_url: str
    target_url: str
    internal: bool
    status_code: int | None
    redirect_chain: list[Any]
    result: LinkResult
    detail: str | None
