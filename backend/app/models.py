"""Database tables for SentinelQA (see docs/ARCHITECTURE.md, section 6).

Design notes:
- Primary keys are random UUIDs, so IDs in URLs cannot be guessed or counted.
- Enums are stored as plain strings (native_enum=False). This works the same on
  PostgreSQL and SQLite and makes adding a new value a simple change.
- JSON columns become JSONB on PostgreSQL (indexable) and JSON elsewhere.
- Credentials for target logins are never stored here: `auth_profile_ref`
  only names environment variables that hold them.
"""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base

JSONType = JSON().with_variant(JSONB(), "postgresql")
# SQLite only auto-increments INTEGER primary keys.
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(UTC)


def _enum(enum_cls: type[enum.Enum], name: str) -> SAEnum:
    """Store the enum's *value* (e.g. 'admin') as a string column."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        length=32,
        validate_strings=True,
        values_callable=lambda members: [member.value for member in members],
    )


# ---------------------------------------------------------------- enums


class Role(enum.StrEnum):
    ADMIN = "admin"
    TESTER = "tester"
    VIEWER = "viewer"


class ScanType(enum.StrEnum):
    CRAWL = "crawl"
    QA = "qa"
    SECURITY = "security"
    FULL = "full"


class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobState(enum.StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DONE = "done"
    FAILED = "failed"


class LinkResult(enum.StrEnum):
    OK = "ok"
    BROKEN = "broken"
    REDIRECT_ISSUE = "redirect_issue"
    OUT_OF_SCOPE = "out_of_scope"
    TIMEOUT = "timeout"


class TestKind(enum.StrEnum):
    __test__ = False  # tell pytest this is not a test class

    POSITIVE = "positive"
    NEGATIVE = "negative"
    BOUNDARY = "boundary"
    EDGE = "edge"


class TestOrigin(enum.StrEnum):
    __test__ = False

    BUILTIN = "builtin"
    AI_DRAFT = "ai_draft"
    USER = "user"


class TestOutcome(enum.StrEnum):
    __test__ = False

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


class Severity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(enum.StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(enum.StrEnum):
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    INFORMATIONAL = "informational"
    FALSE_POSITIVE = "false_positive"


class InsightKind(enum.StrEnum):
    SUMMARY = "summary"
    EXPLANATION = "explanation"
    ROOT_CAUSE = "root_cause"
    REMEDIATION = "remediation"
    DRAFT_TESTS = "draft_tests"
    MISSING_SCENARIOS = "missing_scenarios"


class ReportFormat(enum.StrEnum):
    PDF = "pdf"
    HTML = "html"
    JSON = "json"


# ---------------------------------------------------------------- tables


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(_enum(Role, "user_role"), default=Role.VIEWER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100))
    base_url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(253), index=True)
    is_lab: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    auth_profile_ref: Mapped[dict[str, Any] | None] = mapped_column(JSONType)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="RESTRICT"), index=True
    )
    started_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    type: Mapped[ScanType] = mapped_column(_enum(ScanType, "scan_type"))
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, index=True
    )
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str | None] = mapped_column(String(1000))
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), unique=True
    )
    state: Mapped[JobState] = mapped_column(
        _enum(JobState, "job_state"), default=JobState.PENDING, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    worker_id: Mapped[str | None] = mapped_column(String(100))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Page(Base):
    __tablename__ = "pages"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_ms: Mapped[int | None] = mapped_column(Integer)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str | None] = mapped_column(String(500))
    meta: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    a11y_issues: Mapped[list[Any]] = mapped_column(JSONType, default=list)


class Link(Base):
    __tablename__ = "links"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    source_url: Mapped[str] = mapped_column(Text)
    target_url: Mapped[str] = mapped_column(Text)
    internal: Mapped[bool] = mapped_column(Boolean)
    status_code: Mapped[int | None] = mapped_column(Integer)
    redirect_chain: Mapped[list[Any]] = mapped_column(JSONType, default=list)
    result: Mapped[LinkResult] = mapped_column(_enum(LinkResult, "link_result"))


class TestCase(Base):
    __tablename__ = "test_cases"
    __test__ = False

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(200), unique=True)
    module: Mapped[str] = mapped_column(String(50))
    kind: Mapped[TestKind] = mapped_column(_enum(TestKind, "test_kind"))
    description: Mapped[str] = mapped_column(Text)
    origin: Mapped[TestOrigin] = mapped_column(
        _enum(TestOrigin, "test_origin"), default=TestOrigin.BUILTIN
    )


class TestResult(Base):
    __tablename__ = "test_results"
    __test__ = False

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    test_case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("test_cases.id", ondelete="RESTRICT")
    )
    # No default on purpose: an outcome must always come from a real test run.
    outcome: Mapped[TestOutcome] = mapped_column(_enum(TestOutcome, "test_outcome"))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    failure_message: Mapped[str | None] = mapped_column(Text)
    screenshot_path: Mapped[str | None] = mapped_column(String(500))
    trace_path: Mapped[str | None] = mapped_column(String(500))
    diagnostics: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(100))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), index=True)
    confidence: Mapped[Confidence] = mapped_column(_enum(Confidence, "confidence"))
    # Every finding starts as "suspected"; confirmation is a separate, audited step.
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"), default=FindingStatus.SUSPECTED, index=True
    )
    url: Mapped[str | None] = mapped_column(Text)
    parameter: Mapped[str | None] = mapped_column(String(200))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    reproduction_steps: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    verification_guidance: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(String(20))
    owasp_category: Mapped[str | None] = mapped_column(String(100))
    verified_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AIInsight(Base):
    """AI output lives in its own table so it can never be mistaken for scanner evidence."""

    __tablename__ = "ai_insights"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE")
    )
    kind: Mapped[InsightKind] = mapped_column(_enum(InsightKind, "insight_kind"))
    content: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    format: Mapped[ReportFormat] = mapped_column(_enum(ReportFormat, "report_format"))
    file_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    # Nullable: failed logins for unknown emails have no user.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(100), index=True)
    object_type: Mapped[str | None] = mapped_column(String(50))
    object_id: Mapped[str | None] = mapped_column(String(100))
    ip: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
