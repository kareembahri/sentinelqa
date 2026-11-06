"""Integration tests: the models work against a real (SQLite) database."""

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from app.models import (
    Finding,
    FindingStatus,
    Role,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
    Confidence,
    Target,
    User,
)

EXPECTED_TABLES = {
    "users",
    "targets",
    "scans",
    "jobs",
    "pages",
    "links",
    "test_cases",
    "test_results",
    "findings",
    "ai_insights",
    "reports",
    "audit_logs",
}


def make_user(session: Session, email: str = "tester@example.com") -> User:
    user = User(email=email, password_hash="not-a-real-hash", role=Role.TESTER)
    session.add(user)
    session.flush()
    return user


def test_all_tables_from_the_architecture_exist(engine: Engine) -> None:
    assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES


def test_new_user_gets_safe_defaults(db_session: Session) -> None:
    user = User(email="new@example.com", password_hash="x")
    db_session.add(user)
    db_session.commit()
    assert user.role is Role.VIEWER  # least privilege by default
    assert user.is_active is True
    assert user.failed_logins == 0


def test_enum_is_stored_as_its_value(db_session: Session) -> None:
    make_user(db_session)
    db_session.commit()
    stored = db_session.execute(text("SELECT role FROM users")).scalar_one()
    assert stored == "tester"


def test_duplicate_email_is_rejected(db_session: Session) -> None:
    make_user(db_session, "same@example.com")
    db_session.commit()
    db_session.add(User(email="same@example.com", password_hash="x"))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_invalid_enum_value_is_rejected(db_session: Session) -> None:
    db_session.add(User(email="bad@example.com", password_hash="x", role="superuser"))
    with pytest.raises((StatementError, LookupError)):
        db_session.commit()


def test_scan_and_finding_defaults(db_session: Session) -> None:
    user = make_user(db_session)
    target = Target(
        name="Juice Shop",
        base_url="http://juice-shop:3000",
        host="juice-shop",
        is_lab=True,
        created_by=user.id,
    )
    db_session.add(target)
    db_session.flush()

    scan = Scan(target_id=target.id, started_by=user.id, type=ScanType.SECURITY)
    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        source="header_check",
        title="Missing Content-Security-Policy header",
        category="security_headers",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        evidence={"header": "Content-Security-Policy", "present": False},
    )
    db_session.add(finding)
    db_session.commit()

    assert scan.status is ScanStatus.QUEUED
    assert scan.progress_pct == 0
    # A finding is never confirmed automatically just by being created.
    assert finding.status is FindingStatus.SUSPECTED
    assert finding.evidence["present"] is False
