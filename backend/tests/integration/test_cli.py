"""Integration tests for the create-admin command."""

from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app import cli
from app.models import AuditLog, Role, User
from app.security.passwords import verify_password


@pytest.fixture
def cli_engine(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Engine:
    monkeypatch.setattr(cli, "get_engine", lambda: engine)
    return engine


def answers(monkeypatch: pytest.MonkeyPatch, *values: str) -> None:
    replies: Iterator[str] = iter(values)
    monkeypatch.setattr(cli, "getpass", lambda prompt="": next(replies))


def test_create_admin_stores_a_hashed_password_and_audits(
    cli_engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers(monkeypatch, "A-very-good-password-1", "A-very-good-password-1")
    assert cli.main(["create-admin", "--email", "Kareem@SentinelQA.io"]) == 0

    with Session(cli_engine) as db:
        user = db.scalars(select(User)).one()
        assert user.email == "kareem@sentinelqa.io"
        assert user.role is Role.ADMIN
        assert user.password_hash != "A-very-good-password-1"
        assert verify_password(user.password_hash, "A-very-good-password-1")
        assert db.scalars(select(AuditLog.action)).one() == "user.created"
    assert "A-very-good-password-1" not in capsys.readouterr().out


def test_mismatched_passwords_create_nothing(cli_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    answers(monkeypatch, "A-very-good-password-1", "A-different-password-2")
    assert cli.main(["create-admin", "--email", "a@sentinelqa.io"]) == 1
    with Session(cli_engine) as db:
        assert db.scalars(select(User)).all() == []


def test_weak_password_is_refused_without_echoing_it(
    cli_engine: Engine, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answers(monkeypatch, "short1", "short1")
    assert cli.main(["create-admin", "--email", "a@sentinelqa.io"]) == 1
    errors = capsys.readouterr().err
    assert "password" in errors
    assert "short1" not in errors


def test_duplicate_admin_email_is_refused(cli_engine: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    answers(monkeypatch, *["A-very-good-password-1"] * 4)
    assert cli.main(["create-admin", "--email", "a@sentinelqa.io"]) == 0
    assert cli.main(["create-admin", "--email", "a@sentinelqa.io"]) == 1
