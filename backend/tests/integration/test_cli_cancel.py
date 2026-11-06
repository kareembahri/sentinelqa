"""Cancelling the create-admin prompt must exit cleanly and create nothing."""

import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app import cli
from app.models import User


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, EOFError])
def test_cancel_at_password_prompt_exits_cleanly(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    interruption: type[BaseException],
) -> None:
    monkeypatch.setattr(cli, "get_engine", lambda: engine)

    def interrupted(prompt: str = "") -> str:
        raise interruption

    monkeypatch.setattr(cli, "getpass", interrupted)
    assert cli.main(["create-admin", "--email", "a@sentinelqa.io"]) == 130
    assert "Cancelled" in capsys.readouterr().err
    with Session(engine) as db:
        assert db.scalars(select(User)).all() == []
