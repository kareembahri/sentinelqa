"""Shared test fixtures.

Tests run against an in-memory SQLite database, so they are fast and never
touch your real PostgreSQL data. Environment variables are set *before* the
app is imported, because the app reads its settings at import time.
"""

import os

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-1234567890"
os.environ["ALLOWED_TARGET_HOSTS"] = "juice-shop,localhost"
os.environ["ALLOWED_PRIVATE_LAB_HOSTS"] = "juice-shop"

from collections.abc import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.models  # noqa: E402,F401  (registers tables)
from app.db import Base, get_db  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402


@pytest.fixture
def engine() -> Iterator[Engine]:
    # StaticPool keeps one connection, so every session sees the same in-memory DB.
    test_engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(test_engine)
    yield test_engine
    test_engine.dispose()


@pytest.fixture
def db_session(engine: Engine) -> Iterator[Session]:
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    def override_get_db() -> Iterator[Session]:
        yield db_session

    fastapi_app.dependency_overrides[get_db] = override_get_db
    with TestClient(fastapi_app) as test_client:
        yield test_client
    fastapi_app.dependency_overrides.clear()
