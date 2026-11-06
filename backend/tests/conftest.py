"""Shared test fixtures.

Tests run against an in-memory SQLite database, so they are fast and never
touch your real PostgreSQL data. Environment variables are set *before* the
app is imported, because the app reads its settings at import time.
"""

import os

os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-that-is-long-enough-1234567890"
os.environ["ALLOWED_TARGET_HOSTS"] = "juice-shop,localhost,public.sentinelqa.io"
os.environ["ALLOWED_PRIVATE_LAB_HOSTS"] = "juice-shop"

from collections.abc import Callable, Iterator  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.engine import Engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.models  # noqa: E402,F401  (registers tables)
from app.db import Base, get_db  # noqa: E402
from app.main import app as fastapi_app  # noqa: E402
from app.models import Role, User  # noqa: E402
from app.security import target_guard  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402
from app.security.rate_limit import limiter  # noqa: E402
from app.security.tokens import CSRF_COOKIE, CSRF_HEADER  # noqa: E402

DEFAULT_PASSWORD = "Correct-Horse-Battery-9"

# What the fake DNS answers in tests. Juice Shop lives on a private Docker network.
FAKE_DNS = {
    "juice-shop": ["172.18.0.5"],
    "localhost": ["127.0.0.1"],
    "public.sentinelqa.io": ["93.184.215.14"],
}


@pytest.fixture(autouse=True)
def _reset_rate_limits() -> Iterator[None]:
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """No test ever performs a real DNS lookup. Tests may edit this mapping."""
    answers = {host: list(ips) for host, ips in FAKE_DNS.items()}

    def resolve(host: str, port: int) -> list[str]:
        if host not in answers:
            raise target_guard.TargetValidationError("Target host could not be resolved")
        return answers[host]

    monkeypatch.setattr(target_guard, "resolve_host", resolve)
    return answers


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


@pytest.fixture
def new_client(client: TestClient) -> Iterator[Callable[[], TestClient]]:
    """A second browser: same app and database, separate cookies."""
    extra: list[TestClient] = []

    def make() -> TestClient:
        other = TestClient(fastapi_app)
        extra.append(other)
        return other

    yield make
    for other in extra:
        other.close()


@pytest.fixture
def create_user(db_session: Session) -> Callable[..., User]:
    counter = {"n": 0}

    def make(
        role: Role = Role.TESTER,
        email: str | None = None,
        password: str = DEFAULT_PASSWORD,
        **fields: object,
    ) -> User:
        counter["n"] += 1
        user = User(
            email=email or f"{role.value}{counter['n']}@sentinelqa.io",
            password_hash=hash_password(password),
            role=role,
            **fields,
        )
        db_session.add(user)
        db_session.commit()
        return user

    return make


def csrf_headers(test_client: TestClient) -> dict[str, str]:
    token = test_client.cookies.get(CSRF_COOKIE)
    if token is None:
        token = test_client.get("/api/auth/csrf").json()["csrf_token"]
    return {CSRF_HEADER: token}


def do_login(test_client: TestClient, email: str, password: str = DEFAULT_PASSWORD) -> httpx.Response:
    return test_client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers=csrf_headers(test_client),
    )


@pytest.fixture
def csrf() -> Callable[[TestClient], dict[str, str]]:
    return csrf_headers


@pytest.fixture
def login() -> Callable[..., httpx.Response]:
    return do_login


@pytest.fixture
def login_as(client: TestClient, create_user: Callable[..., User]) -> Callable[[Role], User]:
    """Create a user with the given role and log the main client in as them."""

    def make(role: Role) -> User:
        user = create_user(role=role)
        response = do_login(client, user.email)
        assert response.status_code == 200, response.text
        return user

    return make
