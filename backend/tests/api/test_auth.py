"""API tests for login, logout, sessions, CSRF and rate limiting."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Role, User
from app.security.rate_limit import limiter
from app.security.tokens import CSRF_COOKIE, SESSION_COOKIE

Login = Callable[..., httpx.Response]
Csrf = Callable[[TestClient], dict[str, str]]


def session_cookie_header(response: httpx.Response) -> str:
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{SESSION_COOKIE}="):
            return header
    raise AssertionError("no session cookie was set")


def replace_cookie(test_client: TestClient, name: str, value: str) -> None:
    """Swap a cookie's value, the way an attacker would edit or replay it."""
    test_client.cookies.delete(name)
    test_client.cookies.set(name, value)


def actions(db: Session) -> list[str]:
    return list(db.scalars(select(AuditLog.action).order_by(AuditLog.id)))


# ---------------------------------------------------------------- login


def test_login_succeeds_and_sets_a_hardened_cookie(
    client: TestClient, create_user: Callable[..., User], login: Login, db_session: Session
) -> None:
    user = create_user(role=Role.TESTER)
    response = login(client, user.email)

    assert response.status_code == 200
    assert response.json()["email"] == user.email
    assert "password_hash" not in response.json()

    cookie = session_cookie_header(response).lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert "auth.login.success" in actions(db_session)


def test_email_is_case_insensitive(
    client: TestClient, create_user: Callable[..., User], login: Login
) -> None:
    create_user(email="mixed@sentinelqa.io")
    assert login(client, "MIXED@SentinelQA.io").status_code == 200


def test_wrong_password_and_unknown_email_look_identical(
    client: TestClient, create_user: Callable[..., User], login: Login, db_session: Session
) -> None:
    user = create_user()
    wrong_password = login(client, user.email, "Wrong-Password-000")
    unknown_email = login(client, "nobody@sentinelqa.io")

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json() == {"detail": "Invalid email or password"}
    assert SESSION_COOKIE not in wrong_password.headers.get("set-cookie", "")
    assert actions(db_session).count("auth.login.failed") == 2


def test_inactive_user_cannot_log_in(
    client: TestClient, create_user: Callable[..., User], login: Login
) -> None:
    user = create_user(is_active=False)
    response = login(client, user.email)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


def test_login_rejects_unknown_fields_and_bad_email(client: TestClient, csrf: Csrf) -> None:
    headers = csrf(client)
    extra = client.post(
        "/api/auth/login",
        json={"email": "a@sentinelqa.io", "password": "x", "role": "admin"},
        headers=headers,
    )
    bad_email = client.post(
        "/api/auth/login", json={"email": "not-an-email", "password": "x"}, headers=headers
    )
    too_long = client.post(
        "/api/auth/login", json={"email": "a@sentinelqa.io", "password": "x" * 129}, headers=headers
    )
    assert extra.status_code == bad_email.status_code == too_long.status_code == 422


# ---------------------------------------------------------------- brute force


def test_sixth_login_attempt_in_a_minute_is_rate_limited(
    client: TestClient, create_user: Callable[..., User], login: Login
) -> None:
    user = create_user()
    statuses = [login(client, user.email, "Wrong-Password-000").status_code for _ in range(6)]
    assert statuses == [401, 401, 401, 401, 401, 429]


def test_account_locks_after_five_failures_and_unlocks_after_timeout(
    client: TestClient, create_user: Callable[..., User], login: Login, db_session: Session
) -> None:
    user = create_user()
    for _ in range(5):
        login(client, user.email, "Wrong-Password-000")
    limiter.reset()  # isolate the account lockout from the per-IP rate limit

    locked = login(client, user.email)  # correct password, but the account is locked
    assert locked.status_code == 401
    assert "auth.account.locked" in actions(db_session)

    db_session.refresh(user)
    user.locked_until = datetime.now(UTC) - timedelta(seconds=1)  # pretend 15 minutes passed
    db_session.commit()
    assert login(client, user.email).status_code == 200


# ---------------------------------------------------------------- CSRF


def test_post_without_csrf_token_is_rejected(
    client: TestClient, create_user: Callable[..., User]
) -> None:
    user = create_user()
    response = client.post(
        "/api/auth/login", json={"email": user.email, "password": "Correct-Horse-Battery-9"}
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF token missing or invalid"}


def test_forged_csrf_token_is_rejected(client: TestClient, create_user: Callable[..., User]) -> None:
    user = create_user()
    replace_cookie(client, CSRF_COOKIE, "forged.token")
    response = client.post(
        "/api/auth/login",
        json={"email": user.email, "password": "Correct-Horse-Battery-9"},
        headers={"X-CSRF-Token": "forged.token"},
    )
    assert response.status_code == 403


def test_csrf_header_must_match_cookie(client: TestClient, create_user: Callable[..., User]) -> None:
    user = create_user()
    client.get("/api/auth/csrf")  # sets a real cookie
    other_token = TestClient(client.app).get("/api/auth/csrf").json()["csrf_token"]
    response = client.post(
        "/api/auth/login",
        json={"email": user.email, "password": "Correct-Horse-Battery-9"},
        headers={"X-CSRF-Token": other_token},
    )
    assert response.status_code == 403


def test_get_requests_do_not_need_csrf(client: TestClient) -> None:
    assert client.get("/api/health").status_code == 200


# ---------------------------------------------------------------- sessions


def test_me_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_the_logged_in_user(client: TestClient, login_as: Callable[[Role], User]) -> None:
    user = login_as(Role.VIEWER)
    body = client.get("/api/auth/me").json()
    assert body["id"] == str(user.id)
    assert body["role"] == "viewer"


def test_tampered_session_cookie_is_rejected(client: TestClient, login_as: Callable[[Role], User]) -> None:
    login_as(Role.TESTER)
    token = client.cookies.get(SESSION_COOKIE)
    assert token is not None
    replace_cookie(client, SESSION_COOKIE, token[:-3] + ("aaa" if not token.endswith("aaa") else "bbb"))
    assert client.get("/api/auth/me").status_code == 401


def test_logout_invalidates_even_a_stolen_copy_of_the_cookie(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, db_session: Session
) -> None:
    login_as(Role.TESTER)
    stolen = client.cookies.get(SESSION_COOKIE)
    assert stolen is not None

    assert client.post("/api/auth/logout", headers=csrf(client)).status_code == 204
    assert "auth.logout" in actions(db_session)

    replace_cookie(client, SESSION_COOKIE, stolen)  # attacker replays the old cookie
    assert client.get("/api/auth/me").status_code == 401


def test_deactivating_a_user_ends_their_session_immediately(
    client: TestClient,
    new_client: Callable[[], TestClient],
    create_user: Callable[..., User],
    login: Login,
    csrf: Csrf,
) -> None:
    tester = create_user(role=Role.TESTER)
    admin = create_user(role=Role.ADMIN)

    assert login(client, tester.email).status_code == 200
    admin_browser = new_client()
    assert login(admin_browser, admin.email).status_code == 200

    response = admin_browser.patch(
        f"/api/users/{tester.id}", json={"is_active": False}, headers=csrf(admin_browser)
    )
    assert response.status_code == 200
    assert client.get("/api/auth/me").status_code == 401
