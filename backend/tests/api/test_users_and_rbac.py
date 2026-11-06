"""API tests for user management and role-based access control."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Role, User

Csrf = Callable[[TestClient], dict[str, str]]


@pytest.mark.parametrize("role", [Role.VIEWER, Role.TESTER])
def test_non_admins_cannot_list_users_and_the_attempt_is_audited(
    client: TestClient, login_as: Callable[[Role], User], db_session: Session, role: Role
) -> None:
    user = login_as(role)
    response = client.get("/api/users")
    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions"}

    denied = db_session.scalars(select(AuditLog).where(AuditLog.action == "authz.denied")).all()
    assert len(denied) == 1
    assert denied[0].user_id == user.id
    assert denied[0].details["path"] == "/api/users"


def test_unauthenticated_requests_get_401_not_403(client: TestClient) -> None:
    assert client.get("/api/users").status_code == 401


def test_admin_can_create_and_list_users(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf
) -> None:
    login_as(Role.ADMIN)
    response = client.post(
        "/api/users",
        json={"email": "New.Tester@SentinelQA.io", "password": "A-long-enough-pass-1", "role": "tester"},
        headers=csrf(client),
    )
    assert response.status_code == 201
    assert response.json()["email"] == "new.tester@sentinelqa.io"
    assert response.json()["role"] == "tester"

    emails = [u["email"] for u in client.get("/api/users").json()]
    assert "new.tester@sentinelqa.io" in emails


def test_new_users_default_to_viewer(client: TestClient, login_as: Callable[[Role], User], csrf: Csrf) -> None:
    login_as(Role.ADMIN)
    response = client.post(
        "/api/users",
        json={"email": "default@sentinelqa.io", "password": "A-long-enough-pass-1"},
        headers=csrf(client),
    )
    assert response.json()["role"] == "viewer"


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "weak@sentinelqa.io", "password": "short"},
        {"email": "weak@sentinelqa.io", "password": "x" * 129},
        {"email": "not-an-email", "password": "A-long-enough-pass-1"},
        {"email": "x@sentinelqa.io", "password": "A-long-enough-pass-1", "role": "superuser"},
        {"email": "x@sentinelqa.io", "password": "A-long-enough-pass-1", "is_admin": True},
    ],
)
def test_invalid_user_payloads_are_rejected(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, payload: dict[str, object]
) -> None:
    login_as(Role.ADMIN)
    assert client.post("/api/users", json=payload, headers=csrf(client)).status_code == 422


def test_duplicate_email_returns_409(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf
) -> None:
    admin = login_as(Role.ADMIN)
    response = client.post(
        "/api/users",
        json={"email": admin.email, "password": "A-long-enough-pass-1"},
        headers=csrf(client),
    )
    assert response.status_code == 409


def test_admin_cannot_demote_or_deactivate_themselves(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf
) -> None:
    admin = login_as(Role.ADMIN)
    for payload in ({"role": "viewer"}, {"is_active": False}):
        response = client.patch(f"/api/users/{admin.id}", json=payload, headers=csrf(client))
        assert response.status_code == 400


def test_role_change_is_audited_and_ends_old_sessions(
    client: TestClient,
    new_client: Callable[[], TestClient],
    create_user: Callable[..., User],
    login_as: Callable[[Role], User],
    login: Callable[..., object],
    csrf: Csrf,
    db_session: Session,
) -> None:
    viewer = create_user(role=Role.VIEWER)
    viewer_browser = new_client()
    login(viewer_browser, viewer.email)
    assert viewer_browser.get("/api/auth/me").status_code == 200

    login_as(Role.ADMIN)
    response = client.patch(f"/api/users/{viewer.id}", json={"role": "tester"}, headers=csrf(client))
    assert response.status_code == 200
    assert response.json()["role"] == "tester"

    assert viewer_browser.get("/api/auth/me").status_code == 401  # must log in again
    entry = db_session.scalars(select(AuditLog).where(AuditLog.action == "user.updated")).one()
    assert entry.details["role"] == {"from": "viewer", "to": "tester"}


def test_admin_can_unlock_a_locked_account(
    client: TestClient, login_as: Callable[[Role], User], create_user: Callable[..., User], csrf: Csrf
) -> None:
    from datetime import UTC, datetime, timedelta

    locked = create_user(locked_until=datetime.now(UTC) + timedelta(minutes=10), failed_logins=0)
    login_as(Role.ADMIN)
    response = client.patch(f"/api/users/{locked.id}", json={"unlock": True}, headers=csrf(client))
    assert response.status_code == 200
    assert response.json()["locked_until"] is None


def test_patch_unknown_user_returns_404(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf
) -> None:
    login_as(Role.ADMIN)
    response = client.patch(
        "/api/users/00000000-0000-0000-0000-000000000000", json={"unlock": True}, headers=csrf(client)
    )
    assert response.status_code == 404


def test_audit_log_is_admin_only(client: TestClient, login_as: Callable[[Role], User]) -> None:
    login_as(Role.TESTER)
    assert client.get("/api/audit").status_code == 403


def test_admin_can_read_and_filter_the_audit_log(
    client: TestClient, login_as: Callable[[Role], User]
) -> None:
    login_as(Role.ADMIN)
    entries = client.get("/api/audit", params={"action": "auth.login.success"}).json()
    assert len(entries) == 1
    assert entries[0]["action"] == "auth.login.success"
