"""API tests for scan targets: authorization rules and the target guard."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Role, Scan, ScanType, User

Csrf = Callable[[TestClient], dict[str, str]]
JUICE_SHOP = {"name": "Juice Shop", "base_url": "http://juice-shop:3000", "is_lab": True}


def test_admin_can_register_juice_shop_as_lab_target(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, db_session: Session
) -> None:
    login_as(Role.ADMIN)
    response = client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["host"] == "juice-shop"
    assert body["base_url"] == "http://juice-shop:3000/"
    assert body["is_lab"] is True

    created = db_session.scalars(select(AuditLog).where(AuditLog.action == "target.created")).one()
    assert created.details["addresses"] == ["172.18.0.5"]


def test_tester_can_add_target_but_not_mark_it_as_lab(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf
) -> None:
    login_as(Role.TESTER)
    as_lab = client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client))
    assert as_lab.status_code == 403

    not_lab = client.post("/api/targets", json={**JUICE_SHOP, "is_lab": False}, headers=csrf(client))
    assert not_lab.status_code == 201


def test_viewer_cannot_add_targets(client: TestClient, login_as: Callable[[Role], User], csrf: Csrf) -> None:
    login_as(Role.VIEWER)
    assert client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client)).status_code == 403


@pytest.mark.parametrize(
    "base_url",
    [
        "http://evil.example.com/",
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8000/",
        "file:///etc/passwd",
        "http://admin:pw@juice-shop:3000/",
    ],
)
def test_unauthorized_or_dangerous_urls_are_refused_and_audited(
    client: TestClient,
    login_as: Callable[[Role], User],
    csrf: Csrf,
    db_session: Session,
    base_url: str,
) -> None:
    login_as(Role.ADMIN)
    response = client.post(
        "/api/targets", json={"name": "Bad", "base_url": base_url, "is_lab": False}, headers=csrf(client)
    )
    assert response.status_code == 400
    rejected = db_session.scalars(select(AuditLog).where(AuditLog.action == "target.rejected")).all()
    assert len(rejected) == 1


def test_dns_pointing_to_metadata_service_is_refused(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, fake_dns: dict[str, list[str]]
) -> None:
    fake_dns["juice-shop"] = ["169.254.169.254"]
    login_as(Role.ADMIN)
    response = client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client))
    assert response.status_code == 400
    assert "blocked" in response.json()["detail"]


def test_target_name_is_validated(client: TestClient, login_as: Callable[[Role], User], csrf: Csrf) -> None:
    login_as(Role.ADMIN)
    for name in ("", "   ", "x" * 101):
        response = client.post("/api/targets", json={**JUICE_SHOP, "name": name}, headers=csrf(client))
        assert response.status_code == 422


def test_viewer_can_list_and_read_targets(
    client: TestClient,
    new_client: Callable[[], TestClient],
    create_user: Callable[..., User],
    login_as: Callable[[Role], User],
    login: Callable[..., object],
    csrf: Csrf,
) -> None:
    login_as(Role.ADMIN)
    target_id = client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client)).json()["id"]

    viewer_browser = new_client()
    login(viewer_browser, create_user(role=Role.VIEWER).email)
    assert len(viewer_browser.get("/api/targets").json()) == 1
    assert viewer_browser.get(f"/api/targets/{target_id}").json()["name"] == "Juice Shop"


def test_tester_cannot_turn_a_target_into_a_lab_target(
    client: TestClient,
    new_client: Callable[[], TestClient],
    create_user: Callable[..., User],
    login_as: Callable[[Role], User],
    login: Callable[..., object],
    csrf: Csrf,
) -> None:
    login_as(Role.TESTER)
    target_id = client.post(
        "/api/targets", json={**JUICE_SHOP, "is_lab": False}, headers=csrf(client)
    ).json()["id"]

    assert client.patch(f"/api/targets/{target_id}", json={"is_lab": True}, headers=csrf(client)).status_code == 403
    renamed = client.patch(f"/api/targets/{target_id}", json={"name": "Shop"}, headers=csrf(client))
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "Shop"

    admin_browser = new_client()
    login(admin_browser, create_user(role=Role.ADMIN).email)
    promoted = admin_browser.patch(
        f"/api/targets/{target_id}", json={"is_lab": True}, headers=csrf(admin_browser)
    )
    assert promoted.status_code == 200
    assert promoted.json()["is_lab"] is True


def test_only_admins_delete_and_scan_history_is_protected(
    client: TestClient,
    new_client: Callable[[], TestClient],
    create_user: Callable[..., User],
    login_as: Callable[[Role], User],
    login: Callable[..., object],
    csrf: Csrf,
    db_session: Session,
) -> None:
    admin = login_as(Role.ADMIN)
    first = client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client)).json()["id"]
    second = client.post("/api/targets", json=JUICE_SHOP, headers=csrf(client)).json()["id"]

    tester_browser = new_client()
    login(tester_browser, create_user(role=Role.TESTER).email)
    assert tester_browser.delete(f"/api/targets/{first}", headers=csrf(tester_browser)).status_code == 403

    import uuid

    db_session.add(Scan(target_id=uuid.UUID(second), started_by=admin.id, type=ScanType.CRAWL))
    db_session.commit()

    assert client.delete(f"/api/targets/{first}", headers=csrf(client)).status_code == 204
    assert client.delete(f"/api/targets/{second}", headers=csrf(client)).status_code == 409
    assert client.get(f"/api/targets/{first}").status_code == 404
