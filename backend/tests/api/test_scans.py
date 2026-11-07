"""API tests for starting, following and cancelling scans."""

import uuid
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, Job, JobState, Link, LinkResult, Page, Role, Scan, ScanStatus, Target, User

Csrf = Callable[[TestClient], dict[str, str]]


@pytest.fixture
def target(db_session: Session, create_user: Callable[..., User]) -> Target:
    owner = create_user(role=Role.ADMIN, email="owner@sentinelqa.io")
    juice = Target(name="Juice Shop", base_url="http://juice-shop:3000/", host="juice-shop", is_lab=True, created_by=owner.id)
    db_session.add(juice)
    db_session.commit()
    return juice


def start(client: TestClient, csrf: Csrf, target_id: uuid.UUID, **body: object):  # type: ignore[no-untyped-def]
    return client.post("/api/scans", json={"target_id": str(target_id), **body}, headers=csrf(client))


def test_tester_queues_a_crawl_and_a_job_is_created(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target, db_session: Session
) -> None:
    login_as(Role.TESTER)
    response = start(client, csrf, target.id)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "queued"
    assert body["type"] == "crawl"
    assert body["progress_pct"] == 0
    assert body["config"]["max_pages"] == 50  # defaults were applied
    assert "logout" in body["config"]["exclude_patterns"]

    job = db_session.scalars(select(Job)).one()
    assert str(job.scan_id) == body["id"]
    assert job.state is JobState.PENDING
    assert db_session.scalars(select(AuditLog.action).where(AuditLog.action == "scan.created")).one()


def test_viewer_cannot_start_scans(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target
) -> None:
    login_as(Role.VIEWER)
    assert start(client, csrf, target.id).status_code == 403


def test_scan_requires_csrf_and_login(client: TestClient, target: Target) -> None:
    assert client.post("/api/scans", json={"target_id": str(target.id)}).status_code == 403  # no CSRF
    client.get("/api/auth/csrf")
    token = client.cookies.get("sqa_csrf")
    response = client.post("/api/scans", json={"target_id": str(target.id)}, headers={"X-CSRF-Token": token})
    assert response.status_code == 401  # CSRF ok, but not logged in


def test_unknown_target_returns_404(client: TestClient, login_as: Callable[[Role], User], csrf: Csrf) -> None:
    login_as(Role.TESTER)
    assert start(client, csrf, uuid.uuid4()).status_code == 404


@pytest.mark.parametrize("scan_type", ["qa", "security", "full"])
def test_later_phase_scan_types_are_refused_honestly(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target, scan_type: str
) -> None:
    login_as(Role.TESTER)
    response = start(client, csrf, target.id, type=scan_type)
    assert response.status_code == 400
    assert "not available yet" in response.json()["detail"]


@pytest.mark.parametrize(
    "options",
    [
        {"max_pages": 0},
        {"max_pages": 501},
        {"max_depth": 11},
        {"max_duration_s": 5},
        {"timeout_s": 60},
        {"delay_ms": -1},
        {"exclude_patterns": ["x"] * 21},
        {"exclude_patterns": [""]},
        {"follow_external_links": True},  # unknown option: rejected, not ignored
    ],
)
def test_out_of_bounds_options_are_rejected(
    client: TestClient,
    login_as: Callable[[Role], User],
    csrf: Csrf,
    target: Target,
    options: dict[str, object],
) -> None:
    login_as(Role.TESTER)
    assert start(client, csrf, target.id, options=options).status_code == 422


def test_target_that_no_longer_passes_the_guard_is_refused(
    client: TestClient,
    login_as: Callable[[Role], User],
    csrf: Csrf,
    target: Target,
    fake_dns: dict[str, list[str]],
    db_session: Session,
) -> None:
    fake_dns["juice-shop"] = ["169.254.169.254"]  # DNS changed after the target was registered
    login_as(Role.TESTER)
    response = start(client, csrf, target.id)
    assert response.status_code == 400
    assert db_session.scalars(select(Scan)).all() == []
    assert db_session.scalars(select(AuditLog.action).where(AuditLog.action == "scan.rejected")).one()


def test_active_scan_limit_per_user(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target
) -> None:
    login_as(Role.TESTER)
    codes = [start(client, csrf, target.id).status_code for _ in range(4)]
    assert codes == [202, 202, 202, 409]


def test_cancel_queued_scan_also_retires_its_job(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target, db_session: Session
) -> None:
    login_as(Role.TESTER)
    scan_id = start(client, csrf, target.id).json()["id"]
    response = client.post(f"/api/scans/{scan_id}/cancel", headers=csrf(client))
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert response.json()["finished_at"] is not None
    assert db_session.scalars(select(Job)).one().state is JobState.DONE

    again = client.post(f"/api/scans/{scan_id}/cancel", headers=csrf(client))
    assert again.status_code == 409


def test_list_and_filter_scans(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target
) -> None:
    login_as(Role.TESTER)
    first = start(client, csrf, target.id).json()["id"]
    start(client, csrf, target.id)
    client.post(f"/api/scans/{first}/cancel", headers=csrf(client))

    assert len(client.get("/api/scans").json()) == 2
    cancelled = client.get("/api/scans", params={"status": "cancelled"}).json()
    assert [scan["id"] for scan in cancelled] == [first]
    assert client.get("/api/scans", params={"target_id": str(uuid.uuid4())}).json() == []


def test_detail_summary_and_result_endpoints(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target, db_session: Session
) -> None:
    login_as(Role.TESTER)
    scan_id = uuid.UUID(start(client, csrf, target.id).json()["id"])
    db_session.add_all(
        [
            Page(scan_id=scan_id, url="http://juice-shop:3000/", status_code=200, response_ms=100, depth=0,
                 title="Home", meta={}, a11y_issues=[{"type": "missing_alt"}, {"type": "missing_label"}]),
            Page(scan_id=scan_id, url="http://juice-shop:3000/x", status_code=500, response_ms=300, depth=1,
                 meta={}, a11y_issues=[]),
            Link(scan_id=scan_id, source_url="http://juice-shop:3000/", target_url="http://juice-shop:3000/x",
                 internal=True, status_code=500, redirect_chain=[], result=LinkResult.BROKEN, detail="HTTP 500"),
            Link(scan_id=scan_id, source_url="http://juice-shop:3000/", target_url="https://other.example/",
                 internal=False, status_code=None, redirect_chain=[], result=LinkResult.OUT_OF_SCOPE),
        ]
    )
    db_session.commit()

    summary = client.get(f"/api/scans/{scan_id}").json()["summary"]
    assert summary["pages"] == 2
    assert summary["http_error_pages"] == 1
    assert summary["avg_response_ms"] == 200
    assert summary["max_response_ms"] == 300
    assert summary["links_total"] == 2
    assert summary["links_by_result"] == {"ok": 0, "broken": 1, "redirect_issue": 0, "out_of_scope": 1, "timeout": 0}
    assert summary["accessibility_issues"] == 2

    assert [page["depth"] for page in client.get(f"/api/scans/{scan_id}/pages").json()] == [0, 1]
    broken = client.get(f"/api/scans/{scan_id}/links", params={"result": "broken"}).json()
    assert len(broken) == 1 and broken[0]["detail"] == "HTTP 500"
    external = client.get(f"/api/scans/{scan_id}/links", params={"internal": "false"}).json()
    assert [link["target_url"] for link in external] == ["https://other.example/"]


def test_viewer_can_read_results_and_missing_scan_is_404(
    client: TestClient, login_as: Callable[[Role], User]
) -> None:
    login_as(Role.VIEWER)
    missing = uuid.uuid4()
    for path in ("", "/pages", "/links"):
        assert client.get(f"/api/scans/{missing}{path}").status_code == 404


def test_scan_state_after_worker_finishes_is_reported(
    client: TestClient, login_as: Callable[[Role], User], csrf: Csrf, target: Target, db_session: Session
) -> None:
    login_as(Role.TESTER)
    scan_id = start(client, csrf, target.id).json()["id"]
    scan = db_session.get(Scan, uuid.UUID(scan_id))
    assert scan is not None
    scan.status = ScanStatus.COMPLETED
    scan.progress_pct = 100
    db_session.commit()
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "completed"
    assert client.post(f"/api/scans/{scan_id}/cancel", headers=csrf(client)).status_code == 409
