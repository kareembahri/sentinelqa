"""API tests for /api/health and the response headers every endpoint sends."""

from collections.abc import Iterator
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.db import get_db
from app.main import app as fastapi_app


def test_health_reports_ok_when_database_is_reachable(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


class BrokenSession:
    """Stands in for a database session whose connection is down."""

    def execute(self, *args: Any, **kwargs: Any) -> None:
        raise OperationalError("SELECT 1", {}, Exception("connection refused to 10.0.0.5"))


def test_health_reports_503_without_leaking_details_when_database_is_down() -> None:
    def broken_db() -> Iterator[BrokenSession]:
        yield BrokenSession()

    fastapi_app.dependency_overrides[get_db] = broken_db
    try:
        with TestClient(fastapi_app) as test_client:
            response = test_client.get("/api/health")
    finally:
        fastapi_app.dependency_overrides.clear()

    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"
    # The internal error text must not reach the client.
    assert "10.0.0.5" not in response.text
    assert "connection refused" not in response.text


def test_security_headers_are_present(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_every_response_has_a_request_id(client: TestClient) -> None:
    first = client.get("/api/health").headers["X-Request-ID"]
    second = client.get("/api/health").headers["X-Request-ID"]
    assert len(first) == 32
    assert first != second


def test_unknown_route_returns_404_json(client: TestClient) -> None:
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
