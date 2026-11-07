"""The development docs page fills in the CSRF header automatically."""

from fastapi.testclient import TestClient


def test_docs_page_is_served_with_csrf_interceptor(client: TestClient) -> None:
    response = client.get("/docs")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    page = response.text
    assert "requestInterceptor" in page
    assert "sqa_csrf" in page and "X-CSRF-Token" in page
    assert "swagger-ui-dist@5.17.14" in page  # pinned version, not "latest"
    # The docs page loads Swagger UI from a CDN, so it must not get the API's strict CSP.
    assert "default-src 'none'" not in response.headers.get("content-security-policy", "")


def test_api_schema_is_still_available(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert "/api/scans" in schema["paths"]
    assert "/docs" not in schema["paths"]


def test_csrf_is_still_enforced_for_other_clients(client: TestClient) -> None:
    # The convenience lives only in the docs page's JavaScript. The server still requires the header.
    assert client.post("/api/auth/login", json={"email": "a@sentinelqa.io", "password": "x"}).status_code == 403
