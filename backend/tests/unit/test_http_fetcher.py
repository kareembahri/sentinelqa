"""Unit tests for the real HTTP fetcher, using httpx's mock transport (no network)."""

import httpx
import pytest

from worker.scanner.fetcher import FetchError
from worker.scanner.http_fetcher import USER_AGENT, HttpxFetcher


def fetcher_for(handler) -> HttpxFetcher:  # type: ignore[no-untyped-def]
    return HttpxFetcher(5, max_body_bytes=1000, transport=httpx.MockTransport(handler))


def test_does_not_follow_redirects() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/"})

    with fetcher_for(handler) as fetcher:
        response = fetcher.fetch("http://juice-shop:3000/", read_body=True)
    assert response.status_code == 302
    assert response.headers["location"] == "http://169.254.169.254/"
    assert seen == ["http://juice-shop:3000/"]


def test_sends_an_honest_user_agent() -> None:
    agents: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        agents.append(request.headers["user-agent"])
        return httpx.Response(200)

    with fetcher_for(handler) as fetcher:
        fetcher.fetch("http://juice-shop:3000/", read_body=False)
    assert agents == [USER_AGENT]


def test_body_is_limited_and_optional() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 5000, headers={"Content-Type": "text/html"})

    with fetcher_for(handler) as fetcher:
        full = fetcher.fetch("http://juice-shop:3000/", read_body=True)
        skipped = fetcher.fetch("http://juice-shop:3000/", read_body=False)
    assert len(full.body) == 1000
    assert skipped.body == b""
    assert full.is_html
    assert full.elapsed_ms >= 0


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (httpx.ConnectTimeout("slow"), "timeout"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.ConnectError("refused"), "connection"),
        (httpx.RemoteProtocolError("garbage"), "connection"),
    ],
)
def test_network_errors_become_fetch_errors(error: Exception, kind: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    with fetcher_for(handler) as fetcher, pytest.raises(FetchError) as caught:
        fetcher.fetch("http://juice-shop:3000/", read_body=True)
    assert caught.value.kind == kind
