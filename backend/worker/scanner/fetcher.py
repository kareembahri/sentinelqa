"""The interface between the crawler and the network.

The crawler never talks to the network directly. It asks a Fetcher for one
URL at a time. In production that is HttpxFetcher (http_fetcher.py); in tests
it is a fake website held in memory. This keeps the crawl logic testable
without any real HTTP traffic.

Rules every Fetcher follows:
- It never follows redirects itself. The crawler follows them one hop at a
  time so it can check each hop against the authorized scope.
- It reads at most a fixed number of body bytes.
- Network problems are raised as FetchError, never as library-specific errors.
"""

from dataclasses import dataclass
from typing import Literal, Protocol

FetchErrorKind = Literal["timeout", "connection", "invalid"]


@dataclass(frozen=True)
class FetchResponse:
    url: str
    status_code: int
    headers: dict[str, str]  # header names in lower case
    body: bytes
    elapsed_ms: int

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type or "application/xhtml+xml" in self.content_type


class FetchError(Exception):
    def __init__(self, kind: FetchErrorKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


class Fetcher(Protocol):
    def fetch(self, url: str, *, read_body: bool) -> FetchResponse:
        """Send one GET request, without following redirects."""
        ...
