"""Crawl scope: which URLs belong to the authorized target.

A URL is in scope only if it has the same scheme, host and port as the
target's base URL, and its path is under the base path. Anything else is
recorded as "out of scope" and is never requested, so the crawler cannot
wander onto other websites, even through redirects.
"""

from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


def _netloc(host: str, port: int, scheme: str) -> str:
    display = f"[{host}]" if ":" in host else host
    return display if port == DEFAULT_PORTS[scheme] else f"{display}:{port}"


@dataclass(frozen=True)
class Scope:
    scheme: str
    host: str
    port: int
    start_path: str
    base_path: str  # always ends with "/"
    exclude_patterns: tuple[str, ...] = field(default=())

    @classmethod
    def from_base_url(cls, base_url: str, exclude_patterns: tuple[str, ...] = ()) -> "Scope":
        parts = urlsplit(base_url)
        scheme = parts.scheme.lower()
        if scheme not in DEFAULT_PORTS or not parts.hostname:
            raise ValueError("Base URL must be an absolute http(s) URL")
        path = parts.path or "/"
        base_path = path if path.endswith("/") else path + "/"
        return cls(
            scheme=scheme,
            host=parts.hostname,
            port=parts.port or DEFAULT_PORTS[scheme],
            start_path=path,
            base_path=base_path,
            exclude_patterns=tuple(p.lower() for p in exclude_patterns if p),
        )

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{_netloc(self.host, self.port, self.scheme)}"

    @property
    def start_url(self) -> str:
        return self.origin + self.start_path

    def normalize(self, url: str) -> str | None:
        """Canonical form used for de-duplication, or None if it is not a usable http(s) URL.

        Removes the #fragment (it never reaches the server), user:password@
        credentials, and default ports; lower-cases scheme and host.
        """
        try:
            parts = urlsplit(url.strip())
            port = parts.port
        except ValueError:
            return None
        scheme = parts.scheme.lower()
        host = parts.hostname
        if scheme not in DEFAULT_PORTS or not host:
            return None
        netloc = _netloc(host, port or DEFAULT_PORTS[scheme], scheme)
        return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))

    def in_scope(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            return False
        scheme = parts.scheme.lower()
        if scheme != self.scheme or parts.hostname != self.host:
            return False
        if (port or DEFAULT_PORTS.get(scheme)) != self.port:
            return False
        path = parts.path or "/"
        return path.startswith(self.base_path) or path == self.base_path.rstrip("/")

    def excluded(self, url: str) -> bool:
        """True if the URL matches a configured exclusion such as 'logout'."""
        lowered = url.lower()
        return any(pattern in lowered for pattern in self.exclude_patterns)
