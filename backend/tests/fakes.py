"""A fake website for crawler and worker tests. No real network traffic is ever made."""

from dataclasses import dataclass, field

from worker.scanner.fetcher import FetchError, FetchResponse

BASE = "http://juice-shop:3000"


@dataclass
class FakePage:
    status: int = 200
    body: str = ""
    content_type: str = "text/html; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)
    error: str | None = None  # "timeout" or "connection" to simulate network failures
    elapsed_ms: int = 12


def html(body: str, *, title: str = "Page", lang: str = "en") -> str:
    return (
        f'<!doctype html><html lang="{lang}"><head><title>{title}</title>'
        '<meta name="viewport" content="width=device-width"></head>'
        f"<body>{body}</body></html>"
    )


def redirect(location: str, status: int = 301) -> FakePage:
    return FakePage(status=status, body="", headers={"location": location})


class FakeFetcher:
    def __init__(self, pages: dict[str, FakePage]) -> None:
        self.pages = pages
        self.requests: list[str] = []
        self.closed = False

    def fetch(self, url: str, *, read_body: bool) -> FetchResponse:
        self.requests.append(url)
        page = self.pages.get(url, FakePage(status=404, body="<h1>Not found</h1>"))
        if page.error:
            raise FetchError(page.error, "Request timed out" if page.error == "timeout" else "Connection failed")
        headers = {"content-type": page.content_type, **{k.lower(): v for k, v in page.headers.items()}}
        return FetchResponse(
            url=url,
            status_code=page.status,
            headers=headers,
            body=page.body.encode() if read_body else b"",
            elapsed_ms=page.elapsed_ms,
        )

    def close(self) -> None:
        self.closed = True


def juice_like_site() -> dict[str, FakePage]:
    """A small site with the kinds of problems the scanner must find."""
    return {
        f"{BASE}/robots.txt": FakePage(body="User-agent: *\nDisallow: /ftp\nDisallow: /*.bak$\n", content_type="text/plain"),
        f"{BASE}/": FakePage(
            body=html(
                '<a href="/about">About</a>'
                '<a href="/missing">Old page</a>'
                '<a href="https://external.example/">Partner</a>'
                '<a href="/logout">Log out</a>'
                '<a href="/old-about">Moved</a>'
                '<a href="mailto:help@juice.shop">Mail</a>'
                '<a href="#top">Top</a>'
                '<img src="/logo.png" alt="Juice Shop">'
                '<img src="/banner.png">'
                '<script src="/main.js"></script>'
                '<form><input type="text" id="q"><button></button></form>',
                title="OWASP Juice Shop",
            )
        ),
        f"{BASE}/about": FakePage(body=html('<a href="/">Home</a><a href="/deep/1">More</a>', title="About")),
        f"{BASE}/old-about": redirect("/about"),
        f"{BASE}/deep/1": FakePage(body=html('<a href="/deep/2">Deeper</a>', title="Deep 1")),
        f"{BASE}/deep/2": FakePage(body=html('<a href="/deep/3">Deeper</a>', title="Deep 2")),
        f"{BASE}/logo.png": FakePage(content_type="image/png", body="PNG"),
        f"{BASE}/banner.png": FakePage(content_type="image/png", body="PNG"),
        f"{BASE}/main.js": FakePage(content_type="application/javascript", body="console.log(1)"),
        f"{BASE}/ftp": FakePage(
            body=html('<a href="/ftp/legal.md">legal.md</a><a href="/ftp/backup.bak">backup.bak</a>', title="listing /ftp")
        ),
        f"{BASE}/ftp/legal.md": FakePage(content_type="text/markdown", body="# Legal"),
        f"{BASE}/ftp/backup.bak": FakePage(status=403, body="Only .md and .pdf files are allowed!"),
    }
