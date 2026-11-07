"""Unit tests for the crawler, using an in-memory fake website."""

import pytest

from tests.fakes import BASE, FakeFetcher, FakePage, html, juice_like_site, redirect
from worker.scanner.crawler import CrawlLimits, Crawler, CrawlResult, PageRecord
from worker.scanner.scope import Scope

FAST = CrawlLimits(delay_ms=0)


def crawl(
    pages: dict[str, FakePage],
    limits: CrawlLimits = FAST,
    exclude: tuple[str, ...] = ("logout",),
    **kwargs: object,
) -> tuple[CrawlResult, list[PageRecord], FakeFetcher]:
    fetcher = FakeFetcher(pages)
    recorded: list[PageRecord] = []
    crawler = Crawler(
        fetcher,
        Scope.from_base_url(f"{BASE}/", exclude),
        limits,
        on_page=recorded.append,
        **kwargs,  # type: ignore[arg-type]
    )
    return crawler.run(), recorded, fetcher


def link_results(result: CrawlResult) -> dict[str, str]:
    return {link.target_url.removeprefix(BASE): link.result for link in result.links}


# ---------------------------------------------------------------- safety


def test_never_requests_out_of_scope_or_excluded_urls() -> None:
    result, _, fetcher = crawl(juice_like_site())
    assert all(url.startswith(BASE) for url in fetcher.requests)
    assert f"{BASE}/logout" not in fetcher.requests
    results = link_results(result)
    assert result.links and results["https://external.example/".removeprefix(BASE)] == "out_of_scope"
    assert results["/logout"] == "out_of_scope"


def test_redirect_to_another_site_is_reported_and_not_followed() -> None:
    site = {
        f"{BASE}/": FakePage(body=html('<a href="/go">go</a>')),
        f"{BASE}/go": redirect("http://169.254.169.254/latest/meta-data/"),
    }
    result, _, fetcher = crawl(site, CrawlLimits(delay_ms=0, use_robots=False))
    assert not any("169.254" in url for url in fetcher.requests)
    link = next(link for link in result.links if link.target_url.endswith("/go"))
    assert link.result == "redirect_issue"
    assert "outside the authorized target" in (link.detail or "")


def test_before_request_runs_before_every_request() -> None:
    calls: list[int] = []
    result, _, fetcher = crawl(juice_like_site(), before_request=lambda: calls.append(1))
    assert len(calls) == len(fetcher.requests) == result.requests


def test_guard_failure_stops_the_crawl() -> None:
    class GuardError(Exception):
        pass

    def guard() -> None:
        raise GuardError("DNS now points to a blocked range")

    with pytest.raises(GuardError):
        crawl(juice_like_site(), before_request=guard)


def test_delay_between_requests() -> None:
    sleeps: list[float] = []
    result, _, _ = crawl(juice_like_site(), CrawlLimits(delay_ms=250), sleep=sleeps.append)
    assert sleeps and all(s == 0.25 for s in sleeps)
    assert len(sleeps) == result.requests - 1  # no delay before the first request


# ---------------------------------------------------------------- findings


def test_finds_broken_links_redirects_and_resources() -> None:
    result, _, _ = crawl(juice_like_site())
    results = link_results(result)
    assert results["/missing"] == "broken"
    assert results["/about"] == "ok"
    assert results["/old-about"] == "ok"  # a single redirect is fine
    assert results["/logo.png"] == "ok"
    assert results["/banner.png"] == "ok"
    assert results["/main.js"] == "ok"
    missing = next(link for link in result.links if link.target_url.endswith("/missing"))
    assert missing.status_code == 404
    assert missing.detail == "HTTP 404"
    assert missing.source_url == f"{BASE}/"


def test_mailto_and_fragment_links_are_ignored() -> None:
    result, _, _ = crawl(juice_like_site())
    assert not any("mailto" in link.target_url for link in result.links)
    assert not any("#" in link.target_url for link in result.links)


def test_pages_record_status_time_title_and_accessibility() -> None:
    _, pages, _ = crawl(juice_like_site())
    home = next(page for page in pages if page.url == f"{BASE}/")
    assert home.status_code == 200
    assert home.title == "OWASP Juice Shop"
    assert home.response_ms == 12
    assert home.depth == 0
    types = sorted(issue["type"] for issue in home.a11y_issues)
    assert types == ["empty_button", "missing_alt", "missing_label"]


def test_robots_txt_paths_are_discovered_and_wildcards_ignored() -> None:
    result, pages, fetcher = crawl(juice_like_site())
    assert f"{BASE}/ftp" in [page.url for page in pages]
    assert not any("*" in url for url in fetcher.requests)
    assert link_results(result)["/ftp/backup.bak"] == "broken"  # 403
    assert link_results(result)["/ftp/legal.md"] == "ok"
    assert any("robots.txt" in note for note in result.notes)


def test_robots_discovery_can_be_disabled() -> None:
    _, pages, fetcher = crawl(juice_like_site(), CrawlLimits(delay_ms=0, use_robots=False))
    assert f"{BASE}/robots.txt" not in fetcher.requests
    assert f"{BASE}/ftp" not in [page.url for page in pages]


def test_redirected_page_records_final_url() -> None:
    site = {
        f"{BASE}/": redirect("/home"),
        f"{BASE}/home": FakePage(body=html("hello", title="Home")),
    }
    _, pages, _ = crawl(site, CrawlLimits(delay_ms=0, use_robots=False))
    assert pages[0].meta["final_url"] == f"{BASE}/home"
    assert pages[0].title == "Home"


def test_error_pages_are_recorded_with_their_status() -> None:
    site = {f"{BASE}/": FakePage(status=500, body="<h1>Server error</h1>")}
    _, pages, _ = crawl(site, CrawlLimits(delay_ms=0, use_robots=False))
    assert pages[0].status_code == 500
    assert pages[0].meta["problem"] == "HTTP 500"
    assert pages[0].a11y_issues == []  # error pages are not analysed


@pytest.mark.parametrize(
    ("site", "expected_detail"),
    [
        ({"/a": redirect("/b"), "/b": redirect("/a")}, "Redirect loop"),
        (
            {"/a": redirect("/b"), "/b": redirect("/c"), "/c": redirect("/d"), "/d": FakePage(body="x")},
            "Long redirect chain (3 redirects)",
        ),
        ({f"/{i}": redirect(f"/{i + 1}") for i in range(10)}, "More than 5 redirects"),
        ({"/a": FakePage(status=302)}, "Redirect without a Location header"),
    ],
)
def test_redirect_problems(site: dict[str, FakePage], expected_detail: str) -> None:
    first = next(iter(site))
    pages = {BASE + path: page for path, page in site.items()}
    pages[f"{BASE}/"] = FakePage(body=html(f'<a href="{first}">start</a>'))
    result, _, _ = crawl(pages, CrawlLimits(delay_ms=0, use_robots=False, max_depth=0))
    link = next(link for link in result.links if link.target_url == BASE + first)
    assert link.result == "redirect_issue"
    assert link.detail == expected_detail
    assert link.redirect_chain


def test_https_to_http_downgrade_is_reported() -> None:
    secure = "https://juice-shop"
    fetcher = FakeFetcher(
        {
            f"{secure}/": FakePage(body=html('<a href="/login">login</a>')),
            f"{secure}/login": redirect("http://juice-shop/login"),
        }
    )
    result = Crawler(fetcher, Scope.from_base_url(f"{secure}/"), CrawlLimits(delay_ms=0, use_robots=False)).run()
    assert result.links[0].detail == "Redirect downgrades HTTPS to HTTP"
    assert "http://juice-shop/login" not in fetcher.requests


@pytest.mark.parametrize(("error", "expected"), [("timeout", "timeout"), ("connection", "broken")])
def test_network_errors_become_link_results(error: str, expected: str) -> None:
    site = {
        f"{BASE}/": FakePage(body=html('<a href="/slow">slow</a>')),
        f"{BASE}/slow": FakePage(error=error),
    }
    result, _, _ = crawl(site, CrawlLimits(delay_ms=0, use_robots=False))
    assert link_results(result)["/slow"] == expected


def test_same_target_is_checked_only_once() -> None:
    site = {
        f"{BASE}/": FakePage(body=html('<a href="/a">a</a><a href="/b">b</a><img src="/x.png" alt="x">')),
        f"{BASE}/a": FakePage(body=html('<img src="/x.png" alt="x">')),
        f"{BASE}/b": FakePage(body=html('<img src="/x.png" alt="x">')),
        f"{BASE}/x.png": FakePage(content_type="image/png"),
    }
    result, _, fetcher = crawl(site, CrawlLimits(delay_ms=0, use_robots=False))
    assert fetcher.requests.count(f"{BASE}/x.png") == 1
    assert sum(1 for link in result.links if link.target_url.endswith("/x.png")) == 3  # one row per page


# ---------------------------------------------------------------- limits


def test_max_depth() -> None:
    _, pages, _ = crawl(juice_like_site(), CrawlLimits(delay_ms=0, max_depth=1, use_robots=False))
    assert {page.depth for page in pages} == {0, 1}
    assert f"{BASE}/deep/1" not in [page.url for page in pages]


def test_max_pages() -> None:
    result, pages, _ = crawl(juice_like_site(), CrawlLimits(delay_ms=0, max_pages=2))
    assert len(pages) == 2
    assert result.stop_reason == "max_pages"
    assert any("page limit" in note for note in result.notes)


def test_max_links_limits_new_checks() -> None:
    result, _, _ = crawl(juice_like_site(), CrawlLimits(delay_ms=0, max_links=1, max_depth=0, use_robots=False))
    assert any("Link check limit" in note for note in result.notes)


def test_time_limit_stops_the_crawl() -> None:
    ticks = iter(range(0, 10_000, 100))  # every call to the clock is 100 s later
    result, _, _ = crawl(juice_like_site(), CrawlLimits(delay_ms=0, max_duration_s=250), clock=lambda: next(ticks))
    assert result.stop_reason == "max_duration"


def test_cancellation_stops_before_checking_links() -> None:
    checks = iter([False, False, True, True, True])
    result, pages, _ = crawl(juice_like_site(), should_stop=lambda: next(checks, True))
    assert result.stop_reason == "cancelled"
    assert len(pages) == 2
    assert result.links == []


def test_progress_reaches_100_and_never_goes_backwards() -> None:
    seen: list[int] = []
    crawl(juice_like_site(), on_progress=seen.append)
    assert seen[-1] == 100
    assert seen == sorted(seen)
