"""Website crawler and link checker (Module A).

How a crawl works:

Phase 1, pages (progress 0-70%)
    Start at the target's base URL (plus paths listed in robots.txt), fetch
    each page, record status, response time, title, metadata and
    accessibility indicators, and collect every link on it. In-scope page
    links are queued breadth-first until max_depth / max_pages is reached.

Phase 2, links (progress 70-100%)
    Check each unique link target once. Out-of-scope and excluded links are
    recorded but NEVER requested. Results are reused from Phase 1 when the
    page was already fetched.

Safety properties:
    - Every request goes through before_request(), which re-runs the target
      guard (DNS can change during a scan).
    - Redirects are followed hop by hop; a hop that leaves the scope is
      reported and not followed.
    - Limits on pages, depth, duration, link checks and a delay between
      requests keep the load on the target small.
"""

import re
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

from worker.scanner.fetcher import Fetcher, FetchError, FetchResponse
from worker.scanner.html import decode_body, parse_html
from worker.scanner.scope import Scope

# Link result values (identical to app.models.LinkResult).
OK = "ok"
BROKEN = "broken"
REDIRECT_ISSUE = "redirect_issue"
OUT_OF_SCOPE = "out_of_scope"
TIMEOUT = "timeout"

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 5
LONG_REDIRECT_CHAIN = 3
PAGE_TAGS = frozenset({"a", "area", "iframe"})  # links that lead to other pages
MAX_LINK_ROWS = 5000
MAX_DISCOVERED_FROM_ROBOTS = 200
SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)


@dataclass(frozen=True)
class CrawlLimits:
    max_pages: int = 50
    max_depth: int = 3
    max_duration_s: float = 300
    delay_ms: int = 100
    max_links: int = 500
    use_robots: bool = True


@dataclass
class FetchOutcome:
    final_url: str
    response: FetchResponse | None
    redirect_chain: list[dict[str, Any]]
    total_ms: int | None
    result: str
    detail: str | None

    @property
    def status_code(self) -> int | None:
        return self.response.status_code if self.response is not None else None


@dataclass
class PageRecord:
    url: str
    status_code: int | None
    response_ms: int | None
    depth: int
    title: str | None
    meta: dict[str, Any]
    a11y_issues: list[dict[str, Any]]


@dataclass
class LinkRecord:
    source_url: str
    target_url: str
    internal: bool
    status_code: int | None
    redirect_chain: list[dict[str, Any]]
    result: str
    detail: str | None


@dataclass
class CrawlResult:
    pages: int = 0
    links: list[LinkRecord] = field(default_factory=list)
    requests: int = 0
    stop_reason: str = "completed"  # completed | cancelled | max_pages | max_duration
    notes: list[str] = field(default_factory=list)


class Crawler:
    def __init__(
        self,
        fetcher: Fetcher,
        scope: Scope,
        limits: CrawlLimits,
        *,
        before_request: Callable[[], None] = lambda: None,
        should_stop: Callable[[], bool] = lambda: False,
        on_page: Callable[[PageRecord], None] = lambda page: None,
        on_progress: Callable[[int], None] = lambda percent: None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetcher = fetcher
        self._scope = scope
        self._limits = limits
        self._before_request = before_request
        self._should_stop = should_stop
        self._on_page = on_page
        self._on_progress = on_progress
        self._sleep = sleep
        self._clock = clock
        self._requests = 0
        self._outcomes: dict[str, FetchOutcome] = {}
        self._deadline = 0.0

    # ------------------------------------------------------------ requests

    def _request(self, url: str, *, read_body: bool) -> FetchResponse:
        if self._requests and self._limits.delay_ms:
            self._sleep(self._limits.delay_ms / 1000)
        self._before_request()  # may raise: the target no longer passes the guard
        self._requests += 1
        return self._fetcher.fetch(url, read_body=read_body)

    def _fetch(self, url: str, *, read_body: bool) -> FetchOutcome:
        """GET a URL, following in-scope redirects one hop at a time."""
        chain: list[dict[str, Any]] = []
        visited = {url}
        current = url
        total_ms = 0

        def outcome(response: FetchResponse | None, result: str, detail: str | None) -> FetchOutcome:
            return FetchOutcome(current, response, chain, total_ms if response else None, result, detail)

        while True:
            try:
                response = self._request(current, read_body=read_body)
            except FetchError as error:
                return outcome(None, TIMEOUT if error.kind == "timeout" else BROKEN, error.message)
            total_ms += response.elapsed_ms

            if response.status_code not in REDIRECT_STATUSES:
                if response.status_code >= 400:
                    return outcome(response, BROKEN, f"HTTP {response.status_code}")
                if len(chain) >= LONG_REDIRECT_CHAIN:
                    return outcome(response, REDIRECT_ISSUE, f"Long redirect chain ({len(chain)} redirects)")
                return outcome(response, OK, None)

            location = response.headers.get("location", "").strip()
            next_url = self._scope.normalize(urljoin(current, location)) if location else None
            chain.append({"url": current, "status": response.status_code, "location": next_url or location})

            if not location:
                return outcome(response, REDIRECT_ISSUE, "Redirect without a Location header")
            if next_url is None:
                return outcome(response, REDIRECT_ISSUE, "Redirect to an unsupported URL")
            if current.startswith("https://") and next_url.startswith("http://"):
                return outcome(response, REDIRECT_ISSUE, "Redirect downgrades HTTPS to HTTP")
            if not self._scope.in_scope(next_url):
                return outcome(response, REDIRECT_ISSUE, "Redirects outside the authorized target (not followed)")
            if next_url in visited:
                return outcome(response, REDIRECT_ISSUE, "Redirect loop")
            if len(chain) >= MAX_REDIRECTS:
                return outcome(response, REDIRECT_ISSUE, f"More than {MAX_REDIRECTS} redirects")
            visited.add(next_url)
            current = next_url

    # ------------------------------------------------------------ discovery

    def _discover_from_robots(self, notes: list[str]) -> list[str]:
        """Paths listed in robots.txt and sitemaps are discovery hints for an authorized test."""
        robots = self._fetch(self._scope.origin + "/robots.txt", read_body=True)
        response = robots.response
        if response is None or robots.result != OK:
            return []

        found: list[str] = []
        sitemaps: list[str] = []
        for line in decode_body(response.body, response.content_type).splitlines()[:1000]:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.split("#", 1)[0].strip()
            if key in ("allow", "disallow") and value.startswith("/") and not any(c in value for c in "*$"):
                found.append(self._scope.origin + value)
            elif key == "sitemap" and value:
                sitemaps.append(value)

        for sitemap_url in sitemaps[:3]:
            normalized = self._scope.normalize(urljoin(self._scope.origin + "/", sitemap_url))
            if normalized is None or not self._scope.in_scope(normalized):
                continue
            sitemap = self._fetch(normalized, read_body=True)
            if sitemap.response is not None and sitemap.result == OK:
                text = decode_body(sitemap.response.body, sitemap.response.content_type)
                found.extend(SITEMAP_LOC.findall(text)[:MAX_DISCOVERED_FROM_ROBOTS])

        accepted: list[str] = []
        for url in found:
            normalized = self._scope.normalize(url)
            if (
                normalized
                and normalized not in accepted
                and self._scope.in_scope(normalized)
                and not self._scope.excluded(normalized)
            ):
                accepted.append(normalized)
        accepted = accepted[:MAX_DISCOVERED_FROM_ROBOTS]
        if accepted:
            notes.append(f"robots.txt / sitemap: {len(accepted)} URL(s) added to the crawl")
        return accepted

    # ------------------------------------------------------------ main loop

    def _limits_reached(self, result: CrawlResult) -> bool:
        if self._should_stop():
            result.stop_reason = "cancelled"
            return True
        if self._clock() > self._deadline:
            result.stop_reason = "max_duration"
            result.notes.append(f"Stopped after the time limit of {self._limits.max_duration_s:g} seconds")
            return True
        return False

    def run(self) -> CrawlResult:
        result = CrawlResult()
        self._deadline = self._clock() + self._limits.max_duration_s
        start_url = self._scope.normalize(self._scope.start_url) or self._scope.start_url

        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        queued = {start_url}
        if self._limits.use_robots:
            for url in self._discover_from_robots(result.notes):
                if url not in queued:
                    queue.append((url, 1))
                    queued.add(url)

        # (page the link is on, link target) in discovery order
        occurrences: dict[tuple[str, str], None] = {}

        while queue:
            if self._limits_reached(result):
                break
            if result.pages >= self._limits.max_pages:
                result.stop_reason = "max_pages"
                result.notes.append(
                    f"Stopped at the page limit ({self._limits.max_pages}); "
                    f"{len(queue)} discovered page(s) were not visited"
                )
                break

            url, depth = queue.popleft()
            fetched = self._fetch(url, read_body=True)
            self._outcomes[url] = fetched
            self._outcomes.setdefault(fetched.final_url, fetched)
            queued.add(fetched.final_url)
            result.pages += 1

            response = fetched.response
            meta: dict[str, Any] = {}
            title = None
            issues: list[dict[str, Any]] = []
            if response is not None:
                meta["content_type"] = response.content_type[:100]
            if fetched.final_url != url:
                meta["final_url"] = fetched.final_url
            if fetched.result != OK:
                meta["problem"] = fetched.detail

            if response is not None and 200 <= response.status_code < 300 and response.is_html:
                analysis = parse_html(response.body, response.content_type)
                title = analysis.title
                issues = analysis.a11y_issues
                meta.update(analysis.meta)
                if analysis.lang:
                    meta["lang"] = analysis.lang
                base = urljoin(fetched.final_url, analysis.base_href) if analysis.base_href else fetched.final_url

                for link in analysis.links:
                    target = self._scope.normalize(urljoin(base, link.url))
                    if target is None:
                        continue  # mailto:, tel:, javascript:, data: ...
                    if len(occurrences) < MAX_LINK_ROWS:
                        occurrences.setdefault((fetched.final_url, target), None)
                    if (
                        link.tag in PAGE_TAGS
                        and depth < self._limits.max_depth
                        and target not in queued
                        and self._scope.in_scope(target)
                        and not self._scope.excluded(target)
                    ):
                        queue.append((target, depth + 1))
                        queued.add(target)

            self._on_page(
                PageRecord(
                    url=url,
                    status_code=fetched.status_code,
                    response_ms=fetched.total_ms,
                    depth=depth,
                    title=title,
                    meta=meta,
                    a11y_issues=issues,
                )
            )
            self._on_progress(min(70, 70 * result.pages // self._limits.max_pages))

        if result.stop_reason != "cancelled":
            result.links = self._check_links(list(occurrences), result)
        result.requests = self._requests
        return result

    def _check_links(self, occurrences: list[tuple[str, str]], result: CrawlResult) -> list[LinkRecord]:
        targets = list(dict.fromkeys(target for _, target in occurrences))
        verdicts: dict[str, FetchOutcome] = {}
        new_checks = 0
        unchecked = 0

        for index, target in enumerate(targets):
            if self._limits_reached(result):
                break
            if not self._scope.in_scope(target):
                verdicts[target] = FetchOutcome(
                    target, None, [], None, OUT_OF_SCOPE, "Outside the authorized target; not requested"
                )
            elif self._scope.excluded(target):
                verdicts[target] = FetchOutcome(
                    target, None, [], None, OUT_OF_SCOPE, "Excluded by the scan configuration; not requested"
                )
            elif target in self._outcomes:
                verdicts[target] = self._outcomes[target]
            elif new_checks >= self._limits.max_links:
                unchecked += 1
                continue
            else:
                verdicts[target] = self._outcomes[target] = self._fetch(target, read_body=False)
                new_checks += 1
            self._on_progress(70 + 30 * (index + 1) // len(targets))

        if unchecked:
            result.notes.append(f"Link check limit ({self._limits.max_links}) reached; {unchecked} link(s) not checked")

        return [
            LinkRecord(
                source_url=source,
                target_url=target,
                internal=self._scope.in_scope(target),
                status_code=verdicts[target].status_code,
                redirect_chain=verdicts[target].redirect_chain,
                result=verdicts[target].result,
                detail=verdicts[target].detail,
            )
            for source, target in occurrences
            if target in verdicts
        ]
