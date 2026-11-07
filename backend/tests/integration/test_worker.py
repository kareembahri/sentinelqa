"""Integration tests: the worker claims jobs, runs crawls and stores honest results."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Job, JobState, Link, LinkResult, Page, Role, Scan, ScanStatus, ScanType, Target, User
from app.schemas import CrawlOptions
from tests.fakes import BASE, FakeFetcher, FakePage, juice_like_site
from worker.jobs import INTERNAL_ERROR, WORKER_STOPPED, claim_next_job, recover_stale_jobs, run_scan_job

FAST = CrawlOptions(delay_ms=0).model_dump()


@pytest.fixture
def owner(create_user: Callable[..., User]) -> User:
    return create_user(role=Role.TESTER)


@pytest.fixture
def target(db_session: Session, owner: User) -> Target:
    juice = Target(name="Juice Shop", base_url=f"{BASE}/", host="juice-shop", is_lab=True, created_by=owner.id)
    db_session.add(juice)
    db_session.commit()
    return juice


@pytest.fixture
def queue_scan(db_session: Session, target: Target, owner: User) -> Callable[..., tuple[Scan, Job]]:
    def make(config: dict[str, object] | None = None, queued_at: datetime | None = None) -> tuple[Scan, Job]:
        scan = Scan(
            target_id=target.id,
            started_by=owner.id,
            type=ScanType.CRAWL,
            config=config or FAST,
            queued_at=queued_at or datetime.now(UTC),
        )
        db_session.add(scan)
        db_session.flush()
        job = Job(scan_id=scan.id)
        db_session.add(job)
        db_session.commit()
        return scan, job

    return make


def run(db: Session, job: Job, fetcher: FakeFetcher, **kwargs: object) -> None:
    run_scan_job(db, job, get_settings(), lambda timeout: fetcher, **kwargs)  # type: ignore[arg-type]


# ---------------------------------------------------------------- queue


def test_claim_takes_the_oldest_pending_job_once(db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]) -> None:
    now = datetime.now(UTC)
    _, newer = queue_scan(queued_at=now)
    _, older = queue_scan(queued_at=now - timedelta(minutes=1))

    first = claim_next_job(db_session, "worker-a")
    second = claim_next_job(db_session, "worker-b")
    assert first is not None and first.id == older.id
    assert first.state is JobState.CLAIMED and first.worker_id == "worker-a" and first.attempts == 1
    assert second is not None and second.id == newer.id
    assert claim_next_job(db_session, "worker-c") is None


def test_stale_jobs_are_failed_not_left_running(db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]) -> None:
    scan, job = queue_scan()
    claim_next_job(db_session, "dead-worker")
    scan.status = ScanStatus.RUNNING
    job.heartbeat_at = datetime.now(UTC) - timedelta(minutes=10)
    db_session.commit()

    assert recover_stale_jobs(db_session) == 1
    assert job.state is JobState.FAILED
    assert scan.status is ScanStatus.FAILED
    assert "stopped unexpectedly" in (scan.error_message or "")


# ---------------------------------------------------------------- full runs


def test_full_crawl_is_stored_and_completed(db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]) -> None:
    scan, job = queue_scan()
    fetcher = FakeFetcher(juice_like_site())
    run(db_session, job, fetcher)

    assert scan.status is ScanStatus.COMPLETED
    assert scan.progress_pct == 100
    assert scan.started_at is not None and scan.finished_at is not None
    assert job.state is JobState.DONE
    assert fetcher.closed
    assert any("request(s) sent" in note for note in scan.notes or [])

    pages = db_session.scalars(select(Page).where(Page.scan_id == scan.id)).all()
    assert {page.url for page in pages} >= {f"{BASE}/", f"{BASE}/about", f"{BASE}/ftp"}
    results = {link.target_url: link.result for link in db_session.scalars(select(Link).where(Link.scan_id == scan.id))}
    assert results[f"{BASE}/missing"] is LinkResult.BROKEN
    assert results["https://external.example/"] is LinkResult.OUT_OF_SCOPE
    assert all(url.startswith(BASE) for url in fetcher.requests)


def test_target_failing_the_guard_fails_the_scan_without_any_request(
    db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]], fake_dns: dict[str, list[str]]
) -> None:
    scan, job = queue_scan()
    fake_dns["juice-shop"] = ["169.254.169.254"]
    fetcher = FakeFetcher(juice_like_site())
    run(db_session, job, fetcher)

    assert scan.status is ScanStatus.FAILED
    assert "authorization check" in (scan.error_message or "")
    assert fetcher.requests == []
    assert job.state is JobState.FAILED


def test_dns_change_during_the_scan_stops_it(
    db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]], fake_dns: dict[str, list[str]]
) -> None:
    scan, job = queue_scan()

    class RebindingFetcher(FakeFetcher):
        def fetch(self, url: str, *, read_body: bool):  # type: ignore[no-untyped-def]
            response = super().fetch(url, read_body=read_body)
            fake_dns["juice-shop"] = ["10.0.0.1", "169.254.169.254"]  # attacker flips DNS mid-scan
            return response

    fetcher = RebindingFetcher(juice_like_site())
    run(db_session, job, fetcher)
    assert scan.status is ScanStatus.FAILED
    assert "during the scan" in (scan.error_message or "")
    assert len(fetcher.requests) == 1


def test_unexpected_error_fails_the_scan_and_never_reports_success(
    db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]
) -> None:
    scan, job = queue_scan()

    class ExplodingFetcher(FakeFetcher):
        def fetch(self, url: str, *, read_body: bool):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

    run(db_session, job, ExplodingFetcher({}))
    assert scan.status is ScanStatus.FAILED
    assert scan.error_message == INTERNAL_ERROR  # generic message; details are in the worker log
    assert "boom" not in (scan.error_message or "")


def test_cancel_during_the_scan_keeps_partial_results(
    db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]
) -> None:
    scan, job = queue_scan()

    class CancellingFetcher(FakeFetcher):
        def fetch(self, url: str, *, read_body: bool):  # type: ignore[no-untyped-def]
            response = super().fetch(url, read_body=read_body)
            if url == f"{BASE}/":
                scan.status = ScanStatus.CANCELLED  # what POST /cancel does from the API
                db_session.commit()
            return response

    run(db_session, job, CancellingFetcher(juice_like_site()))
    assert scan.status is ScanStatus.CANCELLED
    assert job.state is JobState.DONE
    assert db_session.scalars(select(Page).where(Page.scan_id == scan.id)).all()  # pages kept
    assert db_session.scalars(select(Link).where(Link.scan_id == scan.id)).all() == []


def test_job_for_scan_cancelled_before_start_is_skipped(
    db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]
) -> None:
    scan, job = queue_scan()
    scan.status = ScanStatus.CANCELLED
    db_session.commit()
    fetcher = FakeFetcher(juice_like_site())
    run(db_session, job, fetcher)
    assert fetcher.requests == []
    assert job.state is JobState.DONE
    assert scan.status is ScanStatus.CANCELLED


def test_worker_shutdown_marks_scan_failed_not_completed(
    db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]
) -> None:
    scan, job = queue_scan()
    calls = {"n": 0}

    def shutdown() -> bool:
        calls["n"] += 1
        return calls["n"] > 2

    run(db_session, job, FakeFetcher(juice_like_site()), shutdown_requested=shutdown)
    assert scan.status is ScanStatus.FAILED
    assert scan.error_message == WORKER_STOPPED


def test_tampered_stored_config_is_rejected(db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]) -> None:
    scan, job = queue_scan(config={**FAST, "max_pages": 100000})
    fetcher = FakeFetcher(juice_like_site())
    run(db_session, job, fetcher)
    assert scan.status is ScanStatus.FAILED
    assert "Invalid scan configuration" in (scan.error_message or "")
    assert fetcher.requests == []


def test_limits_are_recorded_as_notes(db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]) -> None:
    scan, job = queue_scan(config={**FAST, "max_pages": 1})
    run(db_session, job, FakeFetcher(juice_like_site()))
    assert scan.status is ScanStatus.COMPLETED
    assert any("page limit" in note for note in scan.notes or [])


def test_long_error_details_are_truncated(db_session: Session, queue_scan: Callable[..., tuple[Scan, Job]]) -> None:
    scan, job = queue_scan(config={**FAST, "use_robots": False})
    site = {f"{BASE}/": FakePage(body='<a href="/x">x</a>'), f"{BASE}/x": FakePage(status=404)}
    run(db_session, job, FakeFetcher(site))
    link = db_session.scalars(select(Link).where(Link.target_url == f"{BASE}/x")).one()
    assert link.detail == "HTTP 404"
