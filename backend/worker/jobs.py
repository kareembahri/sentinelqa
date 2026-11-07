"""Job queue and scan execution.

The API never runs a scan itself. It inserts a `jobs` row; a worker process
claims it with SELECT ... FOR UPDATE SKIP LOCKED, so two workers can never
take the same job, then runs it and writes results as it goes.

Outcome rules:
- A scan is "completed" only if the crawl actually ran to an end (finished
  or hit a configured limit). Any error makes it "failed" with a reason.
- A scan that a user cancels stays "cancelled"; pages found so far are kept.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import Job, JobState, Link, LinkResult, Page, Scan, ScanStatus, Target
from app.schemas import CrawlOptions
from app.security.target_guard import TargetValidationError, validate_target
from worker.scanner.crawler import CrawlLimits, Crawler, PageRecord
from worker.scanner.fetcher import Fetcher
from worker.scanner.scope import Scope

logger = logging.getLogger("sentinelqa.worker")

STALE_AFTER = timedelta(minutes=5)
INTERNAL_ERROR = "Internal error during the scan. The worker log contains the details."
WORKER_STOPPED = "The worker was stopped before the scan finished."

FetcherFactory = Callable[[float], Fetcher]


def _now() -> datetime:
    return datetime.now(UTC)


def claim_next_job(db: Session, worker_id: str) -> Job | None:
    """Take the oldest pending job, or return None if there is none."""
    job = db.scalars(
        select(Job)
        .join(Scan, Scan.id == Job.scan_id)
        .where(Job.state == JobState.PENDING)
        .order_by(Scan.queued_at)
        .limit(1)
        # Row lock: a second worker skips this row instead of waiting for it.
        .with_for_update(skip_locked=True, of=Job)
    ).first()
    if job is None:
        db.rollback()
        return None
    now = _now()
    job.state = JobState.CLAIMED
    job.worker_id = worker_id
    job.claimed_at = now
    job.heartbeat_at = now
    job.attempts += 1
    db.commit()
    return job


def recover_stale_jobs(db: Session, stale_after: timedelta = STALE_AFTER) -> int:
    """Fail jobs whose worker died (no heartbeat for a while). Returns how many were fixed."""
    cutoff = _now() - stale_after
    stale = db.scalars(
        select(Job).where(Job.state == JobState.CLAIMED, Job.heartbeat_at < cutoff)
    ).all()
    for job in stale:
        job.state = JobState.FAILED
        scan = db.get(Scan, job.scan_id)
        if scan is not None and scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            scan.status = ScanStatus.FAILED
            scan.error_message = "The worker stopped unexpectedly during this scan."
            scan.finished_at = _now()
    db.commit()
    return len(stale)


def _fail(db: Session, scan: Scan, job: Job, message: str) -> None:
    db.rollback()
    db.refresh(scan)
    if scan.status != ScanStatus.CANCELLED:
        scan.status = ScanStatus.FAILED
        scan.error_message = message[:1000]
    scan.finished_at = _now()
    job.state = JobState.FAILED
    db.commit()


def _store_page(db: Session, scan_id: object, record: PageRecord) -> None:
    db.add(
        Page(
            scan_id=scan_id,
            url=record.url,
            status_code=record.status_code,
            response_ms=record.response_ms,
            depth=record.depth,
            title=record.title,
            meta=record.meta,
            a11y_issues=record.a11y_issues,
        )
    )


def run_scan_job(
    db: Session,
    job: Job,
    settings: Settings,
    fetcher_factory: FetcherFactory,
    *,
    shutdown_requested: Callable[[], bool] = lambda: False,
    sleep: Callable[[float], None] | None = None,
    clock: Callable[[], float] | None = None,
) -> None:
    scan = db.get(Scan, job.scan_id)
    if scan is None or scan.status != ScanStatus.QUEUED:
        job.state = JobState.DONE  # cancelled (or removed) before a worker got to it
        db.commit()
        return
    target = db.get(Target, scan.target_id)
    assert target is not None  # the foreign key guarantees it

    scan.status = ScanStatus.RUNNING
    scan.started_at = _now()
    scan.progress_pct = 0
    db.commit()
    logger.info("Scan %s started for %s", scan.id, target.base_url)

    try:
        # The stored options were validated by the API; validate again in case the row was edited.
        options = CrawlOptions.model_validate(scan.config or {})
        validate_target(target.base_url, settings, is_lab=target.is_lab)
    except TargetValidationError as exc:
        _fail(db, scan, job, f"Target failed the authorization check: {exc}")
        return
    except ValueError as exc:
        _fail(db, scan, job, f"Invalid scan configuration: {exc}")
        return

    def guard() -> None:
        validate_target(target.base_url, settings, is_lab=target.is_lab)

    def cancelled() -> bool:
        # A fresh query, so a cancel committed by the API is seen immediately.
        status = db.scalar(select(Scan.status).where(Scan.id == scan.id))
        return shutdown_requested() or status == ScanStatus.CANCELLED

    def on_page(record: PageRecord) -> None:
        _store_page(db, scan.id, record)
        job.heartbeat_at = _now()
        db.commit()

    def on_progress(percent: int) -> None:
        if percent > scan.progress_pct:
            scan.progress_pct = percent
            job.heartbeat_at = _now()
            db.commit()

    limits = CrawlLimits(
        max_pages=options.max_pages,
        max_depth=options.max_depth,
        max_duration_s=options.max_duration_s,
        delay_ms=options.delay_ms,
        max_links=options.max_links,
        use_robots=options.use_robots,
    )
    extra: dict[str, Callable[..., object]] = {}
    if sleep is not None:
        extra["sleep"] = sleep
    if clock is not None:
        extra["clock"] = clock

    fetcher = fetcher_factory(options.timeout_s)
    try:
        crawler = Crawler(
            fetcher,
            Scope.from_base_url(target.base_url, tuple(options.exclude_patterns)),
            limits,
            before_request=guard,
            should_stop=cancelled,
            on_page=on_page,
            on_progress=on_progress,
            **extra,  # type: ignore[arg-type]
        )
        result = crawler.run()
    except TargetValidationError as exc:
        _fail(db, scan, job, f"Target stopped passing the authorization check during the scan: {exc}")
        return
    except Exception:
        logger.exception("Scan %s crashed", scan.id)
        _fail(db, scan, job, INTERNAL_ERROR)
        return
    finally:
        close = getattr(fetcher, "close", None)
        if callable(close):
            close()

    if shutdown_requested():
        _fail(db, scan, job, WORKER_STOPPED)
        return

    for link in result.links:
        db.add(
            Link(
                scan_id=scan.id,
                source_url=link.source_url,
                target_url=link.target_url,
                internal=link.internal,
                status_code=link.status_code,
                redirect_chain=link.redirect_chain,
                result=LinkResult(link.result),
                detail=link.detail[:300] if link.detail else None,
            )
        )

    db.refresh(scan)  # pick up a cancel that arrived during the last steps
    notes = list(result.notes)
    notes.append(f"{result.requests} request(s) sent to the target")
    scan.notes = notes
    scan.finished_at = _now()
    if scan.status != ScanStatus.CANCELLED:
        scan.status = ScanStatus.COMPLETED
        scan.progress_pct = 100
    job.state = JobState.DONE
    db.commit()
    logger.info("Scan %s finished: %s, %d pages, %d links", scan.id, scan.status.value, result.pages, len(result.links))
