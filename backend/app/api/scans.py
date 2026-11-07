"""Scans: start, follow, cancel, and read results.

POST /api/scans only *queues* a scan (HTTP 202 Accepted). The worker process
runs it; the dashboard polls GET /api/scans/{id} for progress.
"""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import func, select

from app.audit import client_ip, record
from app.config import get_settings
from app.models import Job, JobState, Link, LinkResult, Page, Scan, ScanStatus, ScanType, Target
from app.schemas import LinkOut, PageOut, ScanCreate, ScanDetail, ScanOut, ScanSummary
from app.security.deps import CSRF_DOC, DbSession, TesterUser, ViewerUser
from app.security.rate_limit import limiter
from app.security.target_guard import TargetValidationError, validate_target

router = APIRouter(prefix="/scans", tags=["scans"])

AVAILABLE_TYPES = frozenset({ScanType.CRAWL})
MAX_ACTIVE_SCANS_PER_USER = 3
ACTIVE = (ScanStatus.QUEUED, ScanStatus.RUNNING)


def _get_scan(db: DbSession, scan_id: uuid.UUID) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def _summary(db: DbSession, scan_id: uuid.UUID) -> ScanSummary:
    pages = db.scalar(select(func.count()).select_from(Page).where(Page.scan_id == scan_id)) or 0
    http_errors = (
        db.scalar(
            select(func.count()).select_from(Page).where(Page.scan_id == scan_id, Page.status_code >= 400)
        )
        or 0
    )
    avg_ms, max_ms = db.execute(
        select(func.avg(Page.response_ms), func.max(Page.response_ms)).where(Page.scan_id == scan_id)
    ).one()
    by_result = {
        result.value: count
        for result, count in db.execute(
            select(Link.result, func.count()).where(Link.scan_id == scan_id).group_by(Link.result)
        ).all()
    }
    issues = sum(len(row or []) for row in db.scalars(select(Page.a11y_issues).where(Page.scan_id == scan_id)))
    return ScanSummary(
        pages=pages,
        http_error_pages=http_errors,
        avg_response_ms=round(avg_ms) if avg_ms is not None else None,
        max_response_ms=max_ms,
        links_total=sum(by_result.values()),
        links_by_result={result.value: by_result.get(result.value, 0) for result in LinkResult},
        accessibility_issues=issues,
    )


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED, dependencies=[CSRF_DOC])
@limiter.limit("10/minute")
def create_scan(request: Request, payload: ScanCreate, actor: TesterUser, db: DbSession) -> Scan:
    if payload.type not in AVAILABLE_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan type '{payload.type.value}' is not available yet. Supported now: crawl.",
        )
    target = db.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    active = db.scalar(
        select(func.count()).select_from(Scan).where(Scan.started_by == actor.id, Scan.status.in_(ACTIVE))
    )
    if (active or 0) >= MAX_ACTIVE_SCANS_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"You already have {MAX_ACTIVE_SCANS_PER_USER} scans queued or running",
        )

    # Checked again now (and again by the worker), because DNS or the allowlist may have changed.
    try:
        validate_target(target.base_url, get_settings(), is_lab=target.is_lab)
    except TargetValidationError as exc:
        record(
            db,
            "scan.rejected",
            user_id=actor.id,
            object_type="target",
            object_id=str(target.id),
            ip=client_ip(request),
            details={"reason": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None

    scan = Scan(
        target_id=target.id,
        started_by=actor.id,
        type=payload.type,
        status=ScanStatus.QUEUED,
        config=payload.options.model_dump(),
    )
    db.add(scan)
    db.flush()
    db.add(Job(scan_id=scan.id))
    record(
        db,
        "scan.created",
        user_id=actor.id,
        object_type="scan",
        object_id=str(scan.id),
        ip=client_ip(request),
        details={"target_id": str(target.id), "type": payload.type.value, "options": scan.config},
    )
    db.commit()
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(
    _: ViewerUser,
    db: DbSession,
    target_id: uuid.UUID | None = None,
    scan_status: ScanStatus | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[Scan]:
    query = select(Scan).order_by(Scan.queued_at.desc())
    if target_id is not None:
        query = query.where(Scan.target_id == target_id)
    if scan_status is not None:
        query = query.where(Scan.status == scan_status)
    return list(db.scalars(query.limit(limit).offset(offset)))


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuid.UUID, _: ViewerUser, db: DbSession) -> ScanDetail:
    scan = _get_scan(db, scan_id)
    return ScanDetail.model_validate({**ScanOut.model_validate(scan).model_dump(), "summary": _summary(db, scan.id)})


@router.post("/{scan_id}/cancel", response_model=ScanOut, dependencies=[CSRF_DOC])
def cancel_scan(scan_id: uuid.UUID, request: Request, actor: TesterUser, db: DbSession) -> Scan:
    scan = _get_scan(db, scan_id)
    if scan.status not in ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Only queued or running scans can be cancelled"
        )
    previous = scan.status
    scan.status = ScanStatus.CANCELLED
    if previous == ScanStatus.QUEUED:
        # Not started yet: finish it now so no worker ever picks it up.
        scan.finished_at = datetime.now(UTC)
        job = db.scalar(select(Job).where(Job.scan_id == scan.id))
        if job is not None and job.state == JobState.PENDING:
            job.state = JobState.DONE
    record(
        db,
        "scan.cancelled",
        user_id=actor.id,
        object_type="scan",
        object_id=str(scan.id),
        ip=client_ip(request),
        details={"previous_status": previous.value},
    )
    db.commit()
    return scan


@router.get("/{scan_id}/pages", response_model=list[PageOut])
def list_pages(
    scan_id: uuid.UUID,
    _: ViewerUser,
    db: DbSession,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[Page]:
    _get_scan(db, scan_id)
    query = select(Page).where(Page.scan_id == scan_id).order_by(Page.depth, Page.url)
    return list(db.scalars(query.limit(limit).offset(offset)))


@router.get("/{scan_id}/links", response_model=list[LinkOut])
def list_links(
    scan_id: uuid.UUID,
    _: ViewerUser,
    db: DbSession,
    result: LinkResult | None = None,
    internal: bool | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> list[Link]:
    _get_scan(db, scan_id)
    query = select(Link).where(Link.scan_id == scan_id).order_by(Link.target_url, Link.source_url)
    if result is not None:
        query = query.where(Link.result == result)
    if internal is not None:
        query = query.where(Link.internal == internal)
    return list(db.scalars(query.limit(limit).offset(offset)))
