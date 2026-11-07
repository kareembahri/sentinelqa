"""Worker process: `python -m worker.runner` (the `worker` service in docker-compose.yml).

Loops forever: claim a job, run it, repeat. Stops cleanly on Ctrl+C or when
Docker sends SIGTERM (`docker compose stop`).
"""

import logging
import os
import signal
import socket
import sys
import threading
from types import FrameType

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.config import get_settings
from app.db import get_engine
from worker.jobs import claim_next_job, recover_stale_jobs, run_scan_job
from worker.scanner.http_fetcher import HttpxFetcher

POLL_SECONDS = 2.0
DATABASE_RETRY_SECONDS = 5.0

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("sentinelqa.worker")


def main() -> int:
    settings = get_settings()
    session_factory = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    stop = threading.Event()

    def request_stop(signum: int, frame: FrameType | None) -> None:
        logger.info("Stop requested; finishing the current step")
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    logger.info("Worker %s started", worker_id)
    with session_factory() as db:
        recovered = recover_stale_jobs(db)
        if recovered:
            logger.warning("Marked %d abandoned scan(s) as failed", recovered)

    while not stop.is_set():
        try:
            with session_factory() as db:
                job = claim_next_job(db, worker_id)
                if job is None:
                    stop.wait(POLL_SECONDS)
                    continue
                logger.info("Claimed job %s (scan %s)", job.id, job.scan_id)
                run_scan_job(
                    db,
                    job,
                    settings,
                    lambda timeout_s: HttpxFetcher(timeout_s),
                    shutdown_requested=stop.is_set,
                )
        except OperationalError:
            logger.exception("Database unavailable; retrying in %.0f seconds", DATABASE_RETRY_SECONDS)
            stop.wait(DATABASE_RETRY_SECONDS)

    logger.info("Worker stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
