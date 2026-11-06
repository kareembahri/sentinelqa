"""Health check: is the API up, and can it reach the database?"""

import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app import __version__
from app.db import get_db

logger = logging.getLogger("sentinelqa.health")
router = APIRouter(tags=["health"])


@router.get("/health")
def health(db: Session = Depends(get_db)) -> JSONResponse:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        # The real error is logged; the response does not reveal connection details.
        logger.exception("Database health check failed")
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "database": "unavailable", "version": __version__},
        )
    return JSONResponse(content={"status": "ok", "database": "ok", "version": __version__})
