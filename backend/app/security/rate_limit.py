"""Rate limiting (slows down password guessing and request flooding).

Limits are counted per client IP address in memory. That is correct for a
single API process; running several processes would need shared storage such
as Redis (storage_uri), which is a one-line change here.
"""

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

LOGIN_LIMIT = "5/minute"


async def rate_limit_exceeded_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RateLimitExceeded)
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please wait a minute and try again."},
        headers={"Retry-After": "60"},
    )
