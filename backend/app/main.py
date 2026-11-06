"""FastAPI application: middleware, error handling and routers."""

import logging
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app import __version__
from app.api import audit, auth, health, targets, users
from app.config import get_settings
from app.security.rate_limit import limiter, rate_limit_exceeded_handler
from app.security.tokens import CSRF_COOKIE, CSRF_HEADER, csrf_request_valid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("sentinelqa")

# Sent on every response. The API only returns JSON, so the content security
# policy can forbid everything. The interactive docs page loads Swagger UI
# scripts from a CDN, so it is excluded from the strict policy.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
STRICT_CSP = "default-src 'none'; frame-ancestors 'none'"
DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/openapi.json"})

# Requests that change state must carry a valid CSRF token.
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def create_app() -> FastAPI:
    settings = get_settings()
    show_docs = settings.environment != "production"

    app = FastAPI(
        title="SentinelQA API",
        version=__version__,
        docs_url="/docs" if show_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if show_docs else None,
    )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    @app.middleware("http")
    async def security_middleware(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id

        # CSRF is enforced here, for every state-changing API route at once,
        # so a new endpoint cannot forget to check it.
        csrf_ok = csrf_request_valid(
            request.cookies.get(CSRF_COOKIE), request.headers.get(CSRF_HEADER), settings
        )
        if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/") and not csrf_ok:
            response: Response = JSONResponse(
                status_code=403, content={"detail": "CSRF token missing or invalid"}
            )
        else:
            response = await call_next(request)

        response.headers["X-Request-ID"] = request_id
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        if request.url.path not in DOCS_PATHS:
            response.headers.setdefault("Content-Security-Policy", STRICT_CSP)
        if settings.cookie_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        # Full details go to the server log; the client gets a generic message
        # plus an ID that links the two.
        request_id = getattr(request.state, "request_id", "unknown")
        logger.exception("Unhandled error (request_id=%s)", request_id)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
        )

    for router in (health.router, auth.router, users.router, targets.router, audit.router):
        app.include_router(router, prefix="/api")
    return app


app = create_app()
