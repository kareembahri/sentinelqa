"""FastAPI application: middleware, error handling and routers."""

import logging
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from app import __version__
from app.api import health
from app.config import get_settings

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

    @app.middleware("http")
    async def request_id_and_security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
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

    app.include_router(health.router, prefix="/api")
    return app


app = create_app()
