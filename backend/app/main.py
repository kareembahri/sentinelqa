"""FastAPI application: middleware, error handling and routers."""

import logging
import uuid
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from slowapi.errors import RateLimitExceeded

from app import __version__
from app.api import audit, auth, health, scans, targets, users
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

# Interactive API docs (development only). Same Swagger UI as FastAPI's default,
# plus a request interceptor that copies the CSRF cookie into the X-CSRF-Token
# header, exactly as the dashboard will. This is safe: only pages served from
# this origin can read the cookie, which is the whole point of the CSRF design.
SWAGGER_UI_VERSION = "5.17.14"
SWAGGER_PAGE = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SentinelQA API - Docs</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@{SWAGGER_UI_VERSION}/swagger-ui-bundle.js"></script>
<script>
function readCookie(name) {{
  const match = document.cookie.match("(?:^|; )" + name + "=([^;]*)");
  return match ? decodeURIComponent(match[1]) : null;
}}
async function csrfToken() {{
  if (!readCookie("{CSRF_COOKIE}")) {{
    await fetch("/api/auth/csrf", {{ credentials: "same-origin" }});
  }}
  return readCookie("{CSRF_COOKIE}");
}}
SwaggerUIBundle({{
  url: "/openapi.json",
  dom_id: "#swagger-ui",
  requestInterceptor: async (request) => {{
    const method = (request.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {{
      request.headers["{CSRF_HEADER}"] = await csrfToken();
    }}
    return request;
  }},
}});
</script>
</body>
</html>
"""

# Requests that change state must carry a valid CSRF token.
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def create_app() -> FastAPI:
    settings = get_settings()
    show_docs = settings.environment != "production"

    app = FastAPI(
        title="SentinelQA API",
        version=__version__,
        docs_url=None,  # served below with automatic CSRF handling
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

    if show_docs:

        @app.get("/docs", include_in_schema=False)
        def swagger_docs() -> HTMLResponse:
            return HTMLResponse(SWAGGER_PAGE)

    for router in (health.router, auth.router, users.router, targets.router, scans.router, audit.router):
        app.include_router(router, prefix="/api")
    return app


app = create_app()
