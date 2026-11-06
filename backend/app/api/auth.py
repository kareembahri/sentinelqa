"""Login, logout, current user and CSRF token endpoints."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import select

from app.audit import client_ip, record
from app.config import Settings, get_settings
from app.models import User, ensure_utc
from app.schemas import CsrfOut, LoginRequest, UserOut
from app.security.deps import CSRF_DOC, CurrentUser, DbSession
from app.security.passwords import DUMMY_HASH, hash_password, needs_rehash, verify_password
from app.security.rate_limit import LOGIN_LIMIT, limiter
from app.security.tokens import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    create_session_token,
    new_csrf_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])

MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
# One message for every failure, so an attacker cannot tell which emails exist,
# whether the password was wrong, or whether the account is locked.
GENERIC_LOGIN_ERROR = "Invalid email or password"


def _login_failed() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_LOGIN_ERROR)


def _set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.access_token_minutes * 60,
        httponly=True,  # JavaScript cannot read it
        secure=settings.cookie_secure,  # HTTPS only (enabled in production)
        samesite="strict",  # never sent on requests started by other websites
        path="/",
    )


@router.get("/csrf", response_model=CsrfOut)
def get_csrf_token(response: Response) -> CsrfOut:
    """Issue a CSRF token (cookie + response body). Call this before the first POST."""
    settings = get_settings()
    token = new_csrf_token(settings)
    response.set_cookie(
        CSRF_COOKIE,
        token,
        httponly=False,  # the dashboard must read it to copy it into the header
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return CsrfOut(csrf_token=token)


@router.post("/login", response_model=UserOut, dependencies=[CSRF_DOC])
@limiter.limit(LOGIN_LIMIT)
def login(request: Request, response: Response, payload: LoginRequest, db: DbSession) -> User:
    settings = get_settings()
    ip = client_ip(request)
    email = str(payload.email).lower()
    now = datetime.now(UTC)

    user = db.scalar(select(User).where(User.email == email))

    if user is None:
        verify_password(DUMMY_HASH, payload.password)  # same delay as a real check
        record(db, "auth.login.failed", ip=ip, details={"email": email, "reason": "unknown_user"})
        db.commit()
        raise _login_failed()

    if user.locked_until is not None and ensure_utc(user.locked_until) > now:
        record(db, "auth.login.failed", user_id=user.id, ip=ip, details={"reason": "locked"})
        db.commit()
        raise _login_failed()

    password_ok = verify_password(user.password_hash, payload.password)

    if not password_ok:
        user.failed_logins += 1
        record(
            db,
            "auth.login.failed",
            user_id=user.id,
            ip=ip,
            details={"reason": "bad_password", "consecutive_failures": user.failed_logins},
        )
        if user.failed_logins >= MAX_FAILED_LOGINS:
            user.locked_until = now + LOCKOUT_DURATION
            user.failed_logins = 0
            record(
                db,
                "auth.account.locked",
                user_id=user.id,
                ip=ip,
                details={"minutes": int(LOCKOUT_DURATION.total_seconds() // 60)},
            )
        db.commit()
        raise _login_failed()

    if not user.is_active:
        record(db, "auth.login.failed", user_id=user.id, ip=ip, details={"reason": "inactive"})
        db.commit()
        raise _login_failed()

    user.failed_logins = 0
    user.locked_until = None
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)

    _set_session_cookie(response, create_session_token(user.id, user.token_version, settings), settings)
    record(db, "auth.login.success", user_id=user.id, ip=ip)
    db.commit()
    return user


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[CSRF_DOC])
def logout(request: Request, user: CurrentUser, db: DbSession) -> Response:
    """End the session. Bumping token_version also invalidates copies of the cookie."""
    user.token_version += 1
    record(db, "auth.logout", user_id=user.id, ip=client_ip(request))
    db.commit()

    settings = get_settings()
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(
        SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict"
    )
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.cookie_secure, samesite="strict")
    return response


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user
