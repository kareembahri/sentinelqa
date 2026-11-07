"""FastAPI dependencies for authentication and role-based access control (RBAC)."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit import client_ip, record
from app.config import get_settings
from app.db import get_db
from app.models import Role, User
from app.security.tokens import SESSION_COOKIE, TokenError, decode_session_token

# Higher number = more privileges. An admin can do everything a tester can, and so on.
ROLE_RANK = {Role.VIEWER: 0, Role.TESTER: 1, Role.ADMIN: 2}



def _not_authenticated() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise _not_authenticated()
    try:
        claims = decode_session_token(token, get_settings())
    except TokenError:
        raise _not_authenticated() from None

    # Checked against the database on every request, so deactivating a user or
    # logging out takes effect immediately, not when the token expires.
    user = db.get(User, claims.user_id)
    if user is None or not user.is_active or user.token_version != claims.version:
        raise _not_authenticated()
    return user


def require_role(minimum: Role) -> Callable[..., User]:
    """Dependency factory: require_role(Role.TESTER) allows testers and admins."""

    def dependency(
        request: Request,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            record(
                db,
                "authz.denied",
                user_id=user.id,
                ip=client_ip(request),
                details={
                    "method": request.method,
                    "path": request.url.path,
                    "required_role": minimum.value,
                    "user_role": user.role.value,
                },
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return user

    return dependency


CurrentUser = Annotated[User, Depends(get_current_user)]
ViewerUser = Annotated[User, Depends(require_role(Role.VIEWER))]
TesterUser = Annotated[User, Depends(require_role(Role.TESTER))]
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]
DbSession = Annotated[Session, Depends(get_db)]


def csrf_header_for_docs(
    x_csrf_token: Annotated[
        str | None,
        Header(
            alias="X-CSRF-Token",
            description="Filled in automatically by the /docs page. Other clients: send the value of the sqa_csrf cookie.",
        ),
    ] = None,
) -> None:
    """Makes the CSRF header appear in /docs. The real check is in the CSRF middleware."""


CSRF_DOC = Depends(csrf_header_for_docs)
