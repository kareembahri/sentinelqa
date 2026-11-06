"""Session tokens (JWT) and CSRF tokens.

Session token: a signed JWT stored in an HttpOnly cookie. JavaScript cannot
read it, so an XSS bug cannot steal it. It contains the user ID and the user's
token_version, which lets the server revoke every session of a user at once.

CSRF token: random value + HMAC signature ("signed double-submit cookie").
It is stored in a readable cookie and must also be sent in the X-CSRF-Token
header. Another website can make your browser *send* cookies, but it cannot
*read* them to copy the value into a header, so forged requests are rejected.
"""

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

from app.config import Settings

ALGORITHM = "HS256"
ISSUER = "sentinelqa"

SESSION_COOKIE = "sqa_session"
CSRF_COOKIE = "sqa_csrf"
CSRF_HEADER = "X-CSRF-Token"


class TokenError(Exception):
    """The session token is missing, expired, tampered with or malformed."""


@dataclass(frozen=True)
class SessionClaims:
    user_id: uuid.UUID
    version: int


def _key(settings: Settings) -> str:
    return settings.secret_key.get_secret_value()


def create_session_token(
    user_id: uuid.UUID, version: int, settings: Settings, now: datetime | None = None
) -> str:
    issued_at = now or datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "ver": version,
        "iss": ISSUER,
        "iat": issued_at,
        "exp": issued_at + timedelta(minutes=settings.access_token_minutes),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, _key(settings), algorithm=ALGORITHM)


def decode_session_token(token: str, settings: Settings) -> SessionClaims:
    try:
        data = jwt.decode(
            token,
            _key(settings),
            # Only HS256 is accepted. This blocks the classic "alg: none" attack.
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "ver", "iss"]},
        )
        return SessionClaims(user_id=uuid.UUID(data["sub"]), version=int(data["ver"]))
    except (jwt.PyJWTError, ValueError, KeyError, TypeError) as exc:
        raise TokenError("Invalid session token") from exc


def _csrf_signature(nonce: str, settings: Settings) -> str:
    message = f"csrf:{nonce}".encode()
    return hmac.new(_key(settings).encode(), message, hashlib.sha256).hexdigest()


def new_csrf_token(settings: Settings) -> str:
    nonce = secrets.token_urlsafe(32)  # contains only A-Z a-z 0-9 - _
    return f"{nonce}.{_csrf_signature(nonce, settings)}"


def csrf_token_valid(token: str, settings: Settings) -> bool:
    """True if the token was created by this server (signature matches)."""
    nonce, separator, signature = token.partition(".")
    if not separator or not nonce or not signature:
        return False
    expected = _csrf_signature(nonce, settings)
    # compare_digest takes the same time whether or not the values match,
    # so an attacker cannot guess the signature byte by byte from timing.
    return hmac.compare_digest(signature.encode(), expected.encode())


def csrf_request_valid(cookie: str | None, header: str | None, settings: Settings) -> bool:
    """The header must equal the cookie, and the cookie must carry a valid signature."""
    if not cookie or not header:
        return False
    if not hmac.compare_digest(cookie.encode(), header.encode()):
        return False
    return csrf_token_valid(cookie, settings)
