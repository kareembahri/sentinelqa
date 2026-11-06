"""Unit tests for session tokens and CSRF tokens, including tampering attempts."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.config import Settings
from app.security.tokens import (
    ISSUER,
    TokenError,
    create_session_token,
    csrf_request_valid,
    csrf_token_valid,
    decode_session_token,
    new_csrf_token,
)

SETTINGS = Settings(database_url="sqlite://", secret_key="a" * 40, access_token_minutes=60)
OTHER_SETTINGS = Settings(database_url="sqlite://", secret_key="b" * 40)


def test_session_token_round_trip() -> None:
    user_id = uuid.uuid4()
    claims = decode_session_token(create_session_token(user_id, 3, SETTINGS), SETTINGS)
    assert claims.user_id == user_id
    assert claims.version == 3


def test_expired_token_is_rejected() -> None:
    issued = datetime.now(UTC) - timedelta(minutes=61)
    token = create_session_token(uuid.uuid4(), 0, SETTINGS, now=issued)
    with pytest.raises(TokenError):
        decode_session_token(token, SETTINGS)


def test_token_signed_with_another_key_is_rejected() -> None:
    token = create_session_token(uuid.uuid4(), 0, OTHER_SETTINGS)
    with pytest.raises(TokenError):
        decode_session_token(token, SETTINGS)


def test_modified_payload_is_rejected() -> None:
    token = create_session_token(uuid.uuid4(), 0, SETTINGS)
    header, payload, signature = token.split(".")
    tampered = ".".join([header, payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB"), signature])
    with pytest.raises(TokenError):
        decode_session_token(tampered, SETTINGS)


def test_unsigned_alg_none_token_is_rejected() -> None:
    now = datetime.now(UTC)
    forged = jwt.encode(
        {"sub": str(uuid.uuid4()), "ver": 0, "iss": ISSUER, "iat": now, "exp": now + timedelta(hours=1)},
        "",
        algorithm="none",
    )
    with pytest.raises(TokenError):
        decode_session_token(forged, SETTINGS)


def test_token_missing_version_claim_is_rejected() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {"sub": str(uuid.uuid4()), "iss": ISSUER, "iat": now, "exp": now + timedelta(hours=1)},
        SETTINGS.secret_key.get_secret_value(),
        algorithm="HS256",
    )
    with pytest.raises(TokenError):
        decode_session_token(token, SETTINGS)


@pytest.mark.parametrize("garbage", ["", "abc", "a.b.c", "x" * 500])
def test_garbage_tokens_are_rejected(garbage: str) -> None:
    with pytest.raises(TokenError):
        decode_session_token(garbage, SETTINGS)


def test_csrf_token_created_by_server_is_valid() -> None:
    assert csrf_token_valid(new_csrf_token(SETTINGS), SETTINGS) is True


@pytest.mark.parametrize("forged", ["", "abc", "abc.", ".abc", "abc.def", "nonce.0000"])
def test_forged_csrf_tokens_are_invalid(forged: str) -> None:
    assert csrf_token_valid(forged, SETTINGS) is False


def test_csrf_token_from_another_server_key_is_invalid() -> None:
    assert csrf_token_valid(new_csrf_token(OTHER_SETTINGS), SETTINGS) is False


def test_csrf_request_requires_matching_header_and_cookie() -> None:
    token = new_csrf_token(SETTINGS)
    assert csrf_request_valid(token, token, SETTINGS) is True
    assert csrf_request_valid(token, None, SETTINGS) is False
    assert csrf_request_valid(None, token, SETTINGS) is False
    assert csrf_request_valid(token, new_csrf_token(SETTINGS), SETTINGS) is False


def test_csrf_check_handles_non_ascii_input_safely() -> None:
    assert csrf_request_valid("é.é", "é.é", SETTINGS) is False
