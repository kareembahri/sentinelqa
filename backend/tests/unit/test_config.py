"""Unit tests for settings validation."""

import pytest
from pydantic import ValidationError

from app.config import Settings

VALID_KEY = "k" * 40


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"database_url": "sqlite://", "secret_key": VALID_KEY}
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_host_lists_are_trimmed_lowercased_and_deduplicated() -> None:
    settings = make_settings(allowed_target_hosts=" Juice-Shop , localhost,,JUICE-SHOP ")
    assert settings.target_hosts == frozenset({"juice-shop", "localhost"})


def test_empty_host_list_means_no_targets_allowed() -> None:
    settings = make_settings(allowed_target_hosts="")
    assert settings.target_hosts == frozenset()


def test_short_secret_key_is_rejected() -> None:
    with pytest.raises(ValidationError, match="at least 32 characters"):
        make_settings(secret_key="too-short")


def test_secret_key_is_hidden_when_printed() -> None:
    settings = make_settings()
    assert VALID_KEY not in repr(settings)
    assert VALID_KEY not in str(settings.secret_key)


def test_production_requires_secure_cookies() -> None:
    with pytest.raises(ValidationError, match="COOKIE_SECURE"):
        make_settings(environment="production", cookie_secure=False)


def test_production_with_secure_cookies_is_accepted() -> None:
    settings = make_settings(environment="production", cookie_secure=True)
    assert settings.environment == "production"


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_settings(environment="staging")


@pytest.mark.parametrize("minutes", [4, 1441])
def test_token_lifetime_bounds_are_enforced(minutes: int) -> None:
    with pytest.raises(ValidationError):
        make_settings(access_token_minutes=minutes)
