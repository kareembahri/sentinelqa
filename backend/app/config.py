"""Typed application settings, read from environment variables.

Secrets (database password, SECRET_KEY) come only from the environment, which
Docker Compose fills from the local `.env` file. Nothing secret lives in code.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_SECRET_KEY_LENGTH = 32


def _split_hosts(raw: str) -> frozenset[str]:
    """Turn 'a.com, B.com,' into {'a.com', 'b.com'}."""
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    environment: Literal["development", "test", "production"] = "development"
    database_url: str
    secret_key: SecretStr
    access_token_minutes: int = Field(default=60, ge=5, le=1440)
    cookie_secure: bool = False

    # Comma-separated host names. Kept as plain strings because pydantic-settings
    # would otherwise expect JSON lists in environment variables.
    allowed_target_hosts: str = ""
    allowed_private_lab_hosts: str = ""

    @field_validator("secret_key")
    @classmethod
    def _secret_key_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_KEY_LENGTH:
            raise ValueError(f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters")
        return value

    @model_validator(mode="after")
    def _production_requires_secure_cookies(self) -> "Settings":
        if self.environment == "production" and not self.cookie_secure:
            raise ValueError("COOKIE_SECURE must be true when ENVIRONMENT=production")
        return self

    @property
    def target_hosts(self) -> frozenset[str]:
        """Hosts that may be scanned at all."""
        return _split_hosts(self.allowed_target_hosts)

    @property
    def private_lab_hosts(self) -> frozenset[str]:
        """Hosts that may resolve to private/loopback IPs and receive active tests."""
        return _split_hosts(self.allowed_private_lab_hosts)


@lru_cache
def get_settings() -> Settings:
    # Values come from environment variables; pydantic validates them here.
    return Settings()  # type: ignore[call-arg]
