"""Security tests for the target guard: SSRF and scope-bypass attempts.

DNS is faked (see the fake_dns fixture in conftest.py), so each test controls
exactly which IP addresses a host name "resolves" to.
"""

import pytest

from app.config import Settings
from app.security.target_guard import TargetValidationError, validate_target

SETTINGS = Settings(
    database_url="sqlite://",
    secret_key="s" * 40,
    allowed_target_hosts="juice-shop,localhost,public.sentinelqa.io",
    allowed_private_lab_hosts="juice-shop",
)


def test_allowlisted_lab_host_on_private_network_is_accepted() -> None:
    result = validate_target("http://juice-shop:3000", SETTINGS, is_lab=True)
    assert result.host == "juice-shop"
    assert result.port == 3000
    assert result.base_url == "http://juice-shop:3000/"
    assert result.is_private is True


def test_public_allowlisted_host_is_accepted_without_lab_flag() -> None:
    result = validate_target("https://public.sentinelqa.io/app", SETTINGS)
    assert result.base_url == "https://public.sentinelqa.io/app"
    assert result.port == 443
    assert result.is_private is False


def test_host_case_and_trailing_dot_are_normalized() -> None:
    result = validate_target("HTTP://Juice-Shop.:3000/", SETTINGS)
    assert result.base_url == "http://juice-shop:3000/"


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example.com/",  # simply not authorized
        "http://juice-shop.evil.com/",  # allowlisted name as a prefix
        "http://evil.com/juice-shop",  # allowlisted name in the path
        "http://2130706433/",  # 127.0.0.1 written as a decimal number
        "http://0x7f000001/",  # 127.0.0.1 in hex
        "http://127.0.0.1/",  # raw IP instead of an allowlisted name
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata by IP
        "http://[::1]/",  # IPv6 loopback
    ],
)
def test_hosts_not_on_the_allowlist_are_rejected(url: str) -> None:
    with pytest.raises(TargetValidationError, match="not an authorized target"):
        validate_target(url, SETTINGS)


@pytest.mark.parametrize(
    "url",
    [
        "ftp://juice-shop/",
        "file:///etc/passwd",
        "gopher://juice-shop:70/",
        "javascript:alert(1)",
        "juice-shop:3000",
    ],
)
def test_non_http_schemes_are_rejected(url: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(url, SETTINGS)


@pytest.mark.parametrize(
    "url",
    [
        "http://admin:secret@juice-shop/",
        "http://juice-shop@evil.com/",  # the real host here is evil.com
        "http://user@juice-shop/",
    ],
)
def test_credentials_in_url_are_rejected(url: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(url, SETTINGS)


@pytest.mark.parametrize(
    "url",
    [
        "http://juice-shop/ path",
        "http://juice-shop\\@evil.com/",
        "http://juice-shop/\r\nX-Injected: 1",
        "http://juice-shop:99999/",
        "http://juice-shop:abc/",
        "http://juice-shop/?q=1",
        "http://juice-shop/#top",
        "http:///nohost",
        "",
        "http://juice-shop/" + "a" * 2100,
    ],
)
def test_malformed_urls_are_rejected(url: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target(url, SETTINGS)


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",  # AWS / GCP / Azure metadata
        "::ffff:169.254.169.254",  # same, as IPv4-mapped IPv6
        "100.100.100.200",  # Alibaba metadata
        "fd00:ec2::254",  # AWS metadata over IPv6
        "0.0.0.0",
        "224.0.0.1",
        "fe80::1",
    ],
)
def test_blocked_ranges_are_rejected_even_for_lab_hosts(
    fake_dns: dict[str, list[str]], address: str
) -> None:
    fake_dns["juice-shop"] = [address]
    with pytest.raises(TargetValidationError, match="blocked address range"):
        validate_target("http://juice-shop:3000", SETTINGS, is_lab=True)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "::1"])
def test_private_addresses_rejected_for_non_lab_hosts(
    fake_dns: dict[str, list[str]], address: str
) -> None:
    fake_dns["public.sentinelqa.io"] = [address]
    with pytest.raises(TargetValidationError, match="private or internal"):
        validate_target("http://public.sentinelqa.io/", SETTINGS)


def test_localhost_is_rejected_because_it_is_not_a_lab_host() -> None:
    with pytest.raises(TargetValidationError, match="private or internal"):
        validate_target("http://localhost:8000/", SETTINGS)


def test_one_bad_address_among_many_rejects_the_host(fake_dns: dict[str, list[str]]) -> None:
    # DNS rebinding style: a public IP plus an internal one.
    fake_dns["public.sentinelqa.io"] = ["93.184.215.14", "10.0.0.5"]
    with pytest.raises(TargetValidationError):
        validate_target("http://public.sentinelqa.io/", SETTINGS)


def test_lab_flag_requires_a_lab_host() -> None:
    with pytest.raises(TargetValidationError, match="ALLOWED_PRIVATE_LAB_HOSTS"):
        validate_target("https://public.sentinelqa.io/", SETTINGS, is_lab=True)


def test_unresolvable_host_is_rejected(fake_dns: dict[str, list[str]]) -> None:
    del fake_dns["juice-shop"]
    with pytest.raises(TargetValidationError, match="could not be resolved"):
        validate_target("http://juice-shop:3000", SETTINGS)


def test_error_messages_do_not_reveal_resolved_addresses(fake_dns: dict[str, list[str]]) -> None:
    fake_dns["public.sentinelqa.io"] = ["10.20.30.40"]
    with pytest.raises(TargetValidationError) as error:
        validate_target("http://public.sentinelqa.io/", SETTINGS)
    assert "10.20.30.40" not in str(error.value)


def test_empty_allowlist_rejects_everything() -> None:
    locked_down = Settings(database_url="sqlite://", secret_key="s" * 40, allowed_target_hosts="")
    with pytest.raises(TargetValidationError):
        validate_target("http://juice-shop:3000", locked_down)
