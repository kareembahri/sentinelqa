"""Unit tests for crawl scope rules."""

import pytest

from worker.scanner.scope import Scope

SCOPE = Scope.from_base_url("http://juice-shop:3000/", ("logout",))


def test_start_url_and_origin() -> None:
    assert SCOPE.origin == "http://juice-shop:3000"
    assert SCOPE.start_url == "http://juice-shop:3000/"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("http://juice-shop:3000/a#section", "http://juice-shop:3000/a"),
        ("HTTP://Juice-Shop:3000/a?x=1", "http://juice-shop:3000/a?x=1"),
        ("http://user:pw@juice-shop:3000/a", "http://juice-shop:3000/a"),
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com:443", "https://example.com/"),
        ("mailto:help@juice.shop", None),
        ("javascript:alert(1)", None),
        ("data:text/html,hi", None),
        ("http://juice-shop:99999/", None),
        ("http:///nohost", None),
    ],
)
def test_normalize(raw: str, expected: str | None) -> None:
    assert SCOPE.normalize(raw) == expected


@pytest.mark.parametrize(
    "url",
    ["http://juice-shop:3000/", "http://juice-shop:3000/ftp/a.md", "http://juice-shop:3000/?q=1"],
)
def test_same_origin_urls_are_in_scope(url: str) -> None:
    assert SCOPE.in_scope(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://juice-shop:3000/",  # different scheme
        "http://juice-shop:3001/",  # different port
        "http://juice-shop/",  # default port 80 is a different port
        "http://evil.com/juice-shop:3000/",
        "http://juice-shop.evil.com:3000/",
        "not a url",
    ],
)
def test_other_origins_are_out_of_scope(url: str) -> None:
    assert not SCOPE.in_scope(url)


def test_base_path_limits_scope() -> None:
    scope = Scope.from_base_url("http://shop.local/app")
    assert scope.in_scope("http://shop.local/app")
    assert scope.in_scope("http://shop.local/app/cart")
    assert not scope.in_scope("http://shop.local/application")
    assert not scope.in_scope("http://shop.local/admin")


def test_exclusions_are_case_insensitive() -> None:
    assert SCOPE.excluded("http://juice-shop:3000/LogOut")
    assert not SCOPE.excluded("http://juice-shop:3000/login")


def test_invalid_base_url_is_rejected() -> None:
    with pytest.raises(ValueError):
        Scope.from_base_url("ftp://juice-shop/")
