"""Unit tests for password hashing."""

from app.security.passwords import hash_password, needs_rehash, verify_password


def test_hash_is_argon2id_and_not_the_password() -> None:
    hashed = hash_password("my secret passphrase")
    assert hashed.startswith("$argon2id$")
    assert "my secret passphrase" not in hashed


def test_same_password_gets_different_hashes_because_of_salt() -> None:
    assert hash_password("same-password-123") != hash_password("same-password-123")


def test_correct_password_verifies() -> None:
    assert verify_password(hash_password("right-password-1"), "right-password-1") is True


def test_wrong_password_is_rejected() -> None:
    assert verify_password(hash_password("right-password-1"), "wrong-password-1") is False


def test_malformed_hash_returns_false_instead_of_crashing() -> None:
    assert verify_password("not-a-hash", "anything") is False
    assert verify_password("", "anything") is False


def test_fresh_hash_does_not_need_rehash() -> None:
    assert needs_rehash(hash_password("x-password-123")) is False
