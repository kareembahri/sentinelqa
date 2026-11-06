"""Password hashing with Argon2id (the algorithm OWASP currently recommends).

Argon2 is deliberately slow and memory-hungry, so a stolen database is very
expensive to brute-force. Each hash includes its own random salt and its
parameters, so two users with the same password get different hashes.
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

_hasher = PasswordHasher()  # Argon2id with the library's RFC 9106 defaults

# Verified against when the email does not exist, so a login for an unknown
# user takes as long as a login for a real one. Without this, response time
# would reveal which emails have accounts.
DUMMY_HASH = _hasher.hash("timing-equalizer-not-a-real-password")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return True only for a correct password. Never raises for bad input."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, ValueError):
        # VerificationError: wrong password. ValueError: malformed hash.
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the hash was made with weaker parameters than today's defaults."""
    return _hasher.check_needs_rehash(password_hash)
