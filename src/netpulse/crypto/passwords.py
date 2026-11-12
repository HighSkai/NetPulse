"""Password hashing with Argon2id (plan section 36).

argon2-cffi's defaults are RFC 9106's second recommended profile (64 MiB of
memory, 3 passes, 4 lanes). A hash carries its own parameters and salt, so
raising them later needs no migration: the next successful sign-in rehashes.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Passwords:
    def __init__(self, hasher: PasswordHasher | None = None) -> None:
        """Tests pass a cheap hasher; nothing else should."""
        self._hasher = hasher or PasswordHasher()
        self._decoy: str | None = None

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, stored: str, password: str) -> bool:
        """Whether the password matches the stored hash. A damaged hash matches nothing."""
        try:
            return self._hasher.verify(stored, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def burn(self, password: str) -> None:
        """Spend the time a real check would, and learn nothing: for a username that does
        not exist, so "unknown user" takes as long as "wrong password"."""
        if self._decoy is None:
            self._decoy = self._hasher.hash("netpulse-decoy-password")
        self.verify(self._decoy, password)

    def needs_rehash(self, stored: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored)
        except InvalidHashError:
            return False
