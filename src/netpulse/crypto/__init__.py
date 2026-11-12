"""Password hashing and certificates (plan sections 36 and 38).

The two places NetPulse relies on someone else's cryptography: Argon2id from
argon2-cffi for passwords, and the `cryptography` package to make the
certificates HTTPS needs. Nothing here is home-made.
"""

from netpulse.crypto.passwords import Passwords

__all__ = ["Passwords"]
