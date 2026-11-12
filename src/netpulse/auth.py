"""Signing in, staying signed in, and passwords (plan section 36).

- A password is checked against its Argon2id hash. An unknown username costs
  the same time as a wrong password, and both get the same answer, so nothing
  here says which usernames exist.
- A session is a random 256-bit token in a cookie. The database holds only its
  SHA-256, so a copy of the file signs nobody in, and any session can be ended
  from the server: on sign-out, on a password change, when an account is
  disabled, or by an administrator.
- Failed sign-ins are counted per address and per username over 15 minutes.
  Past the limit the answer is "try again later" without checking anything.
  Sign-ins from this PC itself are only limited per address, so nobody on the
  network can lock the owner out of their own machine.
- Every method takes the request's Store: this module opens nothing itself.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from netpulse.accounts import (
    SESSION_ABSOLUTE_DAYS,
    SESSION_IDLE_DAYS,
    THROTTLE_PER_ADDRESS,
    THROTTLE_PER_USERNAME,
    THROTTLE_WINDOW_MIN,
    AccountError,
    Role,
    Session,
    User,
    validate_password,
    validate_username,
)
from netpulse.crypto.passwords import Passwords
from netpulse.store import Store

# A session's last-seen time is written at most this often, not on every request.
TOUCH_EVERY_S = 60


class LoginFailed(Exception):
    """Wrong username or password. One message for both, and for a disabled account."""

    def __init__(self) -> None:
        super().__init__("wrong username or password")


class Throttled(Exception):
    """Too many failed sign-ins. Nothing was checked."""

    def __init__(self, retry_after_s: int) -> None:
        minutes = max(1, -(-retry_after_s // 60))
        super().__init__(f"too many failed sign-ins; try again in {minutes} {'minute' if minutes == 1 else 'minutes'}")
        self.retry_after_s = retry_after_s


@dataclass(frozen=True)
class Identity:
    """Who a request is from, and the session that says so."""

    user: User
    session: Session


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Auth:
    def __init__(self, passwords: Passwords | None = None, *, now: Callable[[], datetime] = _utc_now) -> None:
        self.passwords = passwords or Passwords()
        self._now = now

    # Accounts

    def needs_setup(self, store: Store) -> bool:
        """True until the first administrator exists: nothing else is served before that."""
        return store.count_users() == 0

    def create_first_admin(self, store: Store, username: str, password: str) -> User:
        """First-run setup. Refused once any account exists, even if two browsers race."""
        name = validate_username(username)
        return store.add_user(
            name, self.passwords.hash(validate_password(password, name)), Role.ADMIN, now=self._now(), only_if_first=True
        )

    def create_user(
        self, store: Store, username: str, password: str, role: str, permissions=(), *, must_change: bool = True
    ) -> User:
        name = validate_username(username)
        return store.add_user(
            name, self.passwords.hash(validate_password(password, name)), role, permissions,
            must_change_password=must_change, now=self._now(),
        )

    def change_password(self, store: Store, identity: Identity, current: str, new: str) -> None:
        """The signed-in person changes their own password. Their other sessions end."""
        found = store.find_user(identity.user.username)
        if found is None or not self.passwords.verify(found[1], current or ""):
            raise AccountError("current password is not right")
        if current == new:
            raise AccountError("new password must differ from the current one")
        self.set_password(store, identity.user, new, keep_session=identity.session.id)

    def set_password(
        self, store: Store, user: User, new: str, *, must_change: bool = False, keep_session: int | None = None
    ) -> None:
        """Store a new password. Every session of the account ends, except keep_session."""
        hashed = self.passwords.hash(validate_password(new, user.username))
        store.set_password(user.id, hashed, must_change=must_change, keep_session=keep_session, now=self._now())

    @staticmethod
    def temporary_password() -> str:
        """A password to hand someone once; they must change it at their first sign-in."""
        return secrets.token_urlsafe(12)

    # Signing in and out

    def login(self, store: Store, username: str, password: str, ip: str, user_agent: str = "") -> tuple[Identity, str]:
        """Check a username and password. Returns who it is and the session token for their cookie.

        Raises Throttled before checking anything, or LoginFailed.
        """
        now = self._now()
        username = (username or "").strip()
        self._throttle(store, username, ip, now)
        found = store.find_user(username) if username else None
        if found is None:
            self.passwords.burn(password or "")
            ok = False
        else:
            ok = self.passwords.verify(found[1], password or "") and found[0].active
        store.record_attempt(username, ip, ok, now=now)
        if not ok:
            store.audit(username[:64] or "-", "sign-in failed", ip=ip, now=now)
            raise LoginFailed
        user, stored = found
        if self.passwords.needs_rehash(stored):
            store.rehash_password(user.id, self.passwords.hash(password))
        token = secrets.token_urlsafe(32)
        session = store.add_session(
            user.id, token_hash(token), ip, user_agent, now=now, expires=now + timedelta(days=SESSION_ABSOLUTE_DAYS)
        )
        store.audit(user.username, "signed in", ip=ip, now=now)
        return Identity(store.get_user(user.id), session), token

    def _throttle(self, store: Store, username: str, ip: str, now: datetime) -> None:
        window = timedelta(minutes=THROTTLE_WINDOW_MIN)
        since = now - window
        limits = [(THROTTLE_PER_ADDRESS, store.failed_attempts(since=since, ip=ip))]
        if username and not is_loopback(ip):
            limits.append((THROTTLE_PER_USERNAME, store.failed_attempts(since=since, username=username)))
        for limit, (failures, oldest) in limits:
            if failures >= limit:
                opens = datetime.fromisoformat(oldest) + window
                raise Throttled(max(1, int((opens - now).total_seconds())))

    def identify(self, store: Store, token: str | None, ip: str) -> Identity | None:
        """Who a session token belongs to, or None when it is unknown, ended, expired,
        idle too long, or its account is disabled."""
        if not token or len(token) > 200:
            return None
        found = store.session_by_token(token_hash(token))
        if found is None:
            return None
        session, user = found
        now = self._now()
        seen = datetime.fromisoformat(session.last_seen_at)
        if (
            session.revoked_at is not None
            or not user.active
            or datetime.fromisoformat(session.expires_at) <= now
            or now - seen > timedelta(days=SESSION_IDLE_DAYS)
        ):
            return None
        if (now - seen).total_seconds() >= TOUCH_EVERY_S:
            store.touch_session(session.id, ip, now=now)
        return Identity(user, session)

    def logout(self, store: Store, identity: Identity, ip: str = "") -> None:
        store.revoke_session(identity.session.id, now=self._now())
        store.audit(identity.user.username, "signed out", ip=ip, now=self._now())
