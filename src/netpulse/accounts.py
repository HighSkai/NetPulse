"""Accounts, roles and permissions (plan section 35): values and rules.

No SQL, no hashing, no Flask. The store keeps these values, netpulse.auth
signs people in, and the web layer asks `user.can(...)` before every action.

- Two roles. An administrator may do everything. A viewer may look at
  everything except packet captures, and change nothing.
- An administrator can grant a viewer single permissions from GRANTABLE, such
  as acknowledging alerts. Managing users and settings can never be granted:
  an account that needs them is an administrator.
- Permissions are checked on the server for every request. Hiding a button is
  only for tidiness.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

USERNAME_MIN, USERNAME_MAX = 3, 32
PASSWORD_MIN, PASSWORD_MAX = 10, 256

# A session ends after this long without a request, and at the latest this
# long after signing in. Pages that refresh themselves count as requests, so a
# wall display stays signed in until the absolute limit.
SESSION_IDLE_DAYS = 7
SESSION_ABSOLUTE_DAYS = 30

# Sign-in throttling (plan section 36), counted over a sliding window.
THROTTLE_WINDOW_MIN = 15
THROTTLE_PER_ADDRESS = 10  # failed sign-ins from one address
THROTTLE_PER_USERNAME = 20  # failed sign-ins for one username, from anywhere but this PC


class AccountError(ValueError):
    """What was typed cannot be an account. The message names the field."""


class Role:
    ADMIN = "admin"
    VIEWER = "viewer"

    ALL = (ADMIN, VIEWER)
    LABELS = {ADMIN: "Administrator", VIEWER: "Viewer"}


class Permission:
    DEVICES_MANAGE = "devices.manage"
    CHECKS_RUN = "checks.run"
    DISCOVERY_RUN = "discovery.run"
    DIAGNOSTICS_RUN = "diagnostics.run"
    OUTSIDE_RUN = "outside.run"
    CAPTURE_VIEW = "capture.view"
    CAPTURE_RUN = "capture.run"
    ALERTS_ACK = "alerts.ack"
    ALERTS_MANAGE = "alerts.manage"
    SETTINGS_MANAGE = "settings.manage"
    USERS_MANAGE = "users.manage"

    ALL = (
        DEVICES_MANAGE, CHECKS_RUN, DISCOVERY_RUN, DIAGNOSTICS_RUN, OUTSIDE_RUN, CAPTURE_VIEW, CAPTURE_RUN,
        ALERTS_ACK, ALERTS_MANAGE, SETTINGS_MANAGE, USERS_MANAGE,
    )


# What an administrator can give a viewer, with the words the users page shows.
GRANTABLE: dict[str, str] = {
    Permission.ALERTS_ACK: "Acknowledge alerts",
    Permission.CHECKS_RUN: "Run Check now",
    Permission.DIAGNOSTICS_RUN: "Trace paths to a host",
    Permission.DISCOVERY_RUN: "Start discovery sweeps",
    Permission.DEVICES_MANAGE: "Add, edit and delete devices and groups",
    Permission.ALERTS_MANAGE: "Change alert rules and notification channels",
    Permission.OUTSIDE_RUN: "Run checks from outside (sends the host to Globalping)",
    Permission.CAPTURE_VIEW: "See packet captures and download their files",
    Permission.CAPTURE_RUN: "Start, stop and delete packet captures",
}


@dataclass(frozen=True)
class User:
    id: int
    username: str
    role: str
    permissions: frozenset[str] = frozenset()  # extra grants; an administrator needs none
    must_change_password: bool = False
    created_at: str = ""
    password_changed_at: str = ""
    last_login_at: str | None = None
    disabled_at: str | None = None

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN

    @property
    def active(self) -> bool:
        return self.disabled_at is None

    def can(self, permission: str) -> bool:
        """Whether this account may do what the permission names. A disabled account may do nothing."""
        if not self.active:
            return False
        return self.is_admin or permission in self.permissions

    @property
    def role_label(self) -> str:
        return Role.LABELS[self.role]


@dataclass(frozen=True)
class Session:
    """One signed-in browser. The token itself is never stored, only its SHA-256."""

    id: int
    user_id: int
    created_at: str
    last_seen_at: str
    expires_at: str
    ip: str
    user_agent: str
    revoked_at: str | None = None


@dataclass(frozen=True)
class AuditEntry:
    id: int
    at: str
    actor: str
    ip: str
    action: str
    target: str
    detail: str


_USERNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?\Z")

# Not a strength meter: only the passwords people actually reach for first.
# Length does the real work.
_COMMON = frozenset({
    "password", "password1", "password12", "password123", "password1234", "passw0rd", "1234567890", "12345678910",
    "0123456789", "0987654321", "1q2w3e4r5t", "qwertyuiop", "qwerty12345", "qwerty123456", "iloveyou123",
    "administrator", "admin12345", "admin123456", "letmein12345", "welcome12345", "changeme123", "netpulse123",
    "netpulse1234", "netpulseadmin", "1111111111", "0000000000", "abcdefghij", "abc1234567", "aaaaaaaaaa",
})


def validate_username(username: str | None) -> str:
    """The trimmed username, or AccountError. Letters, digits, dot, dash and underscore."""
    name = (username or "").strip()
    if not name:
        raise AccountError("username is required")
    if not USERNAME_MIN <= len(name) <= USERNAME_MAX:
        raise AccountError(f"username must be {USERNAME_MIN} to {USERNAME_MAX} characters")
    if not _USERNAME.match(name):
        raise AccountError("username may use letters, digits, dots, dashes and underscores, and starts and ends with a letter or digit")
    return name


def validate_password(password: str | None, username: str = "") -> str:
    """The password as typed, or AccountError saying what is wrong with it.

    Long beats clever: at least PASSWORD_MIN characters, not the username, not
    one character repeated, and not one of the first passwords anyone tries.
    Nothing is trimmed: spaces are part of a passphrase.
    """
    password = password or ""
    if len(password) < PASSWORD_MIN:
        raise AccountError(f"password must be at least {PASSWORD_MIN} characters")
    if len(password) > PASSWORD_MAX:
        raise AccountError(f"password must be at most {PASSWORD_MAX} characters")
    lowered = password.casefold()
    if username and username.casefold() in lowered and len(username) >= 4:
        raise AccountError("password must not contain the username")
    if len(set(password)) < 4:
        raise AccountError("password must use more than three different characters")
    if lowered in _COMMON:
        raise AccountError("password is one of the first anyone would guess; choose another")
    return password


def validate_role(role: str | None) -> str:
    if role not in Role.ALL:
        raise AccountError("role must be administrator or viewer")
    return role


def validate_grants(role: str, permissions) -> frozenset[str]:
    """The extra permissions an account keeps. An administrator has every one already, so keeps none."""
    chosen = {p for p in (permissions or ()) if p}
    unknown = chosen - set(GRANTABLE)
    if unknown:
        raise AccountError(f"permission cannot be granted: {sorted(unknown)[0]}")
    return frozenset() if role == Role.ADMIN else frozenset(chosen)
