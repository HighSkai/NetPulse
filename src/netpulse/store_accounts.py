"""The repository's account side (plan sections 35 to 37 and 44): settings by
name, users, sessions, sign-in attempts and the audit log.

A mixin for netpulse.store.Store, which owns the connection and the
transaction helper. Nothing here hashes a password or decides who may sign
in: it stores what netpulse.auth hands it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from netpulse.accounts import (
    AccountError,
    AuditEntry,
    Role,
    Session,
    User,
    validate_grants,
    validate_role,
    validate_username,
)

AUDIT_KEEP_DAYS = 365
ATTEMPTS_KEEP_DAYS = 30


class DuplicateUsername(AccountError):
    pass


class LastAdministrator(AccountError):
    """The change would leave NetPulse with no administrator who can sign in."""


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


class AccountsMixin:
    # Settings by name (schema v9). Values are JSON.

    def setting(self, key: str, default=None):
        row = self._conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return default if row is None else json.loads(row["value"])

    def settings_under(self, prefix: str) -> dict:
        """Every setting whose name starts with prefix, as {name: value}."""
        rows = self._conn.execute(
            "SELECT key, value FROM app_settings WHERE key >= ? AND key < ?", (prefix, prefix + "￿")
        ).fetchall()
        return {row["key"]: json.loads(row["value"]) for row in rows}

    def set_setting(self, key: str, value) -> None:
        self.set_settings({key: value})

    def set_settings(self, values: dict) -> None:
        """Several settings in one transaction: all saved, or none. None removes a setting."""
        with self._write():
            for key, value in values.items():
                if value is None:
                    self._conn.execute("DELETE FROM app_settings WHERE key = ?", (key,))
                else:
                    self._conn.execute(
                        "INSERT INTO app_settings (key, value) VALUES (?, ?) "
                        "ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                        (key, json.dumps(value, separators=(",", ":"))),
                    )

    def setting_or_create(self, key: str, make):
        """A setting made once and then kept, such as the cookie-signing key. Safe when two processes start at once."""
        found = self.setting(key)
        if found is not None:
            return found
        with self._write():
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
            if row is not None:
                return json.loads(row["value"])
            value = make()
            self._conn.execute("INSERT INTO app_settings (key, value) VALUES (?, ?)", (key, json.dumps(value)))
            return value

    # Users

    def count_users(self) -> int:
        return self._conn.execute("SELECT count(*) FROM users").fetchone()[0]

    def users(self) -> list[User]:
        rows = self._conn.execute("SELECT * FROM users ORDER BY username COLLATE NOCASE").fetchall()
        return [_user_from_row(r) for r in rows]

    def get_user(self, user_id: int) -> User:
        row = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            raise KeyError(f"user {user_id} not found")
        return _user_from_row(row)

    def find_user(self, username: str) -> tuple[User, str] | None:
        """(the account, its password hash) for a username, compared without case, or None."""
        row = self._conn.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)).fetchone()
        return None if row is None else (_user_from_row(row), row["password_hash"])

    def add_user(
        self, username: str, password_hash: str, role: str, permissions=(), *, must_change_password: bool = False,
        now: datetime | None = None, only_if_first: bool = False,
    ) -> User:
        """A new account. only_if_first refuses unless there is none yet: first-run setup, safe against a race."""
        name, role = validate_username(username), validate_role(role)
        grants = validate_grants(role, permissions)
        stamp = _stamp(now or datetime.now(UTC))
        try:
            with self._write():
                self._conn.execute("BEGIN IMMEDIATE")
                if only_if_first and self.count_users():
                    raise AccountError("setup has already been completed")
                cur = self._conn.execute(
                    """
                    INSERT INTO users (username, password_hash, role, permissions, must_change_password,
                                       created_at, password_changed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (name, password_hash, role, json.dumps(sorted(grants)), int(must_change_password), stamp, stamp),
                )
        except self._integrity_error as exc:
            raise DuplicateUsername(f"username {name} is already taken") from exc
        return self.get_user(cur.lastrowid)

    def update_user(self, user_id: int, *, role: str, permissions=(), disabled: bool, now: datetime | None = None) -> User:
        """Change an account's role, grants and whether it is disabled. Its sessions end if it is
        disabled or loses rights. Raises LastAdministrator rather than lock everyone out."""
        user = self.get_user(user_id)
        role = validate_role(role)
        grants = validate_grants(role, permissions)
        stamp = _stamp(now or datetime.now(UTC))
        with self._write():
            self._conn.execute("BEGIN IMMEDIATE")
            if user.is_admin and user.active and (role != Role.ADMIN or disabled) and self._active_admins() <= 1:
                raise LastAdministrator("this is the only administrator who can sign in; make another one first")
            self._conn.execute(
                "UPDATE users SET role = ?, permissions = ?, disabled_at = ? WHERE id = ?",
                (role, json.dumps(sorted(grants)), (user.disabled_at or stamp) if disabled else None, user_id),
            )
            lost = (user.is_admin and role != Role.ADMIN) or not grants >= user.permissions
            if disabled or lost:
                self._revoke(stamp, "user_id = ?", (user_id,))
        return self.get_user(user_id)

    def delete_user(self, user_id: int) -> User:
        user = self.get_user(user_id)
        with self._write():
            self._conn.execute("BEGIN IMMEDIATE")
            if user.is_admin and user.active and self._active_admins() <= 1:
                raise LastAdministrator("this is the only administrator who can sign in; make another one first")
            self._conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return user

    def set_password(
        self, user_id: int, password_hash: str, *, must_change: bool = False, keep_session: int | None = None,
        now: datetime | None = None,
    ) -> None:
        """Store a new password hash and end the account's sessions, except keep_session."""
        stamp = _stamp(now or datetime.now(UTC))
        with self._write():
            self._conn.execute(
                "UPDATE users SET password_hash = ?, password_changed_at = ?, must_change_password = ? WHERE id = ?",
                (password_hash, stamp, int(must_change), user_id),
            )
            self._revoke(stamp, "user_id = ? AND id IS NOT ?", (user_id, keep_session))

    def rehash_password(self, user_id: int, password_hash: str) -> None:
        """The same password under newer hashing parameters. Sessions stay."""
        with self._write():
            self._conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))

    def _active_admins(self) -> int:
        return self._conn.execute(
            "SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL"
        ).fetchone()[0]

    # Sessions

    def add_session(self, user_id: int, token_hash: str, ip: str, user_agent: str, *, now: datetime, expires: datetime) -> Session:
        stamp = _stamp(now)
        with self._write():
            cur = self._conn.execute(
                """
                INSERT INTO sessions (user_id, token_hash, created_at, last_seen_at, expires_at, ip, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, token_hash, stamp, stamp, _stamp(expires), ip[:45], user_agent[:200]),
            )
            self._conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (stamp, user_id))
        return self.get_session(cur.lastrowid)

    def get_session(self, session_id: int) -> Session:
        row = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            raise KeyError(f"session {session_id} not found")
        return Session(**_without(row, "token_hash"))

    def session_by_token(self, token_hash: str) -> tuple[Session, User] | None:
        """The session a token hash names and its account, whatever their state; the caller judges them."""
        row = self._conn.execute(
            """
            SELECT s.id AS session_id, s.created_at AS session_created_at, s.last_seen_at, s.expires_at, s.ip,
                   s.user_agent, s.revoked_at, u.*
            FROM sessions AS s JOIN users AS u ON u.id = s.user_id WHERE s.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        session = Session(
            id=row["session_id"], user_id=row["id"], created_at=row["session_created_at"],
            last_seen_at=row["last_seen_at"], expires_at=row["expires_at"], ip=row["ip"],
            user_agent=row["user_agent"], revoked_at=row["revoked_at"],
        )
        return session, _user_from_row(row)

    def touch_session(self, session_id: int, ip: str, *, now: datetime) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE sessions SET last_seen_at = ?, ip = ? WHERE id = ?", (_stamp(now), ip[:45], session_id)
            )

    def sessions_of(self, user_id: int, *, now: datetime) -> list[Session]:
        """An account's sessions that could still be used, newest first."""
        rows = self._conn.execute(
            """
            SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
            ORDER BY last_seen_at DESC, id DESC
            """,
            (user_id, _stamp(now)),
        ).fetchall()
        return [Session(**_without(r, "token_hash")) for r in rows]

    def revoke_session(self, session_id: int, *, now: datetime | None = None) -> None:
        with self._write():
            self._revoke(_stamp(now or datetime.now(UTC)), "id = ?", (session_id,))

    def revoke_sessions_of(self, user_id: int, *, except_session: int | None = None, now: datetime | None = None) -> int:
        with self._write():
            return self._revoke(
                _stamp(now or datetime.now(UTC)), "user_id = ? AND id IS NOT ?", (user_id, except_session)
            )

    def _revoke(self, stamp: str, where: str, args: tuple) -> int:
        return self._conn.execute(
            f"UPDATE sessions SET revoked_at = ? WHERE revoked_at IS NULL AND {where}", (stamp, *args)
        ).rowcount

    # Sign-in attempts (plan section 36)

    def record_attempt(self, username: str, ip: str, success: bool, *, now: datetime) -> None:
        with self._write():
            self._conn.execute(
                "INSERT INTO login_attempts (at, username, ip, success) VALUES (?, ?, ?, ?)",
                (_stamp(now), username.strip().casefold()[:64], ip[:45], int(success)),
            )

    def failed_attempts(self, *, since: datetime, ip: str | None = None, username: str | None = None) -> tuple[int, str | None]:
        """(failed sign-ins since then, the oldest one's time) for an address or a username.

        A success ends a streak: only failures after the latest success count.
        """
        column, value = ("ip", ip) if ip is not None else ("username", (username or "").strip().casefold()[:64])
        row = self._conn.execute(
            f"""
            SELECT count(*) AS failures, min(at) AS oldest FROM login_attempts
            WHERE {column} = :value AND success = 0 AND at >= :since AND at > coalesce((
                SELECT max(at) FROM login_attempts WHERE {column} = :value AND success = 1 AND at >= :since
            ), '')
            """,
            {"value": value, "since": _stamp(since)},
        ).fetchone()
        return row["failures"], row["oldest"]

    # The audit log (plan section 44)

    def audit(self, actor: str, action: str, target: str = "", detail: str = "", *, ip: str = "", now: datetime | None = None) -> None:
        with self._write():
            self._conn.execute(
                "INSERT INTO audit_log (at, actor, ip, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)",
                (_stamp(now or datetime.now(UTC)), (actor or "-")[:64], ip[:45], action[:64], target[:200], detail[:500]),
            )

    def audit_entries(self, limit: int = 200, before_id: int | None = None) -> list[AuditEntry]:
        """The newest entries, newest first; before_id pages further back."""
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE id < coalesce(?, 9223372036854775807) ORDER BY id DESC LIMIT ?",
            (before_id, limit),
        ).fetchall()
        return [AuditEntry(**dict(r)) for r in rows]

    def prune_accounts(self, now: datetime) -> tuple[int, int, int]:
        """Upkeep: (sessions, sign-in attempts, audit entries) deleted for being past use."""
        with self._write():
            sessions = self._conn.execute(
                "DELETE FROM sessions WHERE expires_at < ? OR revoked_at < ?",
                (_stamp(now - timedelta(days=1)), _stamp(now - timedelta(days=7))),
            ).rowcount
            attempts = self._conn.execute(
                "DELETE FROM login_attempts WHERE at < ?", (_stamp(now - timedelta(days=ATTEMPTS_KEEP_DAYS)),)
            ).rowcount
            audit = self._conn.execute(
                "DELETE FROM audit_log WHERE at < ?", (_stamp(now - timedelta(days=AUDIT_KEEP_DAYS)),)
            ).rowcount
        return sessions, attempts, audit


def _without(row, *names: str) -> dict:
    values = dict(row)
    for name in names:
        del values[name]
    return values


def _user_from_row(row) -> User:
    return User(
        id=row["id"],
        username=row["username"],
        role=row["role"],
        permissions=frozenset(json.loads(row["permissions"])),
        must_change_password=bool(row["must_change_password"]),
        created_at=row["created_at"],
        password_changed_at=row["password_changed_at"],
        last_login_at=row["last_login_at"],
        disabled_at=row["disabled_at"],
    )
