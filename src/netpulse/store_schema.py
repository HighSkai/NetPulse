"""Schema versions 9 to 11 (plan sections 35 to 42), as migration steps.

netpulse.store applies them, in order, after its own steps 1 to 8, inside the
same transaction and after the same backup. Like those, a step never changes
once released: a file upgraded today must end up the same as one created today.

- v9: accounts. Key-value settings, users, sessions, sign-in attempts, the audit log.
- v10: inventory. Device groups and tags, the inventory and check columns on
  devices, and the rules that let a deleted device be restored or erased and
  old checks be pruned.
- v11: alerts, notification channels and what was sent.
"""

from __future__ import annotations

from netpulse.domain import CHECK_INTERVALS, NOTES_MAX_LEN, TAG_MAX_LEN, TEXT_MAX_LEN, CheckKind, DeviceKind

_UTC = "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]+00:00'"
_MAC = "'[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]'"


def _in(values) -> str:
    return ", ".join(repr(str(v)) if isinstance(v, str) else str(v) for v in values)


V9_SCHEMA: tuple[str, ...] = (
    # Settings added from v9 on are JSON values by name, so a new setting needs no new column.
    """
    CREATE TABLE app_settings (
        key TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
        value TEXT NOT NULL CHECK (json_valid(value))
    ) WITHOUT ROWID
    """,
    f"""
    CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL
            CHECK (length(username) BETWEEN 3 AND 32 AND username NOT GLOB '*[^A-Za-z0-9._-]*'),
        password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 20 AND 500),
        role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
        permissions TEXT NOT NULL DEFAULT '[]'
            CHECK (json_valid(permissions) AND json_type(permissions) = 'array'),
        must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
        created_at TEXT NOT NULL CHECK (created_at GLOB {_UTC}),
        password_changed_at TEXT NOT NULL CHECK (password_changed_at GLOB {_UTC}),
        last_login_at TEXT CHECK (last_login_at IS NULL OR last_login_at GLOB {_UTC}),
        disabled_at TEXT CHECK (disabled_at IS NULL OR disabled_at GLOB {_UTC})
    )
    """,
    "CREATE UNIQUE INDEX idx_users_username ON users(username COLLATE NOCASE)",
    # The browser holds the token; the file holds only its SHA-256, so a copy of
    # the database signs nobody in.
    f"""
    CREATE TABLE sessions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
        created_at TEXT NOT NULL CHECK (created_at GLOB {_UTC}),
        last_seen_at TEXT NOT NULL CHECK (last_seen_at GLOB {_UTC}),
        expires_at TEXT NOT NULL CHECK (expires_at GLOB {_UTC}),
        ip TEXT NOT NULL CHECK (length(ip) <= 45),
        user_agent TEXT NOT NULL CHECK (length(user_agent) <= 200),
        revoked_at TEXT CHECK (revoked_at IS NULL OR revoked_at GLOB {_UTC})
    )
    """,
    "CREATE INDEX idx_sessions_user ON sessions(user_id)",
    f"""
    CREATE TABLE login_attempts (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL CHECK (at GLOB {_UTC}),
        username TEXT NOT NULL CHECK (length(username) <= 64),
        ip TEXT NOT NULL CHECK (length(ip) <= 45),
        success INTEGER NOT NULL CHECK (success IN (0, 1))
    )
    """,
    "CREATE INDEX idx_login_attempts_at ON login_attempts(at)",
    # Who did what, kept as words: an entry outlives the account that made it.
    f"""
    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL CHECK (at GLOB {_UTC}),
        actor TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 64),
        ip TEXT NOT NULL DEFAULT '' CHECK (length(ip) <= 45),
        action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 64),
        target TEXT NOT NULL DEFAULT '' CHECK (length(target) <= 200),
        detail TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 500)
    )
    """,
    "CREATE INDEX idx_audit_at ON audit_log(at DESC, id DESC)",
)


V10_SCHEMA: tuple[str, ...] = (
    f"""
    CREATE TABLE device_groups (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND {TEXT_MAX_LEN} AND name = trim(name)),
        created_at TEXT NOT NULL CHECK (created_at GLOB {_UTC})
    )
    """,
    "CREATE UNIQUE INDEX idx_groups_name ON device_groups(name COLLATE NOCASE)",
    f"ALTER TABLE devices ADD COLUMN kind TEXT NOT NULL DEFAULT 'unknown' CHECK (kind IN ({_in(DeviceKind.ALL)}))",
    "ALTER TABLE devices ADD COLUMN group_id INTEGER REFERENCES device_groups(id)",
    f"ALTER TABLE devices ADD COLUMN vendor TEXT NOT NULL DEFAULT '' CHECK (length(vendor) <= {TEXT_MAX_LEN})",
    f"ALTER TABLE devices ADD COLUMN model TEXT NOT NULL DEFAULT '' CHECK (length(model) <= {TEXT_MAX_LEN})",
    f"ALTER TABLE devices ADD COLUMN location TEXT NOT NULL DEFAULT '' CHECK (length(location) <= {TEXT_MAX_LEN})",
    f"ALTER TABLE devices ADD COLUMN notes TEXT NOT NULL DEFAULT '' CHECK (length(notes) <= {NOTES_MAX_LEN})",
    f"ALTER TABLE devices ADD COLUMN mac TEXT CHECK (mac IS NULL OR mac GLOB {_MAC})",
    "ALTER TABLE devices ADD COLUMN paused INTEGER NOT NULL DEFAULT 0 CHECK (paused IN (0, 1))",
    f"ALTER TABLE devices ADD COLUMN interval_s INTEGER NOT NULL DEFAULT 30 CHECK (interval_s IN ({_in(CHECK_INTERVALS)}))",
    f"ALTER TABLE devices ADD COLUMN check_kind TEXT NOT NULL DEFAULT 'icmp' CHECK (check_kind IN ({_in(CheckKind.ALL)}))",
    "ALTER TABLE devices ADD COLUMN check_port INTEGER CHECK (check_port IS NULL OR check_port BETWEEN 1 AND 65535)",
    "ALTER TABLE devices ADD COLUMN alerts_muted INTEGER NOT NULL DEFAULT 0 CHECK (alerts_muted IN (0, 1))",
    f"""
    CREATE TABLE device_tags (
        device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        tag TEXT NOT NULL CHECK (length(tag) BETWEEN 1 AND {TAG_MAX_LEN} AND tag = trim(tag)),
        PRIMARY KEY (device_id, tag)
    ) WITHOUT ROWID
    """,
    "CREATE INDEX idx_device_tags_tag ON device_tags(tag)",
    # A device accepted from discovery already has a MAC address on the review list.
    """
    UPDATE devices SET mac = (
        SELECT h.mac FROM discovered_hosts AS h WHERE h.device_id = devices.id AND h.mac IS NOT NULL
    )
    WHERE deleted_at IS NULL AND EXISTS (
        SELECT 1 FROM discovered_hosts AS h WHERE h.device_id = devices.id AND h.mac IS NOT NULL
    )
    """,
    # A deleted device can now be restored, or erased with its history, and old
    # checks can be pruned (plan sections 39 and 42). What stays true: a deleted
    # device's name and host never change, and a stored check or event is never edited.
    "DROP TRIGGER devices_retired_read_only",
    """
    CREATE TRIGGER devices_retired_read_only BEFORE UPDATE OF name, host, created_at ON devices
    WHEN OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'retired devices are read-only');
    END
    """,
    "DROP TRIGGER devices_soft_delete_only",
    """
    CREATE TRIGGER devices_soft_delete_first BEFORE DELETE ON devices
    WHEN OLD.deleted_at IS NULL
    BEGIN
        SELECT RAISE(ABORT, 'devices are soft-deleted first: set deleted_at');
    END
    """,
    "DROP TRIGGER check_results_no_delete",
    "DROP TRIGGER device_events_no_delete",
)


V11_SCHEMA: tuple[str, ...] = (
    f"""
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('device_down', 'device_degraded', 'new_host', 'monitoring')),
        severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
        device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
        subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 200),
        detail TEXT NOT NULL DEFAULT '' CHECK (length(detail) <= 500),
        opened_at TEXT NOT NULL CHECK (opened_at GLOB {_UTC}),
        closed_at TEXT CHECK (closed_at IS NULL OR (closed_at GLOB {_UTC} AND closed_at >= opened_at)),
        acked_at TEXT CHECK (acked_at IS NULL OR acked_at GLOB {_UTC}),
        acked_by TEXT CHECK (acked_by IS NULL OR length(acked_by) <= 64),
        notified_open INTEGER NOT NULL DEFAULT 0 CHECK (notified_open IN (0, 1)),
        notified_close INTEGER NOT NULL DEFAULT 0 CHECK (notified_close IN (0, 1)),
        CHECK ((acked_at IS NULL) = (acked_by IS NULL))
    )
    """,
    "CREATE INDEX idx_alerts_time ON alerts(opened_at DESC, id DESC)",
    # At most one open alert of a kind for a device, however often a round looks;
    # and, for alerts about no device, one for each subject.
    """
    CREATE UNIQUE INDEX idx_alerts_one_open_device ON alerts(kind, device_id)
        WHERE closed_at IS NULL AND device_id IS NOT NULL
    """,
    """
    CREATE UNIQUE INDEX idx_alerts_one_open_other ON alerts(kind, subject)
        WHERE closed_at IS NULL AND device_id IS NULL
    """,
    f"""
    CREATE TABLE notification_channels (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND {TEXT_MAX_LEN} AND name = trim(name)),
        kind TEXT NOT NULL CHECK (kind IN ('webhook', 'discord', 'email')),
        config TEXT NOT NULL CHECK (json_valid(config) AND json_type(config) = 'object'),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        min_severity TEXT NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('info', 'warning', 'critical')),
        created_at TEXT NOT NULL CHECK (created_at GLOB {_UTC})
    )
    """,
    "CREATE UNIQUE INDEX idx_channels_name ON notification_channels(name COLLATE NOCASE)",
    f"""
    CREATE TABLE notifications (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL CHECK (at GLOB {_UTC}),
        channel_id INTEGER REFERENCES notification_channels(id) ON DELETE SET NULL,
        channel_name TEXT NOT NULL CHECK (length(channel_name) <= {TEXT_MAX_LEN}),
        summary TEXT NOT NULL CHECK (length(summary) <= 300),
        ok INTEGER NOT NULL CHECK (ok IN (0, 1)),
        error TEXT CHECK (error IS NULL OR length(error) <= 300)
    )
    """,
    "CREATE INDEX idx_notifications_at ON notifications(at DESC, id DESC)",
)


def to_v9(conn) -> None:
    for statement in V9_SCHEMA:
        conn.execute(statement)


def to_v10(conn) -> None:
    for statement in V10_SCHEMA:
        conn.execute(statement)
    # A file that already holds history keeps every check until its owner says
    # otherwise; a new file starts with the default retention (plan section 42).
    if conn.execute("SELECT 1 FROM check_results LIMIT 1").fetchone():
        conn.execute("INSERT INTO app_settings (key, value) VALUES ('retention.raw_days', '0')")


def to_v11(conn) -> None:
    for statement in V11_SCHEMA:
        conn.execute(statement)


MIGRATIONS = {9: to_v9, 10: to_v10, 11: to_v11}
