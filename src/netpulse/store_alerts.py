"""The repository's alert side (plan section 41): alerts, notification channels
and the record of what was sent. A mixin for netpulse.store.Store.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from netpulse.alerts import Alert, AlertRules, Channel, ChannelKind, Severity, Wanted
from netpulse.domain import TEXT_MAX_LEN, ValidationError

KEEP_ALERT_DAYS = 365
KEEP_NOTIFICATIONS = 500
RULES_KEY = "alerts.rules"


class DuplicateChannel(ValidationError):
    pass


def _stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).replace(microsecond=0).isoformat()


class AlertsMixin:
    def alert_rules(self) -> AlertRules:
        return AlertRules.of(self.setting(RULES_KEY, {}))

    def save_alert_rules(self, rules: AlertRules) -> None:
        self.set_setting(RULES_KEY, rules.__dict__)

    # Alerts

    def open_alert(self, wanted: Wanted, *, now: datetime, closed: bool = False) -> Alert | None:
        """Open the alert, or None when one like it is already open. closed=True records
        something that happened rather than a state: opened and closed at once."""
        stamp = _stamp(now)
        try:
            with self._write():
                cur = self._conn.execute(
                    """
                    INSERT INTO alerts (kind, severity, device_id, subject, detail, opened_at, closed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (wanted.kind, wanted.severity, wanted.device_id, wanted.subject[:200], wanted.detail[:500],
                     stamp, stamp if closed else None),
                )
        except self._integrity_error:
            return None
        return self.get_alert(cur.lastrowid)

    def close_alert(self, alert_id: int, *, now: datetime) -> Alert:
        with self._write():
            self._conn.execute(
                "UPDATE alerts SET closed_at = max(?, opened_at) WHERE id = ? AND closed_at IS NULL",
                (_stamp(now), alert_id),
            )
        return self.get_alert(alert_id)

    def ack_alert(self, alert_id: int, by: str, *, now: datetime | None = None) -> Alert:
        """Acknowledge: someone has seen it. It stays open until its cause ends."""
        self.get_alert(alert_id)
        with self._write():
            self._conn.execute(
                "UPDATE alerts SET acked_at = ?, acked_by = ? WHERE id = ? AND acked_at IS NULL",
                (_stamp(now or datetime.now(UTC)), by[:64], alert_id),
            )
        return self.get_alert(alert_id)

    def mark_notified(self, alert_ids, *, opened: bool = False, closed: bool = False) -> None:
        ids = list(alert_ids)
        if not ids or not (opened or closed):
            return
        sets = ", ".join(name for name, on in (("notified_open = 1", opened), ("notified_close = 1", closed)) if on)
        with self._write():
            self._conn.executemany(f"UPDATE alerts SET {sets} WHERE id = ?", [(i,) for i in ids])

    def get_alert(self, alert_id: int) -> Alert:
        row = self._conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None:
            raise KeyError(f"alert {alert_id} not found")
        return _alert_from_row(row)

    def open_alerts(self) -> list[Alert]:
        """Every open alert, the most severe and then the oldest first."""
        rows = self._conn.execute("SELECT * FROM alerts WHERE closed_at IS NULL").fetchall()
        alerts = [_alert_from_row(r) for r in rows]
        return sorted(alerts, key=lambda a: (-Severity.RANK[a.severity], a.opened_at, a.id))

    def recent_alerts(self, limit: int = 100) -> list[Alert]:
        """Closed alerts, newest first."""
        rows = self._conn.execute(
            "SELECT * FROM alerts WHERE closed_at IS NOT NULL ORDER BY closed_at DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_alert_from_row(r) for r in rows]

    def alerts_to_notify(self) -> list[Alert]:
        """Alerts whose opening or closing has not been sent yet, oldest first."""
        rows = self._conn.execute(
            """
            SELECT * FROM alerts
            WHERE notified_open = 0 OR (closed_at IS NOT NULL AND notified_close = 0)
            ORDER BY opened_at, id
            """
        ).fetchall()
        return [_alert_from_row(r) for r in rows]

    def count_open_alerts(self) -> tuple[int, int]:
        """(open alerts, of those not acknowledged), for the tab's badge."""
        row = self._conn.execute(
            "SELECT count(*) AS open, coalesce(sum(acked_at IS NULL), 0) AS unacked FROM alerts WHERE closed_at IS NULL"
        ).fetchone()
        return row["open"], row["unacked"]

    # Channels

    def channels(self) -> list[Channel]:
        rows = self._conn.execute("SELECT * FROM notification_channels ORDER BY name COLLATE NOCASE").fetchall()
        return [_channel_from_row(r) for r in rows]

    def get_channel(self, channel_id: int) -> Channel:
        row = self._conn.execute("SELECT * FROM notification_channels WHERE id = ?", (channel_id,)).fetchone()
        if row is None:
            raise KeyError(f"channel {channel_id} not found")
        return _channel_from_row(row)

    def save_channel(
        self, channel_id: int | None, name: str, kind: str, config: dict, *, enabled: bool = True,
        min_severity: str = Severity.WARNING, now: datetime | None = None,
    ) -> Channel:
        """Add a channel, or replace one. The config is already validated (netpulse.alerts.validate_channel)."""
        name = " ".join((name or "").split())
        if not 1 <= len(name) <= TEXT_MAX_LEN:
            raise ValidationError(f"name must be 1 to {TEXT_MAX_LEN} characters")
        if kind not in ChannelKind.ALL or min_severity not in Severity.ALL:
            raise ValidationError("kind or severity is not one NetPulse knows")
        body = json.dumps(config, separators=(",", ":"))
        try:
            with self._write():
                if channel_id is None:
                    channel_id = self._conn.execute(
                        "INSERT INTO notification_channels (name, kind, config, enabled, min_severity, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (name, kind, body, int(enabled), min_severity, _stamp(now or datetime.now(UTC))),
                    ).lastrowid
                else:
                    self._conn.execute(
                        "UPDATE notification_channels SET name = ?, kind = ?, config = ?, enabled = ?, min_severity = ? "
                        "WHERE id = ?",
                        (name, kind, body, int(enabled), min_severity, channel_id),
                    )
        except self._integrity_error as exc:
            raise DuplicateChannel(f"name: a channel called {name} already exists") from exc
        return self.get_channel(channel_id)

    def delete_channel(self, channel_id: int) -> Channel:
        channel = self.get_channel(channel_id)
        with self._write():
            self._conn.execute("DELETE FROM notification_channels WHERE id = ?", (channel_id,))
        return channel

    # What was sent

    def record_notification(self, channel: Channel, summary: str, error: str | None, *, now: datetime | None = None) -> None:
        with self._write():
            self._conn.execute(
                "INSERT INTO notifications (at, channel_id, channel_name, summary, ok, error) VALUES (?, ?, ?, ?, ?, ?)",
                (_stamp(now or datetime.now(UTC)), channel.id, channel.name, summary[:300], int(error is None),
                 None if error is None else error[:300]),
            )
            self._conn.execute(
                "DELETE FROM notifications WHERE id NOT IN (SELECT id FROM notifications ORDER BY id DESC LIMIT ?)",
                (KEEP_NOTIFICATIONS,),
            )

    def notifications(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def prune_alerts(self, now: datetime) -> int:
        """Upkeep: closed alerts older than KEEP_ALERT_DAYS go."""
        with self._write():
            return self._conn.execute(
                "DELETE FROM alerts WHERE closed_at IS NOT NULL AND closed_at < ?",
                (_stamp(now - timedelta(days=KEEP_ALERT_DAYS)),),
            ).rowcount


def _alert_from_row(row) -> Alert:
    values = dict(row)
    values["notified_open"] = bool(values["notified_open"])
    values["notified_close"] = bool(values["notified_close"])
    return Alert(**values)


def _channel_from_row(row) -> Channel:
    return Channel(
        id=row["id"], name=row["name"], kind=row["kind"], config=json.loads(row["config"]),
        enabled=bool(row["enabled"]), min_severity=row["min_severity"], created_at=row["created_at"],
    )
