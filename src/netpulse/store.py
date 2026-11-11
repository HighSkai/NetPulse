"""SQLite repository. The only module that imports sqlite3 or contains SQL.

It stores and returns the domain values in netpulse.domain. The schema
enforces plan section 5 itself, not just this code:
- devices are soft-deleted (no DELETE) and retired rows are read-only;
- check_results is append-only (no DELETE or UPDATE), so history is never lost;
- at most one live device per host, compared case-insensitively;
- a result is either success with an int RTT, or failure with a known code.

Schema v2 (plan section 15) adds hourly rollups kept by a trigger, and
append-only outage events. Schema v3 (plan section 18) adds a one-row settings
table, schema v4 (plan section 20) the links the user declares between
devices, schema v5 (plan section 21) the review list of discovered hosts, and
schema v6 (plan section 28) packet captures and their per-second counts, and
schema v7 (plan section 30) path traces and their hops, and schema v8 (plan
section 31) the consent to checks from outside and the checks themselves.
Files are upgraded by fixed, versioned migration steps, after a backup.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from pathlib import Path

from netpulse.domain import (
    DEGRADED_WINDOW,
    DOWN_AFTER_FAILURES,
    FILTER_MAX_LEN,
    KEEP_CAPTURE_DAYS,
    KEEP_CAPTURES,
    KEEP_TRACES,
    NAME_MAX_LEN,
    Availability,
    Capture,
    CaptureState,
    CheckResult,
    Device,
    DeviceEvent,
    DeviceStatus,
    Hop,
    HopLabel,
    HourlyRollup,
    SecondCounts,
    Thresholds,
    Trace,
    ValidationError,
    connects_through,
    outage_event,
    validate_name,
    validate_parent,
    validate_thresholds,
)
from netpulse.network import DiscoveredHost, FoundHost, HostState
from netpulse.ping.hosts import validate_host
from netpulse.ping.result import PingResult
from netpulse.probes.globalping import KINDS, MAX_PROBES, CheckRequest, OutsideCheck, ProbeResult, Where

SCHEMA_VERSION = 8
# How long a write waits for another connection's write to finish.
BUSY_TIMEOUT_S = 5.0
# Plan section 28: a capture writes once a second while pages read, so the WAL
# file is cut back to this size after each checkpoint instead of keeping its peak.
WAL_SIZE_LIMIT = 16 * 1024 * 1024

log = logging.getLogger(__name__)

# UTC ISO-8601 with whole seconds, as utc_now() writes it. One fixed format
# means text order is time order, which the history index relies on.
_UTC = "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]+00:00'"
# The first 13 characters of such a timestamp: one UTC hour.
_UTC_HOUR = "'[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]'"

# Migration steps never change once released: a file upgraded today must end
# up the same as one created today. Changes go in a new step.

# Version 1. Error codes are listed literally: adding a code to Error.ALL needs
# a schema migration (tests/test_store.py fails until there is one).
_V1_SCHEMA: tuple[str, ...] = (
    f"""
    CREATE TABLE devices (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL
            CHECK (length(name) BETWEEN 1 AND {NAME_MAX_LEN} AND name = trim(name)),
        host TEXT NOT NULL
            CHECK (length(host) BETWEEN 1 AND 253
                   AND host NOT GLOB '*[^A-Za-z0-9.-]*'
                   AND substr(host, 1, 1) NOT IN ('-', '.')),
        created_at TEXT NOT NULL CHECK (created_at GLOB {_UTC}),
        updated_at TEXT NOT NULL CHECK (updated_at GLOB {_UTC}),
        deleted_at TEXT CHECK (deleted_at IS NULL OR deleted_at GLOB {_UTC})
    )
    """,
    """
    CREATE UNIQUE INDEX idx_devices_live_host
        ON devices(host COLLATE NOCASE) WHERE deleted_at IS NULL
    """,
    f"""
    CREATE TABLE check_results (
        id INTEGER PRIMARY KEY,
        device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
        checked_at TEXT NOT NULL CHECK (checked_at GLOB {_UTC}),
        success INTEGER NOT NULL CHECK (success IN (0, 1)),
        rtt_ms INTEGER CHECK (rtt_ms IS NULL OR (typeof(rtt_ms) = 'integer' AND rtt_ms >= 0)),
        error TEXT CHECK (error IS NULL OR error IN (
            'name_resolution', 'timeout', 'transmit_failed',
            'ttl_expired', 'unreachable', 'unreadable_output'
        )),
        CHECK ((success = 1 AND rtt_ms IS NOT NULL AND error IS NULL)
            OR (success = 0 AND rtt_ms IS NULL AND error IS NOT NULL))
    )
    """,
    # Latest result and history for one device, newest first, ties by id.
    """
    CREATE INDEX idx_results_device_time
        ON check_results(device_id, checked_at DESC, id DESC)
    """,
    """
    CREATE TRIGGER devices_soft_delete_only BEFORE DELETE ON devices
    BEGIN
        SELECT RAISE(ABORT, 'devices are soft-deleted: set deleted_at instead');
    END
    """,
    """
    CREATE TRIGGER devices_retired_read_only BEFORE UPDATE ON devices
    WHEN OLD.deleted_at IS NOT NULL
    BEGIN
        SELECT RAISE(ABORT, 'retired devices are read-only');
    END
    """,
    """
    CREATE TRIGGER check_results_no_delete BEFORE DELETE ON check_results
    BEGIN
        SELECT RAISE(ABORT, 'check history is append-only');
    END
    """,
    """
    CREATE TRIGGER check_results_no_update BEFORE UPDATE ON check_results
    BEGIN
        SELECT RAISE(ABORT, 'check history is append-only');
    END
    """,
)

# Version 2 (plan section 15): hourly rollups and outage events.
_V2_SCHEMA: tuple[str, ...] = (
    # One row per device per UTC hour. rtt_* cover successes only.
    f"""
    CREATE TABLE check_rollups_hourly (
        device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
        hour_utc TEXT NOT NULL CHECK (hour_utc GLOB {_UTC_HOUR}),
        checks INTEGER NOT NULL CHECK (checks >= 1),
        successes INTEGER NOT NULL CHECK (successes BETWEEN 0 AND checks),
        rtt_sum INTEGER NOT NULL CHECK (rtt_sum >= 0),
        rtt_min INTEGER,
        rtt_max INTEGER,
        CHECK ((successes = 0 AND rtt_sum = 0 AND rtt_min IS NULL AND rtt_max IS NULL)
            OR (successes > 0 AND rtt_min >= 0 AND rtt_max >= rtt_min)),
        PRIMARY KEY (device_id, hour_utc)
    ) WITHOUT ROWID
    """,
    # Built from the history so far; the trigger below keeps it up to date.
    """
    INSERT INTO check_rollups_hourly
        (device_id, hour_utc, checks, successes, rtt_sum, rtt_min, rtt_max)
    SELECT device_id, substr(checked_at, 1, 13), count(*), sum(success),
           coalesce(sum(rtt_ms), 0), min(rtt_ms), max(rtt_ms)
    FROM check_results
    GROUP BY device_id, substr(checked_at, 1, 13)
    """,
    # Same transaction as the check, so rollups always match the raw history.
    """
    CREATE TRIGGER check_results_roll_up AFTER INSERT ON check_results
    BEGIN
        INSERT INTO check_rollups_hourly
            (device_id, hour_utc, checks, successes, rtt_sum, rtt_min, rtt_max)
        VALUES (NEW.device_id, substr(NEW.checked_at, 1, 13), 1, NEW.success,
                coalesce(NEW.rtt_ms, 0), NEW.rtt_ms, NEW.rtt_ms)
        ON CONFLICT (device_id, hour_utc) DO UPDATE SET
            checks = checks + 1,
            successes = successes + excluded.successes,
            rtt_sum = rtt_sum + excluded.rtt_sum,
            rtt_min = min(coalesce(rtt_min, excluded.rtt_min), coalesce(excluded.rtt_min, rtt_min)),
            rtt_max = max(coalesce(rtt_max, excluded.rtt_max), coalesce(excluded.rtt_max, rtt_max));
    END
    """,
    f"""
    CREATE TABLE device_events (
        id INTEGER PRIMARY KEY,
        device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
        at TEXT NOT NULL CHECK (at GLOB {_UTC}),
        kind TEXT NOT NULL CHECK (kind IN ('down', 'up')),
        error TEXT CHECK (error IS NULL OR error IN (
            'name_resolution', 'timeout', 'transmit_failed',
            'ttl_expired', 'unreachable', 'unreadable_output'
        )),
        CHECK ((kind = 'down' AND error IS NOT NULL) OR (kind = 'up' AND error IS NULL))
    )
    """,
    """
    CREATE INDEX idx_events_device_time ON device_events(device_id, at DESC, id DESC)
    """,
    """
    CREATE TRIGGER device_events_no_delete BEFORE DELETE ON device_events
    BEGIN
        SELECT RAISE(ABORT, 'device events are append-only');
    END
    """,
    """
    CREATE TRIGGER device_events_no_update BEFORE UPDATE ON device_events
    BEGIN
        SELECT RAISE(ABORT, 'device events are append-only');
    END
    """,
)


# Version 3 (plan section 18): one row of typed settings, starting at the defaults.
_V3_SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        degraded_latency_ms INTEGER NOT NULL
            CHECK (typeof(degraded_latency_ms) = 'integer' AND degraded_latency_ms BETWEEN 1 AND 1000),
        degraded_failures INTEGER NOT NULL
            CHECK (typeof(degraded_failures) = 'integer' AND degraded_failures BETWEEN 1 AND 10)
    )
    """,
    """
    INSERT INTO settings (id, degraded_latency_ms, degraded_failures) VALUES (1, 150, 2)
    """,
    """
    CREATE TRIGGER settings_keep_the_row BEFORE DELETE ON settings
    BEGIN
        SELECT RAISE(ABORT, 'settings has exactly one row: update it instead');
    END
    """,
)


# Version 4 (plan section 20): what a device connects through, as the user
# declared it. Settings, not history: rows are replaced and deleted freely,
# but only ever join two live devices.
_V4_SCHEMA: tuple[str, ...] = (
    """
    CREATE TABLE device_links (
        device_id INTEGER PRIMARY KEY REFERENCES devices(id),
        parent_id INTEGER NOT NULL REFERENCES devices(id)
            CHECK (typeof(parent_id) = 'integer'),
        CHECK (parent_id <> device_id)
    )
    """,
    """
    CREATE TRIGGER device_links_join_live_devices BEFORE INSERT ON device_links
    WHEN EXISTS (
        SELECT 1 FROM devices WHERE id IN (NEW.device_id, NEW.parent_id) AND deleted_at IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'a link joins two live devices');
    END
    """,
    """
    CREATE TRIGGER device_links_stay_live BEFORE UPDATE ON device_links
    WHEN EXISTS (
        SELECT 1 FROM devices WHERE id IN (NEW.device_id, NEW.parent_id) AND deleted_at IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'a link joins two live devices');
    END
    """,
)


# Version 5 (plan section 21): the review list of hosts a sweep found. Settings,
# not history: a sweep updates rows. Identity is the MAC address when known;
# among hosts with no MAC address, the address.
_MAC = "'[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]-[0-9A-F][0-9A-F]'"
_V5_SCHEMA: tuple[str, ...] = (
    f"""
    CREATE TABLE discovered_hosts (
        id INTEGER PRIMARY KEY,
        address TEXT NOT NULL
            CHECK (length(address) BETWEEN 7 AND 15 AND address NOT GLOB '*[^0-9.]*'),
        mac TEXT UNIQUE CHECK (mac IS NULL OR mac GLOB {_MAC}),
        name TEXT CHECK (name IS NULL OR length(name) BETWEEN 1 AND 253),
        answers_ping INTEGER NOT NULL CHECK (answers_ping IN (0, 1)),
        first_seen TEXT NOT NULL CHECK (first_seen GLOB {_UTC}),
        last_seen TEXT NOT NULL CHECK (last_seen GLOB {_UTC} AND last_seen >= first_seen),
        state TEXT NOT NULL DEFAULT 'new' CHECK (state IN ('new', 'accepted', 'ignored')),
        device_id INTEGER REFERENCES devices(id),
        CHECK ((state = 'accepted') = (device_id IS NOT NULL))
    )
    """,
    """
    CREATE UNIQUE INDEX idx_discovered_address_without_mac
        ON discovered_hosts(address) WHERE mac IS NULL
    """,
)


# Version 6 (plan section 28): packet captures and their per-second counts.
# Diagnostics, not monitoring history: captures are deleted by retention or by
# the user, and their counts with them. A capture's file name is a bare name in
# the captures folder, never a path. At most one capture runs.
_V6_SCHEMA: tuple[str, ...] = (
    f"""
    CREATE TABLE captures (
        id INTEGER PRIMARY KEY,
        interface TEXT NOT NULL CHECK (length(interface) BETWEEN 1 AND 255),
        description TEXT NOT NULL CHECK (length(description) <= 255),
        filter TEXT NOT NULL CHECK (length(filter) <= {FILTER_MAX_LEN}),
        snaplen INTEGER NOT NULL CHECK (typeof(snaplen) = 'integer' AND snaplen BETWEEN 64 AND 262144),
        started_at TEXT NOT NULL CHECK (started_at GLOB {_UTC}),
        ended_at TEXT CHECK (ended_at IS NULL OR (ended_at GLOB {_UTC} AND ended_at >= started_at)),
        packets INTEGER NOT NULL DEFAULT 0 CHECK (packets >= 0),
        bytes INTEGER NOT NULL DEFAULT 0 CHECK (bytes >= 0),
        file TEXT NOT NULL UNIQUE
            CHECK (file GLOB 'capture-*.pcap' AND file NOT GLOB '*[/\\:]*' AND length(file) <= 100),
        state TEXT NOT NULL CHECK (state IN ('running', 'stopped', 'limit', 'failed', 'interrupted')),
        note TEXT CHECK (note IS NULL OR length(note) <= 500),
        CHECK ((state = 'running') = (ended_at IS NULL))
    )
    """,
    """
    CREATE UNIQUE INDEX idx_one_running_capture ON captures(state) WHERE state = 'running'
    """,
    """
    CREATE TABLE capture_rates (
        capture_id INTEGER NOT NULL REFERENCES captures(id) ON DELETE CASCADE,
        second INTEGER NOT NULL CHECK (typeof(second) = 'integer' AND second >= 0),
        bytes_in INTEGER NOT NULL CHECK (bytes_in >= 0),
        bytes_out INTEGER NOT NULL CHECK (bytes_out >= 0),
        packets_in INTEGER NOT NULL CHECK (packets_in >= 0),
        packets_out INTEGER NOT NULL CHECK (packets_out >= 0),
        protocols TEXT NOT NULL CHECK (json_valid(protocols) AND json_type(protocols) = 'object'),
        PRIMARY KEY (capture_id, second)
    ) WITHOUT ROWID
    """,
)


# Version 7 (plan section 30): path traces and their hops. Diagnostics, not
# history: the last KEEP_TRACES are kept, and a trace's hops go with it.
_V7_SCHEMA: tuple[str, ...] = (
    f"""
    CREATE TABLE traces (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
        address TEXT NOT NULL CHECK (length(address) BETWEEN 7 AND 15 AND address NOT GLOB '*[^0-9.]*'),
        started_at TEXT NOT NULL CHECK (started_at GLOB {_UTC}),
        rounds INTEGER NOT NULL CHECK (typeof(rounds) = 'integer' AND rounds BETWEEN 1 AND 10),
        reached INTEGER NOT NULL CHECK (reached IN (0, 1)),
        error TEXT CHECK (error IS NULL OR length(error) <= 500)
    )
    """,
    f"""
    CREATE TABLE trace_hops (
        trace_id INTEGER NOT NULL REFERENCES traces(id) ON DELETE CASCADE,
        ttl INTEGER NOT NULL CHECK (typeof(ttl) = 'integer' AND ttl BETWEEN 1 AND 30),
        address TEXT CHECK (address IS NULL OR (length(address) BETWEEN 7 AND 15 AND address NOT GLOB '*[^0-9.]*')),
        sent INTEGER NOT NULL CHECK (sent >= 0),
        received INTEGER NOT NULL CHECK (received BETWEEN 0 AND sent),
        best_ms INTEGER CHECK (best_ms IS NULL OR best_ms >= 0),
        avg_ms REAL CHECK (avg_ms IS NULL OR avg_ms >= 0),
        worst_ms INTEGER CHECK (worst_ms IS NULL OR worst_ms >= best_ms),
        name TEXT CHECK (name IS NULL OR length(name) BETWEEN 1 AND 253),
        label TEXT CHECK (label IS NULL OR label IN ({", ".join(repr(label) for label in HopLabel.ALL)})),
        others TEXT NOT NULL CHECK (json_valid(others) AND json_type(others) = 'array'),
        note TEXT CHECK (note IS NULL OR length(note) <= 500),
        CHECK ((received = 0) = (address IS NULL) AND (received = 0) = (avg_ms IS NULL)),
        PRIMARY KEY (trace_id, ttl)
    ) WITHOUT ROWID
    """,
)


# Version 8 (plan section 31): whether the user agreed to checks from outside,
# kept in the settings row, and the checks. Plan section 31 called this v7, but
# v7 was released with plan section 30 and released steps never change. The
# last KEEP_OUTSIDE_CHECKS are kept.
KEEP_OUTSIDE_CHECKS = 50
_V8_SCHEMA: tuple[str, ...] = (
    f"""
    ALTER TABLE settings ADD COLUMN outside_consent_at TEXT
        CHECK (outside_consent_at IS NULL OR outside_consent_at GLOB {_UTC})
    """,
    f"""
    CREATE TABLE outside_checks (
        id INTEGER PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ({", ".join(repr(k) for k in KINDS)})),
        target TEXT NOT NULL CHECK (length(target) BETWEEN 1 AND 253),
        scope TEXT NOT NULL CHECK (scope IN ('world', 'continent', 'country')),
        code TEXT CHECK ((scope = 'world') = (code IS NULL) AND (code IS NULL OR length(code) = 2)),
        probes INTEGER NOT NULL CHECK (typeof(probes) = 'integer' AND probes BETWEEN 1 AND {MAX_PROBES}),
        port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
        path TEXT NOT NULL CHECK (length(path) BETWEEN 1 AND 200),
        started_at TEXT NOT NULL CHECK (started_at GLOB {_UTC}),
        measurement_id TEXT CHECK (measurement_id IS NULL OR length(measurement_id) BETWEEN 1 AND 64),
        results TEXT NOT NULL CHECK (json_valid(results) AND json_type(results) = 'array'),
        error TEXT CHECK (error IS NULL OR length(error) <= 500)
    )
    """,
)


def _to_v1(conn: sqlite3.Connection) -> None:
    for statement in _V1_SCHEMA:
        conn.execute(statement)


def _to_v2(conn: sqlite3.Connection) -> None:
    for statement in _V2_SCHEMA:
        conn.execute(statement)
    _replay_outage_events(conn)


def _to_v3(conn: sqlite3.Connection) -> None:
    for statement in _V3_SCHEMA:
        conn.execute(statement)


def _to_v4(conn: sqlite3.Connection) -> None:
    for statement in _V4_SCHEMA:
        conn.execute(statement)


def _to_v5(conn: sqlite3.Connection) -> None:
    for statement in _V5_SCHEMA:
        conn.execute(statement)


def _to_v6(conn: sqlite3.Connection) -> None:
    for statement in _V6_SCHEMA:
        conn.execute(statement)


def _to_v7(conn: sqlite3.Connection) -> None:
    for statement in _V7_SCHEMA:
        conn.execute(statement)


def _to_v8(conn: sqlite3.Connection) -> None:
    for statement in _V8_SCHEMA:
        conn.execute(statement)


# Step that brings a file up to each version, applied in order.
_MIGRATIONS = {1: _to_v1, 2: _to_v2, 3: _to_v3, 4: _to_v4, 5: _to_v5, 6: _to_v6, 7: _to_v7, 8: _to_v8}


@dataclass(frozen=True)
class Upkeep:
    """What one maintenance pass did (plan section 32)."""

    traces: int  # deleted past KEEP_TRACES
    outside_checks: int  # deleted past KEEP_OUTSIDE_CHECKS
    checkpointed: bool  # the whole write-ahead log went into the database file


class DuplicateLiveHost(ValueError):
    pass


class CannotOpenDatabase(RuntimeError):
    """The file cannot be used as a NetPulse database. Callers never see sqlite3 errors here."""


class UnsupportedDatabase(CannotOpenDatabase):
    """A SQLite file, but not one this NetPulse can use (unknown or missing schema version)."""


class _Unchanged:
    """update_device's default for parent_id: leave the declared link as it is."""


UNCHANGED = _Unchanged()


def database_size(path: str | Path) -> int:
    """Bytes on disk: the file and its write-ahead log (plan section 32). Missing parts count as nothing."""
    total = 0
    for part in (Path(path), Path(f"{path}-wal")):
        try:
            total += part.stat().st_size
        except OSError:
            pass
    return total


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class Store:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        _migrate(self._conn)

    @classmethod
    def open(cls, path: str | Path) -> Store:
        """Open (or create) a NetPulse database file.

        Raises CannotOpenDatabase, and closes the connection, if the file
        cannot be used; an open handle would keep the file locked on Windows.
        """
        try:
            conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_S)
        except sqlite3.Error as exc:
            raise CannotOpenDatabase(f"cannot open: {exc}") from exc
        try:
            # The scheduler thread writes while web requests read and write,
            # each on its own connection. WAL lets readers run during a write.
            # synchronous=NORMAL is safe in WAL; a power cut can lose only the
            # last few commits, which for monitoring data is the next check.
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute(f"PRAGMA journal_size_limit = {WAL_SIZE_LIMIT}")
            return cls(conn)
        except sqlite3.Error as exc:
            conn.close()
            raise CannotOpenDatabase(f"cannot open: {exc}") from exc
        except BaseException:
            conn.close()
            raise

    def close(self) -> None:
        self._conn.close()

    def add_device(self, name: str, host: str, *, now: str | None = None) -> Device:
        clean_name = validate_name(name)
        clean_host = validate_host(host)
        stamp = _timestamp(now)
        with self._write(host=clean_host):
            cur = self._conn.execute(
                """
                INSERT INTO devices (name, host, created_at, updated_at, deleted_at)
                VALUES (?, ?, ?, ?, NULL)
                """,
                (clean_name, clean_host, stamp, stamp),
            )
        return self.get_device(cur.lastrowid)

    def update_device(
        self,
        device_id: int,
        *,
        name: str | None = None,
        host: str | None = None,
        parent_id: str | int | None | _Unchanged = UNCHANGED,
        now: str | None = None,
    ) -> Device:
        """Edit a live device. The id stays the same, so its history stays attached.

        parent_id is what the device connects through (plan section 20): a
        device id, or None or "" for none. Everything is saved, or nothing.
        """
        device = self.get_device(device_id)
        if not device.is_live:
            raise ValidationError("cannot edit a deleted device")
        clean_name = validate_name(name) if name is not None else device.name
        clean_host = validate_host(host) if host is not None else device.host
        parent = parent_id if isinstance(parent_id, _Unchanged) else validate_parent(parent_id)
        stamp = _timestamp(now)
        with self._write(host=clean_host):
            # Taken now, so the loop check below sees every link until commit.
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                """
                UPDATE devices SET name = ?, host = ?, updated_at = ?
                WHERE id = ? AND deleted_at IS NULL
                """,
                (clean_name, clean_host, stamp, device_id),
            )
            if not isinstance(parent, _Unchanged):
                self._set_link(device_id, clean_name, parent)
        return self.get_device(device_id)

    def _set_link(self, device_id: int, name: str, parent_id: int | None) -> None:
        if parent_id is None:
            self._conn.execute("DELETE FROM device_links WHERE device_id = ?", (device_id,))
            return
        if parent_id == device_id:
            raise ValidationError("a device cannot connect through itself")
        parent = self._conn.execute(
            "SELECT name FROM devices WHERE id = ? AND deleted_at IS NULL", (parent_id,)
        ).fetchone()
        if parent is None:
            raise ValidationError("that device is no longer monitored; choose another")
        if device_id in connects_through(parent_id, self.links()):
            raise ValidationError(f"{parent['name']} already connects through {name}, so that would make a loop")
        self._conn.execute(
            """
            INSERT INTO device_links (device_id, parent_id) VALUES (?, ?)
            ON CONFLICT (device_id) DO UPDATE SET parent_id = excluded.parent_id
            """,
            (device_id, parent_id),
        )

    def links(self) -> dict[int, int]:
        """Declared links between live devices: {device id: the id of what it connects through}."""
        rows = self._conn.execute(
            """
            SELECT l.device_id, l.parent_id
            FROM device_links AS l
            JOIN devices AS d ON d.id = l.device_id AND d.deleted_at IS NULL
            JOIN devices AS p ON p.id = l.parent_id AND p.deleted_at IS NULL
            """
        ).fetchall()
        return {row["device_id"]: row["parent_id"] for row in rows}

    def soft_delete(self, device_id: int, *, now: str | None = None) -> Device:
        """Retire a device. Its row and check history are kept; it is no longer live.

        Links to and from it go (plan section 20): they are settings, not history.
        """
        device = self.get_device(device_id)
        if not device.is_live:
            return device
        stamp = _timestamp(now)
        with self._write():
            self._conn.execute(
                "DELETE FROM device_links WHERE device_id = ? OR parent_id = ?", (device_id, device_id)
            )
            # Plan section 21: a host accepted from discovery is not offered again.
            self._conn.execute(
                "UPDATE discovered_hosts SET state = 'ignored', device_id = NULL WHERE device_id = ?",
                (device_id,),
            )
            self._conn.execute(
                "UPDATE devices SET deleted_at = ?, updated_at = ? WHERE id = ?",
                (stamp, stamp, device_id),
            )
        return self.get_device(device_id)

    # Discovery (plan section 21)

    def record_sweep(self, found: list[FoundHost], *, now: str | None = None) -> None:
        """Add or update each host a sweep found. A host is never listed twice, and its state is kept.

        Identity is the MAC address. A host seen without one matches the
        newest row at its address; a host seen with one also claims the row
        it had at its address before its MAC address was known.
        """
        stamp = _timestamp(now)
        with self._write():
            for host in found:
                row = None
                if host.mac is not None:
                    row = self._conn.execute(
                        "SELECT * FROM discovered_hosts WHERE mac = ?", (host.mac,)
                    ).fetchone() or self._conn.execute(
                        "SELECT * FROM discovered_hosts WHERE mac IS NULL AND address = ?", (str(host.address),)
                    ).fetchone()
                else:
                    row = self._conn.execute(
                        "SELECT * FROM discovered_hosts WHERE address = ? ORDER BY last_seen DESC, id DESC",
                        (str(host.address),),
                    ).fetchone()
                if row is None:
                    self._conn.execute(
                        """
                        INSERT INTO discovered_hosts (address, mac, name, answers_ping, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (str(host.address), host.mac, host.name, int(host.answers_ping), stamp, stamp),
                    )
                else:
                    self._conn.execute(
                        """
                        UPDATE discovered_hosts
                        SET address = ?, mac = coalesce(?, mac), name = coalesce(?, name),
                            answers_ping = ?, last_seen = ?
                        WHERE id = ?
                        """,
                        (str(host.address), host.mac, host.name, int(host.answers_ping), stamp, row["id"]),
                    )

    def discovered(self) -> list[DiscoveredHost]:
        """The review list, by address."""
        rows = self._conn.execute("SELECT * FROM discovered_hosts").fetchall()
        return sorted((_discovered_from_row(r) for r in rows), key=lambda h: (h.address, h.id))

    def get_discovered(self, host_id: int) -> DiscoveredHost:
        row = self._conn.execute("SELECT * FROM discovered_hosts WHERE id = ?", (host_id,)).fetchone()
        if row is None:
            raise KeyError(f"discovered host {host_id} not found")
        return _discovered_from_row(row)

    def accept_discovered(self, host_id: int, *, now: str | None = None) -> Device:
        """Monitor a discovered host through the ordinary add path, or link it to the
        device that already monitors its address."""
        host = self.get_discovered(host_id)
        existing = self._conn.execute(
            "SELECT * FROM devices WHERE host = ? COLLATE NOCASE AND deleted_at IS NULL", (str(host.address),)
        ).fetchone()
        device = _device_from_row(existing) if existing else self.add_device(
            host.suggested_name, str(host.address), now=now
        )
        self._set_host_state(host_id, HostState.ACCEPTED, device.id)
        return device

    def ignore_discovered(self, host_id: int) -> None:
        self.get_discovered(host_id)
        self._set_host_state(host_id, HostState.IGNORED, None)

    def restore_discovered(self, host_id: int) -> None:
        """Review again: back on the list as new."""
        self.get_discovered(host_id)
        self._set_host_state(host_id, HostState.NEW, None)

    def _set_host_state(self, host_id: int, state: str, device_id: int | None) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE discovered_hosts SET state = ?, device_id = ? WHERE id = ?", (state, device_id, host_id)
            )

    def get_device(self, device_id: int) -> Device:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"device {device_id} not found")
        return _device_from_row(row)

    def list_live_devices(self) -> list[Device]:
        rows = self._conn.execute(
            "SELECT * FROM devices WHERE deleted_at IS NULL ORDER BY name COLLATE NOCASE, id"
        ).fetchall()
        return [_device_from_row(r) for r in rows]

    def insert_result(
        self,
        device_id: int,
        result: PingResult,
        *,
        now: str | None = None,
    ) -> CheckResult:
        """Store one check. Its hourly rollup and any outage event go in the same transaction."""
        stamp = _timestamp(now)
        with self._write():
            cur = self._conn.execute(
                """
                INSERT INTO check_results (device_id, checked_at, success, rtt_ms, error)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    stamp,
                    1 if result.success else 0,
                    result.rtt_ms,
                    result.error,
                ),
            )
            _record_outage_event(self._conn, device_id)
        row = self._conn.execute(
            "SELECT * FROM check_results WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return _result_from_row(row)

    def checks_since(self, device_id: int, since: str) -> list[CheckResult]:
        """A device's checks at or after since, oldest first (plan section 17).

        Reads the history index backwards, so there is no sort step.
        """
        rows = self._conn.execute(
            """
            SELECT * FROM check_results
            WHERE device_id = ? AND checked_at >= ?
            ORDER BY checked_at, id
            """,
            (device_id, _timestamp(since)),
        ).fetchall()
        return [_result_from_row(r) for r in rows]

    def hourly_rollups(self, device_id: int, since_hour: str) -> list[HourlyRollup]:
        """A device's hourly rollups from since_hour ('YYYY-MM-DDTHH'), oldest first."""
        rows = self._conn.execute(
            """
            SELECT * FROM check_rollups_hourly
            WHERE device_id = ? AND hour_utc >= ?
            ORDER BY hour_utc
            """,
            (device_id, since_hour),
        ).fetchall()
        return [HourlyRollup(**dict(r)) for r in rows]

    def recent_checks(self, limit: int = DEGRADED_WINDOW) -> dict[int, list[CheckResult]]:
        """Each live device's last limit checks, newest first (plan section 18).

        One query: SQLite does one history-index lookup per device inside it.
        Devices never checked are absent.
        """
        rows = self._conn.execute(
            """
            SELECT r.* FROM devices AS d
            JOIN check_results AS r ON r.id IN (
                SELECT id FROM check_results WHERE device_id = d.id
                ORDER BY checked_at DESC, id DESC LIMIT ?
            )
            WHERE d.deleted_at IS NULL
            ORDER BY r.device_id, r.checked_at DESC, r.id DESC
            """,
            (limit,),
        ).fetchall()
        recent: dict[int, list[CheckResult]] = {}
        for row in rows:
            recent.setdefault(row["device_id"], []).append(_result_from_row(row))
        return recent

    def thresholds(self) -> Thresholds:
        """When a device that is up counts as degraded (plan section 18)."""
        row = self._conn.execute(
            "SELECT degraded_latency_ms, degraded_failures FROM settings WHERE id = 1"
        ).fetchone()
        return Thresholds(latency_ms=row["degraded_latency_ms"], failures=row["degraded_failures"])

    def save_thresholds(self, latency_ms: str | int, failures: str | int) -> Thresholds:
        """Validate and store new thresholds. Raises ValidationError for a bad value."""
        new = validate_thresholds(latency_ms, failures)
        with self._write():
            self._conn.execute(
                "UPDATE settings SET degraded_latency_ms = ?, degraded_failures = ? WHERE id = 1",
                (new.latency_ms, new.failures),
            )
        return self.thresholds()

    def availability_of(self, device_id: int, since_hour: str) -> Availability:
        """One device's checks and successes from since_hour on, from the rollups."""
        row = self._conn.execute(
            """
            SELECT coalesce(sum(checks), 0) AS checks, coalesce(sum(successes), 0) AS successes
            FROM check_rollups_hourly WHERE device_id = ? AND hour_utc >= ?
            """,
            (device_id, since_hour),
        ).fetchone()
        return Availability(checks=row["checks"], successes=row["successes"])

    def last_success(self, device_id: int) -> CheckResult | None:
        """The newest successful check, or None.

        The rollups find the newest hour with a success first, so a device that
        has been down for a month costs one hour of raw rows, not a month.
        """
        row = self._conn.execute(
            """
            SELECT * FROM check_results
            WHERE device_id = :device AND success = 1 AND checked_at >= (
                SELECT hour_utc FROM check_rollups_hourly
                WHERE device_id = :device AND successes > 0
                ORDER BY hour_utc DESC LIMIT 1
            )
            ORDER BY checked_at DESC, id DESC LIMIT 1
            """,
            {"device": device_id},
        ).fetchone()
        return None if row is None else _result_from_row(row)

    def events(self, device_id: int, *, limit: int = 100) -> list[DeviceEvent]:
        """A device's outage events, newest first."""
        rows = self._conn.execute(
            """
            SELECT * FROM device_events WHERE device_id = ?
            ORDER BY at DESC, id DESC LIMIT ?
            """,
            (device_id, limit),
        ).fetchall()
        return [_event_from_row(r) for r in rows]

    def latest_events(self, per_device: int) -> list[DeviceEvent]:
        """Each live device's newest per_device outage events, newest first overall (plan section 26).

        One query: SQLite reads each device's newest events from the event index
        inside it, then sorts only those. Every device's newest event is always
        among them, so its outage, if one is going on, is too.
        """
        rows = self._conn.execute(
            """
            SELECT e.* FROM devices AS d
            JOIN device_events AS e ON e.id IN (
                SELECT id FROM device_events WHERE device_id = d.id
                ORDER BY at DESC, id DESC LIMIT ?
            )
            WHERE d.deleted_at IS NULL
            ORDER BY e.at DESC, e.id DESC
            """,
            (per_device,),
        ).fetchall()
        return [_event_from_row(r) for r in rows]

    def rollups_since(self, since_hour: str) -> list[HourlyRollup]:
        """Every live device's hourly rollups from since_hour ('YYYY-MM-DDTHH') on (plan section 26).

        One query, by the rollups' primary key, device by device.
        """
        rows = self._conn.execute(
            """
            SELECT r.* FROM devices AS d
            JOIN check_rollups_hourly AS r ON r.device_id = d.id AND r.hour_utc >= ?
            WHERE d.deleted_at IS NULL
            ORDER BY r.device_id, r.hour_utc
            """,
            (since_hour,),
        ).fetchall()
        return [HourlyRollup(**dict(r)) for r in rows]

    def history(self, device_id: int, *, limit: int = 100) -> list[CheckResult]:
        rows = self._conn.execute(
            """
            SELECT * FROM check_results
            WHERE device_id = ?
            ORDER BY checked_at DESC, id DESC
            LIMIT ?
            """,
            (device_id, limit),
        ).fetchall()
        return [_result_from_row(r) for r in rows]

    def latest_result(self, device_id: int) -> CheckResult | None:
        newest = self.history(device_id, limit=1)
        return newest[0] if newest else None

    def live_device_statuses(self) -> list[DeviceStatus]:
        """Current status: each live device with its latest result, in name order.

        One query (plan section 16). SQLite does one history-index lookup per
        device inside it, instead of one query per device from Python.
        """
        rows = self._conn.execute(
            """
            SELECT d.*, r.id AS result_id, r.checked_at, r.success, r.rtt_ms, r.error
            FROM devices AS d
            LEFT JOIN check_results AS r ON r.id = (
                SELECT id FROM check_results WHERE device_id = d.id
                ORDER BY checked_at DESC, id DESC LIMIT 1
            )
            WHERE d.deleted_at IS NULL
            ORDER BY d.name COLLATE NOCASE, d.id
            """
        ).fetchall()
        return [
            DeviceStatus(
                _device_from_row(row),
                None
                if row["result_id"] is None
                else CheckResult(
                    id=row["result_id"],
                    device_id=row["id"],
                    checked_at=row["checked_at"],
                    success=bool(row["success"]),
                    rtt_ms=row["rtt_ms"],
                    error=row["error"],
                ),
            )
            for row in rows
        ]

    def availability_since(self, hour_utc: str) -> dict[int, Availability]:
        """Checks and successes per live device, from hourly rollups at or after hour_utc.

        hour_utc is 'YYYY-MM-DDTHH'. Devices with no checks since then are absent.
        """
        rows = self._conn.execute(
            """
            SELECT r.device_id, sum(r.checks) AS checks, sum(r.successes) AS successes
            FROM devices AS d
            JOIN check_rollups_hourly AS r ON r.device_id = d.id AND r.hour_utc >= ?
            WHERE d.deleted_at IS NULL
            GROUP BY r.device_id
            """,
            (hour_utc,),
        ).fetchall()
        return {
            row["device_id"]: Availability(checks=row["checks"], successes=row["successes"])
            for row in rows
        }

    # Packet captures (plan section 28)

    def start_capture(
        self, interface: str, description: str, capture_filter: str, snaplen: int, file: str, *, now: str | None = None
    ) -> Capture:
        """A new running capture. Only one may run: the schema refuses a second."""
        with self._write():
            cur = self._conn.execute(
                """
                INSERT INTO captures (interface, description, filter, snaplen, started_at, file, state)
                VALUES (?, ?, ?, ?, ?, ?, 'running')
                """,
                (interface, description[:255], capture_filter, snaplen, _timestamp(now), file),
            )
        return self.get_capture(cur.lastrowid)

    def save_rates(self, capture_id: int, seconds: list[SecondCounts], packets: int, nbytes: int) -> None:
        """The seconds that changed, and the capture's totals so far, in one transaction (plan section 28).

        A second written before is replaced, so packets that arrive late still count.
        """
        with self._write():
            self._conn.executemany(
                """
                INSERT INTO capture_rates
                    (capture_id, second, bytes_in, bytes_out, packets_in, packets_out, protocols)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (capture_id, second) DO UPDATE SET
                    bytes_in = excluded.bytes_in, bytes_out = excluded.bytes_out,
                    packets_in = excluded.packets_in, packets_out = excluded.packets_out,
                    protocols = excluded.protocols
                """,
                [
                    (capture_id, s.second, s.bytes_in, s.bytes_out, s.packets_in, s.packets_out,
                     json.dumps(dict(s.protocols), separators=(",", ":")))
                    for s in seconds
                ],
            )
            self._conn.execute("UPDATE captures SET packets = ?, bytes = ? WHERE id = ?", (packets, nbytes, capture_id))

    def finish_capture(self, capture_id: int, state: str, note: str | None = None, *, now: str | None = None) -> Capture:
        if state not in CaptureState.ALL or state == CaptureState.RUNNING:
            raise ValueError(f"a capture cannot finish as {state!r}")
        with self._write():
            self._conn.execute(
                "UPDATE captures SET state = ?, note = ?, ended_at = ? WHERE id = ? AND state = 'running'",
                (state, None if note is None else note[:500], _timestamp(now), capture_id),
            )
        return self.get_capture(capture_id)

    def interrupt_running(self, *, now: str | None = None) -> list[Capture]:
        """A capture left running by a NetPulse that stopped: marked interrupted. Its file holds what was written."""
        running = [c for c in self.captures() if c.running]
        return [
            self.finish_capture(c.id, CaptureState.INTERRUPTED, "NetPulse stopped while it ran", now=now)
            for c in running
        ]

    def captures(self) -> list[Capture]:
        """Every capture, newest first."""
        rows = self._conn.execute("SELECT * FROM captures ORDER BY started_at DESC, id DESC").fetchall()
        return [_capture_from_row(r) for r in rows]

    def get_capture(self, capture_id: int) -> Capture:
        row = self._conn.execute("SELECT * FROM captures WHERE id = ?", (capture_id,)).fetchone()
        if row is None:
            raise KeyError(capture_id)
        return _capture_from_row(row)

    def capture_rates(self, capture_id: int) -> list[SecondCounts]:
        """A capture's seconds, oldest first, read by the primary key."""
        rows = self._conn.execute(
            "SELECT * FROM capture_rates WHERE capture_id = ? ORDER BY second", (capture_id,)
        ).fetchall()
        return [_counts_from_row(r) for r in rows]

    def expired_captures(self, now: datetime) -> list[Capture]:
        """Finished captures past retention: beyond the newest KEEP_CAPTURES and older than KEEP_CAPTURE_DAYS."""
        cutoff = (now - timedelta(days=KEEP_CAPTURE_DAYS)).astimezone(UTC).replace(microsecond=0).isoformat()
        return [c for c in self.captures()[KEEP_CAPTURES:] if not c.running and c.started_at < cutoff]

    def delete_capture(self, capture_id: int) -> Capture:
        """Delete a finished capture and its counts. The caller deletes its file."""
        capture = self.get_capture(capture_id)
        if capture.running:
            raise ValueError("a running capture cannot be deleted: stop it first")
        with self._write():
            self._conn.execute("DELETE FROM captures WHERE id = ?", (capture_id,))
        return capture

    # Path traces (plan section 30)

    def save_trace(
        self, target: str, address: str, rounds: int, reached: bool, hops: list[Hop], error: str | None = None,
        *, now: str | None = None,
    ) -> Trace:
        """A finished trace and its hops, in one transaction, then the oldest past KEEP_TRACES go."""
        with self._write():
            cur = self._conn.execute(
                "INSERT INTO traces (target, address, started_at, rounds, reached, error) VALUES (?, ?, ?, ?, ?, ?)",
                (target[:253], address, _timestamp(now), rounds, int(reached), error),
            )
            trace_id = cur.lastrowid
            self._conn.executemany(
                """
                INSERT INTO trace_hops
                    (trace_id, ttl, address, sent, received, best_ms, avg_ms, worst_ms, name, label, others, note)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (trace_id, h.ttl, h.address, h.sent, h.received, h.best_ms, h.avg_ms, h.worst_ms,
                     None if h.name is None else h.name[:253], h.label, json.dumps(list(h.others)), h.note)
                    for h in hops
                ],
            )
            self._prune_traces()
        return self.get_trace(trace_id)

    def _prune_traces(self) -> int:
        return self._conn.execute(
            "DELETE FROM traces WHERE id NOT IN (SELECT id FROM traces ORDER BY started_at DESC, id DESC LIMIT ?)",
            (KEEP_TRACES,),
        ).rowcount

    def traces(self) -> list[Trace]:
        """Every kept trace, newest first, without its hops."""
        rows = self._conn.execute("SELECT * FROM traces ORDER BY started_at DESC, id DESC").fetchall()
        return [_trace_from_row(r, ()) for r in rows]

    def get_trace(self, trace_id: int) -> Trace:
        row = self._conn.execute("SELECT * FROM traces WHERE id = ?", (trace_id,)).fetchone()
        if row is None:
            raise KeyError(trace_id)
        hops = self._conn.execute("SELECT * FROM trace_hops WHERE trace_id = ? ORDER BY ttl", (trace_id,)).fetchall()
        return _trace_from_row(row, tuple(_hop_from_row(h) for h in hops))

    # Checks from outside (plan section 31)

    def outside_consent(self) -> str | None:
        """When the user agreed to send targets to Globalping, or None: nothing may be sent."""
        return self._conn.execute("SELECT outside_consent_at FROM settings WHERE id = 1").fetchone()[0]

    def set_outside_consent(self, agree: bool, *, now: str | None = None) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE settings SET outside_consent_at = ? WHERE id = 1", (_timestamp(now) if agree else None,)
            )

    def save_outside_check(
        self, request: CheckRequest, measurement_id: str | None, results: tuple[ProbeResult, ...] = (),
        error: str | None = None, *, now: str | None = None,
    ) -> OutsideCheck:
        """A check and what came back, then the oldest past KEEP_OUTSIDE_CHECKS go."""
        with self._write():
            cur = self._conn.execute(
                """
                INSERT INTO outside_checks
                    (kind, target, scope, code, probes, port, path, started_at, measurement_id, results, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request.kind, request.target, request.where.scope, request.where.code, request.probes,
                    request.port, request.path, _timestamp(now), measurement_id,
                    json.dumps([r.__dict__ for r in results]), None if error is None else error[:500],
                ),
            )
            self._prune_outside_checks()
        return self.get_outside_check(cur.lastrowid)

    def _prune_outside_checks(self) -> int:
        return self._conn.execute(
            "DELETE FROM outside_checks WHERE id NOT IN "
            "(SELECT id FROM outside_checks ORDER BY started_at DESC, id DESC LIMIT ?)",
            (KEEP_OUTSIDE_CHECKS,),
        ).rowcount

    def outside_checks(self) -> list[OutsideCheck]:
        """Every kept check, newest first."""
        rows = self._conn.execute("SELECT * FROM outside_checks ORDER BY started_at DESC, id DESC").fetchall()
        return [_outside_from_row(r) for r in rows]

    def get_outside_check(self, check_id: int) -> OutsideCheck:
        row = self._conn.execute("SELECT * FROM outside_checks WHERE id = ?", (check_id,)).fetchone()
        if row is None:
            raise KeyError(check_id)
        return _outside_from_row(row)

    def same_outside_check(self, request: CheckRequest, since: str) -> OutsideCheck | None:
        """The newest check that asked exactly this, with an answer, at or after since (plan section 31)."""
        row = self._conn.execute(
            """
            SELECT * FROM outside_checks
            WHERE kind = ? AND target = ? AND scope = ? AND code IS ? AND probes = ? AND port IS ? AND path = ?
              AND started_at >= ? AND error IS NULL
            ORDER BY started_at DESC, id DESC LIMIT 1
            """,
            (request.kind, request.target, request.where.scope, request.where.code, request.probes, request.port,
             request.path, _timestamp(since)),
        ).fetchone()
        return None if row is None else _outside_from_row(row)

    # Upkeep (plan section 32)

    def maintain(self) -> Upkeep:
        """The hourly pass: retention for traces and checks from outside, SQLite's optimize, then a WAL checkpoint.

        Retention also runs on every save; here it catches what a save never
        triggered, such as a lower limit in a new version. Captures have files,
        so the capture service applies theirs. The checkpoint waits at most the
        busy timeout for writers; a reader holding an old snapshot only means
        part of the log stays until the next pass.
        """
        with self._write():
            traces = self._prune_traces()
            outside = self._prune_outside_checks()
        self._conn.execute("PRAGMA optimize")  # first: what it writes goes into the checkpoint too
        busy, _, _ = self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return Upkeep(traces=traces, outside_checks=outside, checkpointed=not busy)

    @contextmanager
    def _write(self, *, host: str | None = None) -> Iterator[None]:
        """One committed transaction. A live-host clash becomes DuplicateLiveHost."""
        try:
            with self._conn:
                yield
        except sqlite3.IntegrityError as exc:
            if host is not None and exc.sqlite_errorname == "SQLITE_CONSTRAINT_UNIQUE":
                raise DuplicateLiveHost(f"a device with host {host} already exists") from exc
            raise


def _migrate(conn: sqlite3.Connection) -> None:
    """Create the schema in a new file, or upgrade an older one (plan section 15).

    A file already at SCHEMA_VERSION costs one read and takes no write lock.
    """
    version = _user_version(conn)
    if version == SCHEMA_VERSION:
        return
    _refuse_unknown(conn, version)
    backup = _back_up(conn, version) if version > 0 else None

    conn.execute("BEGIN IMMEDIATE")
    try:
        version = _user_version(conn)  # another connection may have upgraded it meanwhile
        _refuse_unknown(conn, version)
        for target in range(version + 1, SCHEMA_VERSION + 1):
            _MIGRATIONS[target](conn)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    if backup is not None:
        # Plan section 32: an upgrade changes tables and indexes, so the planner's
        # statistics are rebuilt rather than left describing the old schema.
        conn.execute("ANALYZE")
        conn.commit()
    if backup is not None:
        log.info("upgraded %s to schema version %d; the old file is kept as %s",
                 _database_file(conn), SCHEMA_VERSION, backup)


def _user_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def _refuse_unknown(conn: sqlite3.Connection, version: int) -> None:
    if version > SCHEMA_VERSION:
        raise UnsupportedDatabase(
            f"database schema version {version} is not supported "
            f"(this NetPulse uses version {SCHEMA_VERSION})"
        )
    if version == 0 and conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
        raise UnsupportedDatabase(
            "this database has tables but no NetPulse schema version; "
            "move it aside and start NetPulse with a new file"
        )


def _database_file(conn: sqlite3.Connection) -> Path:
    return Path(conn.execute("PRAGMA database_list").fetchone()["file"])


def _back_up(conn: sqlite3.Connection, version: int) -> Path:
    """Copy the file before an upgrade: <stem>.v<version>-backup-<UTC time><suffix>.

    SQLite's backup API gives a consistent copy even while other connections
    write. The copy keeps the old version, so the older NetPulse can open it.
    """
    original = _database_file(conn)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    copy = original.with_name(f"{original.stem}.v{version}-backup-{stamp}{original.suffix}")
    target = sqlite3.connect(copy)
    try:
        conn.backup(target)
    finally:
        target.close()
    return copy


def _replay_outage_events(conn: sqlite3.Connection) -> None:
    """Derive outage events from existing history, with the same rule as new checks."""
    last_kind: dict[int, str] = {}
    recent: dict[int, deque[CheckResult]] = {}
    rows = conn.execute("SELECT * FROM check_results ORDER BY device_id, checked_at, id")
    for result in map(_result_from_row, rows):
        window = recent.setdefault(result.device_id, deque(maxlen=DOWN_AFTER_FAILURES))
        window.appendleft(result)
        event = outage_event(last_kind.get(result.device_id), list(window))
        if event is not None:
            _insert_event(conn, result.device_id, *event)
            last_kind[result.device_id] = event[0]


def _record_outage_event(conn: sqlite3.Connection, device_id: int) -> None:
    """After a check is inserted: add the outage event it causes, if any."""
    recent = [
        _result_from_row(r)
        for r in conn.execute(
            """
            SELECT * FROM check_results WHERE device_id = ?
            ORDER BY checked_at DESC, id DESC LIMIT ?
            """,
            (device_id, DOWN_AFTER_FAILURES),
        )
    ]
    last = conn.execute(
        "SELECT kind FROM device_events WHERE device_id = ? ORDER BY at DESC, id DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    event = outage_event(last["kind"] if last else None, recent)
    if event is not None:
        _insert_event(conn, device_id, *event)


def _insert_event(conn: sqlite3.Connection, device_id: int, kind: str, check: CheckResult) -> None:
    conn.execute(
        "INSERT INTO device_events (device_id, at, kind, error) VALUES (?, ?, ?, ?)",
        (device_id, check.checked_at, kind, check.error),
    )


def _timestamp(now: str | None) -> str:
    """Normalize to utc_now()'s format. Rejects times without a UTC offset."""
    if now is None:
        return utc_now()
    parsed = datetime.fromisoformat(now)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp needs a UTC offset: {now!r}")
    return parsed.astimezone(UTC).replace(microsecond=0).isoformat()


def _discovered_from_row(row: sqlite3.Row) -> DiscoveredHost:
    return DiscoveredHost(
        id=row["id"],
        address=IPv4Address(row["address"]),
        mac=row["mac"],
        name=row["name"],
        answers_ping=bool(row["answers_ping"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        state=row["state"],
        device_id=row["device_id"],
    )


def _device_from_row(row: sqlite3.Row) -> Device:
    return Device(
        id=row["id"],
        name=row["name"],
        host=row["host"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        deleted_at=row["deleted_at"],
    )


def _result_from_row(row: sqlite3.Row) -> CheckResult:
    return CheckResult(
        id=row["id"],
        device_id=row["device_id"],
        checked_at=row["checked_at"],
        success=bool(row["success"]),
        rtt_ms=row["rtt_ms"],
        error=row["error"],
    )


def _outside_from_row(row: sqlite3.Row) -> OutsideCheck:
    request = CheckRequest(
        kind=row["kind"], target=row["target"], where=Where(row["scope"], row["code"]), probes=row["probes"],
        port=row["port"], path=row["path"],
    )
    results = tuple(ProbeResult(**r) for r in json.loads(row["results"]))
    return OutsideCheck(row["id"], request, row["started_at"], row["measurement_id"], results, row["error"])


def _trace_from_row(row: sqlite3.Row, hops: tuple[Hop, ...]) -> Trace:
    values = dict(row)
    values["reached"] = bool(values["reached"])
    return Trace(**values, hops=hops)


def _hop_from_row(row: sqlite3.Row) -> Hop:
    values = dict(row)
    del values["trace_id"]
    values["others"] = tuple(json.loads(values["others"]))
    return Hop(**values)


def _capture_from_row(row: sqlite3.Row) -> Capture:
    return Capture(**dict(row))


def _counts_from_row(row: sqlite3.Row) -> SecondCounts:
    protocols = sorted(json.loads(row["protocols"]).items(), key=lambda item: (-item[1], item[0]))
    return SecondCounts(
        second=row["second"], bytes_in=row["bytes_in"], bytes_out=row["bytes_out"],
        packets_in=row["packets_in"], packets_out=row["packets_out"], protocols=tuple(protocols),
    )


def _event_from_row(row: sqlite3.Row) -> DeviceEvent:
    return DeviceEvent(
        id=row["id"],
        device_id=row["device_id"],
        at=row["at"],
        kind=row["kind"],
        error=row["error"],
    )
