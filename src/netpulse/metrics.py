"""Dashboard metrics (plan section 16): pure functions over domain values.

No SQL and no Flask. The web layer loads current statuses and rollup counts
from the store and hands them here. It sits in the domain layer because it
reads only domain values, so tests call it without SQLite or a request.
"""

from __future__ import annotations

import statistics
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from netpulse.domain import (
    Availability,
    CheckResult,
    DeviceEvent,
    DeviceState,
    DeviceStatus,
    EventKind,
    HourlyRollup,
    RecentChecks,
    SecondCounts,
    Thresholds,
)

# The availability window: the current UTC hour and the 23 before it.
AVAILABILITY_HOURS = 24

STATUS_FILTERS = ("all", DeviceState.UP, DeviceState.DEGRADED, DeviceState.DOWN, DeviceState.UNCHECKED)

# Why a device that is up counts as degraded (plan section 18).
SLOW = "slow"
FAILING = "failing"


class Sort:
    NAME = "name"
    HOST = "host"
    STATUS = "status"
    LATENCY = "latency"
    AVAILABILITY = "availability"
    CHECKED = "checked"

    ALL = (NAME, HOST, STATUS, LATENCY, AVAILABILITY, CHECKED)


@dataclass(frozen=True)
class DeviceRow:
    """One row of the device table: a live device, its latest check, its availability,
    and, since plan section 18, its recent checks and why it is degraded, if it is."""

    status: DeviceStatus
    availability: Availability
    recent: RecentChecks = RecentChecks(checks=0, failures=0, avg_ms=None)
    degraded_by: tuple[str, ...] = ()  # SLOW and/or FAILING; empty unless up

    @property
    def state(self) -> str:
        """The latest check's state, with up split into up and degraded."""
        return DeviceState.DEGRADED if self.degraded_by else self.status.state

    @property
    def latency_ms(self) -> int | None:
        """The latest RTT, only while the device is up (degraded devices are up)."""
        return self.status.latest.rtt_ms if self.status.state == DeviceState.UP else None


@dataclass(frozen=True)
class FleetSummary:
    monitored: int
    up: int  # up and healthy
    down: int
    unchecked: int
    median_latency_ms: float | None  # None when no device is up; degraded ones count
    availability: Availability  # all live devices over the window
    degraded: int = 0


def availability_window_start(now: datetime, hours: int = AVAILABILITY_HOURS) -> str:
    """The first hour of a window of the current UTC hour and the hours - 1 before it,
    as the rollups store it: 'YYYY-MM-DDTHH'."""
    start = now.astimezone(UTC) - timedelta(hours=hours - 1)
    return start.strftime("%Y-%m-%dT%H")


def device_rows(
    statuses: Iterable[DeviceStatus],
    availability: Mapping[int, Availability],
    recent: Mapping[int, Sequence[CheckResult]] | None = None,
    thresholds: Thresholds = Thresholds(),
) -> list[DeviceRow]:
    """Pair each status with its availability and recent checks, and judge degraded.

    No checks in the window is 0 of 0. Only a device that is up can be degraded.
    """
    none = Availability(checks=0, successes=0)
    rows = []
    for status in statuses:
        checks = RecentChecks.of((recent or {}).get(status.device.id, ()))
        reasons: tuple[str, ...] = ()
        if status.state == DeviceState.UP:
            reasons = tuple(
                reason
                for reason, crossed in ((SLOW, checks.is_slow(thresholds)), (FAILING, checks.is_failing(thresholds)))
                if crossed
            )
        rows.append(DeviceRow(status, availability.get(status.device.id, none), checks, reasons))
    return rows


def summarize(rows: Sequence[DeviceRow]) -> FleetSummary:
    states = [row.state for row in rows]
    latencies = [row.latency_ms for row in rows if row.latency_ms is not None]
    return FleetSummary(
        monitored=len(rows),
        up=states.count(DeviceState.UP),
        degraded=states.count(DeviceState.DEGRADED),
        down=states.count(DeviceState.DOWN),
        unchecked=states.count(DeviceState.UNCHECKED),
        median_latency_ms=statistics.median(latencies) if latencies else None,
        availability=Availability(
            checks=sum(row.availability.checks for row in rows),
            successes=sum(row.availability.successes for row in rows),
        ),
    )


# Status sorts by urgency: down, degraded, not checked, then up.
_STATE_ORDER = {DeviceState.DOWN: 0, DeviceState.DEGRADED: 1, DeviceState.UNCHECKED: 2, DeviceState.UP: 3}

_SORT_KEYS: dict[str, Callable[[DeviceRow], object]] = {
    Sort.NAME: lambda row: row.status.device.name.casefold(),
    Sort.HOST: lambda row: row.status.device.host.casefold(),
    Sort.STATUS: lambda row: _STATE_ORDER[row.state],
    Sort.LATENCY: lambda row: row.latency_ms,
    Sort.AVAILABILITY: lambda row: row.availability.percent,
    Sort.CHECKED: lambda row: row.status.latest.checked_at if row.status.latest else None,
}


def select_rows(
    rows: Iterable[DeviceRow],
    *,
    q: str = "",
    status: str = "all",
    sort: str = Sort.NAME,
    descending: bool = False,
) -> list[DeviceRow]:
    """Filter and sort the table (plan section 16).

    q matches the name or host, ignoring case. Sorting is stable with ties by
    name, and rows with no value for the sort key come last in either direction.
    """
    needle = q.strip().casefold()
    chosen = [
        row
        for row in rows
        if (status == "all" or row.state == status)
        and (
            needle in row.status.device.name.casefold()
            or needle in row.status.device.host.casefold()
        )
    ]
    by_name = sorted(chosen, key=lambda row: (row.status.device.name.casefold(), row.status.device.id))
    key = _SORT_KEYS[sort]
    present = [row for row in by_name if key(row) is not None]
    missing = [row for row in by_name if key(row) is None]
    return sorted(present, key=key, reverse=descending) + missing


# Charts (plan section 17)


@dataclass(frozen=True)
class ChartRange:
    key: str  # the URL value
    label: str
    span: timedelta
    period: timedelta  # one point on the chart; at least twice the check interval
    from_rollups: bool  # beyond 24 h, read hourly rollups instead of raw checks


RANGES = {
    r.key: r
    for r in (
        ChartRange("1h", "1 h", timedelta(hours=1), timedelta(minutes=1), from_rollups=False),
        ChartRange("6h", "6 h", timedelta(hours=6), timedelta(minutes=5), from_rollups=False),
        ChartRange("24h", "24 h", timedelta(hours=24), timedelta(minutes=15), from_rollups=False),
        ChartRange("7d", "7 d", timedelta(days=7), timedelta(hours=1), from_rollups=True),
        ChartRange("30d", "30 d", timedelta(days=30), timedelta(hours=6), from_rollups=True),
    )
}
DEFAULT_RANGE = "24h"


class PeriodState:
    UP = "up"  # every check succeeded
    SOME_FAILED = "partial"
    DOWN = "down"  # every check failed
    NO_DATA = "none"  # no checks: monitoring was not running, which is not "down"


@dataclass(frozen=True)
class Period:
    """One point on a chart: the checks of one device in [start, start + length)."""

    start: datetime
    length: timedelta
    checks: int = 0
    successes: int = 0
    rtt_sum: int = 0
    rtt_min: int | None = None
    rtt_max: int | None = None

    @property
    def availability(self) -> Availability:
        return Availability(checks=self.checks, successes=self.successes)

    @property
    def avg_ms(self) -> float | None:
        return round(self.rtt_sum / self.successes, 1) if self.successes else None

    @property
    def state(self) -> str:
        if self.checks == 0:
            return PeriodState.NO_DATA
        if self.successes == self.checks:
            return PeriodState.UP
        return PeriodState.DOWN if self.successes == 0 else PeriodState.SOME_FAILED


@dataclass(frozen=True)
class Series:
    """A device's checks over a range, one Period per chart point, oldest first."""

    range: ChartRange
    periods: tuple[Period, ...]

    @property
    def availability(self) -> Availability:
        return Availability(
            checks=sum(p.checks for p in self.periods),
            successes=sum(p.successes for p in self.periods),
        )

    @property
    def avg_ms(self) -> float | None:
        successes = sum(p.successes for p in self.periods)
        return round(sum(p.rtt_sum for p in self.periods) / successes, 1) if successes else None

    @property
    def rtt_min(self) -> int | None:
        return min((p.rtt_min for p in self.periods if p.rtt_min is not None), default=None)

    @property
    def rtt_max(self) -> int | None:
        return max((p.rtt_max for p in self.periods if p.rtt_max is not None), default=None)

    @property
    def no_data(self) -> int:
        return sum(1 for p in self.periods if p.state == PeriodState.NO_DATA)

    def chart_data(self) -> dict[str, list]:
        """uPlot's columns: epoch seconds, then lowest, average and highest RTT. None is a gap."""
        return {
            "t": [int(p.start.timestamp()) for p in self.periods],
            "min": [p.rtt_min for p in self.periods],
            "avg": [p.avg_ms for p in self.periods],
            "max": [p.rtt_max for p in self.periods],
        }


def _floor(moment: datetime, step: timedelta) -> datetime:
    """Round down to a whole multiple of step since the Unix epoch, in UTC."""
    seconds, size = int(moment.timestamp()), int(step.total_seconds())
    return datetime.fromtimestamp(seconds - seconds % size, UTC)


def series_start(chart_range: ChartRange, now: datetime) -> datetime:
    """The start of a range's first period.

    Ranges of a day or more count whole UTC hours, exactly like the availability
    figures (the current hour and the ones before it), so a chart's totals match
    them. Shorter ranges roll with the clock.
    """
    if chart_range.span >= timedelta(days=1):
        hours = int(chart_range.span / timedelta(hours=1))
        first_hour = availability_window_start(now, hours)
        return datetime.strptime(first_hour, "%Y-%m-%dT%H").replace(tzinfo=UTC)
    return _floor(now - chart_range.span, chart_range.period)


def series_since(chart_range: ChartRange, now: datetime) -> str:
    """What the store reads from: a check timestamp, or an hour for rollups."""
    start = series_start(chart_range, now)
    return start.strftime("%Y-%m-%dT%H") if chart_range.from_rollups else start.isoformat()


_Sample = tuple[datetime, int, int, int, int | None, int | None]


def _series(chart_range: ChartRange, now: datetime, samples: Iterable[_Sample]) -> Series:
    step = chart_range.period
    first = series_start(chart_range, now)
    count = (now - first) // step + 1  # up to the period now is in; never a future one
    totals: list[list] = [[0, 0, 0, None, None] for _ in range(count)]
    for at, checks, successes, rtt_sum, rtt_min, rtt_max in samples:
        index = (at - first) // step
        if not 0 <= index < count:
            continue
        total = totals[index]
        total[0] += checks
        total[1] += successes
        total[2] += rtt_sum
        if rtt_min is not None:
            total[3] = rtt_min if total[3] is None else min(total[3], rtt_min)
        if rtt_max is not None:
            total[4] = rtt_max if total[4] is None else max(total[4], rtt_max)
    return Series(
        chart_range,
        tuple(Period(first + i * step, step, *total) for i, total in enumerate(totals)),
    )


def bucket_checks(checks: Iterable[CheckResult], chart_range: ChartRange, now: datetime) -> Series:
    """Raw checks into periods (ranges up to 24 h)."""
    return _series(
        chart_range,
        now,
        (
            (datetime.fromisoformat(c.checked_at), 1, int(c.success), c.rtt_ms or 0, c.rtt_ms, c.rtt_ms)
            for c in checks
        ),
    )


def bucket_rollups(rollups: Iterable[HourlyRollup], chart_range: ChartRange, now: datetime) -> Series:
    """Hourly rollups into periods of one or more hours (ranges beyond 24 h)."""
    return _series(
        chart_range,
        now,
        (
            (
                datetime.strptime(r.hour_utc, "%Y-%m-%dT%H").replace(tzinfo=UTC),
                r.checks, r.successes, r.rtt_sum, r.rtt_min, r.rtt_max,
            )
            for r in rollups
        ),
    )


# Outages (plan section 17, from the section 15 events)


@dataclass(frozen=True)
class Outage:
    start: str
    end: str | None  # None: still down
    error: str  # the first failed check's code

    def seconds(self, now: datetime) -> int:
        end = datetime.fromisoformat(self.end) if self.end else now
        return max(0, int((end - datetime.fromisoformat(self.start)).total_seconds()))


def outages(events: Iterable[DeviceEvent]) -> list[Outage]:
    """Pair each down event with the up event after it, newest outage first.

    An up event with no down before it (cut off by a limit) is skipped.
    """
    found: list[Outage] = []
    down: DeviceEvent | None = None
    for event in sorted(events, key=lambda e: (e.at, e.id)):
        if event.kind == EventKind.DOWN:
            down = down or event
        elif down is not None:
            found.append(Outage(down.at, event.at, down.error))
            down = None
    if down is not None:
        found.append(Outage(down.at, None, down.error))
    return found[::-1]


# The overview (plan section 26)


def availability_by_device(rollups: Iterable[HourlyRollup]) -> dict[int, Availability]:
    """Each device's checks and successes over the given hourly rollups."""
    totals: dict[int, tuple[int, int]] = {}
    for rollup in rollups:
        checks, successes = totals.get(rollup.device_id, (0, 0))
        totals[rollup.device_id] = (checks + rollup.checks, successes + rollup.successes)
    return {device: Availability(checks, successes) for device, (checks, successes) in totals.items()}


def open_outages(events: Iterable[DeviceEvent]) -> dict[int, DeviceEvent]:
    """For each device whose newest event is a down, that event: its outage is still going on."""
    newest: dict[int, DeviceEvent] = {}
    for event in events:
        seen = newest.get(event.device_id)
        if seen is None or (event.at, event.id) > (seen.at, seen.id):
            newest[event.device_id] = event
    return {device: event for device, event in newest.items() if event.kind == EventKind.DOWN}


@dataclass(frozen=True)
class Problem:
    """A device that is down or degraded, for the overview's Problems panel."""

    row: DeviceRow
    outage: DeviceEvent | None  # the down event of its outage; None if degraded, or down for too few checks yet

    def seconds(self, now: datetime) -> int | None:
        """How long the outage has lasted so far."""
        if self.outage is None:
            return None
        return max(0, int((now - datetime.fromisoformat(self.outage.at)).total_seconds()))


def problems(rows: Iterable[DeviceRow], outages_now: Mapping[int, DeviceEvent]) -> list[Problem]:
    """Down devices, then degraded ones, worst first, as Nagios lists them.

    Down: the longest outage first, then devices down for fewer checks than an
    outage needs. Degraded: the most failures first, then the slowest.
    """
    rows = list(rows)
    down = [Problem(row, outages_now.get(row.status.device.id)) for row in rows if row.state == DeviceState.DOWN]
    degraded = [Problem(row, None) for row in rows if row.state == DeviceState.DEGRADED]

    def name(problem: Problem) -> tuple[str, int]:
        return problem.row.status.device.name.casefold(), problem.row.status.device.id

    down.sort(key=lambda p: (p.outage is None, p.outage.at if p.outage else "", *name(p)))
    degraded.sort(key=lambda p: (-p.row.recent.failures, -(p.row.recent.avg_ms or 0), *name(p)))
    return down + degraded


# Breakdowns, each as (key, label, count) in a fixed order, empty categories kept.

STATE_LABELS = (
    (DeviceState.UP, "up"),
    (DeviceState.DEGRADED, "degraded"),
    (DeviceState.DOWN, "down"),
    (DeviceState.UNCHECKED, "not checked"),
)
AVAILABILITY_BANDS = (("high", "99.9 % or more"), ("mid", "99 to 99.9 %"), ("low", "under 99 %"), ("none", "no data"))
LATENCY_BANDS = (
    ("fast", "under 10 ms"),
    ("good", "10 to 49 ms"),
    ("slow", "50 to 149 ms"),
    ("slowest", "150 ms or more"),
    ("none", "no data"),
)


def availability_band(availability: Availability) -> str:
    """Whole counts, not a rounded percentage, decide the band: 999 of 1000 is 99.9 %."""
    checks, successes = availability.checks, availability.successes
    if checks == 0:
        return "none"
    if successes * 1000 >= checks * 999:
        return "high"
    return "mid" if successes * 100 >= checks * 99 else "low"


def latency_band(avg_ms: float | None) -> str:
    """By the average of the recent checks that got an answer (plan section 18)."""
    if avg_ms is None:
        return "none"
    if avg_ms < 10:
        return "fast"
    if avg_ms < 50:
        return "good"
    return "slow" if avg_ms < 150 else "slowest"


def _breakdown(keys: Iterable[str], labels: Sequence[tuple[str, str]]) -> list[tuple[str, str, int]]:
    counts: dict[str, int] = {}
    for key in keys:
        counts[key] = counts.get(key, 0) + 1
    return [(key, label, counts.get(key, 0)) for key, label in labels]


def by_state(rows: Iterable[DeviceRow]) -> list[tuple[str, str, int]]:
    return _breakdown((row.state for row in rows), STATE_LABELS)


def by_availability(rows: Iterable[DeviceRow]) -> list[tuple[str, str, int]]:
    return _breakdown((availability_band(row.availability) for row in rows), AVAILABILITY_BANDS)


def by_latency(rows: Iterable[DeviceRow]) -> list[tuple[str, str, int]]:
    return _breakdown((latency_band(row.recent.avg_ms) for row in rows), LATENCY_BANDS)


@dataclass(frozen=True)
class LedgerEntry:
    """One line of the recent events ledger."""

    event: DeviceEvent
    lasted_s: int | None  # how long the outage lasted, or has lasted so far; None if cut off
    ongoing: bool  # a down event whose outage has not ended


def ledger(events: Iterable[DeviceEvent], now: datetime, limit: int = 20) -> list[LedgerEntry]:
    """The newest events, newest first, each with how long its outage lasted.

    A down event is paired with the up after it, and an up with the down before
    it. A pair cut in two by the events read gives no length for that half.
    """
    by_device: dict[int, list[DeviceEvent]] = {}
    for event in sorted(events, key=lambda e: (e.at, e.id)):
        by_device.setdefault(event.device_id, []).append(event)
    entries = []
    for device_events in by_device.values():
        for i, event in enumerate(device_events):
            nxt = device_events[i + 1] if i + 1 < len(device_events) else None
            before = device_events[i - 1] if i > 0 else None
            if event.kind == EventKind.DOWN:
                end = datetime.fromisoformat(nxt.at) if nxt is not None else now
                lasted = max(0, int((end - datetime.fromisoformat(event.at)).total_seconds()))
                entries.append(LedgerEntry(event, lasted, ongoing=nxt is None))
            elif before is not None and before.kind == EventKind.DOWN:
                lasted = int((datetime.fromisoformat(event.at) - datetime.fromisoformat(before.at)).total_seconds())
                entries.append(LedgerEntry(event, lasted, ongoing=False))
            else:
                entries.append(LedgerEntry(event, None, ongoing=False))
    entries.sort(key=lambda entry: (entry.event.at, entry.event.id), reverse=True)
    return entries[:limit]


def slowest(rows: Iterable[DeviceRow]) -> list[tuple[int, str, float, str]]:
    """(device id, name, average ms, the average as printed) for every device with an average."""
    return [
        (row.status.device.id, row.status.device.name, row.recent.avg_ms, f"{row.recent.avg_ms:g} ms")
        for row in rows
        if row.recent.avg_ms is not None
    ]


# Traffic (plan section 29)


def rate_chart(seconds: Sequence[SecondCounts], last: int | None = None, span: int | None = None) -> dict[str, list]:
    """uPlot's columns for a capture's rate graph: Unix seconds, then bytes and packets in and out.

    Every second from the first to the last is a point: a second with no
    packets is 0, not a gap. span keeps only the last span seconds, as the live
    graph's rolling ten minutes; last is the newest second, now for a running capture.
    """
    by_second = {s.second: s for s in seconds}
    if not by_second and last is None:
        return {"t": [], "bytes_in": [], "bytes_out": [], "packets_in": [], "packets_out": []}
    end = max([*by_second, *([last] if last is not None else [])])
    start = min(by_second, default=end)
    if span is not None:
        start = max(start, end - span + 1)
    empty = SecondCounts(0)
    points = [by_second.get(t, empty) for t in range(start, end + 1)]
    return {
        "t": list(range(start, end + 1)),
        "bytes_in": [p.bytes_in for p in points],
        "bytes_out": [p.bytes_out for p in points],
        "packets_in": [p.packets_in for p in points],
        "packets_out": [p.packets_out for p in points],
    }


def protocol_totals(seconds: Iterable[SecondCounts]) -> list[tuple[str, int]]:
    """Packets by protocol over a capture's seconds, most first."""
    totals: dict[str, int] = {}
    for second in seconds:
        for protocol, packets in second.protocols:
            totals[protocol] = totals.get(protocol, 0) + packets
    return sorted(totals.items(), key=lambda item: (-item[1], item[0]))
