"""Domain model (plan section 9, step 1): what NetPulse stores, not how it looks.

Plain immutable values and the rule for a valid device name. No SQL, no
Flask, no ping.exe. tests/test_architecture.py keeps this module at the
bottom of the layers: it imports nothing else from NetPulse.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

NAME_MAX_LEN = 64

# Plan section 15: failed checks in a row before the outage log says Down.
# One dropped echo is not an outage.
DOWN_AFTER_FAILURES = 2


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Device:
    """A monitored host. deleted_at stays None while the device is live."""

    id: int
    name: str
    host: str
    created_at: str
    updated_at: str
    deleted_at: str | None

    @property
    def is_live(self) -> bool:
        return self.deleted_at is None


@dataclass(frozen=True)
class CheckResult:
    """One stored check of one device: success with an RTT, or failure with a code."""

    id: int
    device_id: int
    checked_at: str
    success: bool
    rtt_ms: int | None
    error: str | None


class DeviceState:
    """What a device's latest check says. A single failure already counts as down here;
    the 2-check debounce applies only to the outage log (plan section 15).

    DEGRADED (plan section 18) is never a DeviceStatus.state: it needs the recent
    checks and the thresholds, so the metrics module works it out for each row.
    """

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    UNCHECKED = "unchecked"


@dataclass(frozen=True)
class DeviceStatus:
    """A live device and its latest check result (None if never checked)."""

    device: Device
    latest: CheckResult | None

    @property
    def state(self) -> str:
        if self.latest is None:
            return DeviceState.UNCHECKED
        return DeviceState.UP if self.latest.success else DeviceState.DOWN


@dataclass(frozen=True)
class Availability:
    """Checks and successful checks over a window. A rate of checks, not packet loss."""

    checks: int
    successes: int

    @property
    def percent(self) -> float | None:
        return None if self.checks == 0 else 100 * self.successes / self.checks


@dataclass(frozen=True)
class HourlyRollup:
    """One device's checks in one UTC hour (plan section 15). rtt_* cover successes only."""

    device_id: int
    hour_utc: str  # 'YYYY-MM-DDTHH'
    checks: int
    successes: int
    rtt_sum: int
    rtt_min: int | None
    rtt_max: int | None


class EventKind:
    DOWN = "down"
    UP = "up"


@dataclass(frozen=True)
class DeviceEvent:
    """An outage starting (down, with the first failure's code) or ending (up)."""

    id: int
    device_id: int
    at: str
    kind: str
    error: str | None


def outage_event(
    last_kind: str | None, newest_first: Sequence[CheckResult]
) -> tuple[str, CheckResult] | None:
    """The event a device's newest check causes, if any (plan section 15).

    last_kind is the device's latest event kind, or None. newest_first holds
    its latest checks, newest first, including the one just stored. Returns
    (kind, the check the event is dated at): down at the first failure of
    DOWN_AFTER_FAILURES in a row, up at the first success after a down.
    """
    newest = newest_first[0]
    if newest.success:
        return (EventKind.UP, newest) if last_kind == EventKind.DOWN else None
    if last_kind == EventKind.DOWN:
        return None
    streak = newest_first[:DOWN_AFTER_FAILURES]
    if len(streak) == DOWN_AFTER_FAILURES and not any(r.success for r in streak):
        return EventKind.DOWN, streak[-1]
    return None


def validate_name(name: str) -> str:
    """Return the trimmed name, or raise ValidationError."""
    if name is None:
        raise ValidationError("name is required")
    trimmed = name.strip()
    if not trimmed:
        raise ValidationError("name is required")
    if len(trimmed) > NAME_MAX_LEN:
        raise ValidationError(f"name must be at most {NAME_MAX_LEN} characters")
    if any(unicodedata.category(ch) == "Cc" for ch in trimmed):
        raise ValidationError("name must not contain control characters")
    return trimmed


# Degraded (plan section 18)

# The checks the degraded rules look at: a device's last 10, newest first.
DEGRADED_WINDOW = 10
# ping.exe waits at most 1000 ms for a reply, so a higher threshold could never be crossed.
LATENCY_THRESHOLD_MAX_MS = 1000


@dataclass(frozen=True)
class Thresholds:
    """When a device that is up counts as degraded. The defaults the user accepted."""

    latency_ms: int = 150
    failures: int = 2


def validate_thresholds(latency_ms: str | int, failures: str | int) -> Thresholds:
    """Thresholds from form values, or ValidationError naming the field and its range."""
    return Thresholds(
        latency_ms=_whole_number(latency_ms, "latency threshold", 1, LATENCY_THRESHOLD_MAX_MS),
        failures=_whole_number(failures, "failure threshold", 1, DEGRADED_WINDOW),
    )


def _whole_number(value: str | int, what: str, low: int, high: int) -> int:
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ValidationError(f"{what} must be a whole number") from None
    if not low <= number <= high:
        raise ValidationError(f"{what} must be from {low} to {high}")
    return number


@dataclass(frozen=True)
class RecentChecks:
    """A device's last DEGRADED_WINDOW checks, summed up."""

    checks: int
    failures: int
    avg_ms: float | None  # the successful ones, to 0.1 ms; None if there were none

    @classmethod
    def of(cls, newest_first: Sequence[CheckResult]) -> RecentChecks:
        window = newest_first[:DEGRADED_WINDOW]
        rtts = [c.rtt_ms for c in window if c.success]
        avg = round(sum(rtts) / len(rtts), 1) if rtts else None
        return cls(checks=len(window), failures=len(window) - len(rtts), avg_ms=avg)

    def is_slow(self, thresholds: Thresholds) -> bool:
        return self.avg_ms is not None and self.avg_ms > thresholds.latency_ms

    def is_failing(self, thresholds: Thresholds) -> bool:
        return self.failures >= thresholds.failures


# Declared links (plan section 20): which device each device connects through,
# by id, as {device id: the id of the device it connects through}.


def validate_parent(value: str | int | None) -> int | None:
    """A device id from the Connected through field, or None when it is left empty."""
    text = "" if value is None else str(value).strip()
    if not text:
        return None
    if not text.isdigit():
        raise ValidationError("choose a device from the list")
    return int(text)


def connects_through(device_id: int, links: Mapping[int, int]) -> list[int]:
    """The devices device_id connects through, nearest first. Stops before repeating one."""
    chain: list[int] = []
    current = links.get(device_id)
    while current is not None and current != device_id and current not in chain:
        chain.append(current)
        current = links.get(current)
    return chain


def connected_through(device_id: int, links: Mapping[int, int]) -> set[int]:
    """Every device that connects through device_id, directly or through others."""
    return {child for child in links if child != device_id and device_id in connects_through(child, links)}


# Packet captures (plan section 28): diagnostics, not monitoring history.

# Retention: the last KEEP_CAPTURES captures or KEEP_CAPTURE_DAYS days, whichever keeps more.
KEEP_CAPTURES = 50
KEEP_CAPTURE_DAYS = 30
FILTER_MAX_LEN = 200


class CaptureState:
    RUNNING = "running"
    STOPPED = "stopped"  # the user stopped it
    LIMIT = "limit"  # a limit stopped it; the note says which
    FAILED = "failed"  # a fault on this PC stopped it; the note says what
    INTERRUPTED = "interrupted"  # NetPulse stopped while it ran

    ALL = (RUNNING, STOPPED, LIMIT, FAILED, INTERRUPTED)


@dataclass(frozen=True)
class Capture:
    id: int
    interface: str  # Npcap's device name
    description: str  # what the interface was called, kept in case it goes away
    filter: str
    snaplen: int
    started_at: str
    ended_at: str | None
    packets: int
    bytes: int  # on the wire
    file: str  # the PCAP file's name in the captures folder
    state: str
    note: str | None = None

    @property
    def running(self) -> bool:
        return self.state == CaptureState.RUNNING


@dataclass(frozen=True)
class SecondCounts:
    """One second of a capture: traffic into and out of this PC, and packets by protocol."""

    second: int  # Unix time
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    protocols: tuple[tuple[str, int], ...] = ()  # (protocol, packets), most first

    @property
    def packets(self) -> int:
        return self.packets_in + self.packets_out

    @property
    def bytes(self) -> int:
        return self.bytes_in + self.bytes_out


def validate_filter(text: str) -> str:
    """A capture filter as typed, stripped. Npcap compiles it; this only bounds its length."""
    text = text.strip()
    if len(text) > FILTER_MAX_LEN:
        raise ValidationError(f"Filter: at most {FILTER_MAX_LEN} characters")
    return text


# Path traces (plan section 30)

KEEP_TRACES = 100


class HopLabel:
    THIS_NETWORK = "this network"
    PROVIDER = "provider"
    BEYOND = "beyond"

    ALL = (THIS_NETWORK, PROVIDER, BEYOND)


@dataclass(frozen=True)
class Hop:
    """One hop count of a trace, over all its rounds. A hop that never answered has no address: "*"."""

    ttl: int
    address: str | None
    sent: int
    received: int
    best_ms: int | None = None
    avg_ms: float | None = None
    worst_ms: int | None = None
    name: str | None = None
    label: str | None = None
    others: tuple[str, ...] = ()  # other routers that answered for this hop count: load balancing
    note: str | None = None

    @property
    def loss_percent(self) -> float:
        return 0.0 if self.sent == 0 else 100 * (self.sent - self.received) / self.sent


@dataclass(frozen=True)
class Trace:
    id: int
    target: str  # as typed
    address: str  # what it resolved to
    started_at: str
    rounds: int
    reached: bool
    hops: tuple[Hop, ...] = ()
    error: str | None = None
