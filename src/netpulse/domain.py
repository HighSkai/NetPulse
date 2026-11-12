"""Domain model (plan section 9, step 1): what NetPulse stores, not how it looks.

Plain immutable values and the rule for a valid device name. No SQL, no
Flask, no ping.exe. tests/test_architecture.py keeps this module at the
bottom of the layers: it imports nothing else from NetPulse.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

NAME_MAX_LEN = 64

# Plan section 15: failed checks in a row before the outage log says Down.
# One dropped echo is not an outage.
DOWN_AFTER_FAILURES = 2


class ValidationError(ValueError):
    pass


class DeviceKind:
    """What a device is (plan section 39). The user says; NetPulse only suggests."""

    UNKNOWN = "unknown"

    LABELS = {
        "router": "Router", "switch": "Switch", "access_point": "Access point", "firewall": "Firewall",
        "server": "Server", "nas": "NAS", "vm": "Virtual machine", "desktop": "Desktop", "laptop": "Laptop",
        "phone": "Phone", "tablet": "Tablet", "printer": "Printer", "camera": "Camera", "nvr": "NVR",
        "tv": "TV or media player", "smart_home": "Smart home", "iot": "IoT device", "sbc": "Single-board computer",
        "ups": "UPS or power", "appliance": "Network appliance", "service": "Online service", UNKNOWN: "Not set",
    }
    ALL = tuple(LABELS)


class CheckKind:
    """How a device is checked (plan section 40)."""

    ICMP = "icmp"  # an echo: the device answers ping
    TCP = "tcp"  # a TCP connection to one port: for devices that ignore ping

    ALL = (ICMP, TCP)
    LABELS = {ICMP: "Ping (ICMP echo)", TCP: "TCP port"}


# Seconds between checks of one device. The loop runs every 30 s and checks the
# devices that are due, so every choice is a multiple of it.
CHECK_INTERVALS = (30, 60, 300, 900)
DEFAULT_INTERVAL_S = 30
TEXT_MAX_LEN = 64  # vendor, model, location, a group's name
NOTES_MAX_LEN = 2000
TAG_MAX_LEN = 32
TAGS_MAX = 12


@dataclass(frozen=True)
class Device:
    """A monitored host. deleted_at stays None while the device is live.

    Everything after deleted_at is inventory (plan section 39) and how the
    device is checked (plan section 40); all of it has a default, so a device
    is still just a name and a host.
    """

    id: int
    name: str
    host: str
    created_at: str
    updated_at: str
    deleted_at: str | None
    kind: str = DeviceKind.UNKNOWN
    group_id: int | None = None
    vendor: str = ""
    model: str = ""
    location: str = ""
    notes: str = ""
    mac: str | None = None  # AA-BB-CC-DD-EE-FF, as Windows writes it
    paused: bool = False  # not checked, and never alerted on, until resumed
    interval_s: int = DEFAULT_INTERVAL_S
    check_kind: str = CheckKind.ICMP
    check_port: int | None = None  # the TCP port, when check_kind is tcp
    alerts_muted: bool = False
    tags: tuple[str, ...] = ()

    @property
    def is_live(self) -> bool:
        return self.deleted_at is None

    @property
    def kind_label(self) -> str:
        return DeviceKind.LABELS.get(self.kind, self.kind)

    @property
    def check_label(self) -> str:
        """How it is checked, in a few words: "ping" or "TCP 443"."""
        return f"TCP {self.check_port}" if self.check_kind == CheckKind.TCP else "ping"


@dataclass(frozen=True)
class DeviceGroup:
    id: int
    name: str
    devices: int = 0  # live devices in it


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
    PAUSED = "paused"  # plan section 40: not checked until resumed; a DeviceRow's state, like DEGRADED


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


# Inventory (plan section 39)

_MAC_SEPARATORS = str.maketrans("", "", ":-. ")


def _clean_text(value: str | None, what: str, limit: int) -> str:
    text = " ".join((value or "").split()) if limit <= TEXT_MAX_LEN else (value or "").strip()
    if len(text) > limit:
        raise ValidationError(f"{what} must be at most {limit} characters")
    if any(unicodedata.category(ch) == "Cc" and ch not in "\n\r\t" for ch in text):
        raise ValidationError(f"{what} must not contain control characters")
    return text


def validate_kind(kind: str | None) -> str:
    kind = (kind or DeviceKind.UNKNOWN).strip().lower().replace(" ", "_").replace("-", "_")
    if kind in DeviceKind.LABELS:
        return kind
    by_label = {label.casefold(): key for key, label in DeviceKind.LABELS.items()}
    if kind.replace("_", " ") in by_label:  # an imported file may hold the label
        return by_label[kind.replace("_", " ")]
    raise ValidationError(f"type must be one of {', '.join(k for k in DeviceKind.ALL if k != DeviceKind.UNKNOWN)}")


def validate_mac(mac: str | None) -> str | None:
    """A MAC address as AA-BB-CC-DD-EE-FF, from any common way of writing one. Empty is None."""
    text = (mac or "").strip()
    if not text:
        return None
    digits = text.translate(_MAC_SEPARATORS).upper()
    if len(digits) != 12 or any(ch not in "0123456789ABCDEF" for ch in digits):
        raise ValidationError("MAC address must be six pairs of hex digits, such as AA-BB-CC-DD-EE-FF")
    return "-".join(digits[i : i + 2] for i in range(0, 12, 2))


def validate_tags(tags) -> tuple[str, ...]:
    """Tags from a comma-separated field or a list: lower case, each once, in order."""
    parts = tags.split(",") if isinstance(tags, str) else list(tags or ())
    clean: list[str] = []
    for part in parts:
        tag = " ".join(str(part).split()).casefold()
        if not tag:
            continue
        if len(tag) > TAG_MAX_LEN:
            raise ValidationError(f"tags must be at most {TAG_MAX_LEN} characters each")
        if any(unicodedata.category(ch) == "Cc" for ch in tag):
            raise ValidationError("tags must not contain control characters")
        if tag not in clean:
            clean.append(tag)
    if len(clean) > TAGS_MAX:
        raise ValidationError(f"tags: at most {TAGS_MAX} on one device")
    return tuple(clean)


def validate_interval(value: str | int | None) -> int:
    text = str(DEFAULT_INTERVAL_S if value in (None, "") else value).strip()
    if not text.isdigit() or int(text) not in CHECK_INTERVALS:
        raise ValidationError(f"interval must be one of {', '.join(map(str, CHECK_INTERVALS))} seconds")
    return int(text)


def validate_check(kind: str | None, port: str | int | None) -> tuple[str, int | None]:
    """(check kind, port). A TCP check needs a port; a ping has none."""
    kind = (kind or CheckKind.ICMP).strip().lower()
    if kind in ("ping", ""):
        kind = CheckKind.ICMP
    if kind not in CheckKind.ALL:
        raise ValidationError("check must be ping or a TCP port")
    if kind == CheckKind.ICMP:
        return kind, None
    text = "" if port is None else str(port).strip()
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        raise ValidationError("port must be a number from 1 to 65535 for a TCP check")
    return kind, int(text)


@dataclass(frozen=True)
class Inventory:
    """A device's inventory fields and check settings, validated together (plan section 39)."""

    kind: str = DeviceKind.UNKNOWN
    vendor: str = ""
    model: str = ""
    location: str = ""
    notes: str = ""
    mac: str | None = None
    paused: bool = False
    interval_s: int = DEFAULT_INTERVAL_S
    check_kind: str = CheckKind.ICMP
    check_port: int | None = None
    alerts_muted: bool = False
    tags: tuple[str, ...] = ()

    @classmethod
    def of(cls, values) -> Inventory:
        """From form or file values, by field name. Missing fields take their defaults.

        Raises ValidationError naming the field.
        """
        get = values.get
        check_kind, check_port = validate_check(get("check_kind"), get("check_port"))
        return cls(
            kind=validate_kind(get("kind")),
            vendor=_clean_text(get("vendor"), "vendor", TEXT_MAX_LEN),
            model=_clean_text(get("model"), "model", TEXT_MAX_LEN),
            location=_clean_text(get("location"), "location", TEXT_MAX_LEN),
            notes=_clean_text(get("notes"), "notes", NOTES_MAX_LEN),
            mac=validate_mac(get("mac")),
            paused=_flag(get("paused")),
            interval_s=validate_interval(get("interval_s")),
            check_kind=check_kind,
            check_port=check_port,
            alerts_muted=_flag(get("alerts_muted")),
            tags=validate_tags(get("tags") or ""),
        )


def _flag(value) -> bool:
    return str(value or "").strip().lower() in ("1", "yes", "true", "on", "y")


def validate_group_name(name: str | None) -> str:
    text = _clean_text(name, "group name", TEXT_MAX_LEN)
    if not text:
        raise ValidationError("group name is required")
    return text


# Guesses at what a device is, from its name (plan section 39). Only ever a
# suggestion the page marks as a guess: a name is not evidence of much.
# (type, words found anywhere in the name, short words that must be a whole part of it).
_KIND_HINTS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("printer", ("printer", "laserjet", "officejet", "deskjet", "epson", "brother"), ()),
    ("camera", ("camera", "doorbell", "reolink"), ("cam", "wyze", "arlo")),
    ("nvr", (), ("nvr", "dvr")),
    ("nas", ("synology", "diskstation", "truenas", "unraid"), ("nas", "qnap")),
    ("tv", ("roku", "chromecast", "firetv", "appletv", "bravia"), ("tv",)),
    ("phone", ("iphone", "android"), ("phone", "pixel", "galaxy")),
    ("tablet", ("ipad", "tablet"), ()),
    ("laptop", ("laptop", "macbook", "thinkpad", "notebook"), ()),
    ("desktop", ("desktop", "workstation"), ("imac", "pc")),
    ("sbc", ("raspberry", "pihole", "octopi"), ("rpi", "pi")),
    ("smart_home", ("alexa", "homepod", "smartthings", "tasmota", "shelly"), ("echo", "nest", "hue", "myq", "esp")),
    ("access_point", ("accesspoint", "unifi"), ("ap", "eero", "orbi", "deco")),
    ("switch", ("switch",), ()),
    ("router", ("router", "gateway", "fritz"), ()),
    ("server", ("server", "proxmox"), ("srv", "esxi", "docker")),
    ("ups", (), ("ups", "apc")),
)
_NAME_PARTS = re.compile(r"[^a-z0-9]+")


def guess_kind(name: str | None) -> str | None:
    """A device type suggested by a host or device name, or None. A guess, never a fact.

    Only the first label of a host name is read, so a domain such as
    home.arpa never decides the type.
    """
    text = (name or "").casefold().strip()
    if not text or text.replace(".", "").isdigit():
        return None
    label = text.split(".", 1)[0]
    parts = [part.rstrip("0123456789") for part in _NAME_PARTS.split(label) if part]
    for kind, anywhere, whole in _KIND_HINTS:
        if any(word in label for word in anywhere) or any(word in parts for word in whole):
            return kind
    return None


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
