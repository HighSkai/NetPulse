"""Running packet captures (plan section 28): one at a time, on its own thread.

- Nothing is captured until the user starts it. The capture reads packets in
  batches from the PacketSource of plan section 27 and decodes them on its
  own thread, never in a request.
- Live data stays in memory: the last 5,000 packet summaries, per-second
  counts in and out of this PC by protocol over a rolling ten minutes, and the
  top talkers. Web requests read them under a lock.
- Every capture also writes a PCAP file to the captures folder next to the
  database. Per-second counts are written once a second, in one transaction.
- A limit (10 minutes, 100 MB, a million packets) ends it, and so does a
  fault on this PC, which is shown in the status, never raised.
- Tests drive it with a fake source and a fake clock; nothing sleeps.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path

from netpulse.capture import (
    SNAPLEN_FULL,
    SNAPLEN_HEADERS,
    CaptureSession,
    CaptureUnavailable,
    Interface,
    PacketSource,
    RawPacket,
)
from netpulse.capture.decode import PacketSummary, decode
from netpulse.capture.pcap import PcapError, PcapWriter, complete_length, read_packets
from netpulse.domain import Capture, CaptureState, SecondCounts, ValidationError, validate_filter
from netpulse.network import Adapter
from netpulse.store import Store

log = logging.getLogger(__name__)

BATCH_WAIT_MS = 250
FLUSH_EVERY_S = 1.0
RECENT_LIMIT = 5000
RATE_WINDOW_S = 600  # the live graph's rolling ten minutes
TALKER_LIMIT = 10_000  # addresses counted at most, so a scan cannot fill memory
PAGE_SIZE = 100  # packets on one page of a finished capture (plan section 29)
SNAPLENS = (SNAPLEN_FULL, SNAPLEN_HEADERS)


@dataclass(frozen=True)
class CaptureLimits:
    """The first one reached stops a capture. Shown before it starts (plan section 28)."""

    seconds: int = 600
    bytes: int = 100_000_000  # of the PCAP file
    packets: int = 1_000_000


class CaptureBusy(Exception):
    """A capture is already running: there is one at a time."""


@dataclass(frozen=True)
class Talker:
    address: str  # the other end: an IP address, or a MAC address for a frame with no IP
    packets: int
    bytes: int


@dataclass(frozen=True)
class TrafficStatus:
    running: bool = False
    capture: Capture | None = None  # the running capture, or the last one this run of NetPulse
    packets: int = 0
    bytes: int = 0  # on the wire
    file_bytes: int = 0
    elapsed_s: float = 0.0
    limits: CaptureLimits = CaptureLimits()

    @property
    def error(self) -> str | None:
        """Why the last capture stopped, if a fault on this PC stopped it."""
        if self.capture is not None and self.capture.state == CaptureState.FAILED:
            return self.capture.note
        return None


def duration_text(seconds: int) -> str:
    """10 minutes, 1 minute, or 90 seconds: a limit as the page and the note say it."""
    if seconds % 60:
        return f"{seconds} seconds"
    minutes = seconds // 60
    return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"


def size_text(nbytes: int) -> str:
    """100 MB, or the bytes when not whole megabytes."""
    return f"{nbytes // 1_000_000} MB" if nbytes % 1_000_000 == 0 else f"{nbytes:,} bytes"


def captures_folder(database: Path) -> Path:
    """The captures folder: next to the database, named after its file. netpulse.db -> netpulse-captures."""
    return database.with_name(f"{database.stem}-captures")


def folder_size(folder: Path) -> tuple[int, int]:
    """How many capture files the folder holds, and their bytes (plan section 32). No folder: none."""
    try:
        sizes = [entry.stat().st_size for entry in folder.iterdir() if entry.is_file()]
    except OSError:
        return 0, 0
    return len(sizes), sum(sizes)


def capture_file_name(started: datetime, token: str) -> str:
    return f"capture-{started.astimezone(UTC):%Y%m%dT%H%M%SZ}-{token}.pcap"


def filter_presets(web_port: int, devices: Iterable[tuple[str, str]] = ()) -> list[tuple[str, str]]:
    """(label, filter) for the traffic page's presets (plan section 28)."""
    presets = [
        ("Everything", ""),
        ("All but NetPulse's own pages", f"not (host 127.0.0.1 and tcp port {web_port})"),
        ("ICMP only", "icmp or icmp6"),
    ]
    presets += [(f"Only {name}", f"host {host}") for name, host in devices]
    return presets


def _mac(text: str | None) -> str | None:
    return None if text is None else text.replace("-", ":").lower()


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Counts:
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    protocols: dict[str, int] = field(default_factory=dict)

    def frozen(self, second: int) -> SecondCounts:
        ordered = sorted(self.protocols.items(), key=lambda item: (-item[1], item[0]))
        return SecondCounts(second, self.bytes_in, self.bytes_out, self.packets_in, self.packets_out, tuple(ordered))


@dataclass
class _Run:
    """One capture's state, owned by its thread except where the lock says."""

    capture: Capture
    session: CaptureSession
    writer: PcapWriter
    file: object
    mine: frozenset[str]  # this PC's MAC and IP addresses on that interface
    started: float
    flushed: float
    packets: int = 0
    bytes: int = 0
    seconds: dict[int, _Counts] = field(default_factory=dict)
    dirty: set[int] = field(default_factory=set)
    talkers: dict[str, list[int]] = field(default_factory=dict)
    protocols: dict[str, int] = field(default_factory=dict)
    recent: deque = field(default_factory=lambda: deque(maxlen=RECENT_LIMIT))


class TrafficService:
    def __init__(
        self,
        source: PacketSource | None,
        open_store: Callable[[], Store],
        folder: Path,
        *,
        adapters: Callable[[], Iterable[Adapter]] = tuple,
        limits: CaptureLimits = CaptureLimits(),
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = _utc_now,
        unavailable: str = "packet capture is off: Npcap was not found at startup",
    ) -> None:
        """source is None when this PC cannot capture; unavailable then says why.

        adapters gives the adapters of plan section 19, for this PC's MAC address.
        """
        self._source = source
        self._open_store = open_store
        self.folder = folder
        self._adapters = adapters
        self.limits = limits
        self._clock = clock
        self._now = now
        self._unavailable = unavailable
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._run: _Run | None = None
        self._last: Capture | None = None
        self._final: tuple[int, int, int, float] = (0, 0, 0, 0.0)
        self._thread: threading.Thread | None = None
        self._starting = False  # a start is under way: the one slot is taken

    @property
    def available(self) -> bool:
        return self._source is not None

    @property
    def unavailable_reason(self) -> str | None:
        return None if self._source is not None else self._unavailable

    def interfaces(self) -> list[Interface]:
        """Raises CaptureUnavailable when this PC cannot capture."""
        if self._source is None:
            raise CaptureUnavailable(self._unavailable)
        return self._source.interfaces()

    # Starting and stopping

    def start(self, interface: str, capture_filter: str = "", snaplen: int = SNAPLEN_FULL) -> Capture:
        """Start a capture on its own thread.

        Raises CaptureBusy, ValidationError, InvalidFilter or CaptureUnavailable,
        and then nothing is stored or written.
        """
        run = self._begin(interface, capture_filter, snaplen)
        self._thread = threading.Thread(target=self._capture, args=(run,), name="netpulse-capture", daemon=True)
        self._thread.start()
        return run.capture

    def run(self, interface: str, capture_filter: str = "", snaplen: int = SNAPLEN_FULL) -> Capture:
        """One capture on this thread, until it stops. start() runs this on its own."""
        self._capture(self._begin(interface, capture_filter, snaplen))
        return self.status().capture

    def stop(self) -> None:
        """Ask the running capture to stop. It finishes its batch and writes what it has."""
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        """Wait for the capture thread. For tests and shutdown."""
        if self._thread is not None:
            self._thread.join(timeout)

    def _begin(self, interface: str, capture_filter: str, snaplen: int) -> _Run:
        """Open the interface, the file and the row, holding the one capture slot throughout,
        so a second start can never leave a row or a file behind."""
        with self._lock:
            if self._run is not None or self._starting:
                raise CaptureBusy("a capture is already running; stop it first")
            self._starting = True
        try:
            run = self._open_run(interface, capture_filter, snaplen)
            with self._lock:
                self._run = run
                self._stop.clear()
            return run
        finally:
            with self._lock:
                self._starting = False

    def _open_run(self, interface: str, capture_filter: str, snaplen: int) -> _Run:
        text = validate_filter(capture_filter)
        if snaplen not in SNAPLENS:
            raise ValidationError(f"Snapshot length: {SNAPLEN_FULL} (whole packets) or {SNAPLEN_HEADERS} (headers only)")
        chosen = next((i for i in self.interfaces() if i.name == interface), None)
        if chosen is None:
            raise CaptureUnavailable(f"no such interface: {interface}")
        adapter = chosen.adapter(self._adapters())
        mine = {str(a) for a in chosen.addresses} | ({_mac(adapter.mac)} if adapter and adapter.mac else set())
        session = self._source.open(interface, snaplen=snaplen, capture_filter=text)
        started = self._now()
        name = capture_file_name(started, secrets.token_hex(4))
        path = self.folder / name
        file = None
        try:
            self.folder.mkdir(parents=True, exist_ok=True)
            file = path.open("xb")
            writer = PcapWriter(file, session.link_type, snaplen)
            store = self._open_store()
            try:
                capture = store.start_capture(
                    interface, chosen.description, text, snaplen, name, now=started.replace(microsecond=0).isoformat()
                )
            finally:
                store.close()
        except BaseException:
            session.close()
            if file is not None:
                file.close()
                path.unlink(missing_ok=True)
            raise
        started_clock = self._clock()
        return _Run(capture, session, writer, file, frozenset(mine), started_clock, started_clock)

    # The capture loop

    def _capture(self, run: _Run) -> None:
        state, note = CaptureState.STOPPED, None
        store = self._open_store()
        try:
            while not self._stop.is_set():
                try:
                    batch = run.session.next_batch(BATCH_WAIT_MS)
                except CaptureUnavailable as exc:
                    state, note = CaptureState.FAILED, str(exc)
                    break
                reached = self._take(run, batch)
                now = self._clock()
                if reached is None and now - run.started >= self.limits.seconds:
                    reached = f"reached the limit of {duration_text(self.limits.seconds)}"
                if now - run.flushed >= FLUSH_EVERY_S:
                    self._flush(store, run, now)
                if reached is not None:
                    state, note = CaptureState.LIMIT, reached
                    break
        except Exception:
            log.exception("the capture on %s failed", run.capture.interface)
            state, note = CaptureState.FAILED, "the capture stopped on an error; the NetPulse log has the details"
        finally:
            self._end(store, run, state, note)

    def _take(self, run: _Run, batch: list[RawPacket]) -> str | None:
        """Count, keep and write a batch. Returns the limit reached, if one was."""
        reached = None
        with self._lock:
            for packet in batch:
                summary = decode(packet)
                run.writer.write(packet)
                out = summary.src_mac in run.mine or summary.src in run.mine
                second = packet.time_ns // 1_000_000_000
                counts = run.seconds.setdefault(second, _Counts())
                if out:
                    counts.bytes_out += summary.length
                    counts.packets_out += 1
                else:
                    counts.bytes_in += summary.length
                    counts.packets_in += 1
                counts.protocols[summary.protocol] = counts.protocols.get(summary.protocol, 0) + 1
                run.protocols[summary.protocol] = run.protocols.get(summary.protocol, 0) + 1
                run.dirty.add(second)
                other = summary.dst if out else summary.src
                if other is not None and (other in run.talkers or len(run.talkers) < TALKER_LIMIT):
                    talker = run.talkers.setdefault(other, [0, 0])
                    talker[0] += 1
                    talker[1] += summary.length
                run.recent.append(summary)
                run.packets += 1
                run.bytes += summary.length
                if run.packets >= self.limits.packets:
                    reached = f"reached the limit of {self.limits.packets:,} packets"
                elif run.writer.bytes_written >= self.limits.bytes:
                    reached = f"reached the limit of {size_text(self.limits.bytes)}"
                if reached is not None:
                    break
        return reached

    def _flush(self, store: Store, run: _Run, now: float) -> None:
        """The changed seconds and the totals, in one transaction, then the file to disk."""
        with self._lock:
            changed = [run.seconds[s].frozen(s) for s in sorted(run.dirty)]
            run.dirty.clear()
            packets, nbytes = run.packets, run.bytes
            newest = max(run.seconds, default=0)
            for second in [s for s in run.seconds if s <= newest - RATE_WINDOW_S]:
                del run.seconds[second]
        store.save_rates(run.capture.id, changed, packets, nbytes)
        run.writer.flush()
        run.flushed = now

    def _end(self, store: Store, run: _Run, state: str, note: str | None) -> None:
        try:
            run.session.close()
            self._flush(store, run, self._clock())
            run.file.close()
            finished = store.finish_capture(run.capture.id, state, note, now=self._timestamp())
        except Exception:
            log.exception("could not finish the capture on %s", run.capture.interface)
            finished = run.capture
        finally:
            store.close()
        with self._lock:
            self._final = (run.packets, run.bytes, run.writer.bytes_written, self._clock() - run.started)
            self._last = finished
            self._run = None
        self.cleanup()

    def _timestamp(self) -> str:
        return self._now().astimezone(UTC).replace(microsecond=0).isoformat()

    # Reading the live data

    def status(self) -> TrafficStatus:
        with self._lock:
            run = self._run
            if run is not None:
                return TrafficStatus(
                    True, run.capture, run.packets, run.bytes, run.writer.bytes_written,
                    self._clock() - run.started, self.limits,
                )
            packets, nbytes, file_bytes, elapsed = self._final
            return TrafficStatus(False, self._last, packets, nbytes, file_bytes, elapsed, self.limits)

    def recent(self, limit: int = RECENT_LIMIT) -> list[PacketSummary]:
        """The newest packet summaries, newest first."""
        with self._lock:
            if self._run is None:
                return []
            newest = list(self._run.recent)[-limit:] if limit else []
        return newest[::-1]

    def rates(self) -> list[SecondCounts]:
        """The running capture's seconds over the last ten minutes, oldest first."""
        with self._lock:
            if self._run is None:
                return []
            return [self._run.seconds[s].frozen(s) for s in sorted(self._run.seconds)]

    def protocols(self) -> list[tuple[str, int]]:
        """Packets by protocol over the whole running capture, most first."""
        with self._lock:
            if self._run is None:
                return []
            return sorted(self._run.protocols.items(), key=lambda item: (-item[1], item[0]))

    def talkers(self, limit: int = 10) -> list[Talker]:
        """The addresses this PC exchanged the most bytes with, most first."""
        with self._lock:
            if self._run is None:
                return []
            ranked = sorted(self._run.talkers.items(), key=lambda item: (-item[1][1], item[0]))
        return [Talker(address, packets, nbytes) for address, (packets, nbytes) in ranked[:limit]]

    # Files and retention

    def path_of(self, capture: Capture) -> Path:
        """A capture's file. The schema allows only a bare name, so it is always inside the folder."""
        return self.folder / capture.file

    def packets(self, capture: Capture, offset: int = 0, limit: int = PAGE_SIZE) -> tuple[list[PacketSummary], bool]:
        """A page of a capture's packets read from its file, oldest first, and whether more follow (plan section 29).

        A running capture's file is read as it stands. A missing or unreadable file is an empty page.
        """
        try:
            with self.path_of(capture).open("rb") as file:
                _, packets = read_packets(file)
                chunk = list(islice(packets, offset, offset + limit + 1))
        except (OSError, PcapError):
            return [], False
        return [decode(p) for p in chunk[:limit]], len(chunk) > limit

    def download_length(self, capture: Capture) -> int:
        """How much of the file to send: up to the last whole packet, so a running capture downloads cleanly."""
        with self.path_of(capture).open("rb") as file:
            return complete_length(file)

    def delete(self, capture_id: int) -> Capture:
        """Delete a finished capture, its counts and its file. Raises KeyError or ValueError."""
        store = self._open_store()
        try:
            capture = store.delete_capture(capture_id)
        finally:
            store.close()
        self.path_of(capture).unlink(missing_ok=True)
        return capture

    def recover(self) -> None:
        """At startup: a capture left running by an earlier NetPulse is interrupted; old ones go."""
        store = self._open_store()
        try:
            for capture in store.interrupt_running(now=self._timestamp()):
                log.warning("capture %d was still running when NetPulse stopped; kept as interrupted", capture.id)
        finally:
            store.close()
        self.cleanup()

    def cleanup(self) -> list[Capture]:
        """Retention (plan section 28): delete captures past it, with their files."""
        store = self._open_store()
        try:
            expired = store.expired_captures(self._now())
        finally:
            store.close()
        for capture in expired:
            self.delete(capture.id)
        return expired
