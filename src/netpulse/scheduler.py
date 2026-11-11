"""Background checks (plan section 6).

- One in-process thread. Every CHECK_INTERVAL_S it checks each live device
  once, one at a time, through run_check (the same path as Check now).
- Rounds never overlap. If a round runs past the next tick, that tick is
  skipped rather than started late, so a slow round is never followed by a
  burst of back-to-back rounds.
- A Heartbeat records what the loop did, so the dashboard can tell
  "monitoring stopped" from "devices are down" (plan section 13).
- Every MAINTENANCE_INTERVAL_S, between rounds, it runs the maintenance
  pass (plan section 32): retention, a WAL checkpoint and SQLite's
  optimize. A failed pass is logged and tried again an interval later.
- Tests drive it with a fake clock and wait function; nothing sleeps.
"""

from __future__ import annotations

import logging
import math
import os
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from netpulse.checks import CHECK_INTERVAL_S, run_round
from netpulse.ping.result import Pinger, PingerUnavailable, PingResult
from netpulse.store import Store, Upkeep

log = logging.getLogger(__name__)

# Status-bar text for a round that failed on anything but PingerUnavailable.
# The traceback is in the log; the page only needs to say where to look.
ROUND_FAILED = "the last check round failed; see the NetPulse log"

# Plan section 32: upkeep runs hourly, the first time an hour after start
# (startup has just applied capture retention).
MAINTENANCE_INTERVAL_S = 3600


class MonitorState:
    """What the status bar says about the check loop (plan section 13)."""

    RUNNING = "running"
    STARTING = "starting"
    LATE = "late"
    FAILING = "failing"
    NOT_RUNNING = "not_running"


@dataclass(frozen=True)
class MonitorStatus:
    state: str
    last_round_age_s: int | None  # whole seconds since the last round finished
    devices: int | None  # devices checked in that round
    up: int | None  # of those, how many answered (plan section 25)
    error: str | None  # why the newest round failed


class Heartbeat:
    """What the check loop last did. In memory only.

    The scheduler thread writes it and web requests read it, so every access
    holds a lock. Reading it never touches the database.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._alive = False
        self._in_round = False
        self._last_finished: float | None = None
        self._devices: int | None = None
        self._up: int | None = None
        self._error: str | None = None

    def loop_started(self) -> None:
        with self._lock:
            self._alive = True

    def loop_stopped(self) -> None:
        with self._lock:
            self._alive = False
            self._in_round = False

    def round_started(self) -> None:
        with self._lock:
            self._in_round = True

    def round_finished(self, devices: int, up: int) -> None:
        with self._lock:
            self._in_round = False
            self._last_finished = self._clock()
            self._devices = devices
            self._up = up
            self._error = None

    def round_failed(self, error: str) -> None:
        """Keeps the last good round's time: the bar shows the error until a round succeeds."""
        with self._lock:
            self._in_round = False
            self._error = error

    def status(self, interval_s: float) -> MonitorStatus:
        with self._lock:
            age = None if self._last_finished is None else self._clock() - self._last_finished
            if not self._alive:
                state = MonitorState.NOT_RUNNING
            elif self._error is not None:
                state = MonitorState.FAILING
            elif age is None:
                state = MonitorState.STARTING
            elif not self._in_round and age > 2 * interval_s:
                state = MonitorState.LATE
            else:
                state = MonitorState.RUNNING
            return MonitorStatus(
                state=state,
                last_round_age_s=None if age is None else int(age),
                devices=self._devices,
                up=self._up,
                error=self._error,
            )


def failure_message(exc: Exception) -> str:
    """A fault on this PC names itself; anything else points at the log."""
    return str(exc) if isinstance(exc, PingerUnavailable) else ROUND_FAILED


def next_round_start(started: float, now: float, interval_s: float) -> tuple[float, int]:
    """First tick on the grid started + k * interval_s (k >= 1) not before now.

    Returns (that tick, how many ticks the round ran past and so skipped).
    """
    ticks = max(1, math.ceil((now - started) / interval_s))
    return started + ticks * interval_s, ticks - 1


def maintain(store: Store, cleanup_captures: Callable[[], object] | None = None) -> Upkeep:
    """One maintenance pass: capture retention, which deletes files too, then the database's own."""
    if cleanup_captures is not None:
        cleanup_captures()
    return store.maintain()


def should_start_scheduler(debug: bool, environ: Mapping[str, str] = os.environ) -> bool:
    """Flask's debug reloader runs a file-watching parent and a serving child.

    Only the child (WERKZEUG_RUN_MAIN=true) may run checks, or every device
    would be pinged twice per round.
    """
    return not debug or environ.get("WERKZEUG_RUN_MAIN") == "true"


class Scheduler:
    def __init__(
        self,
        open_store: Callable[[], Store],
        pinger: Pinger,
        *,
        interval_s: float = CHECK_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], bool] | None = None,
        heartbeat: Heartbeat | None = None,
        cleanup_captures: Callable[[], object] | None = None,
        maintenance_s: float = MAINTENANCE_INTERVAL_S,
    ) -> None:
        """open_store gives a fresh Store per round: SQLite connections stay on one thread.

        wait(seconds) blocks and returns True when the loop should stop.
        By default it waits on stop(). heartbeat is shared with the web app;
        by default the scheduler keeps its own, on the same clock.
        cleanup_captures is the capture service's retention, run with each
        maintenance pass.
        """
        self._open_store = open_store
        self._pinger = pinger
        self.interval_s = interval_s
        self._clock = clock
        self.heartbeat = heartbeat if heartbeat is not None else Heartbeat(clock)
        self._stop = threading.Event()
        self._wait = wait or self._stop.wait
        self._round_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._cleanup_captures = cleanup_captures
        self.maintenance_s = maintenance_s

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("scheduler already started")
        self._thread = threading.Thread(
            target=self.run_forever, name="netpulse-scheduler", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float | None = 5.0) -> None:
        """Ask the loop to stop and wait for the current check to finish."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def run_once(self) -> list[tuple[int, PingResult]] | None:
        """Check every live device once.

        Returns None, without pinging anything, if a round is already running.
        """
        if not self._round_lock.acquire(blocking=False):
            log.warning("previous check round is still running; skipping this one")
            return None
        try:
            self.heartbeat.round_started()
            try:
                store = self._open_store()
                try:
                    results = run_round(store, self._pinger)
                finally:
                    store.close()
            except Exception as exc:
                self.heartbeat.round_failed(failure_message(exc))
                raise
            self.heartbeat.round_finished(len(results), sum(result.success for _, result in results))
            return results
        finally:
            self._round_lock.release()

    def run_maintenance(self) -> Upkeep | None:
        """One maintenance pass, on a Store of its own. None if it failed: the log says why."""
        try:
            store = self._open_store()
            try:
                upkeep = maintain(store, self._cleanup_captures)
            finally:
                store.close()
        except Exception:
            log.exception("maintenance failed; trying again in %d s", self.maintenance_s)
            return None
        log.info(
            "maintenance: deleted %d trace(s) and %d check(s) from outside; WAL %s",
            upkeep.traces, upkeep.outside_checks, "checkpointed" if upkeep.checkpointed else "busy, partly kept",
        )
        return upkeep

    def run_forever(self) -> None:
        """Run rounds until stop(). The first round starts immediately."""
        self.heartbeat.loop_started()
        try:
            started = self._clock()
            next_maintenance = started + self.maintenance_s
            while not self._stop.is_set():
                try:
                    results = self.run_once()
                except PingerUnavailable as exc:
                    # The same fault every round until someone fixes the PC: one line, no traceback.
                    log.error("cannot check devices: %s; trying again next round", exc)
                except Exception:
                    log.exception("check round failed; trying again next round")
                else:
                    if results is not None:
                        log.debug("checked %d device(s)", len(results))

                if self._clock() >= next_maintenance:
                    self.run_maintenance()
                    next_maintenance = self._clock() + self.maintenance_s

                now = self._clock()
                next_start, skipped = next_round_start(started, now, self.interval_s)
                if skipped:
                    log.warning(
                        "check round took %.1f s, longer than the %s s interval; skipped %d round(s)",
                        now - started,
                        self.interval_s,
                        skipped,
                    )
                if self._wait(max(0.0, next_start - now)):
                    return
                started = next_start
        finally:
            self.heartbeat.loop_stopped()
