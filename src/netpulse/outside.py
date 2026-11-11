"""Checks from outside this network (plan section 31), through Globalping.

- Nothing is sent until the user agrees. The answer is kept in the settings row.
- Only public targets: refused before anything is sent.
- One check at a time, on its own thread, never in a request.
- An answer is kept for 10 minutes: the same check asked again within that
  time shows it, instead of asking Globalping again.
- A rate limit, an outage or a timeout is shown as the service's failure,
  never as the target being down, and is kept with the check.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

from netpulse.probes.globalping import CheckRequest, GlobalpingClient, GlobalpingError, public_target
from netpulse.store import Store

log = logging.getLogger(__name__)

KEEP_ANSWER = timedelta(minutes=10)


class NotConsented(Exception):
    """The user has not agreed to send targets to Globalping."""


class OutsideState:
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"


@dataclass(frozen=True)
class OutsideStatus:
    state: str = OutsideState.IDLE
    request: CheckRequest | None = None
    check_id: int | None = None
    reused: bool = False  # the answer came from a check within the last 10 minutes


def _utc_now() -> datetime:
    return datetime.now(UTC)


class OutsideChecker:
    def __init__(
        self, open_store: Callable[[], Store], client: GlobalpingClient, *, now: Callable[[], datetime] = _utc_now
    ) -> None:
        self._open_store = open_store
        self._client = client
        self._now = now
        self._lock = threading.Lock()
        self._status = OutsideStatus()
        self._thread: threading.Thread | None = None

    def consented(self) -> bool:
        store = self._open_store()
        try:
            return store.outside_consent() is not None
        finally:
            store.close()

    def consent(self, agree: bool) -> None:
        store = self._open_store()
        try:
            store.set_outside_consent(agree, now=self._stamp(self._now()))
        finally:
            store.close()

    def status(self) -> OutsideStatus:
        with self._lock:
            return self._status

    def start(self, request: CheckRequest) -> bool:
        """Check on its own thread. False, and nothing is sent, if a check is running.

        Raises NotConsented or ValueError (a target that is not public) before anything is sent.
        """
        request = self._ready(request)
        with self._lock:
            if self._status.state == OutsideState.RUNNING:
                return False
            self._status = OutsideStatus(OutsideState.RUNNING, request)
        if self._reuse(request):
            return True
        self._thread = threading.Thread(target=self._run, args=(request,), name="netpulse-outside", daemon=True)
        self._thread.start()
        return True

    def run(self, request: CheckRequest) -> OutsideStatus:
        """One check on this thread. start() runs this on its own."""
        request = self._ready(request)
        with self._lock:
            self._status = OutsideStatus(OutsideState.RUNNING, request)
        if not self._reuse(request):
            self._run(request)
        return self.status()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def _ready(self, request: CheckRequest) -> CheckRequest:
        if not self.consented():
            raise NotConsented("agree to checks from outside first: nothing is sent until you do")
        return replace(request, target=public_target(request.target))

    def _reuse(self, request: CheckRequest) -> bool:
        started = self._now()
        store = self._open_store()
        try:
            same = store.same_outside_check(request, self._stamp(started - KEEP_ANSWER))
        finally:
            store.close()
        if same is None:
            return False
        with self._lock:
            self._status = OutsideStatus(OutsideState.DONE, request, same.id, reused=True)
        return True

    def _run(self, request: CheckRequest) -> None:
        started = self._stamp(self._now())
        measurement_id, results, error = None, (), None
        try:
            measurement = self._client.measure(request)
            measurement_id, results = measurement.id, measurement.results
        except (GlobalpingError, ValueError) as exc:
            error = str(exc)
        except Exception:
            log.exception("the check of %s from outside failed", request.target)
            error = "The check stopped on an error; the NetPulse log has the details."
        store = self._open_store()
        try:
            check = store.save_outside_check(request, measurement_id, results, error, now=started)
        finally:
            store.close()
        with self._lock:
            self._status = OutsideStatus(OutsideState.DONE, request, check.id)

    @staticmethod
    def _stamp(moment: datetime) -> str:
        return moment.astimezone(UTC).replace(microsecond=0).isoformat()
