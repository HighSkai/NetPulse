"""The network reader contract, its error, and the cache in front of it (plan section 19)."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from netpulse.network import Neighbour, NetworkInfo

# A read starts PowerShell and takes about half a second (decision 003), so
# pages and the map's 30 s poll share one. A failed read is retried sooner.
GOOD_READ_TTL_S = 300
FAILED_READ_TTL_S = 30


class NetworkInfoUnavailable(RuntimeError):
    """Windows could not report the network settings. The message says why, for the page."""


@runtime_checkable
class NetworkReader(Protocol):
    def read(self) -> NetworkInfo:
        """This PC's network settings now.

        Raises NetworkInfoUnavailable when they cannot be read. A failed read
        is never reported as a PC with no network.
        """

    def neighbours(self) -> tuple[Neighbour, ...]:
        """The IPv4 neighbours Windows confirmed recently (plan section 21). Never cached."""


class NoNetworkReader:
    """For an app started without a reader: every read fails and says so."""

    def read(self) -> NetworkInfo:
        raise NetworkInfoUnavailable("NetPulse was started without a network reader")

    def neighbours(self) -> tuple[Neighbour, ...]:
        raise NetworkInfoUnavailable("NetPulse was started without a network reader")


class CachedNetworkReader:
    """Keeps a good read for 5 minutes and a failed one for 30 s. One read at a time."""

    def __init__(self, reader: NetworkReader, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._reader = reader
        self._clock = clock
        self._lock = threading.Lock()
        self._info: NetworkInfo | None = None
        self._error: str | None = None
        self._expires: float | None = None

    def read(self) -> NetworkInfo:
        # Holding the lock while reading makes a second request wait for the
        # same read instead of starting another PowerShell.
        with self._lock:
            now = self._clock()
            if self._expires is None or now >= self._expires:
                try:
                    self._info, self._error = self._reader.read(), None
                    self._expires = now + GOOD_READ_TTL_S
                except NetworkInfoUnavailable as exc:
                    self._info, self._error = None, str(exc)
                    self._expires = now + FAILED_READ_TTL_S
            if self._error is not None:
                raise NetworkInfoUnavailable(self._error)
            assert self._info is not None
            return self._info

    def neighbours(self) -> tuple[Neighbour, ...]:
        """Always fresh: a sweep needs the table as it is now."""
        return self._reader.neighbours()

    def refresh(self) -> None:
        """Forget the last read, so the next one asks Windows again."""
        with self._lock:
            self._expires = None
