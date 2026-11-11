"""Reverse DNS names for the hosts a sweep finds (plan section 21) and the hops
of a trace (plan section 30).

Home routers often answer with the names their DHCP clients gave. A lookup
can take seconds when nothing answers, so a sweep or a trace runs them all at
once and waits a fixed time. The offline test guard blocks the real lookup.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from ipaddress import IPv4Address


def reverse_name(address: IPv4Address) -> str | None:
    """The address's name, or None when there is none."""
    try:
        name = socket.gethostbyaddr(str(address))[0]
    except OSError:
        return None
    name = name.strip().rstrip(".")
    return name if name and name != str(address) else None


class Lookups:
    """Name lookups running alongside a sweep or a trace, one thread each.

    A lookup still running at collect() is left behind on a daemon thread, so
    a DNS server that never answers holds up neither the caller nor the app's exit.
    """

    def __init__(self, lookup: Callable[[IPv4Address], str | None]) -> None:
        self._lookup = lookup
        self._lock = threading.Lock()
        self._names: dict[IPv4Address, str] = {}
        self._threads: dict[IPv4Address, threading.Thread] = {}

    def start(self, address: IPv4Address) -> None:
        with self._lock:
            if address in self._threads:
                return
            thread = threading.Thread(target=self._run, args=(address,), name="netpulse-name", daemon=True)
            self._threads[address] = thread
        thread.start()

    def _run(self, address: IPv4Address) -> None:
        name = self._lookup(address)
        if name:
            with self._lock:
                self._names[address] = name

    def collect(self, wait_s: float, clock: Callable[[], float]) -> dict[IPv4Address, str]:
        """The names found within wait_s from now."""
        deadline = clock() + wait_s
        with self._lock:
            threads = list(self._threads.values())
        for thread in threads:
            thread.join(max(0.0, deadline - clock()))
        with self._lock:
            return dict(self._names)
