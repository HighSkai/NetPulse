"""TCP checks (plan section 40): for devices that ignore ping.

Windows PCs, cameras and much of the smart-home world drop ICMP echoes, so a
ping check shows them as down for ever. A TCP check opens a connection to one
port the user names, measures how long that took, and closes it. Nothing is
sent over it.

The result uses the same six codes as a ping: a refused connection is
`unreachable` (the port is closed, whatever the device is doing), no answer in
time is `timeout`.
"""

from __future__ import annotations

import socket
import time

from netpulse.ping.hosts import validate_host
from netpulse.ping.result import Error, PingResult

DEFAULT_TIMEOUT_S = 2.0


class TcpChecker:
    """Safe to call from many threads at once: each check has its own socket."""

    def __init__(self, *, timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self.timeout_s = timeout_s

    def check(self, host: str, port: int) -> PingResult:
        """Open and close one connection. Raises InvalidHost for a host that fails validation."""
        target = validate_host(host)
        if not 1 <= int(port) <= 65535:
            raise ValueError("a TCP port is from 1 to 65535")
        started = time.perf_counter()
        try:
            connection = socket.create_connection((target, int(port)), timeout=self.timeout_s)
        except socket.gaierror:
            return PingResult.fail(Error.NAME_RESOLUTION)
        except TimeoutError:
            return PingResult.fail(Error.TIMEOUT)
        except OSError:
            # Refused, or no route to the host or its network.
            return PingResult.fail(Error.UNREACHABLE)
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        connection.close()
        return PingResult.ok(elapsed_ms)
