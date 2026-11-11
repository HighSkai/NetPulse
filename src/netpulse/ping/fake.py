from __future__ import annotations

from netpulse.ping.hosts import validate_host
from netpulse.ping.result import Error, PingResult


class FakePinger:
    """Test double: host -> canned result. Unknown hosts fail as unreadable.

    Validates hosts like OsPinger, so a test cannot pass with a host that
    production would reject.
    """

    def __init__(self, responses: dict[str, PingResult] | None = None) -> None:
        self.responses = dict(responses or {})
        self.calls: list[str] = []

    def ping(self, host: str) -> PingResult:
        validate_host(host)
        self.calls.append(host)
        if host in self.responses:
            return self.responses[host]
        return PingResult.fail(Error.UNREADABLE_OUTPUT)
