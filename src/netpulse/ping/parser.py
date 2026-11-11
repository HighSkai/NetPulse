"""Classify English Windows ping.exe output for one echo (-n 1).

Plan section 4:
1. Scan failure phrases first.
2. Take an RTT only from a "Reply from" echo line, never the statistics block.
3. An echo line needs bytes= or TTL=, plus time=Nms or time<1ms.
4. A "Reply from" line that says unreachable or TTL expired is not an echo.
"""

from __future__ import annotations

import re

from netpulse.ping.result import Error, PingResult

# Matched against the lowercased buffer (stdout + stderr). Multi-word phrases,
# so a hostname echoed in the output (no spaces allowed) cannot trigger one.
_FAILURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"could not find host"), Error.NAME_RESOLUTION),
    (re.compile(r"destination (?:host|net|protocol|port) unreachable"), Error.UNREACHABLE),
    (re.compile(r"ttl expired"), Error.TTL_EXPIRED),
    (re.compile(r"request timed out"), Error.TIMEOUT),
    (re.compile(r"transmit failed|general failure"), Error.TRANSMIT_FAILED),
)

_REPLY_PREFIX = "reply from "
_ECHO_FIELD = re.compile(r"\b(?:bytes|ttl)=\d+", re.IGNORECASE)
# time<1ms is the only "<" form ping.exe prints; it means faster than 1 ms.
_RTT = re.compile(r"\btime(?:=(\d+)|<1)ms\b", re.IGNORECASE)


def parse_ping_output(text: str) -> PingResult:
    lowered = text.lower()
    for pattern, code in _FAILURES:
        if pattern.search(lowered):
            return PingResult.fail(code)

    for line in text.splitlines():
        rtt = _echo_rtt(line)
        if rtt is not None:
            return PingResult.ok(rtt)

    return PingResult.fail(Error.UNREADABLE_OUTPUT)


def _echo_rtt(line: str) -> int | None:
    """RTT in ms if line is a real echo reply, else None."""
    stripped = line.strip()
    lowered = stripped.lower()
    if not lowered.startswith(_REPLY_PREFIX):
        return None
    if "unreachable" in lowered or "ttl expired" in lowered:
        return None
    if _ECHO_FIELD.search(stripped) is None:
        return None
    match = _RTT.search(stripped)
    if match is None:
        return None
    return int(match.group(1)) if match.group(1) is not None else 0
