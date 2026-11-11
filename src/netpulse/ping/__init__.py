"""Ping port: the Pinger contract, its test double, and the ping.exe parser.

OsPinger is deliberately not imported here. It is the only module that uses
subprocess, and importing this package must not pull it in. The app entry
point imports netpulse.ping.os_pinger directly.
"""

from netpulse.ping.fake import FakePinger
from netpulse.ping.hosts import InvalidHost, validate_host
from netpulse.ping.parser import parse_ping_output
from netpulse.ping.result import Error, Pinger, PingerUnavailable, PingResult

__all__ = [
    "Error",
    "FakePinger",
    "InvalidHost",
    "PingResult",
    "Pinger",
    "PingerUnavailable",
    "parse_ping_output",
    "validate_host",
]
