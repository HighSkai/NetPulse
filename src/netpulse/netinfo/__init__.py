"""Network information port: the reader contract, its cache and test double, and the parser.

PowerShellNetworkReader is deliberately not imported here, as OsPinger is not
in netpulse.ping. It starts a process, and importing this package must not
pull it in. The app entry point imports netpulse.netinfo.powershell directly.
"""

from netpulse.netinfo.fake import FakeNetworkReader, home_network
from netpulse.netinfo.parser import parse_neighbours_json, parse_network_json
from netpulse.netinfo.reader import (
    CachedNetworkReader,
    NetworkInfoUnavailable,
    NetworkReader,
    NoNetworkReader,
)

__all__ = [
    "CachedNetworkReader",
    "FakeNetworkReader",
    "NetworkInfoUnavailable",
    "NetworkReader",
    "NoNetworkReader",
    "home_network",
    "parse_neighbours_json",
    "parse_network_json",
]
