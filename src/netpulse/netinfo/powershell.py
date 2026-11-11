"""Reads this PC's network settings from Windows through PowerShell (decision 003).

With os_pinger, one of the only two modules that start a process. The script
is a constant: nothing from the user or the network goes into it, and it only
reads. It queries the CIM classes behind the Get-Net* commands directly,
because importing those commands' modules took 3.1 s and the classes 0.5 s.
"""

from __future__ import annotations

import base64
import logging
import os
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime

from netpulse.netinfo.parser import parse_neighbours_json, parse_network_json
from netpulse.netinfo.reader import NetworkInfoUnavailable
from netpulse.network import Neighbour, NetworkInfo

DEFAULT_TIMEOUT_S = 15.0
_CREATE_NO_WINDOW = 0x08000000

log = logging.getLogger(__name__)

# Each script prints one JSON object in plain ASCII: every other character is
# escaped, so the console code page cannot change it. AddressFamily 2 is IPv4.
_HEAD = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Read-Class([string] $Class, [string[]] $Property, [string] $Filter, [string] $Namespace = 'root/StandardCimv2') {
  $query = @{ Namespace = $Namespace; ClassName = $Class; Property = $Property }
  if ($Filter) { $query.Filter = $Filter }
  Get-CimInstance @query | Select-Object -Property $Property
}
$settings = [ordered]@{
"""
_TAIL = r"""}
$json = [pscustomobject]$settings | ConvertTo-Json -Depth 4 -Compress
[regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
"""

SCRIPT = _HEAD + r"""  computer   = [Environment]::MachineName
  adapters   = @(Read-Class -Class MSFT_NetAdapter -Property InterfaceIndex, Name, InterfaceDescription, PermanentAddress, NetworkAddresses, InterfaceOperationalStatus)
  addresses  = @(Read-Class -Class MSFT_NetIPAddress -Property InterfaceIndex, IPAddress, PrefixLength, AddressState -Filter 'AddressFamily = 2')
  interfaces = @(Read-Class -Class MSFT_NetIPInterface -Property InterfaceIndex, Dhcp, InterfaceMetric -Filter 'AddressFamily = 2')
  routes     = @(Read-Class -Class MSFT_NetRoute -Property InterfaceIndex, NextHop, RouteMetric -Filter "AddressFamily = 2 AND DestinationPrefix = '0.0.0.0/0'")
  dns        = @(Read-Class -Class MSFT_DNSClientServerAddress -Property InterfaceIndex, ServerAddresses -Filter 'AddressFamily = 2')
  profiles   = @(Read-Class -Class MSFT_NetConnectionProfile -Property InterfaceIndex, NetworkCategory, IPv4Connectivity)
  leases     = @(Read-Class -Class Win32_NetworkAdapterConfiguration -Property InterfaceIndex, DHCPEnabled, DHCPServer, DHCPLeaseObtained, DHCPLeaseExpires -Filter 'IPEnabled = True' -Namespace root/cimv2)
  neighbours = @(Read-Class -Class MSFT_NetNeighbor -Property InterfaceIndex, IPAddress, LinkLayerAddress, State -Filter 'AddressFamily = 2')
""" + _TAIL

# Plan section 21: the IPv4 neighbour table, read after a sweep.
NEIGHBOUR_SCRIPT = _HEAD + r"""  neighbours = @(Read-Class -Class MSFT_NetNeighbor -Property InterfaceIndex, IPAddress, LinkLayerAddress, State -Filter 'AddressFamily = 2')
""" + _TAIL


def default_powershell_executable() -> str:
    """Absolute path to Windows PowerShell, for the same reason ping.exe has one (plan section 3.3)."""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")


def build_powershell_args(executable: str, script: str = SCRIPT) -> list[str]:
    """argv that runs a script. Execution policy covers script files, not commands."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class PowerShellNetworkReader:
    """Production network reader: Windows PowerShell with a list of args, no shell."""

    def __init__(
        self,
        *,
        executable: str | None = None,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        now: Callable[[], datetime] = _utc_now,
        platform: str | None = None,
    ) -> None:
        self.executable = executable or default_powershell_executable()
        self.timeout_s = timeout_s
        self._now = now
        self._platform = platform or sys.platform

    def read(self) -> NetworkInfo:
        return parse_network_json(self._run(SCRIPT), self._now())

    def neighbours(self) -> tuple[Neighbour, ...]:
        """The IPv4 neighbours Windows confirmed recently (plan section 21)."""
        return parse_neighbours_json(self._run(NEIGHBOUR_SCRIPT))

    def _run(self, script: str) -> str:
        if self._platform != "win32":
            raise NetworkInfoUnavailable(
                f"network settings are read from Windows, and this system is {self._platform!r}"
            )
        try:
            completed = subprocess.run(
                build_powershell_args(self.executable, script),
                capture_output=True,
                timeout=self.timeout_s,
                shell=False,
                creationflags=_CREATE_NO_WINDOW,
            )
        except subprocess.TimeoutExpired as exc:
            raise NetworkInfoUnavailable(
                f"Windows took more than {self.timeout_s:g} s to report the network settings"
            ) from exc
        except OSError as exc:
            raise NetworkInfoUnavailable(f"cannot run {self.executable}: {exc}") from exc
        if completed.returncode != 0:
            # PowerShell's own message is in the display language and may be
            # long, so it goes to the log, and the page gets the exit code.
            log.warning("network settings: PowerShell said: %s", completed.stderr[:2000].decode("utf-8", "replace"))
            raise NetworkInfoUnavailable(
                f"PowerShell stopped with exit code {completed.returncode}; the log has its message"
            )
        try:
            return completed.stdout.decode("ascii")
        except UnicodeDecodeError as exc:
            raise NetworkInfoUnavailable("PowerShell printed something other than the expected JSON") from exc
