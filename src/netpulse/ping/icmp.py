"""Pings with Windows' IcmpSendEcho, for discovery sweeps (decision 004).

With os_pinger and the PowerShell reader, one of the only modules that reach
outside Python: here through ctypes, with no process. A thread waiting in
IcmpSendEcho costs almost nothing, so a sweep can wait on many addresses at
once. Monitoring keeps ping.exe (plan section 3).
"""

from __future__ import annotations

import ctypes
import socket
import sys
from ctypes import wintypes
from ipaddress import IPv4Address

from netpulse.ping.hosts import InvalidHost, validate_host
from netpulse.ping.result import Error, PingerUnavailable, PingResult

DEFAULT_TIMEOUT_MS = 1000
_PAYLOAD = b"NetPulse discovery sweep"
_INVALID_HANDLE = ctypes.c_void_p(-1).value

# IP_STATUS values from ipexport.h: numbers, never sentences.
IP_SUCCESS = 0
STATUS_ERRORS = {
    11002: Error.UNREACHABLE,  # IP_DEST_NET_UNREACHABLE
    11003: Error.UNREACHABLE,  # IP_DEST_HOST_UNREACHABLE
    11004: Error.UNREACHABLE,  # IP_DEST_PROT_UNREACHABLE
    11005: Error.UNREACHABLE,  # IP_DEST_PORT_UNREACHABLE
    11010: Error.TIMEOUT,  # IP_REQ_TIMED_OUT
    11013: Error.TTL_EXPIRED,  # IP_TTL_EXPIRED_TRANSIT
    11014: Error.TTL_EXPIRED,  # IP_TTL_EXPIRED_REASSEM
}


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.ULONG),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


# One reply, its echoed data, and room for an ICMP error message, as the docs ask.
REPLY_SIZE = ctypes.sizeof(ICMP_ECHO_REPLY) + len(_PAYLOAD) + 8 + 8


def _open_dll():
    """The real iphlpapi.dll. tests/conftest.py blocks this, so no test sends an echo."""
    return ctypes.WinDLL("iphlpapi", use_last_error=True)


def _load_iphlpapi():
    """iphlpapi.dll with the three functions typed. Windows only."""
    if sys.platform != "win32":
        raise PingerUnavailable(f"IcmpSendEcho needs Windows (this system is {sys.platform!r})")
    dll = _open_dll()
    dll.IcmpCreateFile.restype = wintypes.HANDLE
    dll.IcmpSendEcho.argtypes = [
        wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.WORD,
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
    ]
    dll.IcmpSendEcho.restype = wintypes.DWORD
    dll.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
    return dll


class IcmpApi:
    """One echo through IcmpSendEcho. Tests hand it a fake dll; nothing else changes."""

    def __init__(self, dll=None) -> None:
        self._dll = dll if dll is not None else _load_iphlpapi()

    def echo(self, address: IPv4Address, timeout_ms: int) -> tuple[int, int]:
        """(IP_STATUS, round-trip ms). Raises PingerUnavailable if Windows refuses a handle."""
        status, rtt, _ = self._send(address, timeout_ms, None)
        return status, rtt

    def echo_with_ttl(self, address: IPv4Address, ttl: int, timeout_ms: int) -> tuple[int, int, IPv4Address | None]:
        """(IP_STATUS, round-trip ms, who answered) for one echo that may cross at most ttl routers.

        Plan section 30: a router that drops it for running out of hops answers
        IP_TTL_EXPIRED_TRANSIT from its own address; the target answers IP_SUCCESS.
        """
        if not 1 <= ttl <= 255:
            raise ValueError("a time-to-live is from 1 to 255")
        return self._send(address, timeout_ms, IP_OPTION_INFORMATION(Ttl=ttl))

    def _send(
        self, address: IPv4Address, timeout_ms: int, options: IP_OPTION_INFORMATION | None
    ) -> tuple[int, int, IPv4Address | None]:
        handle = self._dll.IcmpCreateFile()
        if handle in (None, 0, _INVALID_HANDLE):
            raise PingerUnavailable(f"Windows refused an ICMP handle (error {ctypes.get_last_error()})")
        try:
            reply = ctypes.create_string_buffer(REPLY_SIZE)
            # IPAddr holds the address's bytes in network order.
            destination = int.from_bytes(address.packed, "little")
            count = self._dll.IcmpSendEcho(
                handle, destination, _PAYLOAD, len(_PAYLOAD),
                None if options is None else ctypes.pointer(options), reply, REPLY_SIZE, timeout_ms,
            )
            if count == 0:
                return ctypes.get_last_error(), 0, None
            parsed = ICMP_ECHO_REPLY.from_buffer(reply)
            responder = IPv4Address(parsed.Address.to_bytes(4, "little")) if parsed.Address else None
            return parsed.Status, parsed.RoundTripTime, responder
        finally:
            self._dll.IcmpCloseHandle(handle)


def resolve(host: str) -> IPv4Address:
    """What the user typed as an IPv4 address: the address itself, or its name looked up (plan section 30).

    Raises ValueError with a message to show when it is not a host or has no address.
    """
    try:
        target = validate_host(host)
    except InvalidHost as exc:
        raise ValueError(str(exc)) from exc
    try:
        return IPv4Address(target)
    except ValueError:
        pass
    try:
        return IPv4Address(socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0])
    except OSError:
        raise ValueError(f"no IPv4 address found for {target}") from None


def result_of(status: int, rtt_ms: int) -> PingResult:
    """An IP_STATUS as one of the six stable codes (plan section 2)."""
    if status == IP_SUCCESS:
        return PingResult.ok(int(rtt_ms))
    return PingResult.fail(STATUS_ERRORS.get(status, Error.TRANSMIT_FAILED))


class IcmpPinger:
    """A Pinger for discovery sweeps: IcmpSendEcho, safe to call from many threads at once."""

    def __init__(self, *, timeout_ms: int = DEFAULT_TIMEOUT_MS, api: IcmpApi | None = None) -> None:
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        self.timeout_ms = timeout_ms
        self._api = api if api is not None else IcmpApi()

    def ping(self, host: str) -> PingResult:
        target = validate_host(host)
        try:
            address = IPv4Address(target)
        except ValueError:
            try:
                address = IPv4Address(socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0])
            except OSError:
                return PingResult.fail(Error.NAME_RESOLUTION)
        return result_of(*self._api.echo(address, self.timeout_ms))
