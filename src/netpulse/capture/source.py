"""The capture contract (plan section 27), mirroring the ping port of plan section 2.

A PacketSource lists this PC's interfaces and opens one. The CaptureSession it
returns hands over the packets that arrived, a batch at a time, and closes.
A fault on this PC, such as Npcap missing, access refused or the interface
gone, is raised as CaptureUnavailable and is never data. A filter Npcap cannot
compile is InvalidFilter, with Npcap's own message, so the page can show it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol, runtime_checkable

from netpulse.network import Adapter

# Link types (pcap's DLT_ numbers, also written in PCAP files).
LINKTYPE_NULL = 0  # BSD loopback: a 4-byte address family, then the packet. Npcap's loopback adapter
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # a bare IPv4 or IPv6 packet

# The whole packet by default, or headers only, as a privacy option (plan section 28).
SNAPLEN_FULL = 262144
SNAPLEN_HEADERS = 128


class CaptureUnavailable(Exception):
    """This PC cannot capture now. Not a fact about the network."""


class InvalidFilter(ValueError):
    """A capture filter Npcap could not compile. The message is Npcap's."""


@dataclass(frozen=True)
class RawPacket:
    time_ns: int  # since 1970, UTC
    original_length: int  # on the wire; the captured bytes may be fewer
    link_type: int
    data: bytes

    @property
    def captured_length(self) -> int:
        return len(self.data)

    def __post_init__(self) -> None:
        if self.original_length < len(self.data):
            raise ValueError("a packet cannot be shorter on the wire than captured")


@dataclass(frozen=True)
class Interface:
    """One interface Npcap can capture on."""

    name: str  # Npcap's device name, such as \\Device\\NPF_{GUID}
    description: str
    addresses: tuple[IPv4Address | IPv6Address, ...]
    loopback: bool = False

    def adapter(self, adapters: Iterable[Adapter]) -> Adapter | None:
        """The adapter of plan section 19 this interface is, if any.

        Npcap does not report MAC addresses on Windows, so the match is by IPv4
        address: an adapter that is up always has one (plan section 19). The
        adapter then gives the MAC address.
        """
        mine = {a for a in self.addresses if isinstance(a, IPv4Address)}
        return next((a for a in adapters if mine & {i.ip for i in a.addresses}), None)


@runtime_checkable
class CaptureSession(Protocol):
    link_type: int

    def next_batch(self, wait_ms: int) -> list[RawPacket]:
        """The packets that arrived, waiting at most about wait_ms for the first.

        An empty list means nothing arrived. Raises CaptureUnavailable if the
        capture broke, for example because the interface went away.
        """
        ...

    def close(self) -> None: ...


@runtime_checkable
class PacketSource(Protocol):
    def interfaces(self) -> list[Interface]:
        """Raises CaptureUnavailable when this PC cannot capture at all."""
        ...

    def open(self, interface: str, *, snaplen: int = SNAPLEN_FULL, capture_filter: str = "") -> CaptureSession:
        """Start capturing on one interface. Raises CaptureUnavailable or InvalidFilter."""
        ...
