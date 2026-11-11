"""A PacketSource for tests (plan section 27): it replays packets, usually from fixture PCAP files.

Like FakePinger, it is a map, not a simulation: each interface name maps to
the packets it will hand out, a batch at a time. It can also be told to refuse
to list or open, or to reject a filter, the way Npcap would.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from netpulse.capture.pcap import read_packets
from netpulse.capture.source import (
    LINKTYPE_ETHERNET,
    SNAPLEN_FULL,
    CaptureUnavailable,
    Interface,
    InvalidFilter,
    RawPacket,
)


def packets_from(path: Path) -> tuple[int, list[RawPacket]]:
    """(link type, packets) of a PCAP file."""
    with path.open("rb") as file:
        header, packets = read_packets(file)
        return header.link_type, list(packets)


class FakeCaptureSession:
    def __init__(self, packets: Sequence[RawPacket], link_type: int, batch_size: int, snaplen: int) -> None:
        self.link_type = link_type
        self._packets = list(packets)
        self._batch_size = batch_size
        self._snaplen = snaplen
        self.closed = False
        self.fail_with: str | None = None  # set to break the capture, as an interface that went away

    def next_batch(self, wait_ms: int) -> list[RawPacket]:
        if self.closed:
            raise CaptureUnavailable("the capture is closed")
        if self.fail_with is not None:
            raise CaptureUnavailable(self.fail_with)
        batch, self._packets = self._packets[: self._batch_size], self._packets[self._batch_size :]
        # Npcap hands over at most snaplen bytes of each packet.
        return [RawPacket(p.time_ns, p.original_length, p.link_type, p.data[: self._snaplen]) for p in batch]

    def close(self) -> None:
        self.closed = True


class FakePacketSource:
    def __init__(
        self,
        captures: Mapping[str, Iterable[RawPacket] | Path] | None = None,
        *,
        interfaces: Sequence[Interface] | None = None,
        batch_size: int = 100,
        unavailable: str | None = None,
        invalid_filters: Mapping[str, str] | None = None,
    ) -> None:
        """captures maps an interface name to its packets, or to a PCAP file of them.

        unavailable: the message every call raises as CaptureUnavailable.
        invalid_filters: filter text -> the error Npcap would give for it.
        """
        self._captures: dict[str, tuple[int, list[RawPacket]]] = {}
        for name, packets in (captures or {}).items():
            if isinstance(packets, Path):
                self._captures[name] = packets_from(packets)
            else:
                listed = list(packets)
                self._captures[name] = (listed[0].link_type if listed else LINKTYPE_ETHERNET, listed)
        self._interfaces = list(interfaces) if interfaces is not None else [
            Interface(name, f"Fake interface {name}", ()) for name in self._captures
        ]
        self._batch_size = batch_size
        self._unavailable = unavailable
        self._invalid_filters = dict(invalid_filters or {})
        self.opened: list[tuple[str, int, str]] = []  # (interface, snaplen, filter) per open
        self.sessions: list[FakeCaptureSession] = []

    def interfaces(self) -> list[Interface]:
        if self._unavailable is not None:
            raise CaptureUnavailable(self._unavailable)
        return list(self._interfaces)

    def open(self, interface: str, *, snaplen: int = SNAPLEN_FULL, capture_filter: str = "") -> FakeCaptureSession:
        if self._unavailable is not None:
            raise CaptureUnavailable(self._unavailable)
        if interface not in {i.name for i in self._interfaces}:
            raise CaptureUnavailable(f"no such interface: {interface}")
        if capture_filter in self._invalid_filters:
            raise InvalidFilter(self._invalid_filters[capture_filter])
        self.opened.append((interface, snaplen, capture_filter))
        link_type, packets = self._captures.get(interface, (LINKTYPE_ETHERNET, []))
        session = FakeCaptureSession(packets, link_type, self._batch_size, snaplen)
        self.sessions.append(session)
        return session
