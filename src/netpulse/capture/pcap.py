"""Classic libpcap files (plan section 27): pure, so Wireshark and tcpdump open what NetPulse writes.

The writer uses microsecond timestamps, little-endian, and the interface's link
type. The reader also takes the other byte order and nanosecond files, so it can
page through any classic capture. It stops quietly at a last record cut short,
because a capture that is still running may be part-way through writing one.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from netpulse.capture.source import SNAPLEN_FULL, RawPacket

MAGIC_MICRO = 0xA1B2C3D4
MAGIC_NANO = 0xA1B23C4D
VERSION = (2, 4)
_FILE_HEADER = struct.Struct("<IHHiIII")  # magic, version, zone, sigfigs, snaplen, link type
_RECORD = struct.Struct("<IIII")  # seconds, fraction, captured length, original length
FILE_HEADER_SIZE = _FILE_HEADER.size
RECORD_HEADER_SIZE = _RECORD.size
MEDIA_TYPE = "application/vnd.tcpdump.pcap"


class PcapError(ValueError):
    """Not a classic PCAP file."""


def file_header(link_type: int, snaplen: int = SNAPLEN_FULL) -> bytes:
    return _FILE_HEADER.pack(MAGIC_MICRO, *VERSION, 0, 0, snaplen, link_type)


def record(packet: RawPacket) -> bytes:
    """One packet as a record: its header, then its captured bytes."""
    seconds, nanoseconds = divmod(packet.time_ns, 1_000_000_000)
    return _RECORD.pack(seconds, nanoseconds // 1000, len(packet.data), packet.original_length) + packet.data


class PcapWriter:
    """Writes one capture to an open binary file, packet by packet."""

    def __init__(self, file: BinaryIO, link_type: int, snaplen: int = SNAPLEN_FULL) -> None:
        self._file = file
        self.link_type = link_type
        self.bytes_written = 0
        self._write(file_header(link_type, snaplen))

    def write(self, packet: RawPacket) -> None:
        if packet.link_type != self.link_type:
            raise ValueError(f"a packet of link type {packet.link_type} in a file of link type {self.link_type}")
        self._write(record(packet))

    def flush(self) -> None:
        self._file.flush()

    def _write(self, data: bytes) -> None:
        self._file.write(data)
        self.bytes_written += len(data)


@dataclass(frozen=True)
class PcapHeader:
    link_type: int
    snaplen: int
    nanoseconds: bool
    byte_order: str  # "<" or ">"


def read_header(file: BinaryIO) -> PcapHeader:
    head = file.read(FILE_HEADER_SIZE)
    if len(head) < FILE_HEADER_SIZE:
        raise PcapError("too short for a PCAP file header")
    for order in "<>":
        magic = struct.unpack(order + "I", head[:4])[0]
        if magic in (MAGIC_MICRO, MAGIC_NANO):
            _, major, minor, _, _, snaplen, link_type = struct.unpack(order + "IHHiIII", head)
            if (major, minor) != VERSION:
                raise PcapError(f"PCAP version {major}.{minor} is not 2.4")
            return PcapHeader(link_type & 0xFFFF, snaplen, magic == MAGIC_NANO, order)
    raise PcapError("not a classic PCAP file (pcapng is not read)")


def complete_length(file: BinaryIO) -> int:
    """How many bytes of the file end with a whole record (plan section 29).

    A capture that is still running may be part-way through writing a packet;
    a download of it stops before that packet. Reads record headers only.
    """
    header = read_header(file)
    record_format = struct.Struct(header.byte_order + "IIII")
    size = file.seek(0, io.SEEK_END)
    end = FILE_HEADER_SIZE
    while end + RECORD_HEADER_SIZE <= size:
        file.seek(end)
        captured = record_format.unpack(file.read(RECORD_HEADER_SIZE))[2]
        if end + RECORD_HEADER_SIZE + captured > size:
            break
        end += RECORD_HEADER_SIZE + captured
    return end


def read_packets(file: BinaryIO) -> tuple[PcapHeader, Iterator[RawPacket]]:
    """The file's header, and its packets in order. Reads lazily."""
    header = read_header(file)
    record_format = struct.Struct(header.byte_order + "IIII")
    unit = 1 if header.nanoseconds else 1000

    def packets() -> Iterator[RawPacket]:
        while True:
            head = file.read(RECORD_HEADER_SIZE)
            if len(head) < RECORD_HEADER_SIZE:
                return  # the end, or a record still being written
            seconds, fraction, captured, original = record_format.unpack(head)
            data = file.read(captured)
            if len(data) < captured:
                return
            yield RawPacket(seconds * 1_000_000_000 + fraction * unit, max(original, captured), header.link_type, data)

    return header, packets()
