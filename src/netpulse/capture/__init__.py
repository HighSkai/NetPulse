"""Capture port (plan section 27): the PacketSource contract and its test double.

NpcapSource is deliberately not imported here. It is the only module that
calls wpcap.dll, and importing this package must not pull it in. The app
entry point imports netpulse.capture.npcap directly. The decoder and the PCAP
reader and writer are pure, in netpulse.capture.decode and netpulse.capture.pcap.
"""

from netpulse.capture.fake import FakePacketSource
from netpulse.capture.source import (
    LINKTYPE_ETHERNET,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    SNAPLEN_FULL,
    SNAPLEN_HEADERS,
    CaptureSession,
    CaptureUnavailable,
    Interface,
    InvalidFilter,
    PacketSource,
    RawPacket,
)

__all__ = [
    "LINKTYPE_ETHERNET",
    "LINKTYPE_NULL",
    "LINKTYPE_RAW",
    "SNAPLEN_FULL",
    "SNAPLEN_HEADERS",
    "CaptureSession",
    "CaptureUnavailable",
    "FakePacketSource",
    "Interface",
    "InvalidFilter",
    "PacketSource",
    "RawPacket",
]
