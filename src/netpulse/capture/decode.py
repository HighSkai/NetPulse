"""Packet headers into a one-line summary (plan section 27). Pure, and it never raises.

Reads Ethernet II, 802.1Q VLAN tags, the BSD loopback header, IPv4, IPv6 with
its common extension headers, ARP, TCP (ports and flags), UDP, ICMP and
ICMPv6 (type and code). It reads headers only: payloads are never decoded
(plan section 23). A packet that ends early, or is malformed, gives what was
read so far, marked truncated.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from netpulse.capture.source import LINKTYPE_ETHERNET, LINKTYPE_NULL, LINKTYPE_RAW, RawPacket

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
VLAN_TAGS = (0x8100, 0x88A8, 0x9100)  # 802.1Q, and the outer tags of stacked VLANs

# The loopback header's address family: IPv4 is 2 everywhere; IPv6 differs by system.
NULL_IPV4 = 2
NULL_IPV6 = (10, 23, 24, 28, 30)

IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 132: "SCTP"}
# IPv6 extension headers that are followed by another header: hop-by-hop,
# routing, destination options. Fragment (44) and AH (51) are handled apart.
IPV6_EXTENSIONS = (0, 43, 60)
TCP_FLAGS = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")


class _Short(Exception):
    """The packet ended before a header did."""


@dataclass(frozen=True)
class PacketSummary:
    time_ns: int
    length: int  # on the wire
    protocol: str  # the innermost header read: TCP, UDP, ICMP, ARP, IPv4, Ethernet, ...
    src: str | None = None  # IP address, or the MAC address for a frame with no IP
    dst: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: tuple[str, ...] = ()
    icmp_type: int | None = None
    icmp_code: int | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    vlan: int | None = None
    truncated: bool = False


class _Reader:
    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data, self.offset = data, offset

    def take(self, size: int) -> bytes:
        end = self.offset + size
        if end > len(self.data):
            raise _Short
        chunk = self.data[self.offset : end]
        self.offset = end
        return chunk

    def unpack(self, fmt: str) -> tuple:
        return struct.unpack(fmt, self.take(struct.calcsize(fmt)))

    def skip_to(self, offset: int) -> None:
        if offset > len(self.data):
            raise _Short
        self.offset = offset


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def decode(packet: RawPacket) -> PacketSummary:
    """Never raises: a short or malformed packet is summarised as far as it goes, marked truncated."""
    found: dict = {"protocol": "unknown"}
    truncated = False
    try:
        _link(packet, _Reader(packet.data), found)
    except (_Short, struct.error, ValueError):
        truncated = True
    return PacketSummary(time_ns=packet.time_ns, length=packet.original_length, truncated=truncated, **found)


def _link(packet: RawPacket, r: _Reader, found: dict) -> None:
    if packet.link_type == LINKTYPE_ETHERNET:
        found["protocol"] = "Ethernet"
        dst, src, ethertype = r.take(6), r.take(6), r.unpack("!H")[0]
        found["dst_mac"], found["src_mac"] = mac(dst), mac(src)
        found["src"], found["dst"] = found["src_mac"], found["dst_mac"]
        while ethertype in VLAN_TAGS:
            tag, ethertype = r.unpack("!HH")
            found.setdefault("vlan", tag & 0x0FFF)  # the outermost tag
        if ethertype < 0x0600:
            return  # an 802.3 length, not a type: LLC frames are not read
        _network(ethertype, r, found)
    elif packet.link_type == LINKTYPE_NULL:
        found["protocol"] = "Loopback"
        # The family is in the capturing system's byte order; Windows is little-endian.
        family = r.unpack("<I")[0]
        if family == NULL_IPV4:
            _network(ETHERTYPE_IPV4, r, found)
        elif family in NULL_IPV6:
            _network(ETHERTYPE_IPV6, r, found)
    elif packet.link_type == LINKTYPE_RAW:
        found["protocol"] = "IP"
        version = r.data[0] >> 4 if r.data else None
        if version is None:
            raise _Short
        _network(ETHERTYPE_IPV4 if version == 4 else ETHERTYPE_IPV6, r, found)


def _network(ethertype: int, r: _Reader, found: dict) -> None:
    if ethertype == ETHERTYPE_IPV4:
        _ipv4(r, found)
    elif ethertype == ETHERTYPE_IPV6:
        _ipv6(r, found)
    elif ethertype == ETHERTYPE_ARP:
        _arp(r, found)
    else:
        found["protocol"] = f"0x{ethertype:04x}"


def _ipv4(r: _Reader, found: dict) -> None:
    start = r.offset
    version_ihl, _, _, _, fragment, _, protocol, _, src, dst = r.unpack("!BBHHHBBH4s4s")
    if version_ihl >> 4 != 4 or (version_ihl & 0x0F) < 5:
        raise ValueError("not an IPv4 header")
    found["protocol"] = "IPv4"
    found["src"], found["dst"] = str(IPv4Address(src)), str(IPv4Address(dst))
    r.skip_to(start + (version_ihl & 0x0F) * 4)
    if fragment & 0x1FFF:
        found["protocol"] = IP_PROTOCOLS.get(protocol, f"IP {protocol}")
        return  # a later fragment carries no transport header
    _transport(protocol, r, found)


def _ipv6(r: _Reader, found: dict) -> None:
    first, _, next_header, _, src, dst = r.unpack("!IHBB16s16s")
    if first >> 28 != 6:
        raise ValueError("not an IPv6 header")
    found["protocol"] = "IPv6"
    found["src"], found["dst"] = str(IPv6Address(src)), str(IPv6Address(dst))
    while next_header in (*IPV6_EXTENSIONS, 44, 51):
        start = r.offset
        following, length = r.unpack("!BB")
        if next_header == 44:  # fragment: fixed 8 bytes
            offset = r.unpack("!H")[0] >> 3
            r.skip_to(start + 8)
            if offset:
                found["protocol"] = IP_PROTOCOLS.get(following, f"IP {following}")
                return
        elif next_header == 51:  # AH: length in 4-byte units, less 2
            r.skip_to(start + (length + 2) * 4)
        else:
            r.skip_to(start + (length + 1) * 8)
        next_header = following
    _transport(next_header, r, found)


def _transport(protocol: int, r: _Reader, found: dict) -> None:
    found["protocol"] = IP_PROTOCOLS.get(protocol, f"IP {protocol}")
    if protocol == 6:
        found["src_port"], found["dst_port"], _, _, _, flags = r.unpack("!HHIIBB")
        found["tcp_flags"] = tuple(name for bit, name in enumerate(TCP_FLAGS) if flags & (1 << bit))
    elif protocol in (17, 132):
        found["src_port"], found["dst_port"] = r.unpack("!HH")
    elif protocol in (1, 58):
        found["icmp_type"], found["icmp_code"] = r.unpack("!BB")


def _arp(r: _Reader, found: dict) -> None:
    found["protocol"] = "ARP"
    hardware, protocol, hw_len, proto_len, _ = r.unpack("!HHBBH")
    r.take(hw_len)  # the sender's hardware address
    sender = r.take(proto_len)
    r.take(hw_len)  # the target's
    target = r.take(proto_len)
    if hardware == 1 and protocol == ETHERTYPE_IPV4 and (hw_len, proto_len) == (6, 4):
        found["src"], found["dst"] = str(IPv4Address(sender)), str(IPv4Address(target))
