"""Packet capture through Npcap's wpcap.dll (plan section 27, decision 006).

With os_pinger, the PowerShell reader and the ICMP pinger, one of the only
modules that reach outside Python, here through ctypes. Only the entry point
imports it. It uses only libpcap's functions to list devices, open one,
compile and set a filter, read the next packet, and close.

The DLL is loaded by absolute path from Npcap's folder under System32, never
from the DLL search path, and is a parameter, so tests hand in a fake. Npcap
is a driver the user installs; NetPulse never ships or installs it.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from netpulse.capture.source import (
    SNAPLEN_FULL,
    CaptureUnavailable,
    Interface,
    InvalidFilter,
    RawPacket,
)

ERRBUF_SIZE = 256  # PCAP_ERRBUF_SIZE
PCAP_IF_LOOPBACK = 0x00000001
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
PCAP_CHAR_ENC_UTF_8 = 1
AF_INET = 2
AF_INET6 = 23  # Windows' value
# How long one read waits for packets, in ms. next_batch waits in steps of it.
READ_TIMEOUT_MS = 100
MAX_BATCH = 2000
# Not promiscuous: capture this PC's own traffic and broadcasts, not other machines'.
PROMISCUOUS = 0


class timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]  # long is 32 bits on Windows


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_char * 14)]


class pcap_addr(ctypes.Structure):
    pass


pcap_addr._fields_ = [
    ("next", ctypes.POINTER(pcap_addr)),
    ("addr", ctypes.POINTER(sockaddr)),
    ("netmask", ctypes.POINTER(sockaddr)),
    ("broadaddr", ctypes.POINTER(sockaddr)),
    ("dstaddr", ctypes.POINTER(sockaddr)),
]


class pcap_if(ctypes.Structure):
    pass


pcap_if._fields_ = [
    ("next", ctypes.POINTER(pcap_if)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(pcap_addr)),
    ("flags", ctypes.c_uint32),
]


class bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


def npcap_folder(environ=os.environ) -> Path:
    """Npcap's folder under System32, following SystemRoot like PING.EXE's path (plan section 3.2)."""
    return Path(environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"


def _open_dll(path: Path):
    """The real wpcap.dll. tests/conftest.py blocks this, so no test opens Npcap.

    An absolute path makes Windows look for its Packet.dll beside it, not on the search path.
    """
    return ctypes.CDLL(str(path))


def _load_wpcap(folder: Path | None = None, platform: str = sys.platform):
    if platform != "win32":
        raise CaptureUnavailable(f"packet capture needs Windows and Npcap (this system is {platform!r})")
    path = (folder or npcap_folder()) / "wpcap.dll"
    if not path.is_file():
        raise CaptureUnavailable(f"Npcap is not installed: {path} was not found. Install it from npcap.com")
    try:
        dll = _open_dll(path)
    except OSError as exc:
        raise CaptureUnavailable(f"cannot load Npcap's {path}: {exc}") from exc
    c_void, c_int, c_char_p = ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p
    dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), c_char_p]
    dll.pcap_findalldevs.restype = c_int
    dll.pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if)]
    dll.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
    dll.pcap_open_live.restype = c_void
    dll.pcap_compile.argtypes = [c_void, ctypes.POINTER(bpf_program), c_char_p, c_int, ctypes.c_uint32]
    dll.pcap_compile.restype = c_int
    dll.pcap_setfilter.argtypes = [c_void, ctypes.POINTER(bpf_program)]
    dll.pcap_setfilter.restype = c_int
    dll.pcap_freecode.argtypes = [ctypes.POINTER(bpf_program)]
    dll.pcap_next_ex.argtypes = [
        c_void, ctypes.POINTER(ctypes.POINTER(pcap_pkthdr)), ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    dll.pcap_next_ex.restype = c_int
    dll.pcap_datalink.argtypes = [c_void]
    dll.pcap_datalink.restype = c_int
    dll.pcap_geterr.argtypes = [c_void]
    dll.pcap_geterr.restype = c_char_p
    dll.pcap_close.argtypes = [c_void]
    if hasattr(dll, "pcap_init"):  # Npcap 1.0 and later: names and errors in UTF-8
        dll.pcap_init.argtypes = [ctypes.c_uint, c_char_p]
        dll.pcap_init(PCAP_CHAR_ENC_UTF_8, ctypes.create_string_buffer(ERRBUF_SIZE))
    return dll


def _text(raw: bytes | None) -> str:
    return "" if raw is None else raw.decode("utf-8", errors="replace")


def _address(entry: pcap_addr) -> IPv4Address | IPv6Address | None:
    if not entry.addr:
        return None
    family = entry.addr.contents.sa_family
    raw = ctypes.string_at(entry.addr, 28 if family == AF_INET6 else 16)
    if family == AF_INET:
        return IPv4Address(raw[4:8])  # sockaddr_in: family, port, then the address
    if family == AF_INET6:
        return IPv6Address(raw[8:24])  # sockaddr_in6: family, port, flow info, then the address
    return None


class NpcapSource:
    """A PacketSource on Npcap. Tests hand it a fake dll; nothing else changes."""

    def __init__(self, dll=None) -> None:
        self._dll = dll if dll is not None else _load_wpcap()

    def interfaces(self) -> list[Interface]:
        errbuf = ctypes.create_string_buffer(ERRBUF_SIZE)
        first = ctypes.POINTER(pcap_if)()
        if self._dll.pcap_findalldevs(ctypes.pointer(first), errbuf) == -1:
            raise CaptureUnavailable(f"Npcap could not list interfaces: {_text(errbuf.value)}")
        found = []
        try:
            node = first
            while node:
                device = node.contents
                addresses, entry = [], device.addresses
                while entry:
                    address = _address(entry.contents)
                    if address is not None:
                        addresses.append(address)
                    entry = entry.contents.next
                found.append(
                    Interface(
                        name=_text(device.name),
                        description=_text(device.description),
                        addresses=tuple(addresses),
                        loopback=bool(device.flags & PCAP_IF_LOOPBACK),
                    )
                )
                node = device.next
        finally:
            if first:
                self._dll.pcap_freealldevs(first)
        return found

    def open(self, interface: str, *, snaplen: int = SNAPLEN_FULL, capture_filter: str = "") -> NpcapSession:
        try:
            text = capture_filter.encode("ascii")
        except UnicodeEncodeError:
            raise InvalidFilter("a capture filter is plain ASCII") from None
        errbuf = ctypes.create_string_buffer(ERRBUF_SIZE)
        handle = self._dll.pcap_open_live(interface.encode("utf-8"), snaplen, PROMISCUOUS, READ_TIMEOUT_MS, errbuf)
        if not handle:
            # Npcap's own words, such as "Access is denied" when it is set to Administrators only.
            raise CaptureUnavailable(f"Npcap could not open {interface}: {_text(errbuf.value)}")
        try:
            if capture_filter:
                self._set_filter(handle, text)
            return NpcapSession(self._dll, handle, self._dll.pcap_datalink(handle))
        except BaseException:
            self._dll.pcap_close(handle)
            raise

    def _set_filter(self, handle, text: bytes) -> None:
        program = bpf_program()
        if self._dll.pcap_compile(handle, ctypes.pointer(program), text, 1, PCAP_NETMASK_UNKNOWN) == -1:
            raise InvalidFilter(_text(self._dll.pcap_geterr(handle)))
        try:
            if self._dll.pcap_setfilter(handle, ctypes.pointer(program)) == -1:
                raise CaptureUnavailable(f"Npcap could not set the filter: {_text(self._dll.pcap_geterr(handle))}")
        finally:
            self._dll.pcap_freecode(ctypes.pointer(program))


class NpcapSession:
    def __init__(self, dll, handle, link_type: int) -> None:
        self._dll = dll
        self._handle = handle
        self.link_type = link_type

    def next_batch(self, wait_ms: int) -> list[RawPacket]:
        """Reads until a read times out with packets in hand, the batch is full, or wait_ms passed with none."""
        if self._handle is None:
            raise CaptureUnavailable("the capture is closed")
        batch: list[RawPacket] = []
        quiet = max(1, wait_ms // READ_TIMEOUT_MS)  # read timeouts allowed before giving up
        header = ctypes.POINTER(pcap_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        while len(batch) < MAX_BATCH:
            status = self._dll.pcap_next_ex(self._handle, ctypes.pointer(header), ctypes.pointer(data))
            if status == 1:
                h = header.contents
                time_ns = h.ts.tv_sec * 1_000_000_000 + h.ts.tv_usec * 1000
                batch.append(RawPacket(time_ns, max(h.len, h.caplen), self.link_type, ctypes.string_at(data, h.caplen)))
            elif status == 0:
                quiet -= 1
                if batch or quiet <= 0:
                    break
            elif status == -2:
                break  # end of a file; never on a live interface
            else:
                raise CaptureUnavailable(f"the capture stopped: {_text(self._dll.pcap_geterr(self._handle))}")
        return batch

    def close(self) -> None:
        if self._handle is not None:
            self._dll.pcap_close(self._handle)
            self._handle = None
