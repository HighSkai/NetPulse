from __future__ import annotations

import ipaddress
import re

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)
_NUMERIC_LABEL = re.compile(r"^(?:\d+|0x[0-9a-f]*)$", re.IGNORECASE)


class InvalidHost(ValueError):
    pass


def validate_host(host: str) -> str:
    """Return a trimmed hostname or IPv4 string, or raise InvalidHost.

    Hosts are passed as subprocess argv, never through a shell. Still reject
    values that look like switches or contain whitespace.
    """
    if host is None:
        raise InvalidHost("host is required")
    trimmed = host.strip()
    if not trimmed:
        raise InvalidHost("host is required")
    if any(ch.isspace() for ch in trimmed):
        raise InvalidHost("host must not contain whitespace")
    if trimmed[0] in "-/":
        raise InvalidHost("host must not look like a command switch")

    try:
        addr = ipaddress.IPv4Address(trimmed)
    except ipaddress.AddressValueError:
        addr = None
    if addr is not None:
        return str(addr)

    if not _HOSTNAME.fullmatch(trimmed):
        raise InvalidHost("host must be an IPv4 address or hostname")
    if _NUMERIC_LABEL.fullmatch(trimmed.rsplit(".", 1)[-1]):
        # Not a real hostname (no top-level domain is numeric), and Windows
        # would read it as an address: 010.0.0.1 is 8.0.0.1 (octal),
        # 192.168.1 is 192.168.0.1, 2130706433 is 127.0.0.1.
        raise InvalidHost("host looks like an address but is not dotted IPv4 like 192.168.1.10")
    return trimmed
