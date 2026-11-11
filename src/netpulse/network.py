"""This PC's network settings, as values (plan section 19).

netpulse.netinfo reads them from Windows, and netpulse.topology builds the map
from them. Nothing here reads the network or starts a process.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv4Interface, IPv4Network


class Category:
    """The network category Windows gives a connection."""

    PUBLIC = "public"
    PRIVATE = "private"
    DOMAIN = "domain"


class Connectivity:
    """What Windows says a connection reaches (plan section 22)."""

    INTERNET = "internet"
    LOCAL = "local network only"
    NO_TRAFFIC = "no traffic"
    DISCONNECTED = "disconnected"


@dataclass(frozen=True)
class Lease:
    """This PC's DHCP lease on one adapter. Any part Windows does not report is None."""

    server: IPv4Address | None
    obtained: datetime | None
    expires: datetime | None


@dataclass(frozen=True)
class Adapter:
    """A network adapter that is up and has at least one IPv4 address in use."""

    index: int
    name: str
    description: str
    mac: str | None
    addresses: tuple[IPv4Interface, ...]
    gateways: tuple[IPv4Address, ...] = ()
    dns_servers: tuple[IPv4Address, ...] = ()
    dhcp: bool | None = None
    category: str | None = None
    connectivity: str | None = None  # plan section 22
    lease: Lease | None = None  # plan section 22: only while DHCP gave the address

    def __post_init__(self) -> None:
        if not self.addresses:
            raise ValueError(f"adapter {self.name!r} has no IPv4 address")

    @property
    def subnets(self) -> tuple[IPv4Network, ...]:
        """Each subnet this adapter has an address in, once, in address order."""
        return tuple(dict.fromkeys(address.network for address in self.addresses))


@dataclass(frozen=True)
class Neighbour:
    """An IPv4 address on a local network, and the MAC address Windows found for it.

    Only entries Windows confirmed recently (plan section 21).
    """

    address: IPv4Address
    mac: str


@dataclass(frozen=True)
class NetworkInfo:
    """What Windows reported, and when. Adapters come in Windows' order of preference."""

    computer: str
    adapters: tuple[Adapter, ...]
    preferred_gateway: IPv4Address | None
    read_at: datetime
    # Plan section 22: each gateway's MAC address, from Windows' neighbour table.
    gateway_macs: tuple[tuple[IPv4Address, str], ...] = ()

    def __post_init__(self) -> None:
        if self.read_at.tzinfo is None:
            raise ValueError("read_at must be timezone-aware")
        if self.preferred_gateway is not None and self.preferred_gateway not in self.gateways:
            raise ValueError("the preferred gateway must be one of an adapter's gateways")

    @property
    def gateways(self) -> tuple[IPv4Address, ...]:
        return tuple(dict.fromkeys(g for adapter in self.adapters for g in adapter.gateways))

    def mac_of(self, gateway: IPv4Address) -> str | None:
        return dict(self.gateway_macs).get(gateway)

    @property
    def gateway_adapter(self) -> Adapter | None:
        """The adapter whose gateway Windows prefers."""
        return next((a for a in self.adapters if self.preferred_gateway in a.gateways), None)

    @property
    def own_addresses(self) -> frozenset[IPv4Address]:
        """This PC's IPv4 addresses on its adapters (not loopback)."""
        return frozenset(a.ip for adapter in self.adapters for a in adapter.addresses)


# Discovery (plan section 21)


class HostState:
    """Where a discovered host stands on the review list."""

    NEW = "new"
    ACCEPTED = "accepted"
    IGNORED = "ignored"


@dataclass(frozen=True)
class FoundHost:
    """What one sweep learned about one address."""

    address: IPv4Address
    mac: str | None
    name: str | None
    answers_ping: bool


@dataclass(frozen=True)
class DiscoveredHost:
    """A host on the review list, as stored. Identity is the MAC address when known."""

    id: int
    address: IPv4Address
    mac: str | None
    name: str | None
    answers_ping: bool
    first_seen: str
    last_seen: str
    state: str
    device_id: int | None

    @property
    def private_mac(self) -> bool:
        """A locally administered MAC: phones make these up, per network or over time."""
        return self.mac is not None and bool(int(self.mac[:2], 16) & 0b10)

    @property
    def suggested_name(self) -> str:
        """The device name Accept uses: the host's name, or its address."""
        return (self.name or str(self.address))[:64]
