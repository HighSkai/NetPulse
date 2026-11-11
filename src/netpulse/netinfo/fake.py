from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Interface

from netpulse.netinfo.reader import NetworkInfoUnavailable
from netpulse.network import Adapter, Category, Neighbour, NetworkInfo

READ_AT = datetime(2026, 10, 13, 12, 0, tzinfo=UTC)


def home_network(*, read_at: datetime = READ_AT) -> NetworkInfo:
    """A typical home network: one Wi-Fi adapter on 192.168.1.0/24 behind 192.168.1.1."""
    gateway = IPv4Address("192.168.1.1")
    wifi = Adapter(
        index=12,
        name="Wi-Fi",
        description="Example Wireless Adapter",
        mac="02-00-5E-10-00-01",
        addresses=(IPv4Interface("192.168.1.23/24"),),
        gateways=(gateway,),
        dns_servers=(gateway,),
        dhcp=True,
        category=Category.PRIVATE,
    )
    return NetworkInfo(computer="DESKTOP-TEST", adapters=(wifi,), preferred_gateway=gateway, read_at=read_at)


class FakeNetworkReader:
    """Canned network settings for tests, or a canned failure. Counts its reads."""

    def __init__(
        self,
        info: NetworkInfo | None = None,
        *,
        error: str | None = None,
        neighbour_list: tuple[Neighbour, ...] = (),
    ) -> None:
        self.info = info if info is not None else home_network()
        self.error = error  # set it to make reads fail, clear it to make them work again
        self.neighbour_list = neighbour_list
        self.neighbour_error: str | None = None
        self.reads = 0

    def read(self) -> NetworkInfo:
        self.reads += 1
        if self.error is not None:
            raise NetworkInfoUnavailable(self.error)
        return self.info

    def neighbours(self) -> tuple[Neighbour, ...]:
        if self.neighbour_error is not None:
            raise NetworkInfoUnavailable(self.neighbour_error)
        return self.neighbour_list
