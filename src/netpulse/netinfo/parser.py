"""Turns the PowerShell reader's JSON into NetworkInfo (plan section 19, decision 003).

The JSON holds Windows' CIM objects as they are: enumerations arrive as
numbers, not words, so nothing here depends on the display language.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Interface, ip_address, ip_interface

from netpulse.netinfo.reader import NetworkInfoUnavailable
from netpulse.network import Adapter, Category, Connectivity, Lease, Neighbour, NetworkInfo

# Values of the CIM enumerations NetPulse reads.
OPERATIONAL_STATUS_UP = 1  # MSFT_NetAdapter.InterfaceOperationalStatus
ADDRESS_STATE_PREFERRED = 4  # MSFT_NetIPAddress.AddressState: in use, not tentative
DHCP = {0: False, 1: True}  # MSFT_NetIPInterface.Dhcp
CATEGORIES = {0: Category.PUBLIC, 1: Category.PRIVATE, 2: Category.DOMAIN}  # MSFT_NetConnectionProfile
# MSFT_NetConnectionProfile.IPv4Connectivity (plan section 22). 2 is "subnet".
CONNECTIVITY = {
    0: Connectivity.DISCONNECTED,
    1: Connectivity.NO_TRAFFIC,
    2: Connectivity.LOCAL,
    3: Connectivity.LOCAL,
    4: Connectivity.INTERNET,
}
# How ConvertTo-Json in Windows PowerShell writes a date: milliseconds since 1970, UTC.
CIM_DATE = re.compile(r"/Date\((-?\d+)\)/")
NO_NEXT_HOP = "0.0.0.0"  # an on-link route has no gateway
# MSFT_NetNeighbor.State values for an entry confirmed recently: Probe, Delay
# and Reachable. Stale entries may be left from long ago (plan section 21),
# and Permanent ones are broadcast and multicast addresses.
RECENT_NEIGHBOUR_STATES = {2, 3, 5}

UNREADABLE = "Windows reported the network settings in a form NetPulse cannot read"


def parse_network_json(text: str, read_at: datetime) -> NetworkInfo:
    """Raises NetworkInfoUnavailable if the text is not what the reader's script prints."""
    try:
        return _parse(json.loads(text), read_at)
    except (ValueError, KeyError, TypeError) as exc:
        raise NetworkInfoUnavailable(UNREADABLE) from exc


def _parse(raw: object, read_at: datetime) -> NetworkInfo:
    if not isinstance(raw, dict) or not isinstance(raw["computer"], str) or not raw["computer"]:
        raise TypeError("expected an object with the computer's name")

    up = {
        _index(a): a
        for a in _records(raw, "adapters")
        if a.get("InterfaceOperationalStatus") == OPERATIONAL_STATUS_UP
    }
    addresses: dict[int, list[IPv4Interface]] = {}
    for record in _records(raw, "addresses"):
        if record.get("AddressState") == ADDRESS_STATE_PREFERRED:
            address = ip_interface(f"{record['IPAddress']}/{int(record['PrefixLength'])}")
            if isinstance(address, IPv4Interface):
                addresses.setdefault(_index(record), []).append(address)
    interfaces = {_index(r): r for r in _records(raw, "interfaces")}
    routes: dict[int, list[tuple[int, IPv4Address]]] = {}
    for record in _records(raw, "routes"):
        if record["NextHop"] != NO_NEXT_HOP:
            routes.setdefault(_index(record), []).append(
                (int(record["RouteMetric"]), IPv4Address(record["NextHop"]))
            )
    dns = {_index(r): _ipv4_list(r.get("ServerAddresses")) for r in _records(raw, "dns")}
    profiles = _records(raw, "profiles")
    categories = {_index(r): CATEGORIES.get(r.get("NetworkCategory")) for r in profiles}
    connectivity = {_index(r): CONNECTIVITY.get(r.get("IPv4Connectivity")) for r in profiles}
    leases = {_index(r): _lease(r) for r in _records(raw, "leases") if r.get("DHCPEnabled") is True}

    def metric(index: int) -> int:
        return int(interfaces.get(index, {}).get("InterfaceMetric") or 0)

    adapters = []
    for index, record in up.items():
        if index not in addresses:
            continue  # no IPv4 address in use, so nothing on it to place
        adapters.append(
            Adapter(
                index=index,
                name=_text(record, "Name"),
                description=_text(record, "InterfaceDescription"),
                mac=_mac(record),
                addresses=tuple(addresses[index]),
                gateways=tuple(dict.fromkeys(hop for _, hop in sorted(routes.get(index, []), key=_by_metric))),
                dns_servers=dns.get(index, ()),
                dhcp=DHCP.get(interfaces.get(index, {}).get("Dhcp")),
                category=categories.get(index),
                connectivity=connectivity.get(index),
                lease=leases.get(index),
            )
        )
    adapters.sort(key=lambda a: (metric(a.index), a.name.casefold(), a.index))

    # Windows sends traffic for other networks by the default route with the
    # lowest route metric plus interface metric.
    candidates = [
        (route_metric + metric(adapter.index), str(hop), hop)
        for adapter in adapters
        for route_metric, hop in routes.get(adapter.index, [])
    ]
    preferred = min(candidates)[2] if candidates else None
    gateways = {hop for adapter in adapters for hop in adapter.gateways}
    macs: dict[IPv4Address, str] = {}
    for record in _records(raw, "neighbours"):
        mac = _unicast_mac(record.get("LinkLayerAddress"))
        address = IPv4Address(record["IPAddress"]) if mac is not None else None
        if address in gateways:
            macs.setdefault(address, mac)
    return NetworkInfo(
        computer=raw["computer"],
        adapters=tuple(adapters),
        preferred_gateway=preferred,
        read_at=read_at,
        gateway_macs=tuple(sorted(macs.items())),
    )


def _lease(record: dict) -> Lease:
    server = record.get("DHCPServer")
    return Lease(
        server=IPv4Address(server) if isinstance(server, str) and server else None,
        obtained=_cim_date(record.get("DHCPLeaseObtained")),
        expires=_cim_date(record.get("DHCPLeaseExpires")),
    )


def _cim_date(value: object) -> datetime | None:
    if value is None:
        return None
    match = CIM_DATE.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError(f"not a date: {value!r}")
    return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=UTC)


def parse_neighbours_json(text: str) -> tuple[Neighbour, ...]:
    """The neighbour script's JSON as the entries confirmed recently, each address once."""
    try:
        raw = json.loads(text)
        if not isinstance(raw, dict):
            raise TypeError("expected an object")
        found: dict[IPv4Address, Neighbour] = {}
        for record in _records(raw, "neighbours"):
            mac = _unicast_mac(record.get("LinkLayerAddress"))
            if record.get("State") in RECENT_NEIGHBOUR_STATES and mac is not None:
                address = IPv4Address(record["IPAddress"])
                found.setdefault(address, Neighbour(address, mac))
        return tuple(found.values())
    except (ValueError, KeyError, TypeError) as exc:
        raise NetworkInfoUnavailable(UNREADABLE) from exc


def _unicast_mac(value: object) -> str | None:
    """A device's MAC address, or None for an empty, broadcast or multicast one."""
    mac = _format_mac(value)
    if mac is None or mac == "00-00-00-00-00-00" or int(mac[:2], 16) & 1:
        return None
    return mac


def _records(raw: dict, key: str) -> list[dict]:
    """A list of objects. PowerShell turns a list of one into the object itself."""
    value = raw.get(key)
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    raise TypeError(f"{key} is not a list of objects")


def _index(record: dict) -> int:
    index = record["InterfaceIndex"]
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("InterfaceIndex is not a number")
    return index


def _text(record: dict, key: str) -> str:
    value = record.get(key)
    return value if isinstance(value, str) else ""


def _by_metric(route: tuple[int, IPv4Address]) -> tuple[int, str]:
    return route[0], str(route[1])


def _ipv4_list(value: object) -> tuple[IPv4Address, ...]:
    """DNS servers: IPv4 only. A list of one may arrive as a plain string."""
    items = [value] if isinstance(value, str) else value or []
    if not isinstance(items, list):
        raise TypeError("ServerAddresses is not a list")
    return tuple(a for a in (ip_address(item) for item in items) if isinstance(a, IPv4Address))


def _mac(record: dict) -> str | None:
    """The adapter's current MAC address, as Windows writes it: 00-00-5E-00-53-01.

    NetworkAddresses is the address in use, which differs from the permanent
    one when Windows randomises it on Wi-Fi.
    """
    current = record.get("NetworkAddresses")
    if isinstance(current, list):
        current = current[0] if current else None
    for value in (current, record.get("PermanentAddress")):
        mac = _format_mac(value)
        if mac is not None:
            return mac
    return None


def _format_mac(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    digits = value.replace("-", "").replace(":", "").upper()
    if len(digits) == 12 and all(c in "0123456789ABCDEF" for c in digits):
        return "-".join(digits[i : i + 2] for i in range(0, 12, 2))
    return None
