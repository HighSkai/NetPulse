"""The topology map, as a tree (plan sections 19 and 20).

Built from this PC's network settings, the dashboard's device rows and the
links the user declared. Every line in it says where it came from: reported by
Windows, inferred by NetPulse from addresses, or declared by the user. A ping
proves that a device answers, not the path to it, so this module draws no line
it cannot explain.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from ipaddress import IPv4Address, IPv4Network

from netpulse.domain import connects_through
from netpulse.metrics import DeviceRow
from netpulse.network import NetworkInfo

LOOPBACK = IPv4Network("127.0.0.0/8")
PC_ID = "pc"
OTHER_ID = "other"


class Kind:
    PC = "pc"
    SUBNET = "subnet"
    GATEWAY = "gateway"
    OTHER = "other"
    DEVICE = "device"


class Evidence:
    """Where a line came from. Measured lines have no source in v2 (plan section 19)."""

    REPORTED = "reported"
    INFERRED = "inferred"
    DECLARED = "declared"  # plan section 20

    WORDS = {REPORTED: "Reported by Windows", INFERRED: "Inferred", DECLARED: "Declared by you"}


# Siblings are listed hubs first, then gateways, Other networks, and devices by name.
_SIBLING_ORDER = {Kind.SUBNET: 0, Kind.GATEWAY: 1, Kind.OTHER: 2, Kind.DEVICE: 3}


@dataclass(frozen=True)
class Node:
    """One node, and the line to it from its parent. A node without a parent has no line."""

    id: str
    kind: str
    label: str
    detail: str = ""
    parent: str | None = None
    evidence: str | None = None
    reason: str = ""
    row: DeviceRow | None = None  # the monitored device this node shows

    @property
    def explanation(self) -> str:
        """The line's evidence and reason, or why a device has no line."""
        if self.evidence is not None:
            return f"{Evidence.WORDS[self.evidence]}: {self.reason}"
        if self.kind == Kind.DEVICE:
            return f"Not placed: {self.reason}"
        return self.reason


@dataclass(frozen=True)
class Topology:
    """Nodes in tree order: a parent always comes before its children."""

    nodes: tuple[Node, ...]
    network_error: str | None = None

    def children(self, node_id: str) -> list[Node]:
        return [node for node in self.nodes if node.parent == node_id]

    @property
    def roots(self) -> list[Node]:
        """This PC, and Other networks when Windows has no default route."""
        return [n for n in self.nodes if n.parent is None and n.kind != Kind.DEVICE]

    @property
    def unplaced(self) -> list[Node]:
        return [n for n in self.nodes if n.parent is None and n.kind == Kind.DEVICE]

    def elements(self) -> list[dict]:
        """The tree in Cytoscape.js's format: nodes, then one edge per line."""
        nodes = []
        for node in self.nodes:
            data: dict = {"id": node.id, "kind": node.kind, "label": node.label}
            if node.detail:
                data["detail"] = node.detail
            if node.row is not None:
                data["state"] = node.row.state
            nodes.append({"group": "nodes", "data": data})
        edges = [
            {
                "group": "edges",
                "data": {
                    "id": f"{node.parent}>{node.id}",
                    "source": node.parent,
                    "target": node.id,
                    "evidence": node.evidence,
                    "explanation": node.explanation,
                },
            }
            for node in self.nodes
            if node.parent is not None
        ]
        return nodes + edges


def subnet_id(network: IPv4Network) -> str:
    return f"subnet:{network}"


def gateway_id(address: IPv4Address) -> str:
    return f"gateway:{address}"


def device_node_id(device_id: int) -> str:
    return f"device:{device_id}"


def build_topology(
    info: NetworkInfo | None,
    rows: Sequence[DeviceRow],
    links: Mapping[int, int] | None = None,
    *,
    network_error: str | None = None,
) -> Topology:
    """The map's tree. info is None when the network settings could not be read.

    links are the declared links between live devices, {device id: what it
    connects through}, as Store.links returns them.
    """
    rows = sorted(rows, key=lambda r: (r.status.device.name.casefold(), r.status.device.id))
    by_address: dict[IPv4Address, DeviceRow] = {}
    for row in rows:
        address = _ipv4(row.status.device.host)
        if address is not None:
            by_address.setdefault(address, row)

    pc = Node(PC_ID, Kind.PC, info.computer if info else "This PC", detail="this PC")
    hubs = _hubs(info, pc)
    gateways = _gateways(info, hubs, by_address)
    gateway_addresses = {address for address, _ in gateways}

    nodes: dict[str, Node] = {pc.id: pc}
    nodes.update((hub.id, hub) for hub in hubs)
    nodes.update((node.id, node) for _, node in gateways)
    # The node that shows each device: its own, or its gateway's.
    shown_by = {node.row.status.device.id: node.id for _, node in gateways if node.row is not None}

    outside = []
    for row in rows:
        device = row.status.device
        address = _ipv4(device.host)
        node = Node(device_node_id(device.id), Kind.DEVICE, device.name, detail=device.host, row=row)
        if address is None:
            node = _with(node, reason="it is known by a name, and the map places devices by IPv4 address")
        elif address in gateway_addresses and by_address[address] is row:
            continue  # drawn as its gateway node
        elif address in LOOPBACK:
            node = _line(node, pc, Evidence.INFERRED, f"{address} is a loopback address, so it is this PC")
        elif info is not None and address in info.own_addresses:
            node = _line(node, pc, Evidence.INFERRED, f"{address} is one of this PC's addresses")
        elif info is None:
            node = _with(node, reason="the network settings could not be read")
        else:
            hub = _hub_for(address, hubs)
            if hub is not None:
                node = _line(node, hub, Evidence.INFERRED, f"{address} is in {hub.label}")
            else:
                outside.append((address, node))
        nodes[node.id] = node
        shown_by[device.id] = node.id

    if outside:
        preferred = info.preferred_gateway if info is not None else None
        if preferred is not None:
            [via] = [node for address, node in gateways if address == preferred]
            hub_node = Node(OTHER_ID, Kind.OTHER, "Other networks")
            other_node = _line(hub_node, via, Evidence.REPORTED, f"the default route goes through {preferred}")
        else:
            other_node = Node(OTHER_ID, Kind.OTHER, "Other networks", reason="Windows reports no default route")
        nodes[OTHER_ID] = other_node
        for address, node in outside:
            nodes[node.id] = _line(node, other_node, Evidence.INFERRED, f"{address} is outside this PC's subnets")

    _declare(nodes, shown_by, links or {})
    return Topology(nodes=_tree_order(nodes), network_error=network_error)


def _declare(nodes: dict[str, Node], shown_by: Mapping[int, str], links: Mapping[int, int]) -> None:
    """Hang devices from what the user said they connect through (plan section 20).

    A declared line replaces NetPulse's guess, never what Windows reports, so a
    gateway keeps its place. Links in a loop are ignored, so the map never loops.
    """
    for device_id, parent_id in links.items():
        if device_id not in shown_by or parent_id not in shown_by or _in_a_loop(device_id, links):
            continue
        node, parent = nodes[shown_by[device_id]], nodes[shown_by[parent_id]]
        if node.evidence == Evidence.REPORTED:
            continue
        nodes[node.id] = _with(
            node, parent=parent.id, evidence=Evidence.DECLARED, reason=f"{node.label} connects through {parent.label}"
        )


def _in_a_loop(device_id: int, links: Mapping[int, int]) -> bool:
    chain = connects_through(device_id, links)
    return links.get(chain[-1] if chain else device_id) == device_id


def _tree_order(nodes: dict[str, Node]) -> tuple[Node, ...]:
    """Every node after its parent, depth first: This PC's tree, then the nodes with no line."""
    position = {node_id: index for index, node_id in enumerate(nodes)}
    children: dict[str | None, list[Node]] = {}
    for node in nodes.values():
        children.setdefault(node.parent, []).append(node)
    ordered: list[Node] = []

    def visit(node: Node) -> None:
        ordered.append(node)
        for child in sorted(children.get(node.id, []), key=lambda n: (_SIBLING_ORDER[n.kind], position[n.id])):
            visit(child)

    for root in sorted(children.get(None, []), key=lambda n: (n.kind == Kind.DEVICE, position[n.id])):
        visit(root)
    return tuple(ordered)


def _hubs(info: NetworkInfo | None, pc: Node) -> list[Node]:
    """One hub per subnet of this PC's adapters, in Windows' order of preference."""
    facts: dict[IPv4Network, list[str]] = {}
    names: dict[IPv4Network, list[str]] = {}
    for adapter in info.adapters if info is not None else ():
        for address in adapter.addresses:
            facts.setdefault(address.network, []).append(f"{adapter.name} has {address}")
            names.setdefault(address.network, [])
            if adapter.name not in names[address.network]:
                names[address.network].append(adapter.name)
    return [
        _line(Node(subnet_id(net), Kind.SUBNET, str(net), detail=", ".join(names[net])),
              pc, Evidence.REPORTED, _and(facts[net]))
        for net in facts
    ]


def _gateways(
    info: NetworkInfo | None, hubs: list[Node], by_address: dict[IPv4Address, DeviceRow]
) -> list[tuple[IPv4Address, Node]]:
    """Each default gateway once, under the hub of the subnet it is in."""
    found: dict[IPv4Address, tuple[Node, list[str]]] = {}
    for adapter in info.adapters if info is not None else ():
        for address in adapter.gateways:
            if address not in found:
                hub = _hub_for(address, hubs) or _hub_for(adapter.addresses[0].ip, hubs)
                found[address] = (hub, [])
            found[address][1].append(adapter.name)
    gateways = []
    for address, (hub, adapters) in found.items():
        row = by_address.get(address)
        node = Node(
            gateway_id(address),
            Kind.GATEWAY,
            row.status.device.name if row is not None else "Gateway",
            detail=str(address),
            row=row,
        )
        gateways.append((address, _line(node, hub, Evidence.REPORTED, f"the default gateway of {_and(adapters)}")))
    return gateways


def _hub_for(address: IPv4Address, hubs: Iterable[Node]) -> Node | None:
    """The most specific subnet of this PC that holds the address."""
    holding = [hub for hub in hubs if address in IPv4Network(hub.label)]
    return max(holding, key=lambda hub: IPv4Network(hub.label).prefixlen, default=None)


def _line(node: Node, parent: Node, evidence: str, reason: str) -> Node:
    return _with(node, parent=parent.id, evidence=evidence, reason=reason)


def _with(node: Node, **changes) -> Node:
    return replace(node, **changes)


def _ipv4(host: str) -> IPv4Address | None:
    try:
        return IPv4Address(host)
    except ValueError:
        return None


def _and(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
