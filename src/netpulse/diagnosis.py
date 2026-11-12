"""What several devices being down at once might have in common (plan section 41).

Pure functions over the dashboard's rows, the links the user declared and this
PC's network settings. A ping proves that a device answers or does not, never
why, so every finding is a hypothesis: it says how sure it is, and what it
rests on. Nothing here is offered when only one device is down.

- Likely: the evidence is a relationship someone stated or Windows reported,
  such as a device the down devices connect through being down itself.
- Possible: a pattern in the addresses or groups, which fits the cause but
  does not prove it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address

from netpulse.domain import DeviceState, connects_through
from netpulse.metrics import DeviceRow
from netpulse.network import NetworkInfo

LIKELY = "likely"
POSSIBLE = "possible"


@dataclass(frozen=True)
class Finding:
    confidence: str  # LIKELY or POSSIBLE
    summary: str  # one sentence, already hedged
    evidence: str  # what it rests on
    devices: tuple[int, ...] = ()  # the down devices it would explain
    cause: int | None = None  # the device it points at, when it points at one

    @property
    def text(self) -> str:
        return f"{self.summary} ({self.evidence})"


def _ipv4(host: str) -> IPv4Address | None:
    try:
        return IPv4Address(host)
    except ValueError:
        return None


def _names(rows: Sequence[DeviceRow], limit: int = 4) -> str:
    names = [row.status.device.name for row in rows]
    if len(names) > limit:
        return ", ".join(names[:limit]) + f" and {len(names) - limit} more"
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def diagnose(
    rows: Sequence[DeviceRow],
    links: Mapping[int, int] | None = None,
    info: NetworkInfo | None = None,
    groups: Mapping[int, str] | None = None,
) -> list[Finding]:
    """Hypotheses for the devices that are down now, the best supported first."""
    links, groups = links or {}, groups or {}
    checked = [row for row in rows if not row.status.device.paused and row.status.latest is not None]
    by_id = {row.status.device.id: row for row in checked}
    down = [row for row in checked if row.state == DeviceState.DOWN]
    down_ids = {row.status.device.id for row in down}
    if not down:
        return []
    findings: list[Finding] = []
    explained: set[int] = set()

    # 1. Down devices that connect through a device that is down itself.
    behind: dict[int, list[DeviceRow]] = {}
    for row in down:
        chain = [parent for parent in connects_through(row.status.device.id, links) if parent in down_ids]
        if chain:
            behind.setdefault(chain[-1], []).append(row)  # the furthest down device on its path
    for cause_id, affected in behind.items():
        cause = by_id[cause_id]
        findings.append(Finding(
            LIKELY,
            f"{cause.status.device.name} is down, and so {'is' if len(affected) == 1 else 'are'} {_names(affected)}, "
            f"which connect{'s' if len(affected) == 1 else ''} through it",
            "you declared what they connect through",
            tuple(row.status.device.id for row in affected), cause_id,
        ))
        explained.update(row.status.device.id for row in affected)

    local, outside = _split_by_network(checked, info)
    gateway = _gateway_row(checked, info)

    # 2. The gateway is down: nothing beyond this network can answer.
    if gateway is not None and gateway.state == DeviceState.DOWN:
        beyond = [row for row in outside if row.state == DeviceState.DOWN and row.status.device.id not in explained]
        if beyond:
            findings.append(Finding(
                LIKELY,
                f"The gateway {gateway.status.device.name} is down, so {_names(beyond)} on other networks cannot be reached",
                "Windows reports it as this PC's default gateway",
                tuple(row.status.device.id for row in beyond), gateway.status.device.id,
            ))
            explained.update(row.status.device.id for row in beyond)

    # 3. Everything is down, local devices too: suspect this PC's own connection.
    if len(checked) >= 3 and len(down) == len(checked):
        return [Finding(
            POSSIBLE,
            f"All {len(checked)} monitored devices are down at once, so this PC's own network connection is the first thing to check",
            "no device answered, on this network or beyond it",
            tuple(sorted(down_ids)),
        ), *findings]

    # 4. Everything beyond this network is down while local devices answer.
    outside_down = [row for row in outside if row.state == DeviceState.DOWN]
    if (
        len(outside) >= 2 and len(outside_down) == len(outside)
        and any(row.state != DeviceState.DOWN for row in local)
        and not (gateway is not None and gateway.state == DeviceState.DOWN)
    ):
        findings.append(Finding(
            POSSIBLE,
            f"Every monitored host outside this network is down ({_names(outside_down)}) while local devices answer, "
            "which points at the internet connection or the provider",
            "their addresses are outside this PC's subnets",
            tuple(row.status.device.id for row in outside_down),
        ))
        explained.update(row.status.device.id for row in outside_down)

    # 5. A whole group is down while others are not.
    by_group: dict[int, list[DeviceRow]] = {}
    for row in checked:
        if row.status.device.group_id is not None:
            by_group.setdefault(row.status.device.group_id, []).append(row)
    for group_id, members in by_group.items():
        unexplained = [row for row in members if row.status.device.id not in explained]
        if len(members) >= 3 and all(row.state == DeviceState.DOWN for row in members) and unexplained:
            findings.append(Finding(
                POSSIBLE,
                f"Every device in the group {groups.get(group_id, 'that they share')} is down, so they may share "
                "a switch, an access point or a power source",
                "they are in one group, and devices outside it answer",
                tuple(row.status.device.id for row in members),
            ))
    findings.sort(key=lambda finding: (finding.confidence != LIKELY, -len(finding.devices)))
    return findings


def _split_by_network(rows: Sequence[DeviceRow], info: NetworkInfo | None) -> tuple[list[DeviceRow], list[DeviceRow]]:
    """(devices on this PC's subnets, devices beyond them). A device known by name counts as neither."""
    if info is None:
        return [], []
    subnets = [subnet for adapter in info.adapters for subnet in adapter.subnets]
    local, outside = [], []
    for row in rows:
        address = _ipv4(row.status.device.host)
        if address is None or address.is_loopback:
            continue
        (local if any(address in subnet for subnet in subnets) else outside).append(row)
    return local, outside


def _gateway_row(rows: Sequence[DeviceRow], info: NetworkInfo | None) -> DeviceRow | None:
    if info is None or info.preferred_gateway is None:
        return None
    gateway = str(info.preferred_gateway)
    return next((row for row in rows if row.status.device.host == gateway), None)
