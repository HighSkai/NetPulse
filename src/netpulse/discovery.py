"""Discovery sweeps (plan section 21).

A sweep pings every address of one of this PC's private subnets at once,
reads Windows' neighbour table for MAC addresses, looks up names, and writes
what it found to the review list. Nothing is monitored until the user
accepts it. One sweep runs at a time, on its own thread, never inside the
check round.

Plan section 41 adds sweeps on a schedule: off unless an administrator turns
them on for one subnet. A scheduled sweep only ever covers that subnet while
this PC is still on it, so a laptop carried to another network sweeps nothing
there, and it raises an alert for each host it has never seen before.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network

from netpulse.netinfo import NetworkInfoUnavailable, NetworkReader
from netpulse.netinfo.names import Lookups
from netpulse.network import Category, DiscoveredHost, FoundHost, NetworkInfo
from netpulse.ping.result import Pinger, PingerUnavailable
from netpulse.store import Store

# Probes in flight at once. Most addresses are empty and each costs a full
# wait. Measured on a real /24: 64 at once took 6.2 s, 128 took 4.0 s, all 256
# took 3.0 s, and each found the same hosts (plan section 21). Since plan
# section 40 the sweep takes the three seconds longer: 254 lookups in one burst
# is more than some home routers and access points like, and nobody is waiting
# on a scheduled sweep.
SWEEP_WORKERS = 64
# Plan section 41: how often a scheduled sweep may run, in minutes. 0 is off.
SCHEDULES_MIN = (0, 60, 360, 1440)
SCHEDULE_KEY, SCHEDULE_NETWORK_KEY = "discovery.every_min", "discovery.network"
# A host's name is looked up the moment it answers ping. After the neighbour
# table is read, the sweep waits at most this long for the rest.
NAME_WAIT_S = 0.5
# A sweep never covers more than a /24 (plan section 21).
SWEEP_PREFIX = 24
PRIVATE_RANGES = tuple(IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SweepTarget:
    """A subnet a sweep may cover, and the adapter it is on."""

    network: IPv4Network
    adapter: str
    category: str | None
    own: frozenset[IPv4Address]

    @property
    def needs_confirmation(self) -> bool:
        """Windows marks the network Public: the user must say it is theirs."""
        return self.category not in (Category.PRIVATE, Category.DOMAIN)

    @property
    def addresses(self) -> list[IPv4Address]:
        """Every address to ping: not the network or broadcast address, nor this PC's."""
        return [a for a in self.network.hosts() if a not in self.own]


def sweep_targets(info: NetworkInfo) -> list[SweepTarget]:
    """This PC's private subnets, each cut to the /24 around this PC if larger."""
    targets: dict[IPv4Network, SweepTarget] = {}
    own = info.own_addresses
    for adapter in info.adapters:
        for address in adapter.addresses:
            if not any(address.ip in private for private in PRIVATE_RANGES):
                continue
            network = address.network
            if network.prefixlen < SWEEP_PREFIX:
                network = IPv4Network(f"{address.ip}/{SWEEP_PREFIX}", strict=False)
            targets.setdefault(network, SweepTarget(network, adapter.name, adapter.category, own))
    return list(targets.values())


class SweepState:
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True)
class SweepStatus:
    """What the sweep is doing, or what the last one found. Memory only."""

    state: str = SweepState.IDLE
    network: IPv4Network | None = None
    total: int = 0
    pinged: int = 0
    found: int = 0
    answered: int = 0
    seconds: float | None = None
    finished_at: datetime | None = None
    error: str | None = None
    note: str | None = None

    @property
    def arp_only(self) -> int:
        return self.found - self.answered


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Sweeper:
    def __init__(
        self,
        open_store: Callable[[], Store],
        pinger: Pinger,
        network: NetworkReader,
        lookup_name: Callable[[IPv4Address], str | None],
        *,
        workers: int = SWEEP_WORKERS,
        name_wait_s: float = NAME_WAIT_S,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = _utc_now,
        on_new_hosts: Callable[[Store, list[DiscoveredHost]], object] | None = None,
    ) -> None:
        """on_new_hosts gets the hosts a scheduled sweep had never seen before (plan section 41)."""
        self._open_store = open_store
        self._on_new_hosts = on_new_hosts
        self._pinger = pinger
        self._network = network
        self._lookup_name = lookup_name
        self._workers = workers
        self._name_wait_s = name_wait_s
        self._clock = clock
        self._now = now
        self._lock = threading.Lock()
        self._status = SweepStatus()
        self._thread: threading.Thread | None = None

    def status(self) -> SweepStatus:
        with self._lock:
            return self._status

    def start(self, target: SweepTarget, *, scheduled: bool = False) -> bool:
        """Start a sweep on its own thread. False, and nothing starts, if one is running.

        scheduled marks a sweep nobody is watching: it reports the hosts it had never seen.
        """
        with self._lock:
            if self._status.state == SweepState.RUNNING:
                return False
            self._status = SweepStatus(SweepState.RUNNING, target.network, total=len(target.addresses))
            self._thread = threading.Thread(
                target=self._run, args=(target, scheduled), name="netpulse-sweep", daemon=True
            )
        self._thread.start()
        return True

    def join(self, timeout: float | None = None) -> None:
        """Wait for the sweep thread. For tests and shutdown."""
        if self._thread is not None:
            self._thread.join(timeout)

    def run(self, target: SweepTarget, *, scheduled: bool = False) -> SweepStatus:
        """One sweep, on this thread. start() runs this on its own."""
        with self._lock:
            self._status = SweepStatus(SweepState.RUNNING, target.network, total=len(target.addresses))
        self._run(target, scheduled)
        return self.status()

    def _run(self, target: SweepTarget, scheduled: bool = False) -> None:
        started = self._clock()
        try:
            status = self._sweep(target, scheduled)
        except PingerUnavailable as exc:
            status = replace(self.status(), state=SweepState.FAILED, error=f"NetPulse cannot ping from this PC: {exc}")
        except Exception:
            log.exception("sweep of %s failed", target.network)
            status = replace(self.status(), state=SweepState.FAILED, error="The sweep stopped on an error; the log has the details.")
        status = replace(status, seconds=round(self._clock() - started, 1), finished_at=self._now())
        with self._lock:
            self._status = status

    def _sweep(self, target: SweepTarget, scheduled: bool = False) -> SweepStatus:
        names = Lookups(self._lookup_name)
        answered = self._ping_all(target.addresses, names)

        note = None
        try:
            neighbours = {
                n.address: n.mac
                for n in self._network.neighbours()
                if n.address in target.network and n.address not in target.own
                and n.address not in (target.network.network_address, target.network.broadcast_address)
            }
        except NetworkInfoUnavailable as exc:
            neighbours, note = {}, f"MAC addresses are missing: {exc}"

        addresses = sorted(set(answered) | set(neighbours))
        for address in addresses:
            names.start(address)  # the ARP-only hosts; the others started when they answered
        named = names.collect(self._name_wait_s, self._clock)
        found = [FoundHost(a, neighbours.get(a), named.get(a), a in answered) for a in addresses]
        store = self._open_store()
        try:
            new = store.record_sweep(found)
            if scheduled and new and self._on_new_hosts is not None:
                self._on_new_hosts(store, new)
        finally:
            store.close()
        return replace(
            self.status(), state=SweepState.DONE, found=len(found), answered=len(answered), note=note,
        )

    def _ping_all(self, addresses: list[IPv4Address], names: Lookups) -> set[IPv4Address]:
        """Ping every address once, many at a time, and start looking up the name of
        each one that answers. A fault on this PC stops the sweep."""
        answered: set[IPv4Address] = set()

        def probe(address: IPv4Address) -> None:
            result = self._pinger.ping(str(address))
            if result.success:
                names.start(address)
            with self._lock:
                if result.success:
                    answered.add(address)
                self._status = replace(self._status, pinged=self._status.pinged + 1)

        with ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="netpulse-probe") as pool:
            for future in [pool.submit(probe, a) for a in addresses]:
                future.result()  # re-raises PingerUnavailable
        return answered


class SweepSchedule:
    """Sweeps on a schedule (plan section 41). The check loop calls tick() between rounds.

    The settings name one subnet and how often. A sweep starts only when that
    subnet is still one of this PC's, and Windows does not mark its network
    Public: NetPulse never sweeps a network it was not told is the user's own.
    """

    def __init__(
        self,
        sweeper: Sweeper,
        open_store: Callable[[], Store],
        network: NetworkReader,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sweeper = sweeper
        self._open_store = open_store
        self._network = network
        self._clock = clock
        self._last: float | None = None

    def tick(self) -> bool:
        """Start a sweep if one is due. True when it started one."""
        store = self._open_store()
        try:
            every_min = store.setting(SCHEDULE_KEY, 0)
            wanted = store.setting(SCHEDULE_NETWORK_KEY)
        finally:
            store.close()
        if every_min not in SCHEDULES_MIN or not every_min or not wanted:
            return False
        now = self._clock()
        if self._last is not None and now - self._last < every_min * 60:
            return False
        try:
            targets = sweep_targets(self._network.read())
        except NetworkInfoUnavailable:
            return False
        target = next((t for t in targets if str(t.network) == wanted and not t.needs_confirmation), None)
        if target is None:
            return False
        if self._sweeper.start(target, scheduled=True):
            self._last = now
            return True
        return False
