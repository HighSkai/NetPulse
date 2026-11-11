"""Path tracing (plan section 30): where a route slows down or loses packets.

- Echoes with a set time-to-live, through IcmpSendEcho (decision 004). A
  router that drops one for running out of hops answers from its own address:
  that is the hop. An answer from the target ends the trace. No Administrator
  rights, and no tracert.exe output to parse.
- Fast: every hop count from 1 to 30 is probed at once, three echoes each,
  so a round takes about one timeout. Repeat mode runs more rounds, as MTR does.
- Each hop gets its loss, best, average and worst time, a label (this network,
  the provider, beyond), a name looked up at once and capped at 0.5 s, and a
  note where the numbers point at a slow link or at a router that only
  answers some probes.
- One trace at a time, on its own thread; tests drive it with a fake ICMP API.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Protocol

from netpulse.domain import Hop, HopLabel, Trace
from netpulse.netinfo import NetworkInfoUnavailable, NetworkReader
from netpulse.netinfo.names import Lookups
from netpulse.ping.result import PingerUnavailable
from netpulse.store import Store

log = logging.getLogger(__name__)

MAX_HOPS = 30
PROBES_PER_HOP = 3
TIMEOUT_MS = 1000
NAME_WAIT_S = 0.5
ROUNDS = (1, 5, 10)  # single, and the repeat modes offered

IP_SUCCESS = 0
# A router's answers: the hop limit ran out, or it could not reach further.
ROUTER_ANSWERS = {11013, 11014, 11002, 11003, 11004, 11005}

# A jump this big, that stays high after, marks the likely slow link.
JUMP_MS = 20
JUMP_SHARE = 0.5
STAYS_HIGH = 0.8


class EchoApi(Protocol):
    def echo_with_ttl(self, address: IPv4Address, ttl: int, timeout_ms: int) -> tuple[int, int, IPv4Address | None]: ...


class TraceState:
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass(frozen=True)
class TraceStatus:
    state: str = TraceState.IDLE
    target: str = ""
    round: int = 0  # rounds finished
    rounds: int = 0
    trace_id: int | None = None
    error: str | None = None


@dataclass(frozen=True)
class Probe:
    ttl: int
    status: int
    rtt_ms: int
    responder: IPv4Address | None

    @property
    def answered(self) -> bool:
        return self.responder is not None and (self.status == IP_SUCCESS or self.status in ROUTER_ANSWERS)


# Pure: probes into hops, labels and notes


def hops_from(probes: Iterable[Probe], target: IPv4Address) -> tuple[list[Hop], bool]:
    """Each hop count's answers over every round, up to the target. (hops, whether the target answered).

    The path ends at the first hop count the target answered at. Without an
    answer from it, the path ends at the last hop count anything answered.
    """
    by_ttl: dict[int, list[Probe]] = {}
    for probe in probes:
        by_ttl.setdefault(probe.ttl, []).append(probe)
    reached_at = min(
        (ttl for ttl, ps in by_ttl.items() if any(p.status == IP_SUCCESS and p.responder == target for p in ps)),
        default=None,
    )
    last = reached_at if reached_at is not None else max(
        (ttl for ttl, ps in by_ttl.items() if any(p.answered for p in ps)), default=0
    )
    hops = []
    for ttl in range(1, last + 1):
        probes_here = by_ttl.get(ttl, [])
        answers = [p for p in probes_here if p.answered]
        seen = Counter(str(p.responder) for p in answers)
        ranked = [address for address, _ in seen.most_common()]
        rtts = [p.rtt_ms for p in answers]
        hops.append(
            Hop(
                ttl=ttl,
                address=ranked[0] if ranked else None,
                sent=len(probes_here),
                received=len(answers),
                best_ms=min(rtts) if rtts else None,
                avg_ms=round(sum(rtts) / len(rtts), 1) if rtts else None,
                worst_ms=max(rtts) if rtts else None,
                others=tuple(ranked[1:]),
            )
        )
    return hops, reached_at is not None


def label_hops(hops: Sequence[Hop], local: Iterable[IPv4Network], gateway: IPv4Address | None) -> list[Hop]:
    """This network, the provider, or beyond (plan section 30).

    This network: an address in one of this PC's subnets, or the gateway. The
    provider: the first public address, and any private ones on the way to it.
    Beyond: everything after the first public address.
    """
    local = list(local)
    labelled, public_seen = [], False
    for hop in hops:
        if hop.address is None:
            labelled.append(hop)
            continue
        address = IPv4Address(hop.address)
        if public_seen:
            label = HopLabel.BEYOND
        elif address == gateway or any(address in network for network in local):
            label = HopLabel.THIS_NETWORK
        else:
            label = HopLabel.PROVIDER
            public_seen = address.is_global
        labelled.append(replace(hop, label=label))
    return labelled


def annotate(hops: Sequence[Hop]) -> list[Hop]:
    """Notes where the numbers say something (plan section 30).

    - Loss that does not carry on to later hops is a router that answers only
      some probes, which many do on purpose. Loss that carries on to the end is loss.
    - The hop where the average jumps, and stays high after, is the likely slow link.
    """
    notes: dict[int, str] = {}
    for i, hop in enumerate(hops):
        if hop.received == 0 or hop.received == hop.sent:
            continue
        later = [h for h in hops[i + 1 :] if h.sent]
        if later and min(h.loss_percent for h in later) < hop.loss_percent:
            notes[hop.ttl] = "answers only some probes: the router limits its replies, not loss"
        else:
            notes[hop.ttl] = "loss from here to the end of the path"
    slow = slow_link(hops)
    if slow is not None:
        jump = "latency jumps here and stays high after: the likely slow link"
        notes[slow] = f"{notes[slow]}; {jump}" if slow in notes else jump
    return [replace(hop, note=notes.get(hop.ttl)) for hop in hops]


def slow_link(hops: Sequence[Hop]) -> int | None:
    """The hop count where the average jumps the most and stays high after, or None."""
    answering = [h for h in hops if h.avg_ms is not None]
    best: tuple[float, int] | None = None
    for before, hop in zip(answering, answering[1:], strict=False):
        jump = hop.avg_ms - before.avg_ms
        if jump < max(JUMP_MS, JUMP_SHARE * before.avg_ms):
            continue
        after = [h.avg_ms for h in answering if h.ttl > hop.ttl]
        if all(avg >= STAYS_HIGH * hop.avg_ms for avg in after) and (best is None or jump > best[0]):
            best = (jump, hop.ttl)
    return None if best is None else best[1]


# Running traces


def _utc_now() -> datetime:
    return datetime.now(UTC)


class Tracer:
    def __init__(
        self,
        open_store: Callable[[], Store],
        api: EchoApi,
        resolve: Callable[[str], IPv4Address],
        lookup_name: Callable[[IPv4Address], str | None],
        *,
        network: NetworkReader | None = None,
        workers: int = MAX_HOPS * PROBES_PER_HOP,
        timeout_ms: int = TIMEOUT_MS,
        name_wait_s: float = NAME_WAIT_S,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = _utc_now,
    ) -> None:
        """resolve turns what the user typed into an address, or raises ValueError
        with a message to show. network gives this PC's subnets and gateway, for the labels."""
        self._open_store = open_store
        self._api = api
        self._resolve = resolve
        self._lookup_name = lookup_name
        self._network = network
        self._workers = workers
        self._timeout_ms = timeout_ms
        self._name_wait_s = name_wait_s
        self._clock = clock
        self._now = now
        self._lock = threading.Lock()
        self._status = TraceStatus()
        self._thread: threading.Thread | None = None

    def status(self) -> TraceStatus:
        with self._lock:
            return self._status

    def start(self, target: str, rounds: int = 1) -> bool:
        """Trace on its own thread. False, and nothing starts, if a trace is running."""
        if rounds not in ROUNDS:
            raise ValueError(f"rounds is one of {', '.join(map(str, ROUNDS))}")
        with self._lock:
            if self._status.state == TraceState.RUNNING:
                return False
            self._status = TraceStatus(TraceState.RUNNING, target, 0, rounds)
            self._thread = threading.Thread(target=self._run, args=(target, rounds), name="netpulse-trace", daemon=True)
        self._thread.start()
        return True

    def run(self, target: str, rounds: int = 1) -> TraceStatus:
        """One trace on this thread. start() runs this on its own."""
        with self._lock:
            self._status = TraceStatus(TraceState.RUNNING, target, 0, rounds)
        self._run(target, rounds)
        return self.status()

    def join(self, timeout: float | None = None) -> None:
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self, target: str, rounds: int) -> None:
        try:
            trace = self._trace(target.strip(), rounds)
            state, error = TraceState.DONE, None
        except ValueError as exc:  # what the user typed: not a host, or no such name
            trace, state, error = None, TraceState.FAILED, str(exc)
        except PingerUnavailable as exc:
            trace, state, error = None, TraceState.FAILED, f"NetPulse cannot send echoes from this PC: {exc}"
        except Exception:
            log.exception("the trace to %s failed", target)
            trace, state, error = None, TraceState.FAILED, "The trace stopped on an error; the NetPulse log has the details."
        with self._lock:
            self._status = replace(
                self._status, state=state, error=error, trace_id=None if trace is None else trace.id,
            )

    def _trace(self, target: str, rounds: int) -> Trace:
        address = self._resolve(target)
        started = self._now()
        names = Lookups(self._lookup_name)
        probes: list[Probe] = []
        for done in range(rounds):
            probes += self._round(address, names)
            with self._lock:
                self._status = replace(self._status, round=done + 1)
        hops, reached = hops_from(probes, address)
        local, gateway = self._this_network()
        named = names.collect(self._name_wait_s, self._clock)
        hops = [replace(h, name=named.get(IPv4Address(h.address))) if h.address else h for h in hops]
        hops = annotate(label_hops(hops, local, gateway))
        error = None if reached else f"{address} did not answer within {len(hops) or MAX_HOPS} hops"
        store = self._open_store()
        try:
            return store.save_trace(
                target, str(address), rounds, reached, hops, error,
                now=started.astimezone(UTC).replace(microsecond=0).isoformat(),
            )
        finally:
            store.close()

    def _round(self, address: IPv4Address, names: Lookups) -> list[Probe]:
        """Every hop count, PROBES_PER_HOP echoes each, all at once."""

        def probe(ttl: int) -> Probe:
            status, rtt, responder = self._api.echo_with_ttl(address, ttl, self._timeout_ms)
            if responder is not None:
                names.start(responder)
            return Probe(ttl, status, rtt, responder)

        ttls = [ttl for ttl in range(1, MAX_HOPS + 1) for _ in range(PROBES_PER_HOP)]
        with ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="netpulse-hop") as pool:
            return list(pool.map(probe, ttls))  # re-raises PingerUnavailable

    def _this_network(self) -> tuple[list[IPv4Network], IPv4Address | None]:
        if self._network is None:
            return [], None
        try:
            info = self._network.read()
        except NetworkInfoUnavailable:
            return [], None
        return [s for a in info.adapters for s in a.subnets], info.preferred_gateway
