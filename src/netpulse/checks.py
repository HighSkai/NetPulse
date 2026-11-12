"""Checking devices (plan sections 6 and 40).

- run_check checks one device now and stores the result: the Check now button.
- run_round checks every device that is due, many at once, and stores the
  round in one transaction. A hundred devices of which twenty are down take
  about as long as one timeout, not twenty.
- A device is checked by ping, or by a TCP connection to one port when the
  user chose that for a device that ignores ping.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from netpulse.domain import CheckKind, Device
from netpulse.ping.result import Pinger, PingResult
from netpulse.store import Store, utc_now

# Plan section 6: the loop runs a round this often, in seconds, and the
# dashboard re-reads results this often. A device's own interval is a multiple.
CHECK_INTERVAL_S = 30
# Checks in flight at once. Each is a thread waiting on Windows, which costs
# almost nothing; the limit keeps a large inventory from bursting onto a small router.
CHECK_WORKERS = 32


class TcpProbe(Protocol):
    def check(self, host: str, port: int) -> PingResult: ...


class DeviceDeleted(Exception):
    pass


def probe(device: Device, pinger: Pinger, tcp: TcpProbe | None = None) -> PingResult:
    """One check of one device, the way the device is set to be checked."""
    if device.check_kind == CheckKind.TCP and tcp is not None and device.check_port is not None:
        return tcp.check(device.host, device.check_port)
    return pinger.ping(device.host)


def run_check(
    store: Store,
    pinger: Pinger,
    device_id: int,
    *,
    now: str | None = None,
    tcp: TcpProbe | None = None,
) -> PingResult:
    """Check one device and persist the result. Check now, whatever the device's interval.

    PingerUnavailable (a fault on this PC) propagates before anything is stored.
    """
    device: Device = store.get_device(device_id)
    if not device.is_live:
        raise DeviceDeleted(f"device {device_id} is deleted")
    result = probe(device, pinger, tcp)
    store.insert_result(device_id, result, now=now)
    return result


def run_round(
    store: Store,
    pinger: Pinger,
    *,
    now: str | None = None,
    tcp: TcpProbe | None = None,
    workers: int = CHECK_WORKERS,
    tick: int = 0,
) -> list[tuple[int, PingResult]]:
    """Check every device that is due, up to `workers` at once. Used by the scheduler.

    tick counts the loop's rounds: a device on a longer interval is due every
    so many of them. Every result carries the time the round started, so a
    device's checks sit on the loop's 30 s grid however long its neighbours
    took to time out. A device deleted while the round runs is not stored.
    PingerUnavailable stops the round and stores nothing: the same fault would
    hit every device.
    """
    started = now or utc_now()
    devices = store.due_devices(tick, CHECK_INTERVAL_S)
    if not devices:
        return []
    if workers <= 1 or len(devices) == 1:
        results = [probe(device, pinger, tcp) for device in devices]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(devices)), thread_name_prefix="netpulse-check") as pool:
            results = list(pool.map(lambda device: probe(device, pinger, tcp), devices))  # re-raises PingerUnavailable
    out = [(device.id, result) for device, result in zip(devices, results, strict=True)]
    stored = set(store.insert_results(out, now=started))
    return [(device_id, result) for device_id, result in out if device_id in stored]
