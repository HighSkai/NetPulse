from __future__ import annotations

from netpulse.domain import Device
from netpulse.ping.result import Pinger, PingResult
from netpulse.store import Store

# Plan section 6: one interval for every device, in seconds. The scheduler
# runs a round this often and the dashboard re-reads results this often.
CHECK_INTERVAL_S = 30


class DeviceDeleted(Exception):
    pass


def run_check(
    store: Store,
    pinger: Pinger,
    device_id: int,
    *,
    now: str | None = None,
) -> PingResult:
    """Ping one device and persist the result. Shared by the scheduler and Check now.

    PingerUnavailable (a fault on this PC) propagates before anything is stored.
    """
    device: Device = store.get_device(device_id)
    if not device.is_live:
        raise DeviceDeleted(f"device {device_id} is deleted")
    result = pinger.ping(device.host)
    store.insert_result(device_id, result, now=now)
    return result


def run_round(store: Store, pinger: Pinger, *, now: str | None = None) -> list[tuple[int, PingResult]]:
    """Check every live device, one at a time. Used by the scheduler.

    A device deleted while the round is running is skipped, not pinged.
    PingerUnavailable stops the round: the same fault would hit every device.
    """
    out: list[tuple[int, PingResult]] = []
    for device in store.list_live_devices():
        try:
            result = run_check(store, pinger, device.id, now=now)
        except DeviceDeleted:
            continue
        out.append((device.id, result))
    return out
