"""The alert engine (plan section 41): opens and closes alerts, and sends the messages.

- After every check round it compares the alerts that are open with the ones
  the round's results call for (netpulse.alerts.wanted_device_alerts), opens
  what is missing and closes what has ended. It runs on the check loop's own
  thread with the round's Store, and a fault in it is logged, never raised:
  alerting must not stop monitoring.
- Messages go out on a thread of their own, so a mail server that takes ten
  seconds to refuse never delays a round. What was sent, and whether it got
  there, is kept for the alerts page.
- An alert that ends before its delay has passed is never mentioned, in either
  direction. With no channel configured nothing is sent and nothing is held back
  to be sent later.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

from netpulse.alerts import (
    MONITORING_SUBJECT,
    Alert,
    AlertKind,
    AlertRules,
    Channel,
    Message,
    Severity,
    Wanted,
    closed_message,
    opened_message,
    wanted_device_alerts,
)
from netpulse.diagnosis import diagnose
from netpulse.metrics import DeviceRow, device_rows, open_outages
from netpulse.netinfo import NetworkInfoUnavailable, NetworkReader
from netpulse.network import DiscoveredHost
from netpulse.notify import NotifyError, deliver
from netpulse.ping.result import Error
from netpulse.store import Store

log = logging.getLogger(__name__)

_STOP = object()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def lasted_words(seconds: float) -> str:
    """How long something lasted, for a message: 45 s, 12 min, 3 h 5 min, 2 d 4 h."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        rest = seconds // 60 % 60
        return f"{seconds // 3600} h {rest} min" if rest else f"{seconds // 3600} h"
    rest = seconds // 3600 % 24
    return f"{seconds // 86400} d {rest} h" if rest else f"{seconds // 86400} d"


class AlertEngine:
    def __init__(
        self,
        open_store: Callable[[], Store],
        *,
        send: Callable[[Channel, Message], None] = deliver,
        network: NetworkReader | None = None,
        now: Callable[[], datetime] = _utc_now,
        threaded: bool = True,
    ) -> None:
        """send delivers one message or raises NotifyError. network gives this PC's subnets
        and gateway to the diagnosis. threaded=False keeps messages queued until flush(): tests."""
        self._open_store = open_store
        self._send = send
        self._network = network
        self._now = now
        self._queue: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        if threaded:
            self._thread = threading.Thread(target=self._work, name="netpulse-notify", daemon=True)
            self._thread.start()

    # Called by the check loop

    def after_round(self, store: Store) -> None:
        """Bring the open alerts in line with the round just stored, then send what is due."""
        try:
            now = self._now()
            rules = store.alert_rules()
            rows = device_rows(store.live_device_statuses(), {}, store.recent_checks(), store.thresholds())
            wanted = {
                (w.kind, w.device_id): w
                for w in wanted_device_alerts(rows, open_outages(store.latest_events(1)), rules, Error.LABELS)
            }
            current = {(a.kind, a.device_id): a for a in store.open_alerts()}
            for key, want in wanted.items():
                if key not in current:
                    store.open_alert(want, now=now)
            for key, alert in current.items():
                # A round that finished means monitoring works again.
                if key not in wanted and (alert.device_id is not None or alert.kind == AlertKind.MONITORING):
                    store.close_alert(alert.id, now=now)
            self._notify(store, rules, rows, now)
        except Exception:
            log.exception("alerting failed after a check round; monitoring carries on")

    def round_failed(self, reason: str) -> None:
        """The check loop could not run a round: an alert about NetPulse itself."""
        try:
            store = self._open_store()
            try:
                rules = store.alert_rules()
                if rules.monitoring:
                    store.open_alert(Wanted(AlertKind.MONITORING, None, MONITORING_SUBJECT, reason), now=self._now())
                self._notify(store, rules, (), self._now())
            finally:
                store.close()
        except Exception:
            log.exception("alerting failed after a failed check round")

    def hosts_found(self, store: Store, hosts: Sequence[DiscoveredHost]) -> None:
        """A scheduled sweep found hosts it had never seen: one closed alert each, to read."""
        try:
            rules = store.alert_rules()
            if not rules.new_host:
                return
            now = self._now()
            for host in hosts:
                detail = " · ".join(part for part in (str(host.address), host.mac or "", "" if host.answers_ping else "ARP only") if part)
                store.open_alert(Wanted(AlertKind.NEW_HOST, None, host.name or str(host.address), detail), now=now, closed=True)
            self._notify(store, rules, (), now)
        except Exception:
            log.exception("alerting failed after a sweep")

    # Deciding what to send

    def _notify(self, store: Store, rules: AlertRules, rows: Sequence[DeviceRow], now: datetime) -> None:
        pending = store.alerts_to_notify()
        if not pending:
            return
        delay = timedelta(minutes=rules.delay_min)
        opened: list[Alert] = []
        closed: list[Alert] = []
        silent_open: list[int] = []
        silent_close: list[int] = []
        for alert in pending:
            is_state = alert.kind != AlertKind.NEW_HOST
            if not alert.notified_open:
                if alert.closed_at is not None and is_state:
                    silent_open.append(alert.id)  # over before anyone was told: say nothing of either end
                    silent_close.append(alert.id)
                elif not is_state or alert.kind == AlertKind.MONITORING or datetime.fromisoformat(alert.opened_at) <= now - delay:
                    opened.append(alert)
            elif alert.closed_at is not None:
                (closed if rules.recovery and is_state else silent_close).append(alert)

        channels = [channel for channel in store.channels() if channel.enabled]
        if channels and (opened or closed):
            hosts = {row.status.device.id: row.status.device.host for row in rows}
            findings = self._findings(store, rows) if any(a.kind == AlertKind.DEVICE_DOWN for a in opened) else ()
            for channel in channels:
                mine = [a for a in opened if channel.takes(a.severity)]
                for message in opened_message(
                    mine, hosts, with_addresses=channel.include_addresses, findings=findings, group_at=rules.group_at
                ):
                    self._queue.put((channel, message))
                for alert in closed:
                    if channel.takes(alert.severity):
                        lasted = (datetime.fromisoformat(alert.closed_at) - datetime.fromisoformat(alert.opened_at)).total_seconds()
                        self._queue.put((channel, closed_message(
                            alert, hosts, with_addresses=channel.include_addresses, lasted=lasted_words(lasted)
                        )))
        store.mark_notified([a.id for a in opened] + silent_open, opened=True)
        store.mark_notified(
            [a.id for a in closed] + silent_close + [a.id for a in opened if a.closed_at is not None], closed=True
        )

    def _findings(self, store: Store, rows: Sequence[DeviceRow]) -> tuple[str, ...]:
        info = None
        if self._network is not None:
            try:
                info = self._network.read()
            except NetworkInfoUnavailable:
                info = None
        groups = {group.id: group.name for group in store.groups()}
        return tuple(finding.text for finding in diagnose(rows, store.links(), info, groups)[:2])

    # Sending

    def send_test(self, channel: Channel) -> str | None:
        """Send a test message now, on this thread. Returns why it failed, or None."""
        message = Message(
            "Test message from NetPulse", ("If you can read this, the channel works.",), Severity.INFO, event="test"
        )
        try:
            self._send(channel, message)
        except NotifyError as exc:
            return str(exc)
        except Exception:
            log.exception("a test message through %s failed", channel.name)
            return "it stopped on an error; the NetPulse log has the details"
        return None

    def flush(self) -> int:
        """Deliver everything queued, on this thread. For tests and for stopping."""
        sent = 0
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                return sent
            if item is not _STOP:
                self._deliver(*item)
                sent += 1

    def stop(self, timeout: float | None = 5.0) -> None:
        if self._thread is not None:
            self._queue.put(_STOP)
            self._thread.join(timeout)

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                return
            self._deliver(*item)

    def _deliver(self, channel: Channel, message: Message) -> None:
        error = None
        try:
            self._send(channel, message)
        except NotifyError as exc:
            error = str(exc)
        except Exception:
            log.exception("a notification through %s failed", channel.name)
            error = "it stopped on an error; the NetPulse log has the details"
        if error is not None:
            log.warning("notification through %s was not delivered: %s", channel.name, error)
        try:
            store = self._open_store()
            try:
                store.record_notification(channel, message.title, error, now=self._now())
            finally:
                store.close()
        except Exception:
            log.exception("could not record a notification")
