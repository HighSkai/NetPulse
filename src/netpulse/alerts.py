"""Alerts and notification channels (plan section 41): values and rules.

No SQL, no network, no Flask. netpulse.alerting opens and closes alerts after
each check round and sends the messages; this module decides which alerts the
current state calls for, and what a message says.

- An alert is opened by a state and closed when the state ends: a device's
  outage, a device staying degraded, the check loop failing. A newly found
  host is an alert that is closed as it opens: something to read, not a state.
- An outage needs two failed checks in a row (plan section 15), so one dropped
  echo never alerts anyone.
- A paused device, or one whose alerts are muted, never alerts.
- A message says what NetPulse measured. A likely cause is offered as that:
  likely, with the evidence for it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from netpulse.domain import DeviceEvent, DeviceState, ValidationError
from netpulse.metrics import DeviceRow


class AlertKind:
    DEVICE_DOWN = "device_down"
    DEVICE_DEGRADED = "device_degraded"
    NEW_HOST = "new_host"
    MONITORING = "monitoring"

    LABELS = {
        DEVICE_DOWN: "Device down", DEVICE_DEGRADED: "Device degraded", NEW_HOST: "New device found",
        MONITORING: "Monitoring failing",
    }


class Severity:
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    ALL = (INFO, WARNING, CRITICAL)
    RANK = {INFO: 0, WARNING: 1, CRITICAL: 2}
    LABELS = {INFO: "Info", WARNING: "Warning", CRITICAL: "Critical"}


SEVERITY_OF = {
    AlertKind.DEVICE_DOWN: Severity.CRITICAL,
    AlertKind.DEVICE_DEGRADED: Severity.WARNING,
    AlertKind.NEW_HOST: Severity.INFO,
    AlertKind.MONITORING: Severity.CRITICAL,
}

MONITORING_SUBJECT = "NetPulse monitoring"
DELAYS_MIN = (0, 2, 5, 10, 30)


@dataclass(frozen=True)
class Alert:
    id: int
    kind: str
    severity: str
    device_id: int | None
    subject: str  # the device's name when it opened, or what else it is about
    detail: str
    opened_at: str
    closed_at: str | None = None
    acked_at: str | None = None
    acked_by: str | None = None
    notified_open: bool = False
    notified_close: bool = False

    @property
    def open(self) -> bool:
        return self.closed_at is None

    @property
    def acked(self) -> bool:
        return self.acked_at is not None

    @property
    def label(self) -> str:
        return AlertKind.LABELS[self.kind]


@dataclass(frozen=True)
class AlertRules:
    """What alerts, and when a message goes out. The defaults are quiet on purpose."""

    down: bool = True
    degraded: bool = False
    new_host: bool = True
    monitoring: bool = True
    recovery: bool = True  # say when an alert that was notified has ended
    delay_min: int = 0  # notify only if the alert is still open after this long
    group_at: int = 3  # this many alerts opening together go out as one message

    @classmethod
    def of(cls, values: Mapping) -> AlertRules:
        """From stored JSON or form values; anything missing or odd takes its default."""
        defaults = cls()

        def flag(name: str) -> bool:
            value = values.get(name, getattr(defaults, name))
            return value if isinstance(value, bool) else str(value).lower() in ("1", "yes", "true", "on")

        def number(name: str, allowed: Iterable[int]) -> int:
            try:
                value = int(values.get(name, getattr(defaults, name)))
            except (TypeError, ValueError):
                return getattr(defaults, name)
            return value if value in allowed else getattr(defaults, name)

        return cls(
            down=flag("down"), degraded=flag("degraded"), new_host=flag("new_host"), monitoring=flag("monitoring"),
            recovery=flag("recovery"), delay_min=number("delay_min", DELAYS_MIN), group_at=number("group_at", range(2, 21)),
        )

    def enabled(self, kind: str) -> bool:
        return {
            AlertKind.DEVICE_DOWN: self.down, AlertKind.DEVICE_DEGRADED: self.degraded,
            AlertKind.NEW_HOST: self.new_host, AlertKind.MONITORING: self.monitoring,
        }[kind]


@dataclass(frozen=True)
class Wanted:
    """An alert the current state calls for."""

    kind: str
    device_id: int | None
    subject: str
    detail: str

    @property
    def severity(self) -> str:
        return SEVERITY_OF[self.kind]


def wanted_device_alerts(
    rows: Iterable[DeviceRow], open_outages: Mapping[int, DeviceEvent], rules: AlertRules, error_labels: Mapping[str, str]
) -> list[Wanted]:
    """The device alerts that should be open now, from the dashboard's own rows.

    Down means an outage is going on: the debounced event, not one failed check.
    """
    wanted = []
    for row in rows:
        device = row.status.device
        if device.paused or device.alerts_muted:
            continue
        outage = open_outages.get(device.id)
        if outage is not None and row.state == DeviceState.DOWN:
            if rules.down:
                reason = error_labels.get(outage.error or "", outage.error or "no answer")
                wanted.append(Wanted(AlertKind.DEVICE_DOWN, device.id, device.name, f"{device.check_label}: {reason}"))
        elif row.state == DeviceState.DEGRADED and rules.degraded:
            parts = []
            if "slow" in row.degraded_by:
                parts.append(f"average {row.recent.avg_ms:g} ms")
            if "failing" in row.degraded_by:
                parts.append(f"{row.recent.failures} of {row.recent.checks} checks failed")
            wanted.append(Wanted(AlertKind.DEVICE_DEGRADED, device.id, device.name, ", ".join(parts)))
    return wanted


# Channels


class ChannelKind:
    WEBHOOK = "webhook"
    DISCORD = "discord"
    EMAIL = "email"

    ALL = (WEBHOOK, DISCORD, EMAIL)
    LABELS = {WEBHOOK: "Webhook (JSON POST)", DISCORD: "Discord webhook", EMAIL: "Email (SMTP)"}


SMTP_SECURITY = ("starttls", "tls", "none")
_DISCORD_HOSTS = ("discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com")
_EMAIL = re.compile(r"[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+\Z")
_HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")


@dataclass(frozen=True)
class Channel:
    id: int
    name: str
    kind: str
    config: Mapping = field(default_factory=dict)
    enabled: bool = True
    min_severity: str = Severity.WARNING
    created_at: str = ""

    def takes(self, severity: str) -> bool:
        return self.enabled and Severity.RANK[severity] >= Severity.RANK[self.min_severity]

    @property
    def include_addresses(self) -> bool:
        return bool(self.config.get("include_addresses"))

    @property
    def destination(self) -> str:
        """Where it sends, without the secret part: a webhook's address is itself a password."""
        if self.kind == ChannelKind.EMAIL:
            return f"{', '.join(self.config.get('to', []))} through {self.config.get('host', '')}"
        parts = urlsplit(self.config.get("url", ""))
        return f"{parts.scheme}://{parts.netloc}/…"


def validate_channel(kind: str | None, values: Mapping, *, existing: Mapping | None = None) -> dict:
    """A channel's config from form values, or ValidationError naming the field.

    existing is the stored config when editing: a secret left empty keeps its value.
    """
    existing = existing or {}
    include = str(values.get("include_addresses", "")).lower() in ("1", "yes", "true", "on")
    if kind in (ChannelKind.WEBHOOK, ChannelKind.DISCORD):
        url = (values.get("url") or "").strip() or existing.get("url", "")
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
            raise ValidationError("url must be an http or https address")
        if len(url) > 500 or any(ch.isspace() for ch in url):
            raise ValidationError("url must be at most 500 characters, with no spaces")
        if kind == ChannelKind.DISCORD and (parts.scheme != "https" or parts.hostname not in _DISCORD_HOSTS
                                           or not parts.path.startswith("/api/webhooks/")):
            raise ValidationError("url must be a Discord webhook address: https://discord.com/api/webhooks/…")
        return {"url": url, "include_addresses": include}
    if kind == ChannelKind.EMAIL:
        host = (values.get("host") or "").strip()
        if not _HOSTNAME.match(host):
            raise ValidationError("host must be the mail server's name or address")
        port = str(values.get("port") or "587").strip()
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValidationError("port must be a number from 1 to 65535")
        security = (values.get("security") or "starttls").strip()
        if security not in SMTP_SECURITY:
            raise ValidationError("security must be STARTTLS, TLS or none")
        sender = (values.get("sender") or "").strip()
        if not _EMAIL.match(sender):
            raise ValidationError("sender must be an email address")
        to = [part.strip() for part in re.split(r"[,;\s]+", values.get("to") or "") if part.strip()]
        if not to or len(to) > 10 or not all(_EMAIL.match(address) for address in to):
            raise ValidationError("recipients must be one to ten email addresses")
        username = (values.get("username") or "").strip()
        password = values.get("password") or existing.get("password", "")
        if len(username) > 200 or len(password) > 500:
            raise ValidationError("username or password is too long")
        if security == "none" and password:
            raise ValidationError("security: a password is never sent without TLS; choose STARTTLS or TLS")
        return {
            "host": host, "port": int(port), "security": security, "sender": sender, "to": to,
            "username": username, "password": password, "include_addresses": include,
        }
    raise ValidationError("kind must be webhook, Discord or email")


# Messages


@dataclass(frozen=True)
class Message:
    """What one notification says. Every channel sends the same words its own way."""

    title: str
    lines: tuple[str, ...] = ()
    severity: str = Severity.INFO
    event: str = "opened"  # opened, closed or test

    @property
    def text(self) -> str:
        return "\n".join((self.title, *self.lines))

    def payload(self) -> dict:
        """The generic webhook's JSON body."""
        return {
            "source": "netpulse", "event": self.event, "severity": self.severity, "title": self.title,
            "lines": list(self.lines), "text": self.text,
        }


def _named(alert: Alert, hosts: Mapping[int, str], with_addresses: bool) -> str:
    host = hosts.get(alert.device_id) if alert.device_id is not None else None
    return f"{alert.subject} ({host})" if with_addresses and host and host != alert.subject else alert.subject


def opened_message(
    alerts: Sequence[Alert], hosts: Mapping[int, str], *, with_addresses: bool, findings: Sequence[str] = (),
    group_at: int = 3,
) -> list[Message]:
    """The messages for alerts that just became due: one each, or one for all when many open together."""
    if not alerts:
        return []
    worst = max((a.severity for a in alerts), key=Severity.RANK.__getitem__)
    hints = tuple(f"Likely cause: {finding}" for finding in findings)
    if len(alerts) >= group_at:
        names = [_named(a, hosts, with_addresses) for a in alerts]
        shown = names[:10] + ([f"and {len(names) - 10} more"] if len(names) > 10 else [])
        return [Message(f"{len(alerts)} alerts opened together", (*shown, *hints), worst)]
    return [
        Message(
            f"{alert.label}: {_named(alert, hosts, with_addresses)}",
            tuple(part for part in (alert.detail if with_addresses or alert.kind != AlertKind.NEW_HOST else "", *hints) if part),
            alert.severity,
        )
        for alert in alerts
    ]


def closed_message(alert: Alert, hosts: Mapping[int, str], *, with_addresses: bool, lasted: str) -> Message:
    return Message(
        f"Recovered: {_named(alert, hosts, with_addresses)}", (f"{alert.label} ended after {lasted}",),
        Severity.INFO, event="closed",
    )
