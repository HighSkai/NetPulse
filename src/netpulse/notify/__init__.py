"""Sending notifications (plan section 41): a webhook, Discord, or email.

Each sender takes a channel and a message and either delivers it or raises
NotifyError with a reason that is safe to show and to store: a webhook's
address is a secret, so it never appears in one.

These are the only modules, with the Globalping client, that open a
connection to somewhere the user configured. They send only when an
administrator has added a channel, and only the message's words.
"""

from __future__ import annotations

from netpulse.alerts import Channel, ChannelKind, Message
from netpulse.notify.errors import NotifyError
from netpulse.notify.mail import send_email
from netpulse.notify.webhook import send_discord, send_webhook

SENDERS = {ChannelKind.WEBHOOK: send_webhook, ChannelKind.DISCORD: send_discord, ChannelKind.EMAIL: send_email}


def deliver(channel: Channel, message: Message) -> None:
    """Send one message through one channel. Raises NotifyError."""
    SENDERS[channel.kind](channel, message)


__all__ = ["SENDERS", "NotifyError", "deliver"]
