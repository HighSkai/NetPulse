"""Email notifications (plan section 41), by Python's standard SMTP client.

STARTTLS or TLS with the system's trust store. A password is never sent over
a connection that is not encrypted: the channel's settings refuse that
combination before anything is stored.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

from netpulse.alerts import Channel, Message
from netpulse.notify.errors import NotifyError

TIMEOUT_S = 15


def _one_line(text: str) -> str:
    """A header value: a device's name is typed by someone, so no line breaks get through."""
    return " ".join(text.split())[:200]


def build(channel: Channel, message: Message) -> EmailMessage:
    config = channel.config
    mail = EmailMessage()
    mail["Subject"] = _one_line(f"[NetPulse] {message.title}")
    mail["From"] = config["sender"]
    mail["To"] = ", ".join(config["to"])
    mail.set_content(message.text + "\n\nSent by NetPulse.\n")
    return mail


def _connect(config) -> smtplib.SMTP:
    """The real connection. The offline test guard blocks its socket."""
    context = ssl.create_default_context()
    if config["security"] == "tls":
        return smtplib.SMTP_SSL(config["host"], config["port"], timeout=TIMEOUT_S, context=context)
    server = smtplib.SMTP(config["host"], config["port"], timeout=TIMEOUT_S)
    if config["security"] == "starttls":
        server.starttls(context=context)
    return server


def send_email(channel: Channel, message: Message) -> None:
    config = channel.config
    mail = build(channel, message)
    try:
        server = _connect(config)
        try:
            if config.get("username"):
                server.login(config["username"], config.get("password", ""))
            server.send_message(mail)
        finally:
            try:
                server.quit()
            except (OSError, smtplib.SMTPException):
                pass
    except smtplib.SMTPAuthenticationError:
        raise NotifyError(f"{config['host']} refused the username or password") from None
    except (OSError, smtplib.SMTPException, ssl.SSLError) as exc:
        raise NotifyError(f"could not send through {config['host']}: {type(exc).__name__}") from None
