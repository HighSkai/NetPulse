"""Webhook notifications (plan section 41): one JSON POST, by Python's standard HTTP client.

- HTTPS certificates are verified with the system's trust store.
- Redirects are not followed, and the answer's body is not read beyond a few
  bytes: nothing an answer says is shown or kept, only its status.
- A Discord message never pings anyone: mentions are switched off, because a
  device's name is text someone typed.
"""

from __future__ import annotations

import http.client
import json
from urllib.parse import urlsplit

from netpulse import __version__
from netpulse.alerts import Channel, Message
from netpulse.notify.errors import NotifyError

TIMEOUT_S = 10
USER_AGENT = f"NetPulse/{__version__} (network monitor)"
DISCORD_LIMIT = 1900  # Discord refuses content over 2000 characters


def _connection(scheme: str, host: str, port: int | None) -> http.client.HTTPConnection:
    """The real connection. tests/conftest.py blocks this, so no test sends anything."""
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=TIMEOUT_S)
    return http.client.HTTPConnection(host, port, timeout=TIMEOUT_S)


def post_json(url: str, payload: dict) -> int:
    """POST the payload as JSON and return the status. Raises NotifyError when it could not be sent or was refused."""
    parts = urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    body = json.dumps(payload).encode("utf-8")
    try:
        connection = _connection(parts.scheme, parts.hostname or "", parts.port)
    except (OSError, ValueError) as exc:
        raise NotifyError(f"could not connect to {parts.hostname}: {type(exc).__name__}") from None
    try:
        connection.request("POST", path, body, {"Content-Type": "application/json", "User-Agent": USER_AGENT})
        response = connection.getresponse()
        response.read(256)
    except (OSError, http.client.HTTPException) as exc:
        # The exception's own words can hold the address; its kind is enough.
        raise NotifyError(f"could not reach {parts.hostname}: {type(exc).__name__}") from None
    finally:
        connection.close()
    if not 200 <= response.status < 300:
        raise NotifyError(f"{parts.hostname} answered HTTP {response.status}")
    return response.status


def send_webhook(channel: Channel, message: Message) -> None:
    post_json(channel.config["url"], message.payload())


def send_discord(channel: Channel, message: Message) -> None:
    text = f"**{message.title}**" + "".join(f"\n{line}" for line in message.lines)
    post_json(channel.config["url"], {"content": text[:DISCORD_LIMIT], "allowed_mentions": {"parse": []}})
