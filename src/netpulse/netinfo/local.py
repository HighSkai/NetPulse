"""This PC's name and IPv4 addresses, asked of the operating system directly (plan section 38).

The network page reads far more through PowerShell, which takes half a
second. The server only needs to know which addresses it can listen on and
which names it answers to, and needs that at startup, so it asks the resolver.
The offline test guard blocks the lookup.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from collections.abc import Iterable

# A name the access page shows is looked up while the page waits, so not for long.
NAME_WAIT_S = 1.5


def computer_name() -> str:
    """This PC's host name, or "localhost" if it has none."""
    try:
        return socket.gethostname() or "localhost"
    except OSError:
        return "localhost"


def local_ipv4_addresses() -> tuple[str, ...]:
    """This PC's IPv4 addresses, without loopback, in the order the system gives them."""
    try:
        found = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        return ()
    addresses = dict.fromkeys(entry[4][0] for entry in found)
    return tuple(a for a in addresses if not ipaddress.ip_address(a).is_loopback)


def resolve_names(names: Iterable[str], wait_s: float = NAME_WAIT_S) -> dict[str, tuple[str, ...] | None]:
    """Each name's IPv4 addresses, as this PC's resolver answers: () when the name does not
    exist, None when the lookup did not answer within wait_s. All looked up at once."""
    names = list(dict.fromkeys(names))
    found: dict[str, tuple[str, ...]] = {}
    lock = threading.Lock()

    def look(name: str) -> None:
        try:
            answer = tuple(dict.fromkeys(entry[4][0] for entry in socket.getaddrinfo(name, None, socket.AF_INET)))
        except (OSError, UnicodeError):
            answer = ()
        with lock:
            found[name] = answer

    threads = [threading.Thread(target=look, args=(name,), name="netpulse-name", daemon=True) for name in names]
    deadline = time.monotonic() + wait_s
    for thread in threads:
        thread.start()
    for thread in threads:  # one deadline for all of them, not wait_s each
        thread.join(max(0.0, deadline - time.monotonic()))
    with lock:
        return {name: found.get(name) for name in names}
