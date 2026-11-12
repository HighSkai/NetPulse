"""Who can reach NetPulse over the network, and how (plan section 38).

Out of the box NetPulse listens on 127.0.0.1 only, and it stays that way until
the first administrator exists and turns network access on. This module holds
the settings for that, the rules they must pass, and the facts the server and
the pages share:

- AccessSettings: on or off, which of this PC's addresses to listen on, the
  port, whether to use HTTPS and with which certificate, and extra names.
- listen_plan: the addresses those settings mean, given the addresses this PC
  has right now. An address the PC no longer has is left out, never guessed.
- allowed_host: which Host headers are answered. A page on another site that
  points its own name at this PC (DNS rebinding) is refused, signed in or not.
- AccessControl: what is really listening, as the server last reported it,
  and the way a page asks the server to apply new settings.

No sockets and no certificates are opened here; netpulse.server does that.
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from netpulse.crypto.tls import LOCAL_NETWORKS, CertificateInfo, TlsError, check_pair
from netpulse.domain import ValidationError
from netpulse.ping.hosts import InvalidHost, validate_host
from netpulse.store import Store

DEFAULT_PORT = 5000
LOOPBACK = "127.0.0.1"
ALL_INTERFACES = "all"
MAX_NAMES = 5


class Tls:
    OFF = "off"  # plain HTTP
    LOCAL = "local"  # HTTPS with a certificate from NetPulse's own authority
    CUSTOM = "custom"  # HTTPS with a certificate and key the user supplies

    ALL = (OFF, LOCAL, CUSTOM)


@dataclass(frozen=True)
class AccessSettings:
    lan: bool = False
    bind: str = ALL_INTERFACES  # ALL_INTERFACES, or one of this PC's IPv4 addresses
    port: int = DEFAULT_PORT
    tls: str = Tls.LOCAL
    cert_path: str = ""
    key_path: str = ""
    names: tuple[str, ...] = ()  # extra host names this NetPulse answers to

    @property
    def https(self) -> bool:
        """HTTPS is only ever used together with network access: this PC talking to itself needs none."""
        return self.lan and self.tls != Tls.OFF

    @property
    def scheme(self) -> str:
        return "https" if self.https else "http"


_KEYS = ("lan", "bind", "port", "tls", "cert_path", "key_path", "names")


def load_settings(store: Store) -> AccessSettings:
    """The stored settings; anything missing, or no longer valid, takes its default."""
    stored = {key.removeprefix("server."): value for key, value in store.settings_under("server.").items()}
    defaults = AccessSettings()
    port = stored.get("port")
    tls = stored.get("tls")
    names = stored.get("names")
    return AccessSettings(
        lan=stored.get("lan") is True,
        bind=stored["bind"] if isinstance(stored.get("bind"), str) else defaults.bind,
        port=port if isinstance(port, int) and 1 <= port <= 65535 else defaults.port,
        tls=tls if tls in Tls.ALL else defaults.tls,
        cert_path=stored.get("cert_path") if isinstance(stored.get("cert_path"), str) else "",
        key_path=stored.get("key_path") if isinstance(stored.get("key_path"), str) else "",
        names=tuple(n for n in names if isinstance(n, str)) if isinstance(names, list) else (),
    )


def save_settings(store: Store, settings: AccessSettings) -> None:
    store.set_settings({
        f"server.{key}": list(value) if isinstance(value, tuple) else value
        for key, value in ((key, getattr(settings, key)) for key in _KEYS)
    })


def is_private(address: str) -> bool:
    """A private, link-local or carrier-grade NAT address: one that only a local network reaches."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in LOCAL_NETWORKS if ip.version == network.version)


def validate_settings(
    values: Mapping, addresses: Iterable[str], *, public: Iterable[str] = (), current: AccessSettings | None = None
) -> AccessSettings:
    """Settings from the access form, or ValidationError naming the field.

    addresses are this PC's IPv4 addresses now. public are those among them that
    Windows marks as on a Public network. Listening on a public address, or on
    every address when one of them is public, needs the confirmation box:
    NetPulse is for a network you own, not for the internet or a café.
    """
    current = current or AccessSettings()
    addresses, public = list(addresses), set(public)
    lan = str(values.get("lan", "")).lower() in ("1", "yes", "true", "on")
    port_text = str(values.get("port", current.port)).strip()
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValidationError("port must be a number from 1 to 65535")
    names = _names(values.get("names", ""))
    tls = (values.get("tls") or current.tls).strip()
    if tls not in Tls.ALL:
        raise ValidationError("encryption must be one of the choices offered")
    bind = (values.get("bind") or current.bind).strip()
    cert_path, key_path = (values.get("cert_path") or "").strip(), (values.get("key_path") or "").strip()
    if lan:
        if bind != ALL_INTERFACES and bind not in addresses:
            raise ValidationError("interface must be one of this PC's addresses")
        exposed = [a for a in (addresses if bind == ALL_INTERFACES else [bind]) if not is_private(a) or a in public]
        if exposed and str(values.get("confirm_public", "")).lower() not in ("1", "yes", "true", "on"):
            raise ValidationError(
                f"confirm: {exposed[0]} is a public address or on a network Windows marks as Public. "
                "Tick the box only if this is a network you own or manage"
            )
        if tls == Tls.CUSTOM:
            if not cert_path or not key_path:
                raise ValidationError("certificate file and key file are both needed for your own certificate")
            try:
                check_pair(Path(cert_path), Path(key_path))
            except TlsError as exc:
                raise ValidationError(f"certificate: {exc}") from exc
    return AccessSettings(lan, bind, int(port_text), tls, cert_path, key_path, names)


def _names(text: str | Iterable[str]) -> tuple[str, ...]:
    parts = text.replace(",", " ").split() if isinstance(text, str) else list(text)
    names: list[str] = []
    for part in parts:
        try:
            name = validate_host(part).lower().rstrip(".")
        except InvalidHost as exc:
            raise ValidationError(f"names: {part} is not a host name ({exc})") from exc
        if _is_ip(name):
            raise ValidationError(f"names: {part} is an address; NetPulse answers to its addresses already")
        if name not in names:
            names.append(name)
    if len(names) > MAX_NAMES:
        raise ValidationError(f"names: at most {MAX_NAMES}")
    return tuple(names)


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def listen_plan(settings: AccessSettings, addresses: Iterable[str]) -> tuple[list[tuple[str, int]], str | None]:
    """(the addresses to listen on, a note when the chosen one is missing).

    Loopback is always among them, so the PC NetPulse runs on can always reach it.
    """
    if not settings.lan:
        return [(LOOPBACK, settings.port)], None
    if settings.bind == ALL_INTERFACES:
        return [("0.0.0.0", settings.port)], None
    if settings.bind in set(addresses):
        return [(LOOPBACK, settings.port), (settings.bind, settings.port)], None
    return [(LOOPBACK, settings.port)], (
        f"this PC no longer has the address {settings.bind}, so NetPulse is listening on this PC only; "
        "choose an interface again"
    )


def host_of(header: str) -> str:
    """The host part of a Host header, lower case, without port or brackets."""
    host = (header or "").strip().lower()
    if host.startswith("["):  # [::1]:5000
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def allowed_host(header: str, settings: AccessSettings, computer: str) -> bool:
    """Whether a request's Host header names this NetPulse.

    Any IP address does: a name is what DNS rebinding needs, and an address
    cannot be rebound. Of names, only localhost, this PC's own, and the ones
    an administrator added.
    """
    host = host_of(header)
    if not host:
        return False
    if _is_ip(host):
        return True
    return host in {"localhost", computer.lower(), *settings.names}


def local_url(status: AccessStatus) -> str:
    """The address that opens NetPulse on the PC it runs on, as the server is listening now.

    Every listener plan includes this PC, so the port is the first listener's,
    and HTTPS whenever network access uses it, because the same listener serves both.
    """
    port = status.listening[0][1] if status.listening else DEFAULT_PORT
    return f"{status.scheme}://127.0.0.1:{port}/"


class NameState:
    HERE = "here"  # resolves to one of this PC's addresses
    ELSEWHERE = "elsewhere"  # resolves, but to some other machine
    MISSING = "missing"  # does not resolve at all
    UNKNOWN = "unknown"  # the lookup did not answer in time


@dataclass(frozen=True)
class NameCheck:
    name: str
    state: str
    addresses: tuple[str, ...] = ()  # what it resolves to


def check_names(
    names: Iterable[str], resolved: Mapping[str, tuple[str, ...] | None], addresses: Iterable[str]
) -> list[NameCheck]:
    """Whether each name an administrator added really leads to this PC.

    NetPulse can answer to a name, but only DNS (the router, a Pi-hole) or a
    hosts file can send anyone to it. A name that leads nowhere is said so,
    and never offered as a link.
    """
    mine = set(addresses) | {LOOPBACK}
    checks = []
    for name in names:
        found = resolved.get(name)
        if found is None:
            state = NameState.UNKNOWN
        elif not found:
            state = NameState.MISSING
        elif mine & set(found):
            state = NameState.HERE
        else:
            state = NameState.ELSEWHERE
        checks.append(NameCheck(name, state, tuple(found or ())))
    return checks


def urls(
    settings: AccessSettings, addresses: Iterable[str], computer: str, names: Iterable[str] | None = None
) -> list[str]:
    """The addresses to type on another device, most useful first. Empty while access is off.

    names are the added names to offer, by default all of them; the access page
    passes only those that lead to this PC.
    """
    if not settings.lan:
        return []
    hosts = list(settings.names if names is None else names)
    hosts += [a for a in addresses if is_private(a)] if settings.bind == ALL_INTERFACES else [settings.bind]
    default = 443 if settings.https else 80
    suffix = "" if settings.port == default else f":{settings.port}"
    return [f"{settings.scheme}://{host}{suffix}" for host in dict.fromkeys(hosts)]


@dataclass(frozen=True)
class AccessStatus:
    """What the server is doing now, as it last reported."""

    listening: tuple[tuple[str, int], ...] = ()
    scheme: str = "http"
    error: str | None = None  # why the stored settings could not be applied
    note: str | None = None
    certificate: CertificateInfo | None = None  # the one being served, when HTTPS
    authority: CertificateInfo | None = None  # NetPulse's own, when that is what signed it
    forced_local: bool = False  # started with --local-only: the stored settings are ignored
    port_override: int | None = None  # started with --port


class AccessControl:
    """Shared by the web app and the server: one asks, the other applies.

    Pages read status() and call request_apply() after saving settings. The
    server's loop waits on it, applies the stored settings, and sets the new
    status. Without a server behind it (tests, debug mode) applying does nothing.
    """

    def __init__(
        self,
        *,
        addresses: Callable[[], Iterable[str]] = tuple,
        computer: str = "localhost",
        tls_folder: Path | None = None,
        look_up: Callable[[Iterable[str]], Mapping[str, tuple[str, ...] | None]] = lambda names: {},
    ) -> None:
        """look_up looks names up as this PC's resolver answers them; without one, every
        name's state is unknown."""
        self._addresses = addresses
        self.computer = computer
        self.tls_folder = tls_folder
        self.look_up = look_up
        self._lock = threading.Lock()
        self._status = AccessStatus()
        self._apply = threading.Event()

    def addresses(self) -> list[str]:
        return list(self._addresses())

    def status(self) -> AccessStatus:
        with self._lock:
            return self._status

    def set_status(self, status: AccessStatus) -> None:
        with self._lock:
            self._status = status

    def update_status(self, **changes) -> None:
        with self._lock:
            self._status = replace(self._status, **changes)

    def request_apply(self) -> None:
        self._apply.set()

    def wait_for_apply(self, timeout: float | None = None) -> bool:
        """Block until a page asks for new settings to be applied. For the server's loop."""
        asked = self._apply.wait(timeout)
        if asked:
            self._apply.clear()
        return asked
