"""The HTTP server (plan section 38): cheroot, the server CherryPy is built on.

Flask's own server is for development: one thread at a time, and a debugger
that runs code. NetPulse now serves other devices, so it runs a threaded
production server, with HTTPS when network access asks for it.

- It listens where netpulse.access.listen_plan says. With network access off
  that is 127.0.0.1 only.
- New settings are applied without restarting NetPulse: the listeners stop
  and start again, a second or so, while checks carry on.
- Settings that cannot be applied never lock anyone out. If the port is taken
  on a network address, or a certificate will not load, NetPulse falls back to
  plain HTTP on 127.0.0.1 and the access page says why.
- TLS 1.2 or newer only, with the operating system's own defaults for the rest.
"""

from __future__ import annotations

import logging
import ssl
import threading
from collections.abc import Callable
from pathlib import Path

from cheroot import wsgi
from cheroot.ssl.builtin import BuiltinSSLAdapter

from netpulse.access import (
    LOOPBACK,
    AccessControl,
    AccessSettings,
    AccessStatus,
    Tls,
    listen_plan,
    load_settings,
)
from netpulse.crypto.tls import (
    CA_CERT,
    SERVER_CERT,
    SERVER_KEY,
    TlsError,
    describe,
    issue_server_certificate,
    needs_new_certificate,
)
from netpulse.store import Store

log = logging.getLogger(__name__)

THREADS = 12  # request threads for each listener
MAX_BODY = 2 * 1024 * 1024
MAX_HEADERS = 64 * 1024
# A page that asked for new settings gets its answer before the listeners go.
APPLY_GRACE_S = 0.6


class CannotListen(RuntimeError):
    """No listener could be opened, not even on 127.0.0.1. The message says why."""


def _port_in_use(error: OSError) -> bool:
    text = str(error)
    return "10048" in text or "Address already in use" in text or getattr(error, "errno", None) in (98, 10048)


class Listeners:
    """The running cheroot servers for one WSGI app."""

    def __init__(self, app) -> None:
        self._app = app
        self._servers: list[tuple[wsgi.Server, threading.Thread]] = []

    def start(self, addresses: list[tuple[str, int]], certificate: tuple[Path, Path] | None) -> None:
        """Open every address, or none: a failure closes the ones already opened and raises OSError."""
        opened: list[wsgi.Server] = []
        try:
            for address in addresses:
                server = wsgi.Server(
                    address, self._app, numthreads=THREADS, server_name="netpulse", timeout=15, shutdown_timeout=2
                )
                server.max_request_body_size = MAX_BODY
                server.max_request_header_size = MAX_HEADERS
                server.error_log = _log_server_error
                if certificate is not None:
                    adapter = BuiltinSSLAdapter(str(certificate[0]), str(certificate[1]))
                    adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
                    server.ssl_adapter = adapter
                server.prepare()
                opened.append(server)
        except Exception:
            for server in opened:
                server.stop()
            raise
        for server in opened:
            thread = threading.Thread(target=server.serve, name=f"netpulse-http-{server.bind_addr[0]}", daemon=True)
            thread.start()
            self._servers.append((server, thread))

    def stop(self) -> None:
        for server, thread in self._servers:
            server.stop()
            thread.join(5)
        self._servers = []


def _log_server_error(msg: str = "", level: int = logging.INFO, traceback: bool = False) -> None:
    # Cheroot reports dropped connections and failed TLS handshakes here: routine on a
    # network, so they are kept out of the way unless something asks for debug output.
    log.log(logging.DEBUG if level <= logging.INFO else level, "%s", msg.strip(), exc_info=traceback)


class Server:
    def __init__(
        self,
        app,
        open_store: Callable[[], Store],
        control: AccessControl,
        *,
        port_override: int | None = None,
        local_only: bool = False,
        on_ready: Callable[[AccessStatus], object] | None = None,
    ) -> None:
        """port_override is --port, and local_only is --local-only: started that way,
        NetPulse ignores the stored network settings and serves this PC only, over HTTP.
        That is the way back in after a setting that cannot be reached."""
        self._listeners = Listeners(app)
        self._open_store = open_store
        self._control = control
        self._port_override = port_override
        self._local_only = local_only
        self._on_ready = on_ready  # told once, when NetPulse first listens: --open uses it
        self._stop = threading.Event()

    def settings(self) -> AccessSettings:
        """What should be listening: the stored settings, as the command line bends them."""
        store = self._open_store()
        try:
            settings = load_settings(store)
            setup_done = store.count_users() > 0
        finally:
            store.close()
        overrides: dict = {}
        if self._port_override is not None:
            overrides["port"] = self._port_override
        # Nothing but this PC is served until an administrator exists (plan section 37).
        if self._local_only or not setup_done:
            overrides["lan"] = False
        return AccessSettings(**{**settings.__dict__, **overrides})

    def start(self) -> AccessStatus:
        """Apply the settings. Falls back to 127.0.0.1 over HTTP when they cannot be; raises
        CannotListen only when even that fails."""
        settings = self.settings()
        base = AccessStatus(forced_local=self._local_only, port_override=self._port_override)
        addresses, note = listen_plan(settings, self._control.addresses())
        error = None
        try:
            certificate, info, authority = self._certificate(settings)
            self._listeners.start(addresses, certificate)
            status = AccessStatus(
                tuple(addresses), settings.scheme, None, note, info, authority, base.forced_local, base.port_override
            )
        except (OSError, TlsError, ssl.SSLError) as exc:
            if not settings.lan:
                reason = f"port {settings.port} is in use by another program" if isinstance(exc, OSError) and _port_in_use(exc) else str(exc)
                raise CannotListen(reason) from exc
            error = self._explain(exc, settings)
            log.error("network access could not start: %s; serving this PC only", error)
            fallback = [(LOOPBACK, settings.port)]
            try:
                self._listeners.start(fallback, None)
            except OSError as again:
                reason = f"port {settings.port} is in use by another program" if _port_in_use(again) else str(again)
                raise CannotListen(reason) from again
            status = AccessStatus(tuple(fallback), "http", error, note, None, None, base.forced_local, base.port_override)
        self._control.set_status(status)
        for host, port in status.listening:
            log.info("listening on %s://%s:%d", status.scheme, host, port)
        return status

    def _certificate(self, settings: AccessSettings):
        """((certificate file, key file), what it is, the authority's) for HTTPS, or (None, None, None)."""
        if not settings.https:
            return None, None, None
        if settings.tls == Tls.CUSTOM:
            cert, key = Path(settings.cert_path), Path(settings.key_path)
            return (cert, key), describe(cert), None
        folder = self._control.tls_folder
        if folder is None:
            raise TlsError("NetPulse was started without a folder for its certificates")
        names = [*settings.names, *self._control.addresses()]
        if needs_new_certificate(folder, names):
            info = issue_server_certificate(folder, self._control.computer, names)
            log.info("made a new HTTPS certificate for %s", ", ".join(info.names))
        return (folder / SERVER_CERT, folder / SERVER_KEY), describe(folder / SERVER_CERT), describe(folder / CA_CERT)

    @staticmethod
    def _explain(exc: Exception, settings: AccessSettings) -> str:
        if isinstance(exc, OSError) and not isinstance(exc, ssl.SSLError):
            if _port_in_use(exc):
                return f"port {settings.port} is in use by another program on that address"
            return f"Windows would not let NetPulse listen there ({exc.__class__.__name__})"
        if isinstance(exc, ssl.SSLError):
            return "the certificate or its key could not be loaded"
        return str(exc)

    def stop(self) -> None:
        self._stop.set()
        self._control.request_apply()  # wake the loop
        self._listeners.stop()

    def serve_forever(self) -> None:
        """Start, then apply new settings whenever a page asks, until stop() or Ctrl+C."""
        status = self.start()
        if self._on_ready is not None:
            try:
                self._on_ready(status)
            except Exception:
                log.exception("could not do what was asked once NetPulse was listening; it carries on")
        try:
            while not self._stop.is_set():
                if not self._control.wait_for_apply(1.0) or self._stop.is_set():
                    continue
                self._stop.wait(APPLY_GRACE_S)
                log.info("applying new network access settings")
                self._listeners.stop()
                self.start()
        finally:
            self._listeners.stop()
