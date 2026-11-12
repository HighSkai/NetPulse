"""Flask app factory.

The web layer never imports sqlite3, os_pinger or the PowerShell reader. The
entry point hands it a database path, a Pinger, the scheduler's Heartbeat and
a network reader; tests hand it a temp file, a FakePinger and, when they need
them, a Heartbeat on a fake clock and a FakeNetworkReader.

Since plan section 35 every request passes netpulse.web.security first: the
Host check, the CSRF check, setup, the session, and the route's own rule.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, current_app, g, render_template, request

from netpulse.access import AccessControl
from netpulse.accounts import GRANTABLE, Permission
from netpulse.alerting import AlertEngine
from netpulse.auth import Auth
from netpulse.checks import CHECK_INTERVAL_S, TcpProbe
from netpulse.discovery import Sweeper
from netpulse.domain import Availability
from netpulse.netinfo import CachedNetworkReader, NetworkReader, NoNetworkReader
from netpulse.outside import OutsideChecker
from netpulse.ping.result import Error, Pinger
from netpulse.scheduler import Heartbeat, MonitorStatus
from netpulse.store import Store
from netpulse.trace import Tracer
from netpulse.traffic import TrafficService, TrafficStatus
from netpulse.web import security
from netpulse.web.security import CSRF_FIELD, CSRF_HEADER, can, csrf_token, current_user, is_htmx

__all__ = ["CSRF_FIELD", "CSRF_HEADER", "create_app", "csrf_token", "get_store", "is_htmx"]

# Plan section 39: an upload is a device list as CSV, never anything large.
MAX_REQUEST_BYTES = 1024 * 1024

# Plan section 13: the status bar polls faster than the device table. It reads
# only the in-memory heartbeat, and "last round N s ago" should stay current.
STATUS_REFRESH_S = 10

@dataclass(frozen=True)
class Tab:
    key: str  # the digit shown before the name, and Alt + it as the shortcut
    name: str
    endpoint: str
    about: str  # one line for the manual on the settings page
    needs: str | None = None  # the permission an account needs to be shown the tab at all


# Plan section 25: "0:overview 1:devices 2:map 3:traffic 4:probe 5:discover
# 6:network 7:settings". Only pages that exist are listed (plan section 14),
# and each keeps its number as later steps add the others.
TABS = (
    Tab("0", "overview", "netpulse.overview", "problems first, then breakdowns, the slowest devices, recent events and 24 h of status"),
    Tab("1", "devices", "netpulse.dashboard", "every device: its state, latency and availability; add, edit, check now"),
    Tab("2", "map", "netpulse.topology_map", "this PC, its subnets and gateways, and every device, with the evidence for each line"),
    Tab("3", "traffic", "netpulse.traffic", "capture this PC's packets: live rates, protocols, talkers and a PCAP file",
        Permission.CAPTURE_VIEW),
    Tab("4", "probe", "netpulse.probe", "trace the path to a host, hop by hop, to see where it slows down or loses packets"),
    Tab("5", "discover", "netpulse.discover", "sweep one of this PC's subnets, then review what answered"),
    Tab("6", "network", "netpulse.network", "this PC's adapters, gateway and router, as Windows reports them"),
    Tab("7", "settings", "netpulse.settings", "thresholds, retention, network access, accounts, and this manual"),
    Tab("8", "alerts", "netpulse.alerts_page", "what is wrong now, what was, and who has seen it"),
    Tab("9", "reports", "netpulse.reports", "availability and outages for every device over 7, 30 or 90 days"),
)

ERROR_LABELS = Error.LABELS


def create_app(
    *,
    db_path: str | Path,
    pinger: Pinger,
    secret_key: str | None = None,
    heartbeat: Heartbeat | None = None,
    network: NetworkReader | None = None,
    sweeper: Sweeper | None = None,
    traffic: TrafficService | None = None,
    tracer: Tracer | None = None,
    outside: OutsideChecker | None = None,
    auth: Auth | None = None,
    access: AccessControl | None = None,
    alerts: AlertEngine | None = None,
    tcp: TcpProbe | None = None,
) -> Flask:
    """heartbeat is the scheduler's. Without one, no loop reports to the
    page, so the status bar honestly says monitoring is not running.

    network reads this PC's network settings (plan section 19). The app keeps
    its reads in a cache. Without one, pages say the settings are unavailable.

    sweeper runs discovery sweeps (plan section 21). Without one, the
    discovery page lists what earlier sweeps found but cannot sweep.

    traffic runs packet captures (plan section 28). Without one, nothing is captured.

    tracer traces paths (plan section 30). Without one, the probe page lists past traces only.

    outside checks from probes around the world (plan section 31). Without one, nothing is sent.

    auth signs people in (plan section 36). access is what the server shares with
    the access page (plan section 38); without one the page shows the settings but
    nothing applies them. alerts sends test messages (plan section 41). tcp checks
    devices set to a TCP port (plan section 40); without one Check now pings them."""
    app = Flask(__name__)
    setup = Store.open(db_path)  # creates the schema before the first request
    try:
        # Kept in the database, so signing in survives a restart of NetPulse.
        key = secret_key or setup.setting_or_create("secret_key", lambda: secrets.token_hex(32))
    finally:
        setup.close()
    app.config.update(
        SECRET_KEY=key,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_HTTPONLY=True,
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        MAX_FORM_MEMORY_SIZE=MAX_REQUEST_BYTES,
        NETPULSE_DB=str(db_path),
    )
    app.session_interface = security.SchemeAwareSessions()
    app.extensions["netpulse.pinger"] = pinger
    app.extensions["netpulse.heartbeat"] = heartbeat if heartbeat is not None else Heartbeat()
    app.extensions["netpulse.network"] = CachedNetworkReader(network if network is not None else NoNetworkReader())
    app.extensions["netpulse.sweeper"] = sweeper
    app.extensions["netpulse.traffic"] = traffic
    app.extensions["netpulse.tracer"] = tracer
    app.extensions["netpulse.outside"] = outside
    app.extensions["netpulse.auth"] = auth if auth is not None else Auth()
    app.extensions["netpulse.access"] = access if access is not None else AccessControl()
    app.extensions["netpulse.alerts"] = alerts
    app.extensions["netpulse.tcp"] = tcp

    app.before_request(security.check_host)
    app.before_request(security.check_csrf)
    app.before_request(security.gate)
    for code in ERROR_MESSAGES:
        app.register_error_handler(code, _error_page)
    app.register_error_handler(Exception, _fault_page)
    app.after_request(security.security_headers)
    app.teardown_appcontext(_close_store)
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["current_user"] = current_user
    app.jinja_env.globals["can"] = can
    app.jinja_env.globals["Permission"] = Permission
    app.jinja_env.globals["grantable"] = GRANTABLE
    app.jinja_env.globals["open_alert_count"] = open_alert_count
    app.jinja_env.globals["monitor_status"] = monitor_status
    app.jinja_env.globals["capture_status"] = capture_status
    app.jinja_env.globals["refresh_s"] = CHECK_INTERVAL_S
    app.jinja_env.globals["status_refresh_s"] = STATUS_REFRESH_S
    app.jinja_env.globals["tabs"] = TABS
    app.context_processor(lambda: {"now_utc": datetime.now(UTC)})
    app.jinja_env.filters["localtime"] = format_local_time
    app.jinja_env.filters["as_datetime"] = datetime.fromisoformat
    app.jinja_env.filters["shorttime"] = format_short_time
    app.jinja_env.filters["clock"] = format_clock
    app.jinja_env.filters["hour"] = format_hour
    app.jinja_env.filters["packet_time"] = format_packet_time
    app.jinja_env.filters["bytes"] = format_bytes
    app.jinja_env.filters["error_label"] = error_label
    app.jinja_env.filters["age"] = format_age
    app.jinja_env.filters["ms"] = format_ms
    app.jinja_env.filters["percent"] = format_percent
    app.jinja_env.filters["duration"] = format_duration

    # Each adds its routes to bp.
    from netpulse.web import (  # noqa: F401
        account_views,
        admin_views,
        alert_views,
        capture_views,
        inventory_views,
        probe_views,
    )
    from netpulse.web.views import bp

    app.register_blueprint(bp)
    return app


def get_store() -> Store:
    """One SQLite connection per request, closed at teardown."""
    if "store" not in g:
        g.store = Store.open(current_app.config["NETPULSE_DB"])
    return g.store


def get_pinger() -> Pinger:
    return current_app.extensions["netpulse.pinger"]


def get_network() -> CachedNetworkReader:
    return current_app.extensions["netpulse.network"]


def get_sweeper() -> Sweeper | None:
    return current_app.extensions["netpulse.sweeper"]


def get_traffic() -> TrafficService | None:
    return current_app.extensions["netpulse.traffic"]


def get_outside() -> OutsideChecker | None:
    return current_app.extensions["netpulse.outside"]


def get_tracer() -> Tracer | None:
    return current_app.extensions["netpulse.tracer"]


def get_alerts() -> AlertEngine | None:
    return current_app.extensions["netpulse.alerts"]


def get_tcp() -> TcpProbe | None:
    return current_app.extensions["netpulse.tcp"]


def open_alert_count() -> int:
    """Open alerts nobody has acknowledged, for the tab's badge. One small query a page."""
    if "open_alerts" not in g:
        g.open_alerts = get_store().count_open_alerts()[1]
    return g.open_alerts


def audit(action: str, target: str = "", detail: str = "") -> None:
    """Record what the signed-in account just did (plan section 44)."""
    get_store().audit(security.actor(), action, target, detail, ip=security.client_ip())


def capture_status() -> TrafficStatus:
    """Whether a capture is running, for the banner and the status bar (plan section 28). Memory only."""
    traffic = get_traffic()
    return traffic.status() if traffic is not None else TrafficStatus()


def monitor_status() -> MonitorStatus:
    """The check loop's state for the status bar. Memory only, no database."""
    return current_app.extensions["netpulse.heartbeat"].status(CHECK_INTERVAL_S)


def format_local_time(value: str | datetime) -> str:
    """A stored ISO timestamp, or an aware datetime, in this PC's time zone."""
    moment = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    return moment.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def format_short_time(value: str | datetime, now: datetime | None = None) -> str:
    """A time for a narrow table column: the time of day if it is today, else the day and the time.
    The cell's title carries the whole of it."""
    moment = (value if isinstance(value, datetime) else datetime.fromisoformat(value)).astimezone()
    today = (now or datetime.now(UTC)).astimezone().date()
    return moment.strftime("%H:%M:%S") if moment.date() == today else moment.strftime("%m-%d %H:%M")


def format_clock(moment: datetime) -> str:
    """The status bar's clock: this PC's local time of day."""
    return moment.astimezone().strftime("%H:%M:%S")


def format_packet_time(time_ns: int) -> str:
    """A packet's time of day in this PC's time zone, to the microsecond: 14:03:07.123456."""
    seconds, nanoseconds = divmod(time_ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds).strftime("%H:%M:%S") + f".{nanoseconds // 1000:06d}"


def format_bytes(count: int | None) -> str:
    """1.2 MB, 340 KB, 999 B: decimal units, as the capture limits are written."""
    if count is None:
        return "—"
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if count >= size:
            return f"{count / size:.1f} {unit}"
    return f"{count} B"


def format_hour(moment: datetime) -> str:
    """The start of an hour on the status grid, in this PC's time zone: 14:00."""
    return moment.astimezone().strftime("%H:00")


def error_label(code: str | None) -> str:
    return ERROR_LABELS.get(code, code or "")


def format_ms(value: float | None) -> str:
    """14 ms, or 14.5 ms for a median between two devices; a dash when there is none."""
    return "—" if value is None else f"{value:g} ms"


def format_percent(availability: Availability) -> str:
    """Successful checks as a percentage, rounded down to 0.1, from whole counts.

    Rounding down means "100 %" only ever shows when every check succeeded.
    """
    if availability.checks == 0:
        return "—"
    if availability.successes == availability.checks:
        return "100 %"
    tenths = availability.successes * 1000 // availability.checks
    return f"{tenths // 10}.{tenths % 10} %"


def format_duration(seconds: int) -> str:
    """How long an outage or a chart period lasted: 45 s, 12 min, 3 h 5 min, 2 d 4 h."""
    minutes, hours, days = seconds // 60, seconds // 3600, seconds // 86400
    if seconds < 60:
        return f"{seconds} s"
    if seconds < 3600:
        return f"{minutes} min"
    if seconds < 86400:
        rest = minutes % 60
        return f"{hours} h {rest} min" if rest else f"{hours} h"
    rest = hours % 24
    return f"{days} d {rest} h" if rest else f"{days} d"


def format_age(seconds: int) -> str:
    """A short age: 45 s, then whole minutes from 2 min, then whole hours from 2 h."""
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 120 * 60:
        return f"{seconds // 60} min"
    return f"{seconds // 3600} h"


# Plan section 32: what each refusal means, in words, when the code gives none of its own.
ERROR_MESSAGES = {
    400: "That request was refused. Reload the page and try again.",
    401: "You are signed out. Sign in and try again.",
    403: "That is not allowed here.",
    404: "There is nothing here. The device or record may have been deleted.",
    405: "That page does not take this kind of request.",
    409: "Something else is already running. Wait for it to finish.",
    413: "That request is too large.",
    429: "Too many attempts. Wait a little and try again.",
    500: "NetPulse stopped on an error. The NetPulse log has the details.",
    503: "NetPulse cannot do that on this PC right now.",
}


def _error_page(error) -> tuple[str, int]:
    """Refused requests and missing pages, in the app's look (plan section 32).

    Never opens the database. A request for a host this app does not answer to
    fails before any route exists to link to, and gets a plain refusal: the
    app's pages are not shown to another site's name."""
    code = error.code
    described = error.description and error.description != type(error).description
    message = error.description if described else ERROR_MESSAGES[code]
    if code == 400 and "does not answer to the name" in message:
        return f"Bad request: {message}", 400
    return render_template("error.html", code=code, name=error.name, message=message), code


def _fault_page(error: Exception) -> tuple[str, int]:
    """An error nothing caught: logged with its traceback, shown without one."""
    if isinstance(getattr(error, "code", None), int):
        return error.get_response()  # an HTTP refusal with a code given no page of its own
    current_app.logger.exception("request failed: %s %s", request.method, request.path)
    page = render_template("error.html", code=500, name="Internal Server Error", message=ERROR_MESSAGES[500])
    return page, 500


def _close_store(exc: BaseException | None) -> None:
    store = g.pop("store", None)
    if store is not None:
        store.close()
