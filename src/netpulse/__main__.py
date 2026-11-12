"""Entry point: `python -m netpulse`, or `netpulse` once installed.

This is the composition root, the one place that builds the real adapters and
hands them to the web app and the scheduler. Everything else receives a
Pinger, a NetworkReader or a PacketSource. It builds:

- the pinger checks use: IcmpSendEcho (plan section 40), or ping.exe where
  Windows refuses an ICMP handle, and the TCP checker beside it;
- the one Heartbeat the scheduler writes and the status bar reads (plan section 13);
- the PowerShell network reader of the network page and the map (plan section 19);
- the sweeper, the tracer and the capture service (plan sections 21, 28 and 30);
- the checks from outside through Globalping (plan section 31), which send
  nothing until an administrator agrees;
- sign-in, the alert engine and the server (plan sections 36, 38 and 41).

It is also the way back in: `netpulse reset-password NAME` gives an account a
temporary password, from the PC NetPulse runs on (plan section 37), and
`netpulse --local-only` serves this PC alone whatever the network settings say.
`netpulse --open` opens the browser once NetPulse is listening, for the
double-click launcher NetPulse.bat.
"""

from __future__ import annotations

import argparse
import logging
import sys
import webbrowser
from pathlib import Path

from netpulse.access import DEFAULT_PORT, LOOPBACK, AccessControl, AccessStatus, load_settings, local_url
from netpulse.alerting import AlertEngine
from netpulse.auth import Auth
from netpulse.capture import CaptureUnavailable, PacketSource
from netpulse.capture.npcap import NpcapSource
from netpulse.checks import CHECK_INTERVAL_S
from netpulse.crypto.tls import tls_folder
from netpulse.discovery import Sweeper, SweepSchedule
from netpulse.netinfo import CachedNetworkReader, NetworkInfoUnavailable
from netpulse.netinfo.local import computer_name, local_ipv4_addresses, resolve_names
from netpulse.netinfo.names import reverse_name
from netpulse.netinfo.powershell import PowerShellNetworkReader
from netpulse.outside import OutsideChecker
from netpulse.ping.icmp import IcmpApi, IcmpPinger, resolve
from netpulse.ping.os_pinger import OsPinger, UnsupportedPlatform
from netpulse.ping.result import Pinger, PingerUnavailable
from netpulse.ping.tcp import TcpChecker
from netpulse.probes.globalping import GlobalpingClient
from netpulse.scheduler import Heartbeat, Scheduler, should_start_scheduler
from netpulse.server import CannotListen, Server
from netpulse.store import CannotOpenDatabase, Store
from netpulse.trace import Tracer
from netpulse.traffic import TrafficService, captures_folder
from netpulse.web import create_app

# Flask's own server, in debug mode, never listens anywhere but this PC.
HOST = LOOPBACK

log = logging.getLogger("netpulse")


def port_number(text: str) -> int:
    port = int(text)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{port} is not a port between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpulse", description="Network monitor for your own network.")
    parser.add_argument(
        "--db",
        default="netpulse.db",
        help="SQLite file, created if missing (default: %(default)s in the current folder)",
    )
    parser.add_argument(
        "--port", type=port_number, default=None,
        help=f"port to listen on, instead of the one set on the access page (default there: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="serve this PC only, over plain HTTP, whatever the network access settings say",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="open NetPulse in the browser once it is listening (not with --debug)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Flask debug mode on this PC only: reload on code changes, show tracebacks (development only)",
    )
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    reset = commands.add_parser(
        "reset-password", help="give an account a temporary password, printed here; its sessions end"
    )
    reset.add_argument("username")
    commands.add_parser("users", help="list the accounts")
    return parser


def packet_source() -> tuple[PacketSource | None, str]:
    """(Npcap, "") if this PC can capture (plan section 27), else (None, why not).

    Without it, everything else still works.
    """
    try:
        source = NpcapSource()
        interfaces = source.interfaces()
    except CaptureUnavailable as exc:
        log.warning("packet capture is off: %s", exc)
        return None, f"packet capture is off: {exc}"
    log.info("packet capture: Npcap found, %d interface(s)", len(interfaces))
    return source, ""


def monitoring_pinger(fallback: Pinger) -> Pinger:
    """IcmpSendEcho for checks (plan section 40): no process for each ping, and no
    reading of ping.exe's output, so any display language works. Where Windows
    refuses an ICMP handle, ping.exe as before."""
    try:
        pinger = IcmpPinger()
    except PingerUnavailable as exc:
        log.warning("checks use ping.exe, because IcmpSendEcho is unavailable: %s", exc)
        return fallback
    log.info("checks use IcmpSendEcho")
    return pinger


def list_users(db: Path) -> int:
    store = Store.open(db)
    try:
        users = store.users()
    finally:
        store.close()
    if not users:
        print("No accounts yet. Start NetPulse and open it on this PC to create the first administrator.")
        return 0
    for user in users:
        state = "" if user.active else "  (disabled)"
        print(f"{user.username:<32}  {user.role_label}{state}")
    return 0


def reset_password(db: Path, username: str) -> int:
    """The local way back into an account (plan section 37): whoever can run this already
    owns the database file. Prints a temporary password; the account must choose its own next."""
    auth = Auth()
    store = Store.open(db)
    try:
        found = store.find_user(username)
        if found is None:
            print(f"netpulse: there is no account named {username}. `netpulse users` lists them.", file=sys.stderr)
            return 1
        user = found[0]
        password = auth.temporary_password()
        auth.set_password(store, user, password, must_change=True)
        store.audit("console", "reset password", user.username, "from the command line")
    finally:
        store.close()
    print(f"Temporary password for {user.username}: {password}")
    print("Sign in with it and NetPulse asks for a new one. Every session of that account has been signed out.")
    if not user.active:
        print("The account is disabled: an administrator has to enable it before it can sign in.")
    return 0


def open_in_browser(status: AccessStatus) -> None:
    """--open: this PC's own address, at the port and scheme NetPulse is really listening on."""
    url = local_url(status)
    log.info("opening %s in the browser", url)
    webbrowser.open(url)


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    # Absolute, so the web app and the scheduler always open the same file.
    db = Path(args.db).resolve()
    if db.is_dir():
        parser.error(f"--db {args.db} is a folder; give a file such as {db / 'netpulse.db'}")
    if not db.parent.is_dir():
        parser.error(f"--db folder does not exist: {db.parent}")

    if args.command is not None:
        try:
            code = list_users(db) if args.command == "users" else reset_password(db, args.username)
        except CannotOpenDatabase as exc:
            parser.exit(1, f"netpulse: {db}: {exc}\n")
        raise SystemExit(code)

    try:
        ping_exe = OsPinger()
    except UnsupportedPlatform as exc:
        parser.exit(1, f"netpulse: {exc}\n")
    pinger = monitoring_pinger(ping_exe)
    tcp = TcpChecker()
    heartbeat = Heartbeat()
    network = PowerShellNetworkReader()

    def open_store() -> Store:
        return Store.open(db)

    alerts = AlertEngine(open_store, network=CachedNetworkReader(network))
    try:
        # Decision 004: sweeps ping with IcmpSendEcho.
        sweeper = Sweeper(open_store, IcmpPinger(), network, reverse_name, on_new_hosts=alerts.hosts_found)
    except PingerUnavailable as exc:
        log.warning("discovery sweeps are off: %s", exc)
        sweeper = None
    # Plan section 28. The debug reloader's parent process never captures.
    source, why_not = packet_source() if should_start_scheduler(args.debug) else (None, "packet capture is off")

    def adapters():
        try:
            return network.read().adapters
        except NetworkInfoUnavailable:
            return ()

    traffic = TrafficService(source, open_store, captures_folder(db), adapters=adapters, unavailable=why_not)
    try:
        # Plan section 30: traces send echoes with a hop limit, through IcmpSendEcho as sweeps do.
        # Its own cache of the network read, so a trace does not wait for PowerShell each time.
        tracer = Tracer(open_store, IcmpApi(), resolve, reverse_name, network=CachedNetworkReader(network))
    except PingerUnavailable as exc:
        log.warning("tracing is off: %s", exc)
        tracer = None
    control = AccessControl(
        addresses=local_ipv4_addresses, computer=computer_name(), tls_folder=tls_folder(db), look_up=resolve_names,
    )
    try:
        app = create_app(
            db_path=db, pinger=pinger, heartbeat=heartbeat, network=network, sweeper=sweeper, traffic=traffic,
            tracer=tracer, outside=OutsideChecker(open_store, GlobalpingClient()), auth=Auth(), access=control,
            alerts=alerts, tcp=tcp,
        )
    except CannotOpenDatabase as exc:
        parser.exit(1, f"netpulse: {db}: {exc}\n")

    schedule = SweepSchedule(sweeper, open_store, CachedNetworkReader(network)) if sweeper is not None else None
    scheduler = Scheduler(
        open_store, pinger, heartbeat=heartbeat, cleanup_captures=traffic.cleanup, tcp=tcp,
        after_round=alerts.after_round, on_round_failed=alerts.round_failed,
        on_tick=schedule.tick if schedule is not None else None,
    )
    if should_start_scheduler(args.debug):
        log.info("database: %s", db)
        log.info("checking devices every %d s", CHECK_INTERVAL_S)
        scheduler.start()
        traffic.recover()
    try:
        _serve(app, open_store, control, args, parser)
    finally:
        scheduler.stop()
        traffic.stop()
        traffic.join(5)
        alerts.stop()


def _serve(app, open_store, control: AccessControl, args, parser: argparse.ArgumentParser) -> None:
    store = open_store()
    try:
        port = args.port if args.port is not None else load_settings(store).port
        needs_setup = store.count_users() == 0
    finally:
        store.close()
    if needs_setup:
        log.info("first run: open http://%s:%d in a browser on this PC to create the administrator", LOOPBACK, port)
    if args.debug:
        # Development: Flask's own server, on this PC only, whatever the access settings say.
        app.run(host=HOST, port=port, debug=True)
        return
    server = Server(
        app, open_store, control, port_override=args.port, local_only=args.local_only,
        on_ready=open_in_browser if args.open else None,
    )
    try:
        server.serve_forever()
    except CannotListen as exc:
        parser.exit(
            1,
            f"netpulse: cannot listen: {exc}. If NetPulse is already running, use that window, "
            "or close it first. Otherwise start with --port and another port.\n",
        )
    except KeyboardInterrupt:
        log.info("stopping")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
