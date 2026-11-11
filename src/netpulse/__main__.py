"""Entry point: `python -m netpulse`, or `netpulse` once installed.

This is the composition root, the one place that builds the real OsPinger
and hands it to the web app and the scheduler. Everything else receives a
Pinger. It also builds the one Heartbeat the scheduler writes and the status
bar reads (plan section 13), the PowerShell network reader the network
page and the map use (plan section 19), the sweeper discovery uses, with
its own IcmpSendEcho pinger (plan section 21), and the Npcap packet source
(plan section 27) with the capture service that runs on it (plan section 28),
the tracer, with its own IcmpSendEcho API (plan section 30), and the checks
from outside through Globalping (plan section 31), which send nothing until
the user agrees.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from netpulse.capture import CaptureUnavailable, PacketSource
from netpulse.capture.npcap import NpcapSource
from netpulse.checks import CHECK_INTERVAL_S
from netpulse.discovery import Sweeper
from netpulse.netinfo import CachedNetworkReader, NetworkInfoUnavailable
from netpulse.netinfo.names import reverse_name
from netpulse.netinfo.powershell import PowerShellNetworkReader
from netpulse.outside import OutsideChecker
from netpulse.ping.icmp import IcmpApi, IcmpPinger, resolve
from netpulse.ping.os_pinger import OsPinger, UnsupportedPlatform
from netpulse.ping.result import PingerUnavailable
from netpulse.probes.globalping import GlobalpingClient
from netpulse.scheduler import Heartbeat, Scheduler, should_start_scheduler
from netpulse.store import CannotOpenDatabase, Store
from netpulse.trace import Tracer
from netpulse.traffic import TrafficService, captures_folder
from netpulse.web import create_app

# Plan section 7: bind to localhost only. There is no login in v1, and no
# option to listen on another address.
HOST = "127.0.0.1"

log = logging.getLogger("netpulse")


def port_number(text: str) -> int:
    port = int(text)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"{port} is not a port between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netpulse", description="Local network monitor.")
    parser.add_argument(
        "--db",
        default="netpulse.db",
        help="SQLite file, created if missing (default: %(default)s in the current folder)",
    )
    parser.add_argument("--port", type=port_number, default=5000, help="port (default: %(default)s)")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Flask debug mode: reload on code changes, show tracebacks (development only)",
    )
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

    try:
        pinger = OsPinger()
    except UnsupportedPlatform as exc:
        parser.exit(1, f"netpulse: {exc}\n")
    heartbeat = Heartbeat()
    network = PowerShellNetworkReader()
    try:
        # Decision 004: sweeps ping with IcmpSendEcho; monitoring keeps ping.exe.
        sweeper = Sweeper(lambda: Store.open(db), IcmpPinger(), network, reverse_name)
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

    traffic = TrafficService(source, lambda: Store.open(db), captures_folder(db), adapters=adapters, unavailable=why_not)
    try:
        # Plan section 30: traces send echoes with a hop limit, through IcmpSendEcho as sweeps do.
        # Its own cache of the network read, so a trace does not wait for PowerShell each time.
        tracer = Tracer(lambda: Store.open(db), IcmpApi(), resolve, reverse_name, network=CachedNetworkReader(network))
    except PingerUnavailable as exc:
        log.warning("tracing is off: %s", exc)
        tracer = None
    try:
        app = create_app(
            db_path=db, pinger=pinger, heartbeat=heartbeat, network=network, sweeper=sweeper, traffic=traffic,
            tracer=tracer, outside=OutsideChecker(lambda: Store.open(db), GlobalpingClient()),
        )
    except CannotOpenDatabase as exc:
        parser.exit(1, f"netpulse: {db}: {exc}\n")

    scheduler = Scheduler(lambda: Store.open(db), pinger, heartbeat=heartbeat, cleanup_captures=traffic.cleanup)
    if should_start_scheduler(args.debug):
        log.info("database: %s", db)
        log.info("checking live devices every %d s", CHECK_INTERVAL_S)
        scheduler.start()
        traffic.recover()
    try:
        app.run(host=HOST, port=args.port, debug=args.debug)
    finally:
        scheduler.stop()
        traffic.stop()
        traffic.join(5)


if __name__ == "__main__":
    main()
