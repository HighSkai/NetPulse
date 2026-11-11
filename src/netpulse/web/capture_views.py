"""The traffic pages (plan section 29): start and stop a capture, watch it live,
look back at finished ones, download their files and delete them.

The capture itself runs in netpulse.traffic, never in a request. These routes
read its live data from memory, and finished captures from the store and
their files. Every route is listed in README.md (tests/test_web.py checks).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from flask import Response, abort, flash, redirect, render_template, request, url_for

from netpulse.capture import SNAPLEN_FULL, SNAPLEN_HEADERS, CaptureUnavailable, Interface, InvalidFilter
from netpulse.capture.pcap import MEDIA_TYPE
from netpulse.charts import PATTERNS, Slice, bar_list, donut
from netpulse.domain import FILTER_MAX_LEN, Capture, ValidationError
from netpulse.metrics import protocol_totals, rate_chart
from netpulse.netinfo import NetworkInfoUnavailable
from netpulse.network import Adapter
from netpulse.traffic import (
    PAGE_SIZE,
    RATE_WINDOW_S,
    CaptureBusy,
    CaptureLimits,
    TrafficService,
    duration_text,
    filter_presets,
    size_text,
)
from netpulse.web.app import format_bytes, get_network, get_store, get_traffic
from netpulse.web.forms import Refusable
from netpulse.web.views import bp

PACKET_ROWS = 500  # rows in the live packet list
# Protocols get the theme's chart tones in turn; past four they share "other".
PROTOCOL_TONES = ("accent", "select", "warn", "up", "unknown")
DOWNLOAD_CHUNK = 64 * 1024


@dataclass
class CaptureForm(Refusable):
    """The start form's fields, as typed, so a refused start keeps them."""

    interface: str = ""
    filter: str = ""
    headers_only: bool = False
    error: str | None = None
    error_field: str | None = None

    FIELDS = (("filter", r"filter|parse|syntax"), ("headers_only", r"snapshot"), ("interface", r"interface|adapter"))

    @classmethod
    def from_request(cls) -> CaptureForm:
        typed = request.form.get("filter", "").strip()
        return cls(
            interface=request.form.get("interface", ""),
            filter=typed or request.form.get("preset", ""),
            headers_only=request.form.get("headers_only") == "yes",
        )

    @property
    def snaplen(self) -> int:
        return SNAPLEN_HEADERS if self.headers_only else SNAPLEN_FULL



def interface_choices(interfaces: Iterable[Interface], adapters: Iterable[Adapter]) -> list[tuple[str, str]]:
    """(Npcap name, label) for each interface, named as the network page names its adapter (plan section 19).

    Adapters the network page knows come first, then loopback, then the rest.
    """
    adapters = list(adapters)
    known, loopback, others = [], [], []
    for interface in interfaces:
        adapter = interface.adapter(adapters)
        if adapter is not None:
            address = ", ".join(str(a.ip) for a in adapter.addresses)
            known.append((interface.name, f"{adapter.name}: {interface.description or adapter.description} ({address})"))
        elif interface.loopback:
            loopback.append((interface.name, "Loopback: traffic within this PC"))
        else:
            others.append((interface.name, interface.description or interface.name))
    return known + loopback + others


def protocol_donut(chart_id: str, protocols: list[tuple[str, int]]):
    """Packets by protocol: the four busiest, then the rest as "other"."""
    top, rest = protocols[:4], sum(count for _, count in protocols[4:])
    named = [*top, ("other", rest)] if rest else top
    slices = [
        Slice(f"p{i}", name, count, PROTOCOL_TONES[i], PATTERNS[i])
        for i, (name, count) in enumerate(named)
    ]
    return donut(chart_id, "Packets by protocol", slices, unit="packets")


def _traffic() -> TrafficService | None:
    return get_traffic()


def _adapters() -> list[Adapter]:
    try:
        return list(get_network().read().adapters)
    except NetworkInfoUnavailable:
        return []


def _web_port() -> int:
    port = request.host.rpartition(":")[2]
    return int(port) if port.isdigit() else 80


@bp.get("/traffic")
def traffic():
    """Choose an interface and a filter, and start a capture; watch it; list finished ones."""
    return _traffic_page(CaptureForm())


@bp.get("/traffic/view")
def traffic_view():
    """The live part of the traffic page. Polls itself every second while a capture runs.

    When a poll finds the capture has ended, the whole page reloads, so the
    banner and the list of captures show it ended too.
    """
    live = _live(CaptureForm())
    body = render_template("_traffic_view.html", **live)
    if request.headers.get("HX-Request") == "true" and not (live["status"] and live["status"].running):
        return Response(body, headers={"HX-Refresh": "true"})
    return body


@bp.post("/traffic/start")
def start_capture():
    form = CaptureForm.from_request()
    service = _traffic()
    try:
        if service is None:
            raise CaptureUnavailable("packet capture is off in this NetPulse")
        service.start(form.interface, form.filter, form.snaplen)
    except CaptureBusy as exc:
        return _traffic_page(form.fail(exc)), 409
    except (ValidationError, InvalidFilter) as exc:
        return _traffic_page(form.fail(exc)), 422
    except CaptureUnavailable as exc:
        # A fault on this PC: Npcap missing, access refused, the interface gone.
        return _traffic_page(form.fail(exc)), 503
    return redirect(url_for(".traffic"))


@bp.post("/traffic/stop")
def stop_capture():
    service = _traffic()
    if service is not None:
        service.stop()
        service.join(5)  # one read at most, so the page shows it finished
    return redirect(url_for(".traffic"))


@bp.get("/traffic/<int:capture_id>")
def capture_detail(capture_id: int):
    """A capture's facts, its graphs from the stored seconds, and its packets, paged from its file."""
    return _capture_page(_capture_or_404(capture_id))


def _capture_page(capture: Capture, error: str | None = None) -> str:
    capture_id = capture.id
    page = request.args.get("page", "1")
    page = int(page) if page.isdigit() and int(page) > 0 else 1
    service = _traffic()
    packets, more = service.packets(capture, (page - 1) * PAGE_SIZE) if service is not None else ([], False)
    seconds = get_store().capture_rates(capture_id)
    return render_template(
        "capture.html",
        capture=capture,
        chart=rate_chart(seconds),
        protocols=protocol_donut("capture-protocols", protocol_totals(seconds)),
        packets=packets,
        page=page,
        first=(page - 1) * PAGE_SIZE + 1,
        more=more,
        file_bytes=_file_size(service, capture),
        duration=_duration(capture),
        error=error,
    )


@bp.get("/traffic/<int:capture_id>/pcap")
def capture_download(capture_id: int):
    """The capture's PCAP file, as an attachment. A running capture is sent as it stands, to its last whole packet."""
    capture = _capture_or_404(capture_id)
    service = _traffic()
    path = service.path_of(capture) if service is not None else None
    if path is None or not path.is_file():
        abort(404)
    length = service.download_length(capture)
    return Response(
        _read(path, length),
        mimetype=MEDIA_TYPE,
        headers={
            "Content-Length": str(length),
            "Content-Disposition": f'attachment; filename="{capture.file}"',
            "Cache-Control": "no-store",
        },
    )


@bp.post("/traffic/<int:capture_id>/delete")
def delete_capture(capture_id: int):
    """Delete a finished capture, its counts and its file, once the box is ticked."""
    capture = _capture_or_404(capture_id)
    if request.form.get("confirm") != "yes":
        return _capture_page(capture, "Tick the box to confirm: the capture and its file are deleted for good."), 422
    if capture.running:
        abort(409, description="A running capture cannot be deleted. Stop it first.")
    service = _traffic()
    if service is None:
        get_store().delete_capture(capture_id)
    else:
        service.delete(capture_id)
    flash(f"Deleted the capture from {_local(capture.started_at)} and its file.")
    return redirect(url_for(".traffic"))


def _traffic_page(form: CaptureForm) -> str:
    return render_template("traffic.html", captures=get_store().captures(), **_live(form))


def _live(form: CaptureForm) -> dict:
    """What the live part of the page shows: the form, or the running capture."""
    service = _traffic()
    status = service.status() if service is not None else None
    choices, reason = [], None
    if service is None:
        reason = "packet capture is off in this NetPulse"
    elif not service.available:
        reason = service.unavailable_reason
    elif status is None or not status.running:
        try:
            choices = interface_choices(service.interfaces(), _adapters())
        except CaptureUnavailable as exc:
            reason = str(exc)
    devices = [(d.name, d.host) for d in get_store().list_live_devices()] if status is None or not status.running else []
    live = {}
    if status is not None and status.running:
        rates = service.rates()
        newest = max((s.second for s in rates), default=int(datetime.now(UTC).timestamp()))
        live = {
            "chart": rate_chart(rates, last=newest, span=RATE_WINDOW_S),
            "protocols": protocol_donut("live-protocols", service.protocols()),
            "talkers": bar_list(((t.address, t.address, t.bytes, format_bytes(t.bytes)) for t in service.talkers(10)), 10),
            "packets": service.recent(PACKET_ROWS),
        }
    return {
        "form": form,
        "status": status,
        "choices": choices,
        "reason": reason,
        "presets": filter_presets(_web_port(), devices),
        "filter_max": FILTER_MAX_LEN,
        "limits": status.limits if status is not None else CaptureLimits(),
        "duration_text": duration_text,
        "size_text": size_text,
        "page_size": PAGE_SIZE,
        **live,
    }


def _capture_or_404(capture_id: int) -> Capture:
    try:
        return get_store().get_capture(capture_id)
    except KeyError:
        abort(404)


def _file_size(service: TrafficService | None, capture: Capture) -> int | None:
    if service is None:
        return None
    try:
        return service.path_of(capture).stat().st_size
    except OSError:
        return None


def _duration(capture: Capture) -> int | None:
    if capture.ended_at is None:
        return None
    return int((datetime.fromisoformat(capture.ended_at) - datetime.fromisoformat(capture.started_at)).total_seconds())


def _local(stamp: str) -> str:
    return datetime.fromisoformat(stamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _read(path: Path, length: int) -> Iterator[bytes]:
    with path.open("rb") as file:
        left = length
        while left > 0:
            chunk = file.read(min(DOWNLOAD_CHUNK, left))
            if not chunk:
                return
            left -= len(chunk)
            yield chunk

