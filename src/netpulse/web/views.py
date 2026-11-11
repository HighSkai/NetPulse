"""Routes. Every route is listed in README.md (tests/test_web.py checks).

Forms work as plain HTML posts with redirects. With HTMX loaded, the same
routes return HTML snippets instead of full pages.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from netpulse.charts import Slice, bar_list, donut, status_grid
from netpulse.checks import CHECK_INTERVAL_S, run_check
from netpulse.discovery import SWEEP_WORKERS, SweepState, SweepTarget, sweep_targets
from netpulse.domain import (
    DEGRADED_WINDOW,
    DOWN_AFTER_FAILURES,
    LATENCY_THRESHOLD_MAX_MS,
    Device,
    DeviceStatus,
    ValidationError,
    connected_through,
)
from netpulse.metrics import (
    DEFAULT_RANGE,
    RANGES,
    STATUS_FILTERS,
    DeviceRow,
    Sort,
    availability_by_device,
    availability_window_start,
    bucket_checks,
    bucket_rollups,
    by_availability,
    by_latency,
    by_state,
    device_rows,
    ledger,
    open_outages,
    outages,
    problems,
    select_rows,
    series_since,
    slowest,
    summarize,
)
from netpulse.netinfo import NetworkInfoUnavailable
from netpulse.netinfo.reader import FAILED_READ_TTL_S, GOOD_READ_TTL_S
from netpulse.network import HostState
from netpulse.ping.hosts import InvalidHost
from netpulse.ping.result import PingerUnavailable
from netpulse.store import DuplicateLiveHost, database_size
from netpulse.topology import Topology, build_topology
from netpulse.traffic import captures_folder, folder_size
from netpulse.web.app import get_network, get_pinger, get_store, get_sweeper, is_htmx
from netpulse.web.forms import Refusable

bp = Blueprint("netpulse", __name__)

HISTORY_LIMIT = 50
OUTAGE_LIMIT = 20
# Availability windows on the device page, in hours (plan section 17).
AVAILABILITY_WINDOWS = (("24 h", 24), ("7 d", 7 * 24), ("30 d", 30 * 24))
_FORM_ERRORS = (ValidationError, InvalidHost, DuplicateLiveHost)
# The overview's ledger (plan section 26): the newest events, read as each device's newest.
LEDGER_LIMIT = 20
SLOWEST_LIMIT = 10

# How each breakdown's categories are drawn: (tone, fill pattern). Colour is
# never the only signal: no two categories of a chart share a pattern.
STATE_STYLE = {"up": ("up", "solid"), "degraded": ("warn", "stripes"), "down": ("down", "hatch"), "unchecked": ("unknown", "dots")}
AVAILABILITY_STYLE = {"high": ("up", "solid"), "mid": ("warn", "stripes"), "low": ("down", "hatch"), "none": ("unknown", "dots")}
LATENCY_STYLE = {
    "fast": ("accent", "solid"),
    "good": ("select", "stripes"),
    "slow": ("warn", "dots"),
    "slowest": ("down", "hatch"),
    "none": ("unknown", "lines"),
}


@dataclass
class DeviceForm(Refusable):
    name: str = ""
    host: str = ""
    parent: str = ""  # Connected through, on the edit form only (plan section 20)
    error: str | None = None
    error_field: str | None = None

    FIELDS = (("name", r"^name\b"), ("host", r"^host\b|with host"), ("parent", r"connect|choose a device|that device"))

    @classmethod
    def from_request(cls) -> DeviceForm:
        return cls(
            name=request.form.get("name", ""),
            host=request.form.get("host", ""),
            parent=request.form.get("parent", ""),
        )



@dataclass
class SettingsForm(Refusable):
    """The settings page's fields, as typed, so a rejected form keeps them (plan section 18)."""

    latency_ms: str
    failures: str
    error: str | None = None
    error_field: str | None = None

    FIELDS = (("latency_ms", r"latency"), ("failures", r"failure"))

    @classmethod
    def from_request(cls) -> SettingsForm:
        return cls(latency_ms=request.form.get("latency_ms", ""), failures=request.form.get("failures", ""))



@dataclass
class SweepForm(Refusable):
    """The discovery page's sweep form (plan section 21)."""

    error: str | None = None
    error_field: str | None = None

    FIELDS = (("confirm", r"tick the box"), ("network", r"subnet"))


@dataclass(frozen=True)
class DeviceView:
    """The table's search, filter and sort, from the q, status, sort and dir parameters.

    Plan section 16: the server owns the view, so the URL, the poll and every
    form carry it. Unknown values fall back to the defaults.
    """

    q: str = ""
    status: str = "all"
    sort: str = Sort.NAME
    direction: str = "asc"

    @classmethod
    def from_values(cls, values: Mapping[str, str]) -> DeviceView:
        status, sort, direction = values.get("status"), values.get("sort"), values.get("dir")
        return cls(
            q=values.get("q", "").strip()[:100],
            status=status if status in STATUS_FILTERS else "all",
            sort=sort if sort in Sort.ALL else Sort.NAME,
            direction=direction if direction in ("asc", "desc") else "asc",
        )

    @property
    def is_filtered(self) -> bool:
        return bool(self.q) or self.status != "all"

    @property
    def params(self) -> dict[str, str]:
        """URL parameters for this view, leaving out defaults."""
        return _non_default(q=self.q, status=self.status, sort=self.sort, dir=self.direction)

    def sorted_by(self, key: str) -> dict[str, str]:
        """URL parameters for a header link: ascending first, then the reverse."""
        direction = "desc" if self.sort == key and self.direction == "asc" else "asc"
        return _non_default(q=self.q, status=self.status, sort=key, dir=direction)

    def select(self, rows: list[DeviceRow]) -> list[DeviceRow]:
        return select_rows(
            rows, q=self.q, status=self.status, sort=self.sort, descending=self.direction == "desc"
        )


_DEFAULT_PARAMS = {"q": "", "status": "all", "sort": Sort.NAME, "dir": "asc"}


def _non_default(**params: str) -> dict[str, str]:
    return {key: value for key, value in params.items() if value != _DEFAULT_PARAMS[key]}


@bp.get("/")
def overview():
    """Problems first, then breakdowns, then history (plan section 26).

    Five statements: statuses, recent checks, thresholds, the 24 h rollups
    (which give both the availability and the status grid), and the events.
    """
    if _DEVICE_VIEW_PARAMS & request.args.keys():
        # The device table lived here until plan section 26; old bookmarks keep working.
        return redirect(url_for(".dashboard", **request.args.to_dict()))
    store = get_store()
    now = datetime.now(UTC)
    rollups = store.rollups_since(availability_window_start(now))
    rows = device_rows(
        store.live_device_statuses(), availability_by_device(rollups), store.recent_checks(), store.thresholds()
    )
    events = store.latest_events(LEDGER_LIMIT)
    return render_template(
        "overview.html",
        summary=summarize(rows),
        problems=problems(rows, open_outages(events)),
        charts=[
            donut("state", "Devices by state", _slices(by_state(rows), STATE_STYLE), unit="devices"),
            donut("availability", "Checks up, 24 h", _slices(by_availability(rows), AVAILABILITY_STYLE), unit="devices"),
            donut("latency", "Average latency", _slices(by_latency(rows), LATENCY_STYLE), unit="devices"),
        ],
        slowest=bar_list(slowest(rows), SLOWEST_LIMIT),
        ledger=ledger(events, now, LEDGER_LIMIT),
        names={row.status.device.id: row.status.device.name for row in rows},
        grid=status_grid(((row.status.device.id, row.status.device.name) for row in rows), rollups, now),
        down_after=DOWN_AFTER_FAILURES,
        now=now,
    )


_DEVICE_VIEW_PARAMS = {"q", "status", "sort", "dir"}


def _slices(breakdown: list[tuple[str, str, int]], style: Mapping[str, tuple[str, str]]) -> list[Slice]:
    return [Slice(key, label, count, *style[key]) for key, label, count in breakdown]


@bp.get("/devices")
def dashboard():
    """The device table, at its own address since plan section 26."""
    return _dashboard_page(DeviceForm(), _view())


@bp.get("/devices/rows", endpoint="device_rows")
def device_rows_fragment():
    return _rows(_view())


@bp.get("/status")
def status_bar():
    """The monitoring status bar (plan section 13). Reads the heartbeat, not the database.

    With HTMX it also brings the capture banner (plan section 28), out of band.
    """
    bar = render_template("_status_bar.html")
    return bar + render_template("_capture_banner.html", oob=True) if is_htmx() else bar


@bp.post("/devices")
def add_device():
    form = DeviceForm.from_request()
    try:
        get_store().add_device(form.name, form.host)
    except _FORM_ERRORS as exc:
        form.fail(exc)
        if is_htmx():
            return render_template("_add_form.html", form=form), 422
        return _dashboard_page(form, DeviceView()), 422
    if is_htmx():
        return render_template("_add_form.html", form=DeviceForm()) + _rows(_view(), oob=True)
    return redirect(url_for(".dashboard"))


@bp.get("/devices/<int:device_id>")
def device_detail(device_id: int):
    """Facts, charts, outages and recent checks for one device (plan section 17)."""
    device = _live_device_or_404(device_id)
    store = get_store()
    now = datetime.now(UTC)
    chart_range = RANGES.get(request.args.get("range", ""), RANGES[DEFAULT_RANGE])
    since = series_since(chart_range, now)
    if chart_range.from_rollups:
        series = bucket_rollups(store.hourly_rollups(device_id, since), chart_range, now)
    else:
        series = bucket_checks(store.checks_since(device_id, since), chart_range, now)
    history = store.history(device_id, limit=HISTORY_LIMIT)
    thresholds = store.thresholds()
    parent_id = store.links().get(device_id)
    # The same judgement as the dashboard row; the latest checks are already in history.
    [row] = device_rows(
        [DeviceStatus(device, history[0] if history else None)], {}, {device_id: history}, thresholds
    )
    return render_template(
        "device.html",
        device=device,
        view=_view(),
        row=row,
        parent=store.get_device(parent_id) if parent_id is not None else None,
        thresholds=thresholds,
        window=DEGRADED_WINDOW,
        last_up=store.last_success(device_id),
        availability=[
            (label, store.availability_of(device_id, availability_window_start(now, hours)))
            for label, hours in AVAILABILITY_WINDOWS
        ],
        series=series,
        ranges=RANGES.values(),
        # Two events per outage, plus one for an outage still going on.
        outages=outages(store.events(device_id, limit=2 * OUTAGE_LIMIT + 1))[:OUTAGE_LIMIT],
        down_after=DOWN_AFTER_FAILURES,
        now=now,
        history=history,
        limit=HISTORY_LIMIT,
    )


@bp.get("/devices/<int:device_id>/edit")
def edit_device(device_id: int):
    device = _live_device_or_404(device_id)
    parent_id = get_store().links().get(device_id)
    form = DeviceForm(device.name, device.host, "" if parent_id is None else str(parent_id))
    return _edit_page(device, form)


@bp.post("/devices/<int:device_id>/edit")
def update_device(device_id: int):
    device = _live_device_or_404(device_id)
    form = DeviceForm.from_request()
    try:
        get_store().update_device(device_id, name=form.name, host=form.host, parent_id=form.parent)
    except _FORM_ERRORS as exc:
        return _edit_page(device, form.fail(exc)), 422
    return redirect(url_for(".dashboard", **_view().params))


def _edit_page(device: Device, form: DeviceForm) -> str:
    """The edit form. Connected through lists only the devices that would not make a loop."""
    store = get_store()
    below = connected_through(device.id, store.links())
    choices = [d for d in store.list_live_devices() if d.id != device.id and d.id not in below]
    return render_template("edit.html", device=device, form=form, choices=choices, view=_view())


@bp.post("/devices/<int:device_id>/check")
def check_device(device_id: int):
    _live_device_or_404(device_id)
    try:
        run_check(get_store(), get_pinger(), device_id)
    except PingerUnavailable as exc:
        # A fault on this PC, not the device being down (plan section 13).
        abort(503, description=f"NetPulse cannot ping from this PC: {exc}. Nothing was stored.")
    if is_htmx():
        [row] = [r for r in _table_rows() if r.status.device.id == device_id]
        return render_template("_device_row.html", row=row, flash=True, view=_view())
    if request.form.get("return") == "device":  # the device page's own button (plan section 17)
        return redirect(url_for(".device_detail", device_id=device_id, **_view().params))
    return redirect(url_for(".dashboard", **_view().params))


@bp.get("/settings")
def settings():
    """Degraded thresholds, and the numbers that are fixed (plan section 18)."""
    current = get_store().thresholds()
    return _settings_page(SettingsForm(str(current.latency_ms), str(current.failures)))


@bp.post("/settings")
def save_settings():
    form = SettingsForm.from_request()
    try:
        get_store().save_thresholds(form.latency_ms, form.failures)
    except ValidationError as exc:
        return _settings_page(form.fail(exc)), 422
    flash("Saved.")
    return redirect(url_for(".settings"))


def _settings_page(form: SettingsForm) -> str:
    database = Path(current_app.config["NETPULSE_DB"])
    folder = captures_folder(database)
    files, folder_bytes = folder_size(folder)
    return render_template(
        "settings.html",
        form=form,
        # Plan section 32: what NetPulse keeps on this PC, read from the disk on each visit.
        database=database,
        database_bytes=database_size(database),
        folder=folder,
        capture_files=files,
        capture_bytes=folder_bytes,
        window=DEGRADED_WINDOW,
        latency_max=LATENCY_THRESHOLD_MAX_MS,
        interval_s=CHECK_INTERVAL_S,
        down_after=DOWN_AFTER_FAILURES,
    )


@bp.get("/network")
def network():
    """This PC's network settings, as Windows reports them (plan section 19), and
    what Windows and NetPulse already know about the router (plan section 22)."""
    try:
        info, error = get_network().read(), None
    except NetworkInfoUnavailable as exc:
        info, error = None, str(exc)
    gateway_row, gateway_name = None, None
    if info is not None and info.preferred_gateway is not None:
        gateway = str(info.preferred_gateway)
        gateway_row = next((r for r in _table_rows() if r.status.device.host == gateway), None)
        gateway_name = next((h.name for h in get_store().discovered() if str(h.address) == gateway and h.name), None)
    return render_template(
        "network.html",
        info=info,
        error=error,
        gateway_row=gateway_row,
        gateway_device=gateway_row.status.device if gateway_row is not None else None,
        gateway_name=gateway_name,
        # Only linked to, never opened or read by NetPulse.
        admin_url=f"http://{info.preferred_gateway}/" if info and info.preferred_gateway else None,
        good_read_min=GOOD_READ_TTL_S // 60,
        failed_read_s=FAILED_READ_TTL_S,
    )


@bp.post("/network/refresh")
def refresh_network():
    get_network().refresh()
    return redirect(url_for(".network"))


@bp.get("/map")
def topology_map():
    """This PC, its subnets and gateways, and every device, with each line's evidence (plan section 19)."""
    return render_template("map.html", topology=_topology())


@bp.get("/map/view")
def map_view():
    """The map's list and data, polled like the device table."""
    return render_template("_map_view.html", topology=_topology())


@bp.get("/discover")
def discover():
    """Sweep one of this PC's subnets, and review what was found (plan section 21)."""
    return _discover_page()


@bp.get("/discover/view")
def discover_view():
    """The sweep's progress and the review list. Refreshes itself while a sweep runs."""
    return render_template("_discover_view.html", **_review())


@bp.post("/discover")
def start_sweep():
    sweeper = get_sweeper()
    targets, _ = _targets()
    chosen = next((t for t in targets if str(t.network) == request.form.get("network")), None)
    if sweeper is None:
        return _discover_page(SweepForm().fail("this NetPulse was started without a way to sweep")), 503
    if chosen is None:
        return _discover_page(SweepForm().fail("choose one of this PC's subnets")), 422
    if chosen.needs_confirmation and request.form.get("confirm") != "yes":
        return _discover_page(SweepForm().fail(
            f"Windows marks the network on {chosen.adapter} as Public. "
            "Tick the box to confirm it is a network you own or manage."
        )), 422
    if not sweeper.start(chosen):
        flash("A sweep is already running.")
    return redirect(url_for(".discover"))


@bp.post("/discover/<int:host_id>/accept")
def accept_host(host_id: int):
    try:
        device = get_store().accept_discovered(host_id)
    except KeyError:
        abort(404)
    except _FORM_ERRORS as exc:
        flash(f"Could not monitor that host: {exc}.")
    else:
        flash(f"Monitoring {device.name}.")
    return redirect(url_for(".discover"))


@bp.post("/discover/<int:host_id>/ignore")
def ignore_host(host_id: int):
    _discovered_or_404(get_store().ignore_discovered, host_id)
    return redirect(url_for(".discover"))


@bp.post("/discover/<int:host_id>/restore")
def restore_host(host_id: int):
    _discovered_or_404(get_store().restore_discovered, host_id)
    return redirect(url_for(".discover"))


def _discovered_or_404(action, host_id: int) -> None:
    try:
        action(host_id)
    except KeyError:
        abort(404)


def _targets() -> tuple[list[SweepTarget], str | None]:
    """The subnets a sweep may cover, from the cached network read, or why there are none."""
    try:
        return sweep_targets(get_network().read()), None
    except NetworkInfoUnavailable as exc:
        return [], str(exc)


def _discover_page(form: SweepForm | None = None) -> str:
    targets, network_error = _targets()
    return render_template(
        "discover.html",
        form=form or SweepForm(),
        targets=targets,
        network_error=network_error,
        can_sweep=get_sweeper() is not None,
        workers=SWEEP_WORKERS,
        **_review(),
    )


def _review() -> dict:
    """The review list in its three groups, and the sweep's status."""
    store = get_store()
    live = store.list_live_devices()
    by_id = {d.id: d for d in live}
    by_host = {d.host.casefold(): d for d in live}
    hosts = store.discovered()
    sweeper = get_sweeper()
    return {
        "status": sweeper.status() if sweeper is not None else None,
        "running": SweepState.RUNNING,
        "new": [(h, by_host.get(str(h.address))) for h in hosts if h.state == HostState.NEW],
        "accepted": [(h, by_id.get(h.device_id)) for h in hosts if h.state == HostState.ACCEPTED],
        "ignored": [h for h in hosts if h.state == HostState.IGNORED],
    }


@bp.post("/devices/<int:device_id>/delete")
def delete_device(device_id: int):
    _live_device_or_404(device_id)
    get_store().soft_delete(device_id)
    if is_htmx():
        return _rows(_view())
    return redirect(url_for(".dashboard"))


def _view() -> DeviceView:
    """GET parameters, or form fields sent along with a POST (hx-include)."""
    return DeviceView.from_values(request.values)


def _table_rows() -> list[DeviceRow]:
    """Every live device with its latest check, 24 h availability and degraded verdict.

    Four small queries: statuses, availability, recent checks, thresholds.
    """
    store = get_store()
    window = availability_window_start(datetime.now(UTC))
    return device_rows(
        store.live_device_statuses(),
        store.availability_since(window),
        store.recent_checks(),
        store.thresholds(),
    )


def _topology() -> Topology:
    """The map's tree from the dashboard's rows, the declared links and the cached network read."""
    rows, links = _table_rows(), get_store().links()
    try:
        info = get_network().read()
    except NetworkInfoUnavailable as exc:
        return build_topology(None, rows, links, network_error=str(exc))
    return build_topology(info, rows, links)


def _dashboard_page(form: DeviceForm, view: DeviceView) -> str:
    rows = _table_rows()
    return render_template("dashboard.html", form=form, view=view, rows=view.select(rows), total=len(rows))


def _rows(view: DeviceView, *, oob: bool = False) -> str:
    """The table body for this view."""
    rows = _table_rows()
    return render_template("_device_rows.html", rows=view.select(rows), total=len(rows), view=view, oob=oob)


def _live_device_or_404(device_id: int) -> Device:
    """Deleted devices are hidden from the UI in v1 (no Retired view)."""
    try:
        device = get_store().get_device(device_id)
    except KeyError:
        abort(404)
    if not device.is_live:
        abort(404)
    return device
