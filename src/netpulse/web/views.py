"""Routes. Every route is listed in README.md (tests/test_web.py checks).

Forms work as plain HTML posts with redirects. With HTMX loaded, the same
routes return HTML snippets instead of full pages.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from netpulse.accounts import Permission
from netpulse.charts import Slice, bar_list, donut, status_grid
from netpulse.checks import CHECK_INTERVAL_S, run_check
from netpulse.diagnosis import diagnose
from netpulse.discovery import (
    SCHEDULE_KEY,
    SCHEDULE_NETWORK_KEY,
    SCHEDULES_MIN,
    SWEEP_WORKERS,
    SweepState,
    SweepTarget,
    sweep_targets,
)
from netpulse.domain import (
    CHECK_INTERVALS,
    DEGRADED_WINDOW,
    DOWN_AFTER_FAILURES,
    LATENCY_THRESHOLD_MAX_MS,
    CheckKind,
    Device,
    DeviceKind,
    DeviceState,
    DeviceStatus,
    Inventory,
    ValidationError,
    connected_through,
    guess_kind,
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
from netpulse.store import RAW_DAYS_CHOICES, UNCHANGED, DuplicateLiveHost, database_size
from netpulse.topology import Topology, build_topology
from netpulse.traffic import captures_folder, folder_size
from netpulse.web.app import audit, get_network, get_pinger, get_store, get_sweeper, get_tcp, is_htmx
from netpulse.web.forms import Refusable
from netpulse.web.security import SIGNED_IN, access, can

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
    """A device's fields, as typed, so a refused form keeps them. Everything after
    parent is inventory and how the device is checked (plan sections 39 and 40)."""

    name: str = ""
    host: str = ""
    parent: str = ""  # Connected through, on the edit form only (plan section 20)
    kind: str = DeviceKind.UNKNOWN
    group: str = ""  # a group's id, as the select sends it
    new_group: str = ""  # or the name of a group to make
    vendor: str = ""
    model: str = ""
    location: str = ""
    notes: str = ""
    mac: str = ""
    tags: str = ""
    interval_s: str = "30"
    check_kind: str = CheckKind.ICMP
    check_port: str = ""
    paused: str = ""
    alerts_muted: str = ""
    error: str | None = None
    error_field: str | None = None

    FIELDS = (
        ("name", r"^name\b"), ("host", r"^host\b|with host"), ("parent", r"connect|choose a device|that device"),
        ("kind", r"^type\b"), ("new_group", r"group"), ("vendor", r"^vendor"), ("model", r"^model"),
        ("location", r"^location"), ("notes", r"^notes"), ("mac", r"^mac\b"), ("tags", r"^tags"),
        ("interval_s", r"^interval"), ("check_port", r"^port"), ("check_kind", r"^check"),
    )
    _TYPED = ("name", "host", "parent", "kind", "group", "new_group", "vendor", "model", "location", "notes", "mac",
              "tags", "interval_s", "check_kind", "check_port", "paused", "alerts_muted")

    @classmethod
    def from_request(cls) -> DeviceForm:
        defaults = cls()
        return cls(**{name: request.form.get(name, getattr(defaults, name)) for name in cls._TYPED})

    @classmethod
    def of(cls, device: Device, parent_id: int | None) -> DeviceForm:
        """The edit form as it opens: the device as stored."""
        return cls(
            name=device.name, host=device.host, parent="" if parent_id is None else str(parent_id), kind=device.kind,
            group="" if device.group_id is None else str(device.group_id), vendor=device.vendor, model=device.model,
            location=device.location, notes=device.notes, mac=device.mac or "", tags=", ".join(device.tags),
            interval_s=str(device.interval_s), check_kind=device.check_kind,
            check_port="" if device.check_port is None else str(device.check_port),
            paused="yes" if device.paused else "", alerts_muted="yes" if device.alerts_muted else "",
        )

    def inventory(self) -> Inventory:
        """Raises ValidationError naming the field."""
        return Inventory.of({f.name: getattr(self, f.name) for f in fields(self)})

    def group_choice(self) -> str | None:
        """A new group's name if one was typed, else the chosen group's id, else None."""
        return self.new_group.strip() or self.group.strip() or None



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
    kind: str = ""  # plan section 39: a device type, a group's id ("0": in no group), a tag
    group: str = ""
    tag: str = ""

    @classmethod
    def from_values(cls, values: Mapping[str, str]) -> DeviceView:
        status, sort, direction = values.get("status"), values.get("sort"), values.get("dir")
        kind, group = values.get("kind", ""), values.get("group", "").strip()
        return cls(
            q=values.get("q", "").strip()[:100],
            status=status if status in STATUS_FILTERS else "all",
            sort=sort if sort in Sort.ALL else Sort.NAME,
            direction=direction if direction in ("asc", "desc") else "asc",
            kind=kind if kind in DeviceKind.ALL else "",
            group=group if group.isdigit() and len(group) < 10 else "",
            tag=" ".join(values.get("tag", "").split()).casefold()[:32],
        )

    @property
    def is_filtered(self) -> bool:
        return bool(self.q or self.kind or self.group or self.tag) or self.status != "all"

    @property
    def params(self) -> dict[str, str]:
        """URL parameters for this view, leaving out defaults."""
        return self._params(self.sort, self.direction)

    def _params(self, sort: str, direction: str) -> dict[str, str]:
        return _non_default(
            q=self.q, status=self.status, sort=sort, dir=direction, kind=self.kind, group=self.group, tag=self.tag
        )

    def sorted_by(self, key: str) -> dict[str, str]:
        """URL parameters for a header link: ascending first, then the reverse."""
        direction = "desc" if self.sort == key and self.direction == "asc" else "asc"
        return self._params(key, direction)

    def select(self, rows: list[DeviceRow]) -> list[DeviceRow]:
        return select_rows(
            rows, q=self.q, status=self.status, sort=self.sort, descending=self.direction == "desc",
            kind=self.kind, group=int(self.group) if self.group else None, tag=self.tag,
        )


_DEFAULT_PARAMS = {"q": "", "status": "all", "sort": Sort.NAME, "dir": "asc", "kind": "", "group": "", "tag": ""}


def _non_default(**params: str) -> dict[str, str]:
    return {key: value for key, value in params.items() if value != _DEFAULT_PARAMS[key]}


@bp.get("/")
@access(SIGNED_IN)
def overview():
    """Problems first, then breakdowns, then history (plan section 26).

    Statuses, recent checks, thresholds, the 24 h rollups (which give both the
    availability and the status grid), and the events. A paused device is
    counted, and otherwise left out: nothing is being measured about it.
    """
    if _DEVICE_VIEW_PARAMS & request.args.keys():
        # The device table lived here until plan section 26; old bookmarks keep working.
        return redirect(url_for(".dashboard", **request.args.to_dict()))
    store = get_store()
    now = datetime.now(UTC)
    rollups = store.rollups_since(availability_window_start(now))
    every = device_rows(
        store.live_device_statuses(), availability_by_device(rollups), store.recent_checks(), store.thresholds()
    )
    rows = [row for row in every if not row.status.device.paused]
    events = store.latest_events(LEDGER_LIMIT)
    return render_template(
        "overview.html",
        summary=summarize(every),
        findings=_findings(rows),
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


def _findings(rows: list[DeviceRow]) -> list:
    """What the devices that are down may have in common (plan section 41). Asked only
    when at least two are, so a quiet network never waits on the network settings."""
    if sum(1 for row in rows if row.state == DeviceState.DOWN) < 2:
        return []
    store = get_store()
    try:
        info = get_network().read()
    except NetworkInfoUnavailable:
        info = None
    return diagnose(rows, store.links(), info, {group.id: group.name for group in store.groups()})


def _slices(breakdown: list[tuple[str, str, int]], style: Mapping[str, tuple[str, str]]) -> list[Slice]:
    return [Slice(key, label, count, *style[key]) for key, label, count in breakdown]


@bp.get("/devices")
@access(SIGNED_IN)
def dashboard():
    """The device table, at its own address since plan section 26."""
    return _dashboard_page(DeviceForm(), _view())


@bp.get("/devices/rows", endpoint="device_rows")
@access(SIGNED_IN)
def device_rows_fragment():
    return _rows(_view())


@bp.get("/status")
@access(SIGNED_IN)
def status_bar():
    """The monitoring status bar (plan section 13). Reads the heartbeat, not the database.

    With HTMX it also brings the capture banner (plan section 28), out of band.
    """
    bar = render_template("_status_bar.html")
    return bar + render_template("_capture_banner.html", oob=True) if is_htmx() else bar


@bp.post("/devices")
@access(Permission.DEVICES_MANAGE)
def add_device():
    form = DeviceForm.from_request()
    try:
        device = get_store().add_device(form.name, form.host, inventory=form.inventory(), group=form.group_choice())
    except _FORM_ERRORS as exc:
        form.fail(exc)
        if is_htmx():
            return render_template("_add_form.html", form=form, groups=get_store().groups()), 422
        return _dashboard_page(form, DeviceView()), 422
    audit("added device", device.name, device.host)
    if is_htmx():
        return render_template("_add_form.html", form=DeviceForm(), groups=get_store().groups(), added=device) + _rows(_view(), oob=True)
    flash(f"Added {device.name}. Its first check runs within {CHECK_INTERVAL_S} s.")
    return redirect(url_for(".dashboard"))


@bp.get("/devices/<int:device_id>")
@access(SIGNED_IN)
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
        last_up=store.last_up_at(device_id),
        group=next((g.name for g in store.groups() if g.id == device.group_id), None),
        found=next((h for h in store.discovered() if h.device_id == device_id), None),
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
@access(Permission.DEVICES_MANAGE)
def edit_device(device_id: int):
    device = _live_device_or_404(device_id)
    return _edit_page(device, DeviceForm.of(device, get_store().links().get(device_id)))


@bp.post("/devices/<int:device_id>/edit")
@access(Permission.DEVICES_MANAGE)
def update_device(device_id: int):
    device = _live_device_or_404(device_id)
    form = DeviceForm.from_request()
    # The edit page sends every inventory field and says so. A form that sends
    # only a name and a host changes only those.
    whole = request.form.get("inventory") == "yes"
    try:
        saved = get_store().update_device(
            device_id, name=form.name, host=form.host, parent_id=form.parent,
            inventory=form.inventory() if whole else UNCHANGED,
            group=form.group_choice() if whole else UNCHANGED,
        )
    except _FORM_ERRORS as exc:
        return _edit_page(device, form.fail(exc)), 422
    changed = f"host {device.host} to {saved.host}" if saved.host != device.host else ""
    audit("edited device", saved.name, changed)
    flash(f"Saved {saved.name}.")
    if request.form.get("return") == "device":
        return redirect(url_for(".device_detail", device_id=device_id, **_view().params))
    return redirect(url_for(".dashboard", **_view().params))


def _edit_page(device: Device, form: DeviceForm) -> str:
    """The edit form. Connected through lists only the devices that would not make a loop."""
    store = get_store()
    below = connected_through(device.id, store.links())
    choices = [d for d in store.list_live_devices() if d.id != device.id and d.id not in below]
    # A guess from the name, offered only while no type is set, and called a guess.
    suggested = None if device.kind != DeviceKind.UNKNOWN else guess_kind(device.name) or guess_kind(device.host)
    return render_template(
        "edit.html", device=device, form=form, choices=choices, view=_view(), groups=store.groups(),
        kinds=DeviceKind.LABELS, check_kinds=CheckKind.LABELS, intervals=CHECK_INTERVALS,
        suggested=suggested,
    )


@bp.post("/devices/<int:device_id>/pause")
@access(Permission.DEVICES_MANAGE)
def pause_device(device_id: int):
    """Pause or resume a device's checks (plan section 40): `paused=yes` pauses."""
    device = _live_device_or_404(device_id)
    paused = request.form.get("paused") == "yes"
    get_store().set_paused(device_id, paused)
    audit("paused device" if paused else "resumed device", device.name)
    if is_htmx():
        [row] = [r for r in _table_rows() if r.status.device.id == device_id]
        return render_template("_device_row.html", row=row, flash=True, view=_view())
    flash(f"{'Paused' if paused else 'Resumed'} {device.name}.")
    if request.form.get("return") == "device":
        return redirect(url_for(".device_detail", device_id=device_id, **_view().params))
    return redirect(url_for(".dashboard", **_view().params))


@bp.post("/devices/<int:device_id>/check")
@access(Permission.CHECKS_RUN)
def check_device(device_id: int):
    _live_device_or_404(device_id)
    try:
        run_check(get_store(), get_pinger(), device_id, tcp=get_tcp())
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
@access(SIGNED_IN)
def settings():
    """Degraded thresholds, and the numbers that are fixed (plan section 18)."""
    current = get_store().thresholds()
    return _settings_page(SettingsForm(str(current.latency_ms), str(current.failures)))


@bp.post("/settings")
@access(Permission.SETTINGS_MANAGE)
def save_settings():
    form = SettingsForm.from_request()
    try:
        saved = get_store().save_thresholds(form.latency_ms, form.failures)
    except ValidationError as exc:
        return _settings_page(form.fail(exc)), 422
    audit("changed thresholds", detail=f"slow above {saved.latency_ms} ms, failing at {saved.failures} of {DEGRADED_WINDOW}")
    flash("Saved the thresholds.")
    return redirect(url_for(".settings"))


@bp.post("/settings/retention")
@access(Permission.SETTINGS_MANAGE)
def save_retention():
    """How long single checks are kept (plan section 42)."""
    try:
        days = get_store().save_raw_days(request.form.get("raw_days", ""))
    except ValidationError as exc:
        flash(f"Not saved: {exc}.", "error")
        return redirect(url_for(".settings") + "#disk-heading")
    audit("changed retention", detail="keeps every check" if days == 0 else f"keeps checks {days} days")
    flash("Saved. Older checks go at the next hourly upkeep." if days else "Saved. Every check is kept.")
    return redirect(url_for(".settings") + "#disk-heading")


@bp.post("/settings/discovery")
@access(Permission.SETTINGS_MANAGE)
def save_discovery_schedule():
    """Sweeps on a schedule (plan section 41): how often, and which of this PC's subnets."""
    every = request.form.get("every_min", "0")
    targets, _ = _targets()
    chosen = next((t for t in targets if str(t.network) == request.form.get("network")), None)
    if not every.isdigit() or int(every) not in SCHEDULES_MIN:
        flash("Not saved: choose one of the schedules offered.", "error")
    elif int(every) and chosen is None:
        flash("Not saved: choose one of this PC's subnets.", "error")
    elif int(every) and chosen.needs_confirmation:
        flash("Not saved: Windows marks that network as Public, and NetPulse does not sweep a public network by itself.", "error")
    else:
        get_store().set_settings({SCHEDULE_KEY: int(every), SCHEDULE_NETWORK_KEY: str(chosen.network) if chosen else None})
        audit("changed sweep schedule", detail=f"every {every} min on {chosen.network}" if int(every) else "off")
        flash("Saved the sweep schedule.")
    return redirect(url_for(".discover"))


def _settings_page(form: SettingsForm) -> str:
    database = Path(current_app.config["NETPULSE_DB"])
    folder = captures_folder(database)
    files, folder_bytes = folder_size(folder)
    store = get_store()
    return render_template(
        "settings.html",
        form=form,
        raw_days=store.raw_days(),
        raw_days_choices=RAW_DAYS_CHOICES,
        counts=store.counts() if can(Permission.SETTINGS_MANAGE) else None,
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
@access(SIGNED_IN)
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
@access(Permission.DIAGNOSTICS_RUN)
def refresh_network():
    get_network().refresh()
    return redirect(url_for(".network"))


@bp.get("/map")
@access(SIGNED_IN)
def topology_map():
    """This PC, its subnets and gateways, and every device, with each line's evidence (plan section 19)."""
    return render_template("map.html", topology=_topology())


@bp.get("/map/view")
@access(SIGNED_IN)
def map_view():
    """The map's list and data, polled like the device table."""
    return render_template("_map_view.html", topology=_topology())


@bp.get("/discover")
@access(SIGNED_IN)
def discover():
    """Sweep one of this PC's subnets, and review what was found (plan section 21)."""
    return _discover_page()


@bp.get("/discover/view")
@access(SIGNED_IN)
def discover_view():
    """The sweep's progress and the review list. Refreshes itself while a sweep runs."""
    return render_template("_discover_view.html", **_review())


@bp.post("/discover")
@access(Permission.DISCOVERY_RUN)
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
    else:
        audit("started sweep", str(chosen.network))
    return redirect(url_for(".discover"))


@bp.post("/discover/<int:host_id>/accept")
@access(Permission.DEVICES_MANAGE)
def accept_host(host_id: int):
    try:
        device = get_store().accept_discovered(host_id)
    except KeyError:
        abort(404)
    except _FORM_ERRORS as exc:
        flash(f"Could not monitor that host: {exc}.", "error")
    else:
        audit("accepted discovered host", device.name, device.host)
        flash(f"Monitoring {device.name}.")
    return redirect(url_for(".discover"))


@bp.post("/discover/<int:host_id>/ignore")
@access(Permission.DEVICES_MANAGE)
def ignore_host(host_id: int):
    _discovered_or_404(get_store().ignore_discovered, host_id)
    return redirect(url_for(".discover"))


@bp.post("/discover/<int:host_id>/restore")
@access(Permission.DEVICES_MANAGE)
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
    store = get_store()
    return render_template(
        "discover.html",
        form=form or SweepForm(),
        targets=targets,
        network_error=network_error,
        can_sweep=get_sweeper() is not None,
        workers=SWEEP_WORKERS,
        schedules=SCHEDULES_MIN,
        schedule=store.setting(SCHEDULE_KEY, 0),
        schedule_network=store.setting(SCHEDULE_NETWORK_KEY),
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
        "guess": guess_kind,
        "kinds": DeviceKind.LABELS,
        "new": [(h, by_host.get(str(h.address))) for h in hosts if h.state == HostState.NEW],
        "accepted": [(h, by_id.get(h.device_id)) for h in hosts if h.state == HostState.ACCEPTED],
        "ignored": [h for h in hosts if h.state == HostState.IGNORED],
    }


@bp.post("/devices/<int:device_id>/delete")
@access(Permission.DEVICES_MANAGE)
def delete_device(device_id: int):
    device = _live_device_or_404(device_id)
    get_store().soft_delete(device_id)
    audit("deleted device", device.name, device.host)
    if is_htmx():
        return _rows(_view())
    flash(f"Deleted {device.name}. Its history is kept, and it can be restored from the deleted devices list.")
    return redirect(url_for(".dashboard"))


def _view() -> DeviceView:
    """GET parameters, or form fields sent along with a POST (hx-include)."""
    return DeviceView.from_values(request.values)


def _table_rows(groups=None) -> list[DeviceRow]:
    """Every live device with its latest check, 24 h availability and degraded verdict.

    Six small queries: statuses and their tags, availability, recent checks,
    thresholds, and the groups, unless the caller has read those already.
    """
    store = get_store()
    window = availability_window_start(datetime.now(UTC))
    return device_rows(
        store.live_device_statuses(),
        store.availability_since(window),
        store.recent_checks(),
        store.thresholds(),
        {group.id: group.name for group in (store.groups() if groups is None else groups)},
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
    store = get_store()
    groups = store.groups()
    rows = _table_rows(groups)
    return render_template(
        "dashboard.html", form=form, view=view, rows=view.select(rows), total=len(rows), groups=groups,
        kinds=DeviceKind.LABELS, used_kinds=sorted({r.status.device.kind for r in rows} - {DeviceKind.UNKNOWN}),
        tags=store.tags(), check_kinds=CheckKind.LABELS, deleted=store.count_deleted_devices(),
    )


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
