"""The inventory beyond one device (plan sections 39 and 42): groups, importing
and exporting the device list, deleted devices, and the availability report.

Every route is listed in README.md (tests/test_web.py checks).
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime, timedelta

from flask import Response, abort, flash, redirect, render_template, request, url_for

from netpulse.accounts import Permission
from netpulse.domain import ValidationError
from netpulse.inventory import COLUMNS, MAX_ROWS, ImportError_, export_devices, parse_devices
from netpulse.metrics import availability_window_start, report
from netpulse.store import DuplicateLiveHost
from netpulse.web.app import audit, format_duration, format_percent, get_store
from netpulse.web.security import SIGNED_IN, access
from netpulse.web.views import _FORM_ERRORS, _table_rows, bp

REPORT_DAYS = (7, 30, 90)


# Groups


def _groups_page(error: str | None = None, status: int = 200):
    return render_template("groups.html", groups=get_store().groups(), error=error), status


@bp.get("/devices/groups")
@access(SIGNED_IN)
def groups_page():
    return _groups_page()


@bp.post("/devices/groups")
@access(Permission.DEVICES_MANAGE)
def add_group():
    try:
        group = get_store().add_group(request.form.get("name", ""))
    except ValidationError as exc:
        return _groups_page(str(exc), 422)
    audit("added group", group.name)
    flash(f"Added the group {group.name}.")
    return redirect(url_for(".groups_page"))


@bp.post("/devices/groups/<int:group_id>")
@access(Permission.DEVICES_MANAGE)
def rename_group(group_id: int):
    try:
        group = get_store().rename_group(group_id, request.form.get("name", ""))
    except KeyError:
        abort(404)
    except ValidationError as exc:
        return _groups_page(str(exc), 422)
    audit("renamed group", group.name)
    flash(f"Renamed the group to {group.name}.")
    return redirect(url_for(".groups_page"))


@bp.post("/devices/groups/<int:group_id>/delete")
@access(Permission.DEVICES_MANAGE)
def delete_group(group_id: int):
    """Delete a group. Its devices stay, in no group."""
    name = next((g.name for g in get_store().groups() if g.id == group_id), None)
    if name is None:
        abort(404)
    get_store().delete_group(group_id)
    audit("deleted group", name)
    flash(f"Deleted the group {name}. Its devices are in no group now.")
    return redirect(url_for(".groups_page"))


# Deleted devices


def _deleted_page(error: str | None = None, status: int = 200):
    return render_template("deleted.html", devices=get_store().deleted_devices(), error=error), status


@bp.get("/devices/deleted")
@access(SIGNED_IN)
def deleted_devices():
    return _deleted_page()


def _deleted_or_404(device_id: int):
    try:
        device = get_store().get_device(device_id)
    except KeyError:
        abort(404)
    if device.is_live:
        abort(404)
    return device


@bp.post("/devices/<int:device_id>/restore")
@access(Permission.DEVICES_MANAGE)
def restore_device(device_id: int):
    """Bring a deleted device back with its history. Refused while a live device has its host."""
    device = _deleted_or_404(device_id)
    try:
        get_store().restore_device(device_id)
    except DuplicateLiveHost:
        return _deleted_page(
            f"{device.name} was not restored: a device with host {device.host} is being monitored already. "
            "Delete or change that one first.", 409,
        )
    audit("restored device", device.name, device.host)
    flash(f"Restored {device.name}. Checks start again within 30 s.")
    return redirect(url_for(".device_detail", device_id=device_id))


@bp.post("/devices/<int:device_id>/purge")
@access(Permission.DEVICES_MANAGE)
def purge_device(device_id: int):
    """Erase a deleted device and its whole history, once the box is ticked. There is no way back."""
    device = _deleted_or_404(device_id)
    if request.form.get("confirm") != "yes":
        return _deleted_page(f"Tick the box beside {device.name} to confirm: it and its history are erased for good.", 422)
    get_store().purge_device(device_id)
    audit("erased device", device.name, device.host)
    flash(f"Erased {device.name} and its history.")
    return redirect(url_for(".deleted_devices"))


# Import and export


@bp.get("/devices/export.csv")
@access(SIGNED_IN)
def export_csv():
    store = get_store()
    body = export_devices(store.list_live_devices(), {group.id: group.name for group in store.groups()})
    return Response(
        "﻿" + body, mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netpulse-devices.csv"'},
    )


def _import_page(*, error: str | None = None, added=(), skipped=(), text: str = "", status: int = 200):
    page = render_template(
        "import.html", columns=COLUMNS, max_rows=MAX_ROWS, error=error, added=added, skipped=skipped, text=text
    )
    return page, status


@bp.get("/devices/import")
@access(Permission.DEVICES_MANAGE)
def import_page():
    return _import_page()


@bp.post("/devices/import")
@access(Permission.DEVICES_MANAGE)
def import_devices():
    """Add the devices in a CSV file or pasted text. Each row is added or reported with the
    reason it was not; a device that is already monitored is never added twice."""
    upload = request.files.get("file")
    text = request.form.get("text", "")
    if upload is not None and upload.filename:
        raw = upload.read()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")
    try:
        rows = parse_devices(text)
    except ImportError_ as exc:
        message = str(exc)
        return _import_page(error=message[:1].upper() + message[1:] + ".", text=text[:20000], status=422)
    store = get_store()
    added, skipped = [], []
    for row in rows:
        if row.error is not None:
            skipped.append((row, row.error))
            continue
        try:
            added.append(store.add_device(row.name, row.host, inventory=row.inventory, group=row.group or None))
        except _FORM_ERRORS as exc:
            skipped.append((row, str(exc)))
    if added:
        audit("imported devices", detail=f"{len(added)} added, {len(skipped)} skipped")
    return _import_page(added=added, skipped=skipped, status=200 if added or not skipped else 422)


# The availability report (plan section 42)


def _report(days: int):
    store = get_store()
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    rows = [row for row in _table_rows() if not row.status.device.paused]
    return report(
        rows, store.availability_since(availability_window_start(now, days * 24)),
        store.events_since(since.replace(microsecond=0).isoformat()), since, now,
    )


def _days() -> int:
    days = request.args.get("days", "30")
    return int(days) if days.isdigit() and int(days) in REPORT_DAYS else 30


@bp.get("/reports")
@access(SIGNED_IN)
def reports():
    days = _days()
    return render_template("reports.html", rows=_report(days), days=days, choices=REPORT_DAYS)


@bp.get("/reports.csv")
@access(SIGNED_IN)
def reports_csv():
    days = _days()
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(["device", "host", "group", "checks", "checks up", "availability", "outages", "downtime", "longest outage"])
    for entry in _report(days):
        device = entry.row.status.device
        name = f"'{device.name}" if device.name.startswith(("=", "+", "-", "@")) else device.name
        writer.writerow([
            name, device.host, entry.row.group, entry.availability.checks, entry.availability.successes,
            format_percent(entry.availability), entry.outages, format_duration(entry.downtime_s),
            format_duration(entry.longest_s),
        ])
    return Response(
        "﻿" + out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="netpulse-availability-{days}d.csv"'},
    )
