"""Device lists as CSV (plan section 39): importing many devices at once, and exporting them.

Pure functions: text in, values out. The store adds the devices; this module
only reads the file and says, row by row, what is wrong with it.

- The first line names the columns. Only `name` and `host` are needed; the
  rest are the inventory fields, by the names COLUMNS lists.
- A row that cannot be a device is reported with its line number and the
  reason, and the other rows are still read: one typing mistake does not
  throw away a list of sixty devices.
- An exported file imports again unchanged. A cell that a spreadsheet would
  run as a formula is written with a leading apostrophe, and read back without it.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from netpulse.domain import Device, Inventory, ValidationError, validate_name

MAX_ROWS = 2000
COLUMNS = (
    "name", "host", "type", "group", "location", "vendor", "model", "mac", "tags", "notes", "check", "port",
    "interval", "paused",
)
# Other headings people use for the same columns.
_ALIASES = {
    "address": "host", "ip": "host", "ip address": "host", "hostname": "host", "device": "name", "kind": "type",
    "category": "type", "manufacturer": "vendor", "mac address": "mac", "note": "notes", "description": "notes",
    "room": "location", "check_kind": "check", "check_port": "port", "interval_s": "interval",
}
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


class ImportError_(ValueError):
    """The file as a whole cannot be read as a device list."""


@dataclass(frozen=True)
class ImportRow:
    line: int  # in the file, the heading being line 1
    name: str
    host: str
    inventory: Inventory | None
    group: str
    error: str | None = None


def _unguard(cell: str) -> str:
    cell = cell.strip()
    return cell[1:] if len(cell) > 1 and cell[0] == "'" and cell[1] in _FORMULA_STARTS else cell


def _guard(cell: str) -> str:
    return f"'{cell}" if cell.startswith(_FORMULA_STARTS) else cell


def parse_devices(text: str) -> list[ImportRow]:
    """Every data row of a CSV device list, each either ready to add or with its error.

    Raises ImportError_ when there is no heading with name and host, or too many rows.
    """
    text = text.lstrip("﻿")
    if not text.strip():
        raise ImportError_("the file is empty")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), dialect))
    except csv.Error as exc:
        raise ImportError_(f"the file is not readable as CSV: {exc}") from exc
    heading = [_ALIASES.get(cell.strip().lower(), cell.strip().lower()) for cell in rows[0]]
    if "name" not in heading or "host" not in heading:
        raise ImportError_("the first line must name the columns, and name and host must be among them")
    body = [(number, row) for number, row in enumerate(rows[1:], start=2) if any(cell.strip() for cell in row)]
    if len(body) > MAX_ROWS:
        raise ImportError_(f"the file has {len(body)} devices; at most {MAX_ROWS} can be imported at once")
    found = []
    for number, row in body:
        cells = {column: _unguard(cell) for column, cell in zip(heading, row, strict=False) if column in COLUMNS}
        name, host = cells.get("name", ""), cells.get("host", "")
        try:
            validate_name(name or host)
            inventory = Inventory.of({
                "kind": cells.get("type"), "vendor": cells.get("vendor"), "model": cells.get("model"),
                "location": cells.get("location"), "notes": cells.get("notes"), "mac": cells.get("mac"),
                "tags": cells.get("tags", "").replace(";", ","), "check_kind": cells.get("check"),
                "check_port": cells.get("port"), "interval_s": cells.get("interval"), "paused": cells.get("paused"),
            })
        except ValidationError as exc:
            found.append(ImportRow(number, name, host, None, cells.get("group", ""), str(exc)))
            continue
        found.append(ImportRow(number, name or host, host, inventory, cells.get("group", "")))
    return found


def export_devices(devices: Iterable[Device], groups: Mapping[int, str]) -> str:
    """The devices as CSV, with the columns parse_devices reads."""
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(COLUMNS)
    for device in devices:
        writer.writerow([_guard(str(cell)) for cell in (
            device.name, device.host, "" if device.kind == "unknown" else device.kind,
            groups.get(device.group_id, "") if device.group_id is not None else "", device.location, device.vendor,
            device.model, device.mac or "", ", ".join(device.tags), device.notes, device.check_kind,
            device.check_port or "", device.interval_s, "yes" if device.paused else "",
        )])
    return out.getvalue()
