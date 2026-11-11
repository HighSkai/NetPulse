"""Charts drawn on the server (plan section 26): pure functions, no Flask, no SQL.

- Pie and donut charts as SVG. Every slice has a fill pattern as well as a
  colour, so colour is never the only signal, and the page prints each slice's
  count and share beside the chart in a legend that uses the same patterns.
- Horizontal bar lists for top-N breakdowns, as values the page draws.
- A status grid: one row per device, one cell per hour, from hourly rollups.

The SVG names no colour. Each pattern carries a tone class, such as tone-up,
and the stylesheet maps tones to the theme's tokens, so charts follow the theme.
Text placed in the SVG is escaped here, because the web layer inserts it as is.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import escape

from netpulse.domain import Availability, HourlyRollup
from netpulse.metrics import PeriodState, availability_window_start

# Fill patterns, each drawn in its slice's tone. Five, so a five-way breakdown
# never repeats one.
PATTERNS = ("solid", "stripes", "dots", "hatch", "lines")
TONES = ("up", "warn", "down", "unknown", "accent", "select")

SIZE = 120  # the SVG's square viewBox
OUTER = 56  # radius of the ring's outside edge
DONUT_HOLE = 0.64  # inner radius as a share of OUTER

_ID = re.compile(r"[a-z][a-z0-9-]*\Z")


@dataclass(frozen=True)
class Slice:
    """One category of a breakdown, before it is drawn."""

    key: str  # part of the SVG pattern id: lower case, digits and dashes
    label: str
    count: int
    tone: str  # one of TONES
    pattern: str  # one of PATTERNS

    def __post_init__(self) -> None:
        if not _ID.match(self.key):
            raise ValueError(f"slice key must be lower case letters, digits and dashes: {self.key!r}")
        if self.tone not in TONES or self.pattern not in PATTERNS:
            raise ValueError(f"unknown tone or pattern: {self.tone!r}, {self.pattern!r}")
        if self.count < 0:
            raise ValueError("a slice cannot have a negative count")


@dataclass(frozen=True)
class DrawnSlice:
    slice: Slice
    start: float  # where the slice begins, in turns from 12 o'clock, clockwise
    end: float
    path: str | None  # SVG path data; None for an empty slice, which is only in the legend

    @property
    def share(self) -> float:
        return self.end - self.start

    @property
    def percent(self) -> str:
        """The share as printed: one decimal place, 0 and 100 kept whole."""
        value = self.share * 100
        if value == 0 or value == 100:
            return f"{value:.0f} %"
        return f"{value:.1f} %"


@dataclass(frozen=True)
class Donut:
    id: str  # unique on the page: it prefixes the pattern ids
    title: str
    unit: str  # what is counted, for the centre and the summary: "devices"
    total: int
    slices: tuple[DrawnSlice, ...]
    svg: str  # escaped SVG, ready to insert

    def pattern_id(self, drawn: DrawnSlice) -> str:
        return f"{self.id}-{drawn.slice.key}"

    @property
    def summary(self) -> str:
        """The chart in words, for its SVG title: "Devices by state: 2 up, 1 down"."""
        if self.total == 0:
            return f"{self.title}: no data"
        parts = ", ".join(f"{d.slice.count} {d.slice.label}" for d in self.slices if d.slice.count)
        return f"{self.title}: {parts}"


def donut(chart_id: str, title: str, slices: Sequence[Slice], *, unit: str = "", hole: float = DONUT_HOLE) -> Donut:
    """A donut chart. hole=0 draws a pie."""
    if not _ID.match(chart_id):
        raise ValueError(f"chart id must be lower case letters, digits and dashes: {chart_id!r}")
    if len({s.key for s in slices}) != len(slices):
        raise ValueError("slice keys must be unique")
    if not 0 <= hole < 1:
        raise ValueError("the hole is a share of the radius, from 0 up to 1")
    total = sum(s.count for s in slices)
    drawn, start = [], 0.0
    for s in slices:
        end = 1.0 if total and s is _last_counted(slices) else start + (s.count / total if total else 0)
        path = _segment(start, end, OUTER, OUTER * hole) if s.count else None
        drawn.append(DrawnSlice(s, start, end, path))
        start = end
    chart = Donut(chart_id, title, unit, total, tuple(drawn), "")
    return Donut(chart_id, title, unit, total, tuple(drawn), _svg(chart, hole))


def pie(chart_id: str, title: str, slices: Sequence[Slice], *, unit: str = "") -> Donut:
    return donut(chart_id, title, slices, unit=unit, hole=0)


def _last_counted(slices: Sequence[Slice]) -> Slice | None:
    """The last slice with a count, which closes the circle exactly."""
    return next((s for s in reversed(slices) if s.count), None)


# Arc maths. Turns run clockwise from 12 o'clock; SVG's y axis points down.


def point(radius: float, turn: float) -> tuple[float, float]:
    angle = 2 * math.pi * turn - math.pi / 2
    centre = SIZE / 2
    return (round(centre + radius * math.cos(angle), 2), round(centre + radius * math.sin(angle), 2))


def _xy(p: tuple[float, float]) -> str:
    return f"{p[0]:g} {p[1]:g}"


def _segment(start: float, end: float, outer: float, inner: float) -> str:
    """Path data for the ring (or pie) segment from start to end, in turns."""
    if end - start >= 1:
        # A whole circle: one arc cannot start and end at the same point, so
        # draw two halves. The hole, if any, is cut out by the even-odd rule.
        ring = _circle(outer)
        return ring if inner == 0 else f"{ring} {_circle(inner)}"
    large = 1 if end - start > 0.5 else 0
    outer_arc = f"A {outer:g} {outer:g} 0 {large} 1 {_xy(point(outer, end))}"
    if inner == 0:
        return f"M {SIZE / 2:g} {SIZE / 2:g} L {_xy(point(outer, start))} {outer_arc} Z"
    return (
        f"M {_xy(point(outer, start))} {outer_arc} L {_xy(point(inner, end))} "
        f"A {inner:g} {inner:g} 0 {large} 0 {_xy(point(inner, start))} Z"
    )


def _circle(radius: float) -> str:
    return (
        f"M {_xy(point(radius, 0))} A {radius:g} {radius:g} 0 1 1 {_xy(point(radius, 0.5))} "
        f"A {radius:g} {radius:g} 0 1 1 {_xy(point(radius, 0))} Z"
    )


# The patterns, 6 units square. The light ground keeps a patterned slice as
# visible as a solid one; the marks on it are what tell the slices apart.

_MARKS = {
    "solid": "",
    "stripes": '<rect class="fill" width="3" height="6"/>',
    "dots": '<circle class="fill" cx="3" cy="3" r="1.6"/>',
    "hatch": '<path class="line" d="M0 0L6 6M6 0L0 6"/>',
    "lines": '<rect class="fill" width="6" height="2"/>',
}


def pattern(pattern_id: str, tone: str, kind: str) -> str:
    """One SVG pattern: a ground in the tone, then the kind's marks on it."""
    rotate = ' patternTransform="rotate(45)"' if kind == "stripes" else ""
    ground = '<rect class="fill" width="6" height="6"/>' if kind == "solid" else (
        '<rect class="fill ground" width="6" height="6"/>'
    )
    return (
        f'<pattern id="{pattern_id}" class="tone-{tone}" width="6" height="6" patternUnits="userSpaceOnUse"{rotate}>'
        f"{ground}{_MARKS[kind]}</pattern>"
    )


def _svg(chart: Donut, hole: float) -> str:
    title_id = f"{chart.id}-title"
    defs = "".join(pattern(chart.pattern_id(d), d.slice.tone, d.slice.pattern) for d in chart.slices)
    shapes = "".join(
        f'<path class="slice" fill-rule="evenodd" fill="url(#{chart.pattern_id(d)})" d="{d.path}"/>'
        for d in chart.slices
        if d.path is not None
    )
    if chart.total == 0:
        shapes = f'<path class="slice-empty" fill-rule="evenodd" d="{_segment(0, 1, OUTER, OUTER * hole)}"/>'
    centre = ""
    if hole:
        middle = SIZE / 2
        value = escape(str(chart.total)) if chart.total else "—"
        centre = (
            f'<text class="donut-total" x="{middle:g}" y="{middle + 2:g}" text-anchor="middle">{value}</text>'
            f'<text class="donut-unit" x="{middle:g}" y="{middle + 16:g}" text-anchor="middle">{escape(chart.unit)}</text>'
        )
    return (
        f'<svg class="donut" viewBox="0 0 {SIZE} {SIZE}" role="img" aria-labelledby="{title_id}">'
        f'<title id="{title_id}">{escape(chart.summary)}</title>'
        f"<defs>{defs}</defs>{shapes}{centre}</svg>"
    )


# Bar lists


@dataclass(frozen=True)
class Bar:
    key: int | str  # what the bar is about: a device id the page links to, or an address
    label: str
    value: float
    text: str  # the value as printed
    share: float  # of the longest bar, 0 to 100


def bar_list(items: Iterable[tuple[int | str, str, float, str]], limit: int = 10) -> tuple[Bar, ...]:
    """The limit largest (key, label, value, text) items as bars, largest first.

    Ties go by label, so the order is stable. The longest bar is full width.
    """
    top = sorted(items, key=lambda item: (-item[2], item[1].casefold(), str(item[0])))[:limit]
    longest = max((value for _, _, value, _ in top), default=0)
    return tuple(
        Bar(key, label, value, text, 100 * value / longest if longest > 0 else 0)
        for key, label, value, text in top
    )


# The status grid


@dataclass(frozen=True)
class GridCell:
    hour: datetime  # the start of the UTC hour
    availability: Availability

    @property
    def state(self) -> str:
        checks, successes = self.availability.checks, self.availability.successes
        if checks == 0:
            return PeriodState.NO_DATA
        if successes == checks:
            return PeriodState.UP
        return PeriodState.DOWN if successes == 0 else PeriodState.SOME_FAILED


@dataclass(frozen=True)
class GridRow:
    key: int
    label: str
    cells: tuple[GridCell, ...]


@dataclass(frozen=True)
class StatusGrid:
    hours: tuple[datetime, ...]  # the columns, oldest first
    rows: tuple[GridRow, ...]


def status_grid(
    rows: Iterable[tuple[int, str]], rollups: Iterable[HourlyRollup], now: datetime, hours: int = 24
) -> StatusGrid:
    """One row per (key, label), one cell per UTC hour, the current hour last.

    The hours are the availability window's (plan section 16), so the grid and
    the 24 h figures count the same checks. An hour with no checks is no data.
    """
    first = datetime.strptime(availability_window_start(now, hours), "%Y-%m-%dT%H").replace(tzinfo=UTC)
    columns = tuple(first + timedelta(hours=i) for i in range(hours))
    counts: dict[tuple[int, str], Availability] = {
        (r.device_id, r.hour_utc): Availability(r.checks, r.successes) for r in rollups
    }
    none = Availability(0, 0)
    return StatusGrid(
        columns,
        tuple(
            GridRow(
                key,
                label,
                tuple(GridCell(hour, counts.get((key, hour.strftime("%Y-%m-%dT%H")), none)) for hour in columns),
            )
            for key, label in rows
        ),
    )
