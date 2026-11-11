"""The probe page (plan section 30): trace the path to a host, hop by hop.

The trace runs in netpulse.trace on its own thread, never in a request.
These routes start it, show its progress, and show finished traces from the
store. Plan section 31 adds an Outside tab beside the Path tab: checks from
probes around the world, through Globalping, only after the user agrees.
Every route is listed in README.md (tests/test_web.py checks).
"""

from __future__ import annotations

from dataclasses import dataclass

from flask import Response, abort, redirect, render_template, request, url_for

from netpulse.charts import Slice, donut
from netpulse.domain import Trace
from netpulse.outside import KEEP_ANSWER, NotConsented, OutsideState
from netpulse.probes.globalping import CONTINENTS, MAX_PROBES, CheckRequest, OutsideCheck, Where
from netpulse.trace import MAX_HOPS, PROBES_PER_HOP, ROUNDS, TraceState
from netpulse.web.app import get_outside, get_store, get_tracer
from netpulse.web.forms import Refusable
from netpulse.web.views import bp

HISTORY = 20  # past traces listed on the page


@dataclass
class TraceForm(Refusable):
    target: str = ""
    rounds: int = 1
    error: str | None = None
    error_field: str | None = None

    FIELDS = (("target", r"host|address"), ("rounds", r"rounds"))

    @classmethod
    def from_values(cls, values) -> TraceForm:
        rounds = values.get("rounds", "1")
        return cls(target=values.get("target", "").strip()[:253], rounds=int(rounds) if rounds.isdigit() else 1)


@bp.get("/probe")
def probe():
    """The Path tab: a target to trace, the newest or chosen trace, and past ones. ?target= fills the form."""
    return _probe_page(TraceForm.from_values(request.args))


@bp.get("/probe/view")
def probe_view():
    """The trace in progress, or the one just finished. Polls itself every second while a trace runs.

    When a poll finds the trace has finished, the whole page reloads, so the list of past traces has it.
    """
    view = _view(TraceForm())
    body = render_template("_probe_view.html", **view)
    if request.headers.get("HX-Request") == "true" and not view["running"]:
        return Response(body, headers={"HX-Refresh": "true"})
    return body


@bp.post("/probe/trace")
def start_trace():
    form = TraceForm.from_values(request.form)
    tracer = get_tracer()
    if not form.target:
        return _probe_page(form.fail("type a host name or an IPv4 address to trace")), 422
    if form.rounds not in ROUNDS:
        return _probe_page(form.fail(f"Rounds: {', '.join(map(str, ROUNDS))}")), 422
    if tracer is None:
        return _probe_page(form.fail("tracing is off in this NetPulse")), 503
    if not tracer.start(form.target, form.rounds):
        return _probe_page(form.fail("a trace is already running. Wait for it to finish")), 409
    return redirect(url_for(".probe"))


@bp.get("/probe/traces/<int:trace_id>")
def trace_detail(trace_id: int):
    """A finished trace: its hops and its chain."""
    try:
        trace = get_store().get_trace(trace_id)
    except KeyError:
        abort(404)
    return _probe_page(TraceForm(target=trace.target, rounds=trace.rounds), shown=trace)


def _probe_page(form: TraceForm, shown: Trace | None = None) -> str:
    return render_template("probe.html", traces=get_store().traces()[:HISTORY], **_view(form, shown))


def _view(form: TraceForm, shown: Trace | None = None) -> dict:
    tracer = get_tracer()
    status = tracer.status() if tracer is not None else None
    running = status is not None and status.state == TraceState.RUNNING
    if shown is None and status is not None and status.trace_id is not None and not running:
        shown = get_store().get_trace(status.trace_id)  # the trace this NetPulse ran last
    if not form.target and status is not None and status.target and not running:
        form.target = status.target
    return {
        "form": form,
        "status": status,
        "running": running,
        "trace": shown,
        "rounds_choices": ROUNDS,
        "max_hops": MAX_HOPS,
        "probes_per_hop": PROBES_PER_HOP,
        "available": tracer is not None,
    }


# The Outside tab (plan section 31)


@dataclass
class OutsideForm(Refusable):
    """The Outside tab's fields, as typed, so a refused check keeps them."""

    kind: str = "ping"
    target: str = ""
    port: str = ""
    path: str = "/"
    scope: str = "world"
    continent: str = "EU"
    country: str = ""
    probes: str = "3"
    error: str | None = None
    error_field: str | None = None

    FIELDS = (
        ("port", r"^port"), ("path", r"^path"), ("probes", r"^probes"), ("country", r"^where"), ("kind", r"^check"),
        ("target", r"host|address|name|switch|whitespace|reach"),
    )

    @classmethod
    def from_values(cls, values) -> OutsideForm:
        return cls(**{name: values.get(name, getattr(cls, name)).strip() for name in
                      ("kind", "target", "port", "path", "scope", "continent", "country", "probes")})

    def request(self) -> CheckRequest:
        """The check this asks for, or ValueError naming the field."""
        if not self.target:
            raise ValueError("Host: type a public host name or address")
        if self.port and not self.port.isdigit():
            raise ValueError("Port: a number from 1 to 65535")
        if not self.probes.isdigit():
            raise ValueError(f"Probes: 1 to {MAX_PROBES}")
        code = {"world": None, "continent": self.continent, "country": self.country.upper()}.get(self.scope)
        return CheckRequest(
            kind=self.kind, target=self.target, where=Where(self.scope, code), probes=int(self.probes),
            port=int(self.port) if self.port and self.kind in ("tcp", "http") else None,
            path=self.path or "/",
        )



@bp.get("/probe/outside")
def outside():
    """Whether a server can be reached from outside this network: consent first, then checks."""
    return _outside_page(OutsideForm.from_values(request.args))


@bp.get("/probe/outside/view")
def outside_view():
    """The check in progress, or the one just finished. Polls itself every second while one runs."""
    view = _outside_view(OutsideForm())
    body = render_template("_outside_view.html", **view)
    if request.headers.get("HX-Request") == "true" and not view["running"]:
        return Response(body, headers={"HX-Refresh": "true"})
    return body


@bp.post("/probe/outside/consent")
def outside_consent():
    """Agree to send targets to Globalping, or take it back. Nothing is sent before agreeing."""
    checker = get_outside()
    if checker is None:
        abort(503, description="Checks from outside are off in this NetPulse.")
    checker.consent(request.form.get("agree") == "yes")
    return redirect(url_for(".outside"))


@bp.post("/probe/outside/check")
def start_outside_check():
    form = OutsideForm.from_values(request.form)
    checker = get_outside()
    try:
        if checker is None:
            raise NotConsented("checks from outside are off in this NetPulse")
        started = checker.start(form.request())
    except NotConsented as exc:
        return _outside_page(form.fail(exc)), 403
    except ValueError as exc:  # a field, or a target that is not public
        return _outside_page(form.fail(exc)), 422
    if not started:
        return _outside_page(form.fail(ValueError("a check is already running. Wait for it to finish"))), 409
    return redirect(url_for(".outside"))


@bp.get("/probe/outside/checks/<int:check_id>")
def outside_check(check_id: int):
    """A past check from outside."""
    try:
        shown = get_store().get_outside_check(check_id)
    except KeyError:
        abort(404)
    return _outside_page(_form_of(shown.request), shown=shown)


def _form_of(check: CheckRequest) -> OutsideForm:
    return OutsideForm(
        kind=check.kind, target=check.target, port="" if check.port is None else str(check.port), path=check.path,
        scope=check.where.scope, continent=check.where.code if check.where.scope == "continent" else "EU",
        country=check.where.code if check.where.scope == "country" else "", probes=str(check.probes),
    )


def _outside_page(form: OutsideForm, shown: OutsideCheck | None = None) -> str:
    checker = get_outside()
    view = _outside_view(form, shown)
    if not form.target and view["check"] is not None:
        view["form"] = _form_of(view["check"].request)  # ready to ask again, or to change one thing
    return render_template(
        "outside.html",
        checks=get_store().outside_checks()[:HISTORY],
        consented=checker is not None and checker.consented(),
        **view,
    )


def _outside_view(form: OutsideForm, shown: OutsideCheck | None = None) -> dict:
    checker = get_outside()
    status = checker.status() if checker is not None else None
    running = status is not None and status.state == OutsideState.RUNNING
    reused = False
    if shown is None and status is not None and status.check_id is not None and not running:
        shown = get_store().get_outside_check(status.check_id)
        reused = status.reused
    reach = None
    if shown is not None and shown.results:
        reach = donut("reach", "Could reach it", [
            Slice("reached", "reached it", shown.reached, "up", "solid"),
            Slice("unreached", "could not reach it", shown.unreached, "down", "hatch"),
            Slice("failed", "probe could not check", shown.failed, "unknown", "dots"),
        ], unit="probes")
    return {
        "form": form,
        "status": status,
        "running": running,
        "check": shown,
        "reused": reused,
        "reach": reach,
        "available": checker is not None,
        "kinds": (("ping", "Ping"), ("tcp", "TCP ping: is a port open?"), ("traceroute", "Traceroute"), ("http", "HTTP request")),
        "continents": CONTINENTS,
        "max_probes": MAX_PROBES,
        "keep_minutes": int(KEEP_ANSWER.total_seconds() // 60),
    }
