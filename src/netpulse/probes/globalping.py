"""The Globalping client (plan section 31, decision 007): reachability from outside this network.

- Python's standard HTTP client only, to api.globalping.io. It is the only
  module allowed to make HTTP requests (plan section 24).
- It creates a measurement, then polls for the result, waiting longer each
  time, within an overall timeout.
- Only public targets: private, loopback, link-local and reserved addresses,
  and names that only mean something on this network, are refused before
  anything is sent.
- Failures are the service's, never the target's: a rate limit, an outage or
  a timeout raises its own error.
- The transport is a parameter, so tests hand in recorded answers, and the
  offline guard blocks the real connection.
"""

from __future__ import annotations

import http.client
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from ipaddress import ip_address

from netpulse import __version__
from netpulse.ping.hosts import InvalidHost, validate_host

API_HOST = "api.globalping.io"
USER_AGENT = f"NetPulse/{__version__} (local network monitor)"
REQUEST_TIMEOUT_S = 15
OVERALL_TIMEOUT_S = 60
FIRST_WAIT_S = 0.5  # Globalping asks for at least 500 ms between polls
LONGEST_WAIT_S = 2.0
MAX_PROBES = 10

KINDS = ("ping", "tcp", "traceroute", "http")
CONTINENTS = {
    "AF": "Africa", "AS": "Asia", "EU": "Europe", "NA": "North America", "OC": "Oceania", "SA": "South America",
}
# Names that only mean something inside a network.
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".home.arpa", ".internal", ".localdomain", ".corp", ".intranet")

# (status, headers, body) for (method, path, body, headers).
Transport = Callable[[str, str, bytes | None, Mapping[str, str]], tuple[int, Mapping[str, str], bytes]]


class GlobalpingError(Exception):
    """Globalping could not answer. Never a fact about the target."""


class RateLimited(GlobalpingError):
    def __init__(self, message: str, reset_s: int | None) -> None:
        super().__init__(message)
        self.reset_s = reset_s


class ServiceUnavailable(GlobalpingError):
    pass


class NoProbes(GlobalpingError):
    pass


class TimedOut(GlobalpingError):
    pass


@dataclass(frozen=True)
class Where:
    """Where the probes are: the whole world, a continent, or a country."""

    scope: str = "world"  # "world", "continent" or "country"
    code: str | None = None  # a continent code from CONTINENTS, or a two-letter country code

    def __post_init__(self) -> None:
        if self.scope == "world" and self.code is None:
            return
        if self.scope == "continent" and self.code in CONTINENTS:
            return
        if self.scope == "country" and self.code is not None and re.fullmatch(r"[A-Z]{2}", self.code):
            return
        raise ValueError("Where: the whole world, a continent, or a two-letter country code")

    @property
    def label(self) -> str:
        if self.scope == "world":
            return "the whole world"
        return CONTINENTS[self.code] if self.scope == "continent" else self.code


@dataclass(frozen=True)
class CheckRequest:
    kind: str  # one of KINDS
    target: str
    where: Where = Where()
    probes: int = 3
    port: int | None = None  # tcp and http
    path: str = "/"  # http

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"Check: one of {', '.join(KINDS)}")
        if not 1 <= self.probes <= MAX_PROBES:
            raise ValueError(f"Probes: 1 to {MAX_PROBES}")
        if self.kind == "tcp" and self.port is None:
            raise ValueError("Port: a TCP ping needs a port")
        if self.port is not None and not 1 <= self.port <= 65535:
            raise ValueError("Port: 1 to 65535")
        if not self.path.startswith("/") or len(self.path) > 200 or any(c in self.path for c in " \t\r\n"):
            raise ValueError("Path: starts with / and has no spaces, at most 200 characters")


def public_target(text: str) -> str:
    """A host Globalping's probes can reach, or ValueError with the reason. Nothing is sent to check."""
    try:
        host = validate_host(text)
    except InvalidHost as exc:
        raise ValueError(str(exc)) from exc
    try:
        address = ip_address(host)
    except ValueError:
        name = host.lower().rstrip(".")
        if "." not in name or name == "localhost" or name.endswith(LOCAL_SUFFIXES):
            raise ValueError(f"{host} is a name on this network: probes outside it cannot reach it") from None
        return host
    if not address.is_global:
        raise ValueError(f"{host} is a private, loopback, link-local or reserved address: probes outside cannot reach it")
    return host


def request_body(check: CheckRequest) -> dict:
    """The measurement Globalping is asked for: only the target, the kind, and where."""
    body: dict = {"target": check.target, "limit": check.probes}
    if check.where.scope != "world":
        body["locations"] = [{check.where.scope: check.where.code}]
    if check.kind == "ping":
        body.update(type="ping", measurementOptions={"packets": 3})
    elif check.kind == "tcp":
        body.update(type="ping", measurementOptions={"packets": 3, "protocol": "TCP", "port": check.port})
    elif check.kind == "traceroute":
        body.update(type="traceroute")
    else:
        options: dict = {"protocol": "HTTPS" if check.port in (None, 443) else "HTTP", "request": {"method": "HEAD", "path": check.path}}
        if check.port is not None:
            options["port"] = check.port
        body.update(type="http", measurementOptions=options)
    return body


@dataclass(frozen=True)
class ProbeResult:
    """One probe's answer: where it is, and what it found."""

    continent: str
    country: str
    city: str
    network: str
    asn: int | None
    status: str  # finished, failed, offline or in-progress, as Globalping says
    reached: bool
    loss: float | None = None
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None
    http_status: int | None = None
    hops: int | None = None
    address: str | None = None  # what the target resolved to, from there


@dataclass(frozen=True)
class Measurement:
    id: str
    finished: bool
    results: tuple[ProbeResult, ...]


@dataclass(frozen=True)
class OutsideCheck:
    """One check from outside, as kept (plan section 31): what was asked, and what came back."""

    id: int
    request: CheckRequest
    started_at: str
    measurement_id: str | None
    results: tuple[ProbeResult, ...] = ()
    error: str | None = None

    @property
    def reached(self) -> int:
        return sum(1 for r in self.results if r.reached)

    @property
    def unreached(self) -> int:
        return sum(1 for r in self.results if r.status == "finished" and not r.reached)

    @property
    def failed(self) -> int:
        """Probes that could not run the check: not a fact about the target."""
        return sum(1 for r in self.results if r.status != "finished")


def parse_results(kind: str, body: Mapping) -> tuple[ProbeResult, ...]:
    found = []
    for item in body.get("results", ()):
        probe, result = item.get("probe", {}), item.get("result", {})
        status = result.get("status", "failed")
        stats = result.get("stats") or {}
        hops = result.get("hops")
        reached = False
        if status == "finished":
            if kind in ("ping", "tcp"):
                reached = (stats.get("rcv") or 0) > 0
            elif kind == "http":
                reached = result.get("statusCode") is not None
            elif hops:
                reached = hops[-1].get("resolvedAddress") == result.get("resolvedAddress")
        found.append(
            ProbeResult(
                continent=probe.get("continent", ""),
                country=probe.get("country", ""),
                city=probe.get("city", ""),
                network=probe.get("network", ""),
                asn=probe.get("asn"),
                status=status,
                reached=reached,
                loss=stats.get("loss"),
                min_ms=stats.get("min"),
                avg_ms=stats.get("avg") if kind != "http" else _total(result.get("timings")),
                max_ms=stats.get("max"),
                http_status=result.get("statusCode"),
                hops=len(hops) if hops is not None else None,
                address=result.get("resolvedAddress"),
            )
        )
    return tuple(found)


def _total(timings: object) -> float | None:
    """An HTTP check's total time, when the answer has one."""
    return timings.get("total") if isinstance(timings, dict) else None


def _connection() -> http.client.HTTPSConnection:
    """The real connection. tests/conftest.py blocks this, so no test reaches Globalping."""
    return http.client.HTTPSConnection(API_HOST, timeout=REQUEST_TIMEOUT_S)


def https_transport(method: str, path: str, body: bytes | None, headers: Mapping[str, str]) -> tuple[int, dict, bytes]:
    conn = _connection()
    try:
        conn.request(method, path, body, dict(headers))
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    except (OSError, http.client.HTTPException) as exc:
        raise ServiceUnavailable(f"Globalping could not be reached: {exc}") from exc
    finally:
        conn.close()


def _pause(seconds: float) -> None:
    threading.Event().wait(seconds)


class GlobalpingClient:
    def __init__(
        self,
        transport: Transport = https_transport,
        *,
        clock: Callable[[], float] = time.monotonic,
        wait: Callable[[float], None] = _pause,
        timeout_s: float = OVERALL_TIMEOUT_S,
    ) -> None:
        self._transport = transport
        self._clock = clock
        self._wait = wait
        self._timeout_s = timeout_s

    def measure(self, check: CheckRequest) -> Measurement:
        """Ask Globalping for the check and wait for every probe's answer.

        Raises RateLimited, NoProbes, ServiceUnavailable, TimedOut or ValueError (a
        target that is not public), never anything that says the target is down.
        """
        target = public_target(check.target)
        started = self._clock()
        body = json.dumps(request_body(replace(check, target=target))).encode()
        status, headers, payload = self._call("POST", "/v1/measurements", body)
        if status != 202:
            raise self._error(status, headers, payload)
        measurement_id = self._json(payload).get("id")
        if not isinstance(measurement_id, str) or not re.fullmatch(r"[A-Za-z0-9]+", measurement_id):
            raise ServiceUnavailable("Globalping answered without a measurement id")
        pause = FIRST_WAIT_S
        while True:
            self._wait(pause)
            status, headers, payload = self._call("GET", f"/v1/measurements/{measurement_id}", None)
            if status != 200:
                raise self._error(status, headers, payload)
            data = self._json(payload)
            if data.get("status") == "finished":
                try:
                    return Measurement(measurement_id, True, parse_results(check.kind, data))
                except (AttributeError, TypeError, ValueError):
                    raise ServiceUnavailable("Globalping answered with something unexpected") from None
            if self._clock() - started + pause > self._timeout_s:
                raise TimedOut(f"Globalping had not finished after {int(self._timeout_s)} s")
            pause = min(LONGEST_WAIT_S, pause * 1.5)

    def _call(self, method: str, path: str, body: bytes | None) -> tuple[int, Mapping[str, str], bytes]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self._transport(method, path, body, headers)

    @staticmethod
    def _json(payload: bytes) -> dict:
        try:
            data = json.loads(payload)
        except ValueError:
            raise ServiceUnavailable("Globalping answered with something that is not JSON") from None
        if not isinstance(data, dict):
            raise ServiceUnavailable("Globalping answered with something unexpected")
        return data

    def _error(self, status: int, headers: Mapping[str, str], payload: bytes) -> GlobalpingError:
        try:
            message = json.loads(payload)["error"]["message"]
        except (ValueError, KeyError, TypeError):
            message = ""
        if status == 429:
            reset = {k.lower(): v for k, v in headers.items()}.get("x-ratelimit-reset")
            reset_s = int(reset) if reset and reset.isdigit() else None
            when = f"; it allows more in {reset_s // 60 + 1} min" if reset_s is not None else ""
            return RateLimited(f"Globalping's limit for this PC is used up{when}", reset_s)
        if status == 422:
            return NoProbes(f"Globalping has no probes for that: {message or 'try somewhere wider'}")
        if status >= 500:
            return ServiceUnavailable(f"Globalping is not working right now (HTTP {status})")
        return ServiceUnavailable(f"Globalping refused the request (HTTP {status}){': ' + message if message else ''}")
