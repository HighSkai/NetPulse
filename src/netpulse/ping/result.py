from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


class Error:
    """Stable error codes stored in check_results.error. Not OS sentences."""

    TIMEOUT = "timeout"
    UNREACHABLE = "unreachable"
    NAME_RESOLUTION = "name_resolution"
    TRANSMIT_FAILED = "transmit_failed"
    TTL_EXPIRED = "ttl_expired"
    UNREADABLE_OUTPUT = "unreadable_output"

    ALL = frozenset(
        {
            TIMEOUT,
            UNREACHABLE,
            NAME_RESOLUTION,
            TRANSMIT_FAILED,
            TTL_EXPIRED,
            UNREADABLE_OUTPUT,
        }
    )


@dataclass(frozen=True)
class PingResult:
    """One probe. success=True has an int rtt_ms and no error; failure is the reverse."""

    success: bool
    rtt_ms: int | None
    error: str | None

    def __post_init__(self) -> None:
        if self.success:
            if not _is_int(self.rtt_ms) or self.rtt_ms < 0:
                raise ValueError("a successful result needs a non-negative int rtt_ms")
            if self.error is not None:
                raise ValueError("a successful result must not carry an error")
        else:
            if self.rtt_ms is not None:
                raise ValueError("a failed result must have rtt_ms None")
            if self.error not in Error.ALL:
                raise ValueError(f"unknown error code: {self.error!r}")

    @classmethod
    def ok(cls, rtt_ms: int) -> PingResult:
        return cls(success=True, rtt_ms=rtt_ms, error=None)

    @classmethod
    def fail(cls, error: str) -> PingResult:
        return cls(success=False, rtt_ms=None, error=error)


class PingerUnavailable(RuntimeError):
    """The probe could not run on this PC at all, e.g. ping.exe is missing.

    This says nothing about the device, so nothing is stored for it (plan section 13).
    """


@runtime_checkable
class Pinger(Protocol):
    def ping(self, host: str) -> PingResult:
        """Probe host once.

        Returns a failed PingResult for ping failures instead of raising.
        Raises InvalidHost for a host that fails validation, and
        PingerUnavailable when the probe cannot run on this PC.
        """


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
