from __future__ import annotations

import codecs
import ctypes
import os
import subprocess
import sys

from netpulse.ping.hosts import validate_host
from netpulse.ping.parser import parse_ping_output
from netpulse.ping.result import Error, PingerUnavailable, PingResult

# Windows ping -w is milliseconds. The process timeout is slightly longer so
# ping.exe can report the timeout itself before Python kills it.
DEFAULT_WAIT_MS = 1000
_PROCESS_GRACE_S = 1.0
_CREATE_NO_WINDOW = 0x08000000


class UnsupportedPlatform(RuntimeError):
    """v1 pings with Windows ping.exe only; a POSIX pinger is deferred (plan section 10)."""


def default_ping_executable(platform: str | None = None) -> str:
    """Absolute path to System32 ping.exe.

    A bare "ping" lets Windows search python.exe's folder and the working
    directory before System32, so a stray ping.exe there would run instead.
    """
    platform = platform or sys.platform
    if platform != "win32":
        raise UnsupportedPlatform(
            f"NetPulse v1 runs on Windows only, because it pings with Windows ping.exe "
            f"(this system is {platform!r}). A Linux and macOS ping adapter is deferred."
        )
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(system_root, "System32", "PING.EXE")


def build_ping_args(executable: str, host: str, wait_ms: int) -> list[str]:
    """argv for one IPv4 echo. host must already be validated."""
    return [executable, "-n", "1", "-w", str(wait_ms), "-4", host]


_FALLBACK_ENCODING = "cp437"


def encoding_for_code_page(code_page: int) -> str:
    """Python codec for a Windows code page, or cp437 if Python has none."""
    name = f"cp{code_page}"
    try:
        codecs.lookup(name)
    except LookupError:
        return _FALLBACK_ENCODING
    return name


def oem_encoding() -> str:
    """Encoding ping.exe writes to a pipe: the console OEM code page, not UTF-8."""
    if sys.platform != "win32":
        return "utf-8"
    try:
        return encoding_for_code_page(ctypes.windll.kernel32.GetOEMCP())
    except Exception:
        return _FALLBACK_ENCODING


def decode_ping_bytes(data: bytes, encoding: str | None = None) -> str:
    return data.decode(encoding or oem_encoding(), errors="replace")


class OsPinger:
    """Production pinger: OS ping.exe (Windows) with a list of args, no shell."""

    def __init__(
        self,
        *,
        wait_ms: int = DEFAULT_WAIT_MS,
        executable: str | None = None,
    ) -> None:
        if wait_ms <= 0:
            raise ValueError("wait_ms must be positive")
        self.wait_ms = wait_ms
        self.process_timeout_s = wait_ms / 1000 + _PROCESS_GRACE_S
        self.executable = executable or default_ping_executable()

    def ping(self, host: str) -> PingResult:
        target = validate_host(host)
        args = build_ping_args(self.executable, target, self.wait_ms)
        kwargs: dict = {
            "capture_output": True,
            "timeout": self.process_timeout_s,
            "shell": False,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = _CREATE_NO_WINDOW
        try:
            completed = subprocess.run(args, **kwargs)
        except subprocess.TimeoutExpired:
            return PingResult.fail(Error.TIMEOUT)
        except OSError as exc:
            # ping.exe could not start. That is a fault on this PC, not a
            # fact about the device, so it must not become a stored result.
            raise PingerUnavailable(f"cannot run {self.executable}: {exc}") from exc
        encoding = oem_encoding()
        text = (
            decode_ping_bytes(completed.stdout, encoding)
            + "\n"
            + decode_ping_bytes(completed.stderr, encoding)
        )
        return parse_ping_output(text)
