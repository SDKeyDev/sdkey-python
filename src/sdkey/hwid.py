"""Stable hardware ID helper for desktop clients."""

from __future__ import annotations

import hashlib
import platform
import re
import subprocess
import sys
from pathlib import Path

from sdkey.errors import SdkeyError

_LINUX_MACHINE_ID_PATHS = (
    Path("/etc/machine-id"),
    Path("/var/lib/dbus/machine-id"),
)


def get_hardware_id() -> str:
    """Return a SHA-256 hex digest of a stable OS machine identifier.

    Reads a platform-specific machine ID, trims whitespace, hashes the UTF-8
    bytes with SHA-256, and returns lowercase hex (64 characters).

    Opt-in only — pass the result to ``validate`` / ``register`` / ``login`` /
    ``upgrade`` when binding a license to a machine. Omit for web clients.

    Raises:
        SdkeyError: If the platform is unsupported or the machine ID is missing/empty.
    """
    raw = _read_raw_machine_id()
    trimmed = raw.strip()
    if not trimmed:
        raise SdkeyError("HWID_UNAVAILABLE", "Machine identifier is empty")
    return hashlib.sha256(trimmed.encode("utf-8")).hexdigest()


def _read_raw_machine_id() -> str:
    system = platform.system()
    if system == "Windows":
        return _read_windows_machine_guid()
    if system == "Linux":
        return _read_linux_machine_id()
    if system == "Darwin":
        return _read_macos_platform_uuid()
    raise SdkeyError(
        "HWID_UNAVAILABLE",
        f"Unsupported platform for hardware ID: {system or sys.platform}",
    )


def _read_windows_machine_guid() -> str:
    try:
        import winreg
    except ImportError as exc:
        raise SdkeyError(
            "HWID_UNAVAILABLE",
            "winreg is required to read MachineGuid on Windows",
            cause=exc,
        ) from exc

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
    except OSError as exc:
        raise SdkeyError(
            "HWID_UNAVAILABLE",
            "Failed to read Windows MachineGuid from the registry",
            cause=exc,
        ) from exc

    if not isinstance(value, str):
        raise SdkeyError("HWID_UNAVAILABLE", "Windows MachineGuid is not a string")
    return value


def _read_linux_machine_id() -> str:
    errors: list[str] = []
    for path in _LINUX_MACHINE_ID_PATHS:
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    detail = "; ".join(errors) if errors else "no paths available"
    raise SdkeyError(
        "HWID_UNAVAILABLE",
        f"Failed to read Linux machine-id ({detail})",
    )


def _read_macos_platform_uuid() -> str:
    try:
        completed = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SdkeyError(
            "HWID_UNAVAILABLE",
            "Failed to run ioreg for IOPlatformUUID",
            cause=exc,
        ) from exc

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise SdkeyError(
            "HWID_UNAVAILABLE",
            f"ioreg failed while reading IOPlatformUUID"
            + (f": {stderr}" if stderr else ""),
        )

    match = re.search(
        r'"IOPlatformUUID"\s*=\s*"([^"]+)"',
        completed.stdout or "",
    )
    if match is None:
        raise SdkeyError("HWID_UNAVAILABLE", "IOPlatformUUID not found in ioreg output")
    return match.group(1)
