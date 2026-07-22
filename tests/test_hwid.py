from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sdkey import get_hardware_id
from sdkey.errors import SdkeyError
from sdkey.hwid import (
    _read_linux_machine_id,
    _read_macos_platform_uuid,
    _read_raw_machine_id,
    _read_windows_machine_guid,
)


def test_get_hardware_id_hashes_trimmed_utf8_machine_id() -> None:
    raw = "  abc-machine-id\n"
    expected = hashlib.sha256(b"abc-machine-id").hexdigest()

    with patch("sdkey.hwid._read_raw_machine_id", return_value=raw):
        assert get_hardware_id() == expected
        assert len(get_hardware_id()) == 64
        assert get_hardware_id() == get_hardware_id().lower()


def test_get_hardware_id_rejects_empty_after_trim() -> None:
    with patch("sdkey.hwid._read_raw_machine_id", return_value="  \n\t"):
        with pytest.raises(SdkeyError) as exc_info:
            get_hardware_id()
    assert exc_info.value.code == "HWID_UNAVAILABLE"
    assert "empty" in exc_info.value.message.lower()


def test_get_hardware_id_rejects_unsupported_platform() -> None:
    with patch("sdkey.hwid.platform.system", return_value="FreeBSD"):
        with pytest.raises(SdkeyError) as exc_info:
            _read_raw_machine_id()
    assert exc_info.value.code == "HWID_UNAVAILABLE"
    assert "Unsupported platform" in exc_info.value.message


def test_read_linux_machine_id_prefers_etc_machine_id(tmp_path: Path) -> None:
    primary = tmp_path / "etc-machine-id"
    fallback = tmp_path / "dbus-machine-id"
    primary.write_text("primary-id\n", encoding="utf-8")
    fallback.write_text("fallback-id\n", encoding="utf-8")

    with patch(
        "sdkey.hwid._LINUX_MACHINE_ID_PATHS",
        (primary, fallback),
    ):
        assert _read_linux_machine_id() == "primary-id\n"


def test_read_linux_machine_id_falls_back_to_dbus(tmp_path: Path) -> None:
    primary = tmp_path / "missing-etc"
    fallback = tmp_path / "dbus-machine-id"
    fallback.write_text("dbus-id\n", encoding="utf-8")

    with patch(
        "sdkey.hwid._LINUX_MACHINE_ID_PATHS",
        (primary, fallback),
    ):
        assert _read_linux_machine_id() == "dbus-id\n"


def test_read_linux_machine_id_raises_when_missing(tmp_path: Path) -> None:
    with patch(
        "sdkey.hwid._LINUX_MACHINE_ID_PATHS",
        (tmp_path / "a", tmp_path / "b"),
    ):
        with pytest.raises(SdkeyError) as exc_info:
            _read_linux_machine_id()
    assert exc_info.value.code == "HWID_UNAVAILABLE"


def test_read_macos_platform_uuid_parses_ioreg_output() -> None:
    stdout = (
        '+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice>\n'
        '    {\n'
        '      "IOPlatformUUID" = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"\n'
        "    }\n"
    )
    completed = MagicMock(returncode=0, stdout=stdout, stderr="")
    with patch("sdkey.hwid.subprocess.run", return_value=completed) as run:
        assert _read_macos_platform_uuid() == "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
        run.assert_called_once()
        assert run.call_args.args[0] == [
            "ioreg",
            "-rd1",
            "-c",
            "IOPlatformExpertDevice",
        ]


def test_read_macos_platform_uuid_raises_when_missing() -> None:
    completed = MagicMock(returncode=0, stdout="no uuid here", stderr="")
    with patch("sdkey.hwid.subprocess.run", return_value=completed):
        with pytest.raises(SdkeyError) as exc_info:
            _read_macos_platform_uuid()
    assert exc_info.value.code == "HWID_UNAVAILABLE"


def test_read_windows_machine_guid_reads_registry() -> None:
    mock_winreg = MagicMock()
    mock_key = MagicMock()
    mock_winreg.HKEY_LOCAL_MACHINE = object()
    mock_winreg.OpenKey.return_value.__enter__.return_value = mock_key
    mock_winreg.OpenKey.return_value.__exit__.return_value = None
    mock_winreg.QueryValueEx.return_value = ("GUID-FROM-REGISTRY", 1)

    with patch.dict("sys.modules", {"winreg": mock_winreg}):
        assert _read_windows_machine_guid() == "GUID-FROM-REGISTRY"

    mock_winreg.OpenKey.assert_called_once()
    mock_winreg.QueryValueEx.assert_called_once_with(mock_key, "MachineGuid")


def test_sha256_fixture_matches_known_vector() -> None:
    # Fixed vector for the hash step of the shared HWID contract.
    assert (
        hashlib.sha256(b"test-machine-id").hexdigest()
        == "9fa52d819a388ed6c394855fe82c664d771f939b2fa1fee83ff3030e9ca2a284"
    )
    with patch("sdkey.hwid._read_raw_machine_id", return_value="test-machine-id"):
        assert get_hardware_id() == (
            "9fa52d819a388ed6c394855fe82c664d771f939b2fa1fee83ff3030e9ca2a284"
        )
