"""Wire-protocol constants (protocol v1)."""

from __future__ import annotations

from typing import Final, Literal

PROTOCOL_VERSION: Final[int] = 1

CLOCK_SKEW_SECONDS: Final[int] = 60

CLIENT_NONCE_BYTES: Final[int] = 32
SERVER_NONCE_BYTES: Final[int] = 32
VALIDATE_NONCE_BYTES: Final[int] = 16

AES_GCM_IV_BYTES: Final[int] = 12
AES_GCM_TAG_BITS: Final[int] = 128
AES_GCM_TAG_BYTES: Final[int] = 16
SESSION_AES_KEY_BYTES: Final[int] = 32

SESSION_HKDF_INFO_PREFIX: Final[str] = "sdkey-session-v1"

VALIDATE_FAILURE_CODES: Final[tuple[str, ...]] = (
    "SESSION_EXPIRED",
    "CLOCK_SKEW",
    "REPLAY",
    "LICENSE_NOT_FOUND",
    "APP_MISMATCH",
    "BANNED",
    "EXPIRED",
    "HWID_MISMATCH",
    "DECRYPT_FAIL",
    "APP_DISABLED",
)

ValidateFailureCode = Literal[
    "SESSION_EXPIRED",
    "CLOCK_SKEW",
    "REPLAY",
    "LICENSE_NOT_FOUND",
    "APP_MISMATCH",
    "BANNED",
    "EXPIRED",
    "HWID_MISMATCH",
    "DECRYPT_FAIL",
    "APP_DISABLED",
]
