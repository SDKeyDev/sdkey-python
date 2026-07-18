"""Protocol and transport errors for the SDKey client."""

from __future__ import annotations

from typing import Literal

SdkeyErrorCode = Literal[
    "INIT_FAILED",
    "HELLO_SIGNATURE_INVALID",
    "VALIDATE_RESPONSE_INVALID",
    "RESPONSE_SIGNATURE_INVALID",
    "SESSION_MISMATCH",
    "CLOCK_SKEW",
    "NETWORK",
    "UNKNOWN",
]


class SdkeyError(Exception):
    def __init__(self, code: SdkeyErrorCode, message: str, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.code: SdkeyErrorCode = code
        self.message = message
        if cause is not None:
            self.__cause__ = cause
