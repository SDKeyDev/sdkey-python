"""Public types for the SDKey client."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


HttpPost = Callable[[str, dict[str, Any]], tuple[int, dict[str, Any]]]
"""`(url, json_body) -> (status_code, response_json)`."""


@dataclass(frozen=True)
class SdkeyClientOptions:
    """Constructor options for :class:`~sdkey.client.SdkeyClient`."""

    api_base_url: str
    app_id: str
    app_public_key_b64: str
    http_post: HttpPost | None = None


@dataclass(frozen=True)
class SessionState:
    session_id: str
    aes_key: bytes
    server_nonce_b64: str
    hkdf_salt_b64: str


@dataclass(frozen=True)
class ValidateResult:
    success: bool
    code: str
    message: str
    status: str | None
    expires_at: str | None
    timestamp: int
