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
    app_version: str
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
    subscription_tier: int | None
    timestamp: int


@dataclass(frozen=True)
class ClientAuthUser:
    id: str
    username: str
    email: str | None
    application_id: str


@dataclass(frozen=True)
class ClientAuthLicense:
    id: str
    status: str
    expires_at: str | None
    subscription_tier: int


@dataclass(frozen=True)
class ClientAuthSessionInfo:
    ip: str
    hwid: str | None


@dataclass(frozen=True)
class ClientAuthResult:
    """Result of register / login / upgrade (plaintext client auth)."""

    success: bool
    code: str | None = None
    error: str | None = None
    session_token: str | None = None
    expires_at: str | None = None
    user: ClientAuthUser | None = None
    license: ClientAuthLicense | None = None
    session: ClientAuthSessionInfo | None = None
