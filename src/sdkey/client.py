"""SDKey license client (sealed session protocol)."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sdkey.crypto.constants import (
    CLIENT_NONCE_BYTES,
    CLOCK_SKEW_SECONDS,
    PROTOCOL_VERSION,
    VALIDATE_NONCE_BYTES,
)
from sdkey.crypto.encoding import base64_to_bytes, bytes_to_base64
from sdkey.crypto.seal import (
    derive_session_aes_key,
    import_public_key,
    open_aes_gcm,
    seal_aes_gcm,
    verify_signature,
)
from sdkey.errors import SdkeyError
from sdkey.types import HttpPost, SessionState, ValidateResult


def _default_http_post(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read().decode("utf-8")
            parsed: dict[str, Any] = json.loads(raw) if raw else {}
            return int(response.status), parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
        if not isinstance(parsed, dict):
            parsed = {}
        return int(exc.code), parsed


class SdkeyClient:
    """SDKey license client.

    Flow: ``init()`` (session handshake) → ``validate(license_key, hwid=None)`` (sealed).
    ``validate`` calls ``init`` automatically when no session exists.
    """

    def __init__(
        self,
        *,
        api_base_url: str,
        app_id: str,
        app_version: str,
        app_public_key_b64: str,
        http_post: HttpPost | None = None,
    ) -> None:
        self._api_base_url = api_base_url.rstrip("/")
        self._app_id = app_id
        self._app_version = app_version
        self._app_public_key_b64 = app_public_key_b64
        self._http_post: HttpPost = http_post or _default_http_post
        self._public_key: Ed25519PublicKey | None = None
        self._session: SessionState | None = None

    def get_session(self) -> SessionState | None:
        """Active session, if any."""
        return self._session

    def clear_session(self) -> None:
        """Drop the current session (next ``validate`` will re-init)."""
        self._session = None

    def init(self) -> SessionState:
        self._public_key = import_public_key(self._app_public_key_b64)
        client_nonce = os.urandom(CLIENT_NONCE_BYTES)

        try:
            status, body = self._http_post(
                f"{self._api_base_url}/api/v1/session/init",
                {
                    "appId": self._app_id,
                    "clientNonceB64": bytes_to_base64(client_nonce),
                    "clientVersion": self._app_version,
                },
            )
        except Exception as cause:  # noqa: BLE001 — mirror TS catch-all network mapping
            raise SdkeyError("NETWORK", "session init request failed", cause) from cause

        if status < 200 or status >= 300 or not body.get("success"):
            raise SdkeyError(
                str(body.get("code") or "INIT_FAILED"),
                str(body.get("error") or "session init failed"),
            )

        hello = {
            "appId": self._app_id,
            "hkdfSaltB64": body["hkdfSaltB64"],
            "serverNonceB64": body["serverNonceB64"],
            "sessionId": body["sessionId"],
            "timestamp": body["timestamp"],
            "v": PROTOCOL_VERSION,
        }

        assert self._public_key is not None
        if not verify_signature(self._public_key, hello, body["signatureB64"]):
            raise SdkeyError("HELLO_SIGNATURE_INVALID", "hello signature verification failed")

        aes_key = derive_session_aes_key(
            client_nonce=client_nonce,
            server_nonce=base64_to_bytes(body["serverNonceB64"]),
            salt_b64=body["hkdfSaltB64"],
            app_id=self._app_id,
        )

        self._session = SessionState(
            session_id=body["sessionId"],
            aes_key=aes_key,
            server_nonce_b64=body["serverNonceB64"],
            hkdf_salt_b64=body["hkdfSaltB64"],
        )
        return self._session

    def validate(self, license_key: str, hwid: str | None = None) -> ValidateResult:
        if self._session is None or self._public_key is None:
            self.init()
        session = self._session
        public_key = self._public_key
        assert session is not None
        assert public_key is not None

        inner: dict[str, Any] = {
            "licenseKey": license_key,
            "nonce": bytes_to_base64(os.urandom(VALIDATE_NONCE_BYTES)),
            "timestamp": int(time.time()),
            "v": PROTOCOL_VERSION,
        }
        if hwid is not None:
            # Keep lexicographic key order for the sealed inner JSON.
            inner = {
                "hwid": hwid,
                "licenseKey": inner["licenseKey"],
                "nonce": inner["nonce"],
                "timestamp": inner["timestamp"],
                "v": inner["v"],
            }

        sealed = seal_aes_gcm(
            session.aes_key,
            json.dumps(inner, separators=(",", ":")).encode("utf-8"),
        )

        try:
            _status, envelope = self._http_post(
                f"{self._api_base_url}/api/v1/licenses/validate",
                {
                    "sessionId": session.session_id,
                    **sealed.as_wire(),
                },
            )
        except Exception as cause:  # noqa: BLE001
            raise SdkeyError("NETWORK", "validate request failed", cause) from cause

        if (
            not envelope.get("ivB64")
            or not envelope.get("ciphertextB64")
            or not envelope.get("tagB64")
            or not envelope.get("signatureB64")
        ):
            if envelope.get("code") == "SESSION_EXPIRED":
                self.clear_session()
            raise SdkeyError(
                str(envelope.get("code") or "VALIDATE_RESPONSE_INVALID"),
                str(envelope.get("error") or "invalid validate response"),
            )

        plain_bytes = open_aes_gcm(
            session.aes_key,
            {
                "ivB64": envelope["ivB64"],
                "ciphertextB64": envelope["ciphertextB64"],
                "tagB64": envelope["tagB64"],
            },
        )
        plaintext: dict[str, Any] = json.loads(plain_bytes.decode("utf-8"))

        if not verify_signature(public_key, plaintext, envelope["signatureB64"]):
            raise SdkeyError("RESPONSE_SIGNATURE_INVALID", "response signature verification failed")

        if plaintext.get("sessionId") != session.session_id:
            raise SdkeyError("SESSION_MISMATCH", "sessionId mismatch")
        if abs(int(time.time()) - int(plaintext["timestamp"])) > CLOCK_SKEW_SECONDS:
            raise SdkeyError("CLOCK_SKEW", "response clock skew")

        if plaintext.get("code") == "SESSION_EXPIRED":
            self.clear_session()

        tier_raw = plaintext.get("subscriptionTier")
        subscription_tier: int | None
        if tier_raw is None:
            subscription_tier = None
        else:
            subscription_tier = int(tier_raw)

        return ValidateResult(
            success=bool(plaintext["success"]),
            code=str(plaintext["code"]),
            message=str(plaintext["message"]),
            status=plaintext.get("status"),
            expires_at=plaintext.get("expiresAt"),
            subscription_tier=subscription_tier,
            timestamp=int(plaintext["timestamp"]),
        )
