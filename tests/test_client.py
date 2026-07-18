from __future__ import annotations

import json
import os
import time
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sdkey import PROTOCOL_VERSION, SdkeyClient, SdkeyError
from sdkey.crypto.canonical_json import canonical_json
from sdkey.crypto.encoding import base64_to_bytes, bytes_to_base64
from sdkey.crypto.seal import derive_session_aes_key, seal_aes_gcm


def _generate_ed25519_pair() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = bytes_to_base64(private_key.public_key().public_bytes_raw())
    return private_key, public_key_b64


def _sign_payload(private_key: Ed25519PrivateKey, payload: Any) -> str:
    return bytes_to_base64(private_key.sign(canonical_json(payload)))


def test_inits_session_and_validates_sealed_license_response() -> None:
    private_key, public_key_b64 = _generate_ed25519_pair()
    app_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    session_id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    server_nonce = os.urandom(32)
    hkdf_salt = os.urandom(16)
    timestamp = int(time.time())

    captured_client_nonce: bytes | None = None
    call_count = {"n": 0}

    def http_post(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        nonlocal captured_client_nonce
        call_count["n"] += 1

        if url.endswith("/api/v1/session/init"):
            captured_client_nonce = base64_to_bytes(body["clientNonceB64"])
            hello = {
                "appId": app_id,
                "hkdfSaltB64": bytes_to_base64(hkdf_salt),
                "serverNonceB64": bytes_to_base64(server_nonce),
                "sessionId": session_id,
                "timestamp": timestamp,
                "v": PROTOCOL_VERSION,
            }
            return 200, {
                "success": True,
                **hello,
                "signatureB64": _sign_payload(private_key, hello),
            }

        if url.endswith("/api/v1/licenses/validate"):
            assert captured_client_nonce is not None
            aes_key = derive_session_aes_key(
                client_nonce=captured_client_nonce,
                server_nonce=server_nonce,
                salt_b64=bytes_to_base64(hkdf_salt),
                app_id=app_id,
            )
            plaintext = {
                "success": True,
                "code": "OK",
                "message": "valid",
                "status": "active",
                "expiresAt": None,
                "sessionId": session_id,
                "timestamp": int(time.time()),
                "v": PROTOCOL_VERSION,
            }
            sealed = seal_aes_gcm(aes_key, json.dumps(plaintext, separators=(",", ":")).encode())
            return 200, {
                "sessionId": session_id,
                **sealed.as_wire(),
                "signatureB64": _sign_payload(private_key, plaintext),
            }

        return 404, {"error": "not found"}

    client = SdkeyClient(
        api_base_url="https://api.example.test",
        app_id=app_id,
        app_public_key_b64=public_key_b64,
        http_post=http_post,
    )

    result = client.validate("SDKY-TEST-TEST-TEST-TEST", "hwid-1")
    assert result.success is True
    assert result.code == "OK"
    assert client.get_session() is not None
    assert client.get_session().session_id == session_id  # type: ignore[union-attr]
    assert call_count["n"] == 2


def test_throws_sdkey_error_when_hello_signature_is_wrong() -> None:
    _, public_key_b64 = _generate_ed25519_pair()
    other_private, _ = _generate_ed25519_pair()

    def http_post(_url: str, _body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        hello = {
            "appId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "hkdfSaltB64": bytes_to_base64(bytes(16)),
            "serverNonceB64": bytes_to_base64(bytes(32)),
            "sessionId": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "timestamp": int(time.time()),
            "v": PROTOCOL_VERSION,
        }
        return 200, {
            "success": True,
            **hello,
            "signatureB64": _sign_payload(other_private, hello),
        }

    client = SdkeyClient(
        api_base_url="https://api.example.test",
        app_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        app_public_key_b64=public_key_b64,
        http_post=http_post,
    )

    try:
        client.init()
        raise AssertionError("expected SdkeyError")
    except SdkeyError as err:
        assert err.code == "HELLO_SIGNATURE_INVALID"
