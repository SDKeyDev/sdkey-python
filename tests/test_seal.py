from __future__ import annotations

import os

from sdkey.crypto.encoding import bytes_to_base64
from sdkey.crypto.seal import derive_session_aes_key, open_aes_gcm, seal_aes_gcm


def test_aes_gcm_round_trips_plaintext() -> None:
    aes_key = os.urandom(32)
    plaintext = b'{"ok":true}'
    sealed = seal_aes_gcm(aes_key, plaintext)
    opened = open_aes_gcm(aes_key, sealed)
    assert opened == plaintext


def test_derive_session_aes_key_is_deterministic() -> None:
    client_nonce = os.urandom(32)
    server_nonce = os.urandom(32)
    salt_b64 = bytes_to_base64(os.urandom(16))
    app_id = "11111111-2222-3333-4444-555555555555"

    a = derive_session_aes_key(
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        salt_b64=salt_b64,
        app_id=app_id,
    )
    b = derive_session_aes_key(
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        salt_b64=salt_b64,
        app_id=app_id,
    )
    assert bytes_to_base64(a) == bytes_to_base64(b)
    assert len(a) == 32


def test_derive_session_aes_key_changes_when_app_id_changes() -> None:
    client_nonce = bytes([1] * 32)
    server_nonce = bytes([2] * 32)
    salt_b64 = bytes_to_base64(bytes([3] * 16))

    a = derive_session_aes_key(
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        salt_b64=salt_b64,
        app_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )
    b = derive_session_aes_key(
        client_nonce=client_nonce,
        server_nonce=server_nonce,
        salt_b64=salt_b64,
        app_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    )
    assert bytes_to_base64(a) != bytes_to_base64(b)
