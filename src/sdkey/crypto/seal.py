"""Ed25519, HKDF session keys, and AES-GCM seal helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sdkey.crypto.canonical_json import canonical_json
from sdkey.crypto.constants import (
    AES_GCM_IV_BYTES,
    AES_GCM_TAG_BYTES,
    SESSION_AES_KEY_BYTES,
    SESSION_HKDF_INFO_PREFIX,
)
from sdkey.crypto.encoding import base64_to_bytes, bytes_to_base64


def import_public_key(public_key_b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64_to_bytes(public_key_b64))


def verify_signature(
    public_key: Ed25519PublicKey,
    payload: Any,
    signature_b64: str,
) -> bool:
    try:
        public_key.verify(base64_to_bytes(signature_b64), canonical_json(payload))
        return True
    except InvalidSignature:
        return False


def derive_session_aes_key(
    *,
    client_nonce: bytes,
    server_nonce: bytes,
    salt_b64: str,
    app_id: str,
) -> bytes:
    ikm = client_nonce + server_nonce
    salt = base64_to_bytes(salt_b64)
    info = f"{SESSION_HKDF_INFO_PREFIX}{app_id}".encode("utf-8")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_AES_KEY_BYTES,
        salt=salt,
        info=info,
    ).derive(ikm)


@dataclass(frozen=True)
class SealedEnvelope:
    iv_b64: str
    ciphertext_b64: str
    tag_b64: str

    def as_wire(self) -> dict[str, str]:
        return {
            "ivB64": self.iv_b64,
            "ciphertextB64": self.ciphertext_b64,
            "tagB64": self.tag_b64,
        }


def seal_aes_gcm(aes_key: bytes, plaintext: bytes) -> SealedEnvelope:
    iv = os.urandom(AES_GCM_IV_BYTES)
    encrypted = AESGCM(aes_key).encrypt(iv, plaintext, None)
    ciphertext = encrypted[:-AES_GCM_TAG_BYTES]
    tag = encrypted[-AES_GCM_TAG_BYTES:]
    return SealedEnvelope(
        iv_b64=bytes_to_base64(iv),
        ciphertext_b64=bytes_to_base64(ciphertext),
        tag_b64=bytes_to_base64(tag),
    )


def open_aes_gcm(aes_key: bytes, envelope: SealedEnvelope | dict[str, str]) -> bytes:
    if isinstance(envelope, SealedEnvelope):
        iv_b64 = envelope.iv_b64
        ciphertext_b64 = envelope.ciphertext_b64
        tag_b64 = envelope.tag_b64
    else:
        iv_b64 = envelope["ivB64"] if "ivB64" in envelope else envelope["iv_b64"]
        ciphertext_b64 = (
            envelope["ciphertextB64"]
            if "ciphertextB64" in envelope
            else envelope["ciphertext_b64"]
        )
        tag_b64 = envelope["tagB64"] if "tagB64" in envelope else envelope["tag_b64"]

    iv = base64_to_bytes(iv_b64)
    ciphertext = base64_to_bytes(ciphertext_b64)
    tag = base64_to_bytes(tag_b64)
    return AESGCM(aes_key).decrypt(iv, ciphertext + tag, None)
