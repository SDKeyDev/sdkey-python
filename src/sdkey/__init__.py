"""Official Python client for the SDKey license authentication protocol."""

from sdkey.client import SdkeyClient
from sdkey.crypto.canonical_json import canonical_json, canonicalize
from sdkey.crypto.constants import (
    AES_GCM_IV_BYTES,
    CLIENT_NONCE_BYTES,
    CLOCK_SKEW_SECONDS,
    PROTOCOL_VERSION,
    SERVER_NONCE_BYTES,
    SESSION_AES_KEY_BYTES,
    SESSION_HKDF_INFO_PREFIX,
    VALIDATE_FAILURE_CODES,
    VALIDATE_NONCE_BYTES,
    ValidateFailureCode,
)
from sdkey.crypto.encoding import base64_to_bytes, bytes_to_base64
from sdkey.crypto.seal import (
    SealedEnvelope,
    derive_session_aes_key,
    import_public_key,
    open_aes_gcm,
    seal_aes_gcm,
    verify_signature,
)
from sdkey.errors import SdkeyError, SdkeyErrorCode
from sdkey.hwid import get_hardware_id
from sdkey.types import (
    ClientAuthLicense,
    ClientAuthResult,
    ClientAuthSessionInfo,
    ClientAuthUser,
    SdkeyClientOptions,
    SessionState,
    ValidateResult,
)

__all__ = [
    "AES_GCM_IV_BYTES",
    "CLIENT_NONCE_BYTES",
    "CLOCK_SKEW_SECONDS",
    "PROTOCOL_VERSION",
    "SERVER_NONCE_BYTES",
    "SESSION_AES_KEY_BYTES",
    "SESSION_HKDF_INFO_PREFIX",
    "VALIDATE_FAILURE_CODES",
    "VALIDATE_NONCE_BYTES",
    "ClientAuthLicense",
    "ClientAuthResult",
    "ClientAuthSessionInfo",
    "ClientAuthUser",
    "SealedEnvelope",
    "SdkeyClient",
    "SdkeyClientOptions",
    "SdkeyError",
    "SdkeyErrorCode",
    "SessionState",
    "ValidateFailureCode",
    "ValidateResult",
    "base64_to_bytes",
    "bytes_to_base64",
    "canonical_json",
    "canonicalize",
    "derive_session_aes_key",
    "get_hardware_id",
    "import_public_key",
    "open_aes_gcm",
    "seal_aes_gcm",
    "verify_signature",
]

__version__ = "0.3.0"
