"""Base64 helpers (standard and URL-safe)."""

from __future__ import annotations

import base64


def bytes_to_base64(data: bytes | bytearray | memoryview) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def base64_to_bytes(b64: str) -> bytes:
    normalized = b64.replace("-", "+").replace("_", "/")
    pad = "" if len(normalized) % 4 == 0 else "=" * (4 - (len(normalized) % 4))
    return base64.b64decode(normalized + pad)
