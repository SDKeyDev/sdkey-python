"""Deterministic JSON encoding for Ed25519 signing.

Object keys sorted lexicographically, no insignificant whitespace.
"""

from __future__ import annotations

import json
import math
from typing import Any


def canonical_json(value: Any) -> bytes:
    return canonicalize(value).encode("utf-8")


def canonicalize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("canonicalJson: non-finite numbers are not allowed")
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        # Match TS: omit missing keys (undefined), but keep JSON null (Python None).
        keys = sorted(value.keys())
        body = ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{canonicalize(value[k])}" for k in keys
        )
        return "{" + body + "}"
    raise TypeError(f"canonicalJson: unsupported type {type(value).__name__}")
