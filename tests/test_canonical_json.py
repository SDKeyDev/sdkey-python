from __future__ import annotations

from sdkey.crypto.canonical_json import canonical_json, canonicalize


def test_sorts_object_keys_lexicographically() -> None:
    assert canonicalize({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_encodes_null_fields() -> None:
    # TS omits undefined, but keeps JSON null — Python None maps to null.
    assert canonicalize({"a": 1, "b": None}) == '{"a":1,"b":null}'


def test_encodes_nested_structures_without_whitespace() -> None:
    assert canonicalize({"z": [True, None, "x"], "m": {"k": 0}}) == '{"m":{"k":0},"z":[true,null,"x"]}'


def test_returns_utf8_bytes() -> None:
    assert canonical_json({"a": 1}).decode("utf-8") == '{"a":1}'
