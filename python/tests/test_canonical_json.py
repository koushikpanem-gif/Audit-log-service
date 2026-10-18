import json
from pathlib import Path
from typing import cast

import pytest

from audit_log_service.canonical_json import (
    CanonicalJsonError,
    JsonValue,
    canonicalize,
    parse_json,
)

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "test-vectors" / "jcs-v1.json"
)


def _vectors() -> dict[str, object]:
    return cast(dict[str, object], json.loads(VECTORS_PATH.read_text(encoding="utf-8")))


def test_rfc8785_golden_serialization_vectors() -> None:
    vectors = cast(list[dict[str, str]], _vectors()["canonicalization"])

    for vector in vectors:
        actual = canonicalize(parse_json(vector["input"]))
        assert actual == vector["expected"].encode("utf-8"), vector["name"]


@pytest.mark.parametrize(
    "source",
    [
        b'{"x":null,"x":1}',
        b'{"x":1,"\\u0078":2}',
        b"9007199254740992",
        b"-9007199254740992",
        b"NaN",
        b"Infinity",
        b"-Infinity",
        b"1e400",
        b'{"x":"\\uD800"}',
        b'{"x":"\\uDC00"}',
        b'{"x":1} false',
    ],
)
def test_parser_rejects_noncanonical_or_invalid_json(source: bytes) -> None:
    with pytest.raises(CanonicalJsonError):
        parse_json(source)


def test_parser_rejects_invalid_utf8_before_decoding() -> None:
    with pytest.raises(CanonicalJsonError, match="UTF-8"):
        parse_json(b'"\xc3("')


def test_parser_rejects_input_exceeding_byte_limit() -> None:
    with pytest.raises(CanonicalJsonError, match="byte limit"):
        parse_json(b'{"value":"12345"}', max_bytes=10)


def test_parser_checks_depth_before_json_decode() -> None:
    too_deep = b"[" * 11 + b"0" + b"]" * 11
    with pytest.raises(CanonicalJsonError, match="depth"):
        parse_json(too_deep)


@pytest.mark.parametrize(
    "value",
    [
        9_007_199_254_740_992,
        float("inf"),
        float("nan"),
        {"bad": "\ud800"},
        {"bad": "\udc00"},
    ],
)
def test_canonicalizer_rejects_unsupported_values(value: JsonValue) -> None:
    with pytest.raises(CanonicalJsonError):
        canonicalize(value)


def test_canonicalizer_rejects_deep_and_cyclic_values() -> None:
    nested: JsonValue = 0
    for _ in range(11):
        nested = [nested]
    with pytest.raises(CanonicalJsonError, match="depth"):
        canonicalize(nested)

    cyclic: list[JsonValue] = []
    cyclic.append(cyclic)
    with pytest.raises(CanonicalJsonError, match="Cyclic"):
        canonicalize(cyclic)
