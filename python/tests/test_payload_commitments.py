from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from audit_log_service.canonical_json import JsonValue
from audit_log_service.payload_commitments import (
    MAX_PAYLOAD_BYTES,
    MAX_SCALAR_LEAVES,
    REDACTED_VALUE,
    PayloadLeaf,
    PayloadPointerError,
    _commit_payload,
    commit_payload,
    expand_subtree_pointer,
    reveal_payload,
)

VECTORS_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "test-vectors"
    / "payload-commitments-v1.json"
)


def _salts() -> Iterator[bytes]:
    for number in range(1, 1000):
        yield number.to_bytes(32, "big")


def _mixed_payload() -> dict[str, JsonValue]:
    return {
        "a/b": {
            "~key": {"items": [None, "text", 7, {}, []], "emptyArray": []},
            "empty": {},
        },
        "tail": True,
    }


def test_commit_preserves_shape_and_stores_only_scalar_values_outside_tree() -> None:
    salts = iter(_salts())
    result = _commit_payload(_mixed_payload(), lambda size: next(salts))

    branch = cast(dict[str, JsonValue], result.commitments["a/b"])
    keyed = cast(dict[str, JsonValue], branch["~key"])
    values = cast(list[JsonValue], keyed["items"])
    assert values[3:] == [{}, []]
    assert keyed["emptyArray"] == []
    assert branch["empty"] == {}
    assert all(
        isinstance(value, str) and len(value) == 64
        for value in [*values[:3], result.commitments["tail"]]
    )
    assert set(result.leaves) == {
        "/a~1b/~0key/items/0",
        "/a~1b/~0key/items/1",
        "/a~1b/~0key/items/2",
        "/tail",
    }


def test_reveal_round_trips_and_reports_missing_values_as_sorted_redactions() -> None:
    result = _commit_payload(_mixed_payload(), lambda size: bytes([size]) * 32)
    assert reveal_payload(result.commitments, result.leaves).payload == _mixed_payload()

    redacted_leaves = dict(result.leaves)
    del redacted_leaves["/tail"]
    del redacted_leaves["/a~1b/~0key/items/1"]
    revealed = reveal_payload(result.commitments, redacted_leaves)
    assert revealed.payload["tail"] == REDACTED_VALUE
    branch = cast(dict[str, JsonValue], revealed.payload["a/b"])
    keyed = cast(dict[str, JsonValue], branch["~key"])
    values = cast(list[JsonValue], keyed["items"])
    assert values[1] == REDACTED_VALUE
    assert revealed.redacted_paths == ["/a~1b/~0key/items/1", "/tail"]

    utf16_sorted = reveal_payload({"\ue000": "0" * 64, "\U00010000": "0" * 64}, {})
    assert utf16_sorted.redacted_paths == ["/\U00010000", "/\ue000"]


def test_expands_root_and_escaped_subtrees_to_sorted_leaf_pointers() -> None:
    payload = _mixed_payload()
    assert expand_subtree_pointer(payload, "") == [
        "/a~1b/~0key/items/0",
        "/a~1b/~0key/items/1",
        "/a~1b/~0key/items/2",
        "/tail",
    ]
    assert expand_subtree_pointer(payload, "/a~1b/~0key") == [
        "/a~1b/~0key/items/0",
        "/a~1b/~0key/items/1",
        "/a~1b/~0key/items/2",
    ]
    assert expand_subtree_pointer(payload, "/a~1b/~0key/items/1") == [
        "/a~1b/~0key/items/1"
    ]
    assert expand_subtree_pointer(payload, "/a~1b/empty") == []


@pytest.mark.parametrize(
    "pointer",
    [
        "a",
        "/a~",
        "/a~2b",
        "/a~1b/~0key/items/01",
        "/a~1b/~0key/items/-",
        "/a~1b/~0key/items/99",
        "/missing",
    ],
)
def test_rejects_invalid_or_missing_pointer_paths(pointer: str) -> None:
    with pytest.raises(PayloadPointerError):
        expand_subtree_pointer(_mixed_payload(), pointer)


def test_requires_fresh_32_byte_salts_and_detects_wrong_stored_values() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        PayloadLeaf(b"short", "value")

    payload = {"secret": "same"}
    first = commit_payload(payload)
    second = commit_payload(payload)
    assert first.leaves["/secret"].salt != second.leaves["/secret"].salt
    assert first.commitments["secret"] != second.commitments["secret"]

    altered = dict(first.leaves)
    altered["/secret"] = PayloadLeaf(first.leaves["/secret"].salt, "different")
    with pytest.raises(ValueError, match="mismatch"):
        reveal_payload(first.commitments, altered)


def test_checks_leaf_depth_and_size_limits_before_salt_generation() -> None:
    generated: list[int] = []

    def source(size: int) -> bytes:
        generated.append(size)
        return bytes(size)

    with pytest.raises(ValueError, match="leaf limit"):
        _commit_payload(
            {str(index): index for index in range(MAX_SCALAR_LEAVES + 1)}, source
        )
    with pytest.raises(ValueError, match="depth"):
        nested = 1
        for _ in range(10):
            nested = [nested]
        _commit_payload({"deep": cast(JsonValue, nested)}, source)
    with pytest.raises(ValueError, match="byte limit"):
        _commit_payload({"large": "x" * MAX_PAYLOAD_BYTES}, source)
    cyclic: list[JsonValue] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="Cyclic"):
        _commit_payload({"cycle": cyclic}, source)
    assert generated == []

    at_leaf_limit = _commit_payload(
        {str(index): index for index in range(MAX_SCALAR_LEAVES)}, source
    )
    assert len(at_leaf_limit.leaves) == MAX_SCALAR_LEAVES

    at_depth_limit: JsonValue = "ok"
    for _ in range(9):
        at_depth_limit = [at_depth_limit]
    assert len(_commit_payload({"deep": at_depth_limit}, source).leaves) == 1

    at_size_limit = _commit_payload({"x": "x" * (MAX_PAYLOAD_BYTES - 8)}, source)
    assert at_size_limit.leaves["/x"].value == "x" * (MAX_PAYLOAD_BYTES - 8)


def test_matches_shared_fixed_salt_commitment_vectors() -> None:
    vectors = cast(
        dict[str, object], json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    )
    payload = cast(dict[str, JsonValue], vectors["payload"])
    expected_commitments = cast(dict[str, JsonValue], vectors["commitments"])
    expected_leaves = cast(list[dict[str, object]], vectors["leaves"])
    salts = iter(bytes.fromhex(cast(str, leaf["saltHex"])) for leaf in expected_leaves)

    result = _commit_payload(payload, lambda size: next(salts))
    assert result.commitments == expected_commitments
    for expected in expected_leaves:
        pointer = cast(str, expected["pointer"])
        leaf = result.leaves[pointer]
        assert leaf.salt.hex() == expected["saltHex"]
        assert leaf.value == expected["value"]
