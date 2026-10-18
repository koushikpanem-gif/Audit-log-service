import json
from pathlib import Path
from typing import cast

import pytest

from audit_log_service.canonical_json import JsonValue
from audit_log_service.v1_hashes import (
    chain_hash,
    content_hash,
    content_object,
    genesis_hash,
    leaf_hash,
)

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "test-vectors" / "jcs-v1.json"
)


def _hash_vectors() -> dict[str, object]:
    vectors = cast(
        dict[str, object],
        json.loads(VECTORS_PATH.read_text(encoding="utf-8")),
    )
    return cast(dict[str, object], vectors["hashes"])


def test_v1_hashes_match_independent_golden_vectors() -> None:
    vectors = _hash_vectors()
    genesis = genesis_hash(cast(str, vectors["ledgerId"]))
    assert genesis == vectors["genesisHash"]

    leaf = cast(dict[str, object], vectors["leaf"])
    assert (
        leaf_hash(
            bytes.fromhex(cast(str, leaf["saltHex"])),
            cast(str, leaf["pointer"]),
            cast(JsonValue, leaf["value"]),
        )
        == leaf["hash"]
    )

    expected_content = cast(dict[str, object], vectors["content"])
    content = dict(expected_content)
    expected_hash = content.pop("hash")
    assert content_hash(cast(dict[str, JsonValue], content)) == expected_hash
    assert chain_hash(genesis, cast(str, expected_hash)) == vectors["chainHash"]


def test_content_builder_uses_exact_v1_shape_and_maps_timestamp() -> None:
    content = content_object(
        seq=1,
        event_id="evt-1",
        event_type="TEST",
        actor_id="alice",
        resource_type="ACCOUNT",
        resource_id="acct-1",
        occurred_at=None,
        timestamp="2026-01-02T03:04:05.000000Z",
        source="writer",
        payload={"ok": "a" * 64},
    )
    assert set(content) == {
        "v",
        "seq",
        "eventId",
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "occurredAt",
        "recordedAt",
        "source",
        "payload",
    }
    assert content["recordedAt"] == "2026-01-02T03:04:05.000000Z"
    assert content["occurredAt"] is None


@pytest.mark.parametrize(
    "previous,content",
    [
        ("A" * 64, "0" * 64),
        ("0" * 63, "0" * 64),
        ("0" * 64, "0" * 63),
        ("g" * 64, "0" * 64),
    ],
)
def test_chain_hash_rejects_invalid_hash_encodings(previous: str, content: str) -> None:
    with pytest.raises(ValueError):
        chain_hash(previous, content)


def test_leaf_hash_requires_a_32_byte_salt_and_scalar() -> None:
    from audit_log_service.v1_hashes import leaf_hash

    with pytest.raises(ValueError, match="32 bytes"):
        leaf_hash(b"short", "/x", "value")
    with pytest.raises(ValueError, match="scalar"):
        leaf_hash(bytes(32), "/x", {"not": "scalar"})


def test_content_hash_rejects_unknown_or_incomplete_fields() -> None:
    with pytest.raises(ValueError, match="exactly"):
        content_hash({"v": 1})


def test_content_hash_rejects_uncommitted_payload_scalars() -> None:
    content = content_object(
        seq=1,
        event_id="evt-1",
        event_type="TEST",
        actor_id="alice",
        resource_type="ACCOUNT",
        resource_id="acct-1",
        occurred_at=None,
        timestamp="2026-01-02T03:04:05.000000Z",
        source="writer",
        payload={"secret": "a" * 64},
    )
    content["payload"] = {"secret": "plaintext"}
    with pytest.raises(ValueError, match="lowercase SHA-256 hashes"):
        content_hash(content)
