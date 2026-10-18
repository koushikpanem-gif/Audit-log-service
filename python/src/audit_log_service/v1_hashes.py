from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import TypedDict

from audit_log_service.canonical_json import (
    MAX_SAFE_INTEGER,
    JsonValue,
    canonicalize,
)

HASH_VERSION = 1
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_COMMITMENT_RE = _HASH_RE
_CONTENT_KEYS = frozenset(
    {
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
)


class EventContent(TypedDict):
    v: int
    seq: int
    eventId: str
    eventType: str
    actorId: str
    resourceType: str
    resourceId: str
    occurredAt: str | None
    recordedAt: str
    source: str
    payload: dict[str, JsonValue]


def genesis_hash(ledger_id: str) -> str:
    return _hash_domain(
        "audit-log/genesis/v1",
        ledger_id.encode("utf-8", errors="strict"),
    )


def leaf_hash(salt: bytes, pointer: str, value: JsonValue) -> str:
    if len(salt) != 32:
        raise ValueError("Leaf salt must contain exactly 32 bytes")
    if isinstance(value, (dict, list)):
        raise ValueError("Leaf commitment value must be a JSON scalar")
    pointer_bytes = pointer.encode("utf-8", errors="strict")
    return _hash_domain(
        "audit-log/leaf/v1",
        salt,
        b"\x00",
        pointer_bytes,
        b"\x00",
        canonicalize(value),
    )


def content_object(
    *,
    seq: int,
    event_id: str,
    event_type: str,
    actor_id: str,
    resource_type: str,
    resource_id: str,
    occurred_at: str | None,
    timestamp: str,
    source: str,
    payload: dict[str, JsonValue],
) -> EventContent:
    content: EventContent = {
        "v": HASH_VERSION,
        "seq": seq,
        "eventId": event_id,
        "eventType": event_type,
        "actorId": actor_id,
        "resourceType": resource_type,
        "resourceId": resource_id,
        "occurredAt": occurred_at,
        "recordedAt": timestamp,
        "source": source,
        "payload": payload,
    }
    _validate_content(content)
    return content


def content_hash(content: Mapping[str, JsonValue]) -> str:
    _validate_content(content)
    return _hash_domain("audit-log/content/v1", canonicalize(dict(content)))


def chain_hash(previous_hash: str, content_digest: str) -> str:
    previous = _decode_hash(previous_hash)
    content = _decode_hash(content_digest)
    return _hash_domain("audit-log/chain/v1", previous, content)


def _validate_content(content: Mapping[str, object]) -> None:
    if frozenset(content) != _CONTENT_KEYS:
        raise ValueError("V1 content must have exactly the required keys")
    version = content.get("v")
    seq = content.get("seq")
    if type(version) is not int or version != HASH_VERSION:
        raise ValueError("Unsupported content hash version")
    if type(seq) is not int or not 1 <= seq <= MAX_SAFE_INTEGER:
        raise ValueError("Content sequence must be a positive safe integer")
    for key in (
        "eventId",
        "eventType",
        "actorId",
        "resourceType",
        "resourceId",
        "recordedAt",
        "source",
    ):
        if not isinstance(content.get(key), str):
            raise ValueError(f"Content field must be a string: {key}")
    if content.get("occurredAt") is not None and not isinstance(
        content.get("occurredAt"), str
    ):
        raise ValueError("occurredAt must be a string or null")
    payload = content.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("Content payload must be a JSON object")
    pending: list[tuple[object, int]] = [(value, 0) for value in payload.values()]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, str):
            if not _COMMITMENT_RE.fullmatch(value):
                raise ValueError("Payload leaves must be lowercase SHA-256 hashes")
        elif isinstance(value, dict):
            if depth >= 10:
                raise ValueError("Payload nesting depth exceeds the limit")
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            if depth >= 10:
                raise ValueError("Payload nesting depth exceeds the limit")
            pending.extend((child, depth + 1) for child in value)
        else:
            raise ValueError("Payload leaves must be commitment strings")


def _decode_hash(value: str) -> bytes:
    if not _HASH_RE.fullmatch(value):
        raise ValueError("Hash must be lowercase 64-character hexadecimal")
    return bytes.fromhex(value)


def _hash_domain(domain: str, *values: bytes) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("utf-8"))
    digest.update(b"\x00")
    for value in values:
        digest.update(value)
    return digest.hexdigest()
