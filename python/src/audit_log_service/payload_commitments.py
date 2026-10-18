from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypeAlias

from audit_log_service.canonical_json import (
    MAX_NESTING_DEPTH,
    CanonicalJsonError,
    JsonScalar,
    JsonValue,
    canonicalize,
)
from audit_log_service.v1_hashes import leaf_hash

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_SCALAR_LEAVES = 500
REDACTED_VALUE = "[REDACTED]"
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_ARRAY_INDEX_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_Parent: TypeAlias = dict[str, JsonValue] | list[JsonValue]


class PayloadPointerError(ValueError):
    """Raised when a JSON Pointer is malformed or does not resolve."""


@dataclass(frozen=True)
class PayloadLeaf:
    salt: bytes
    value: JsonScalar

    def __post_init__(self) -> None:
        if not isinstance(self.salt, bytes) or len(self.salt) != 32:
            raise ValueError("Leaf salt must contain exactly 32 bytes")


@dataclass(frozen=True)
class CommitmentResult:
    commitments: dict[str, JsonValue]
    leaves: dict[str, PayloadLeaf]


@dataclass(frozen=True)
class RevealResult:
    payload: dict[str, JsonValue]
    redacted_paths: list[str]


def commit_payload(payload: dict[str, JsonValue]) -> CommitmentResult:
    return _commit_payload(payload, secrets.token_bytes)


def _commit_payload(
    payload: dict[str, JsonValue],
    salt_source: Callable[[int], bytes],
) -> CommitmentResult:
    leaf_count = _validate_payload_size(payload)

    commitments: dict[str, JsonValue] = {}
    leaves: dict[str, PayloadLeaf] = {}
    pending: list[tuple[JsonValue, _Parent, str, str | int]] = [
        (value, commitments, _child_pointer("", key), key)
        for key, value in reversed(tuple(payload.items()))
    ]
    while pending:
        value, parent, pointer, token = pending.pop()
        if isinstance(value, dict):
            child: dict[str, JsonValue] = {}
            _assign(parent, token, child)
            pending.extend(
                (item, child, _child_pointer(pointer, key), key)
                for key, item in reversed(tuple(value.items()))
            )
        elif isinstance(value, list):
            child_list: list[JsonValue] = [None] * len(value)
            _assign(parent, token, child_list)
            pending.extend(
                (item, child_list, _child_pointer(pointer, str(index)), index)
                for index, item in reversed(tuple(enumerate(value)))
            )
        else:
            salt = salt_source(32)
            if not isinstance(salt, bytes) or len(salt) != 32:
                raise ValueError("Salt source must return exactly 32 bytes")
            leaves[pointer] = PayloadLeaf(bytes(salt), value)
            _assign(parent, token, leaf_hash(salt, pointer, value))

    if len(leaves) != leaf_count:
        raise RuntimeError("Payload leaf count changed during commitment")
    return CommitmentResult(commitments, leaves)


def reveal_payload(
    commitments: dict[str, JsonValue],
    leaves: Mapping[str, PayloadLeaf],
) -> RevealResult:
    if not isinstance(commitments, dict):
        raise ValueError("Payload commitments must be an object")
    _validate_commitment_tree(commitments)
    payload: dict[str, JsonValue] = {}
    redacted_paths: list[str] = []
    used_leaves: set[str] = set()
    pending: list[
        tuple[
            JsonValue,
            _Parent,
            str,
            str | int,
        ]
    ] = [
        (value, payload, _child_pointer("", key), key)
        for key, value in reversed(tuple(commitments.items()))
    ]
    while pending:
        value, parent, pointer, token = pending.pop()
        if isinstance(value, dict):
            child: dict[str, JsonValue] = {}
            _assign(parent, token, child)
            pending.extend(
                (item, child, _child_pointer(pointer, key), key)
                for key, item in reversed(tuple(value.items()))
            )
        elif isinstance(value, list):
            child_list: list[JsonValue] = [None] * len(value)
            _assign(parent, token, child_list)
            pending.extend(
                (item, child_list, _child_pointer(pointer, str(index)), index)
                for index, item in reversed(tuple(enumerate(value)))
            )
        elif isinstance(value, str) and _HASH_RE.fullmatch(value):
            leaf = leaves.get(pointer)
            if leaf is None:
                _assign(parent, token, REDACTED_VALUE)
                redacted_paths.append(pointer)
                continue
            if leaf_hash(leaf.salt, pointer, leaf.value) != value:
                raise ValueError(f"Payload leaf commitment mismatch at {pointer}")
            used_leaves.add(pointer)
            _assign(parent, token, leaf.value)
        else:
            raise ValueError(f"Malformed payload commitment tree at {pointer}")

    if used_leaves != set(leaves):
        raise ValueError("Stored payload leaves do not match the commitment tree")
    return RevealResult(
        payload,
        sorted(redacted_paths, key=lambda path: path.encode("utf-16-be")),
    )


def expand_subtree_pointer(
    payload: Mapping[str, JsonValue],
    pointer: str,
) -> list[str]:
    if not isinstance(payload, Mapping):
        raise ValueError("Payload must be a JSON object")
    _validate_payload_size(dict(payload))
    tokens = _parse_pointer(pointer)
    node: JsonValue = dict(payload)
    current_pointer = ""
    for token in tokens:
        node = _resolve_child(node, token)
        current_pointer = _child_pointer(current_pointer, token)

    leaves: list[str] = []
    pending: list[tuple[JsonValue, str]] = [(node, current_pointer)]
    while pending:
        value, path = pending.pop()
        if isinstance(value, dict):
            pending.extend(
                (child, _child_pointer(path, key))
                for key, child in reversed(tuple(value.items()))
            )
        elif isinstance(value, list):
            pending.extend(
                (child, _child_pointer(path, str(index)))
                for index, child in reversed(tuple(enumerate(value)))
            )
        else:
            leaves.append(path)
    return sorted(leaves, key=lambda path: path.encode("utf-16-be"))


def _validate_payload(payload: dict[str, JsonValue]) -> int:
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a JSON object")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise CanonicalJsonError("Payload exceeds the byte limit")
    pending: list[tuple[object, int, bool]] = [
        (value, 1, False) for value in payload.values()
    ]
    for key in payload:
        if not isinstance(key, str):
            raise CanonicalJsonError("JSON object keys must be strings")
    text_bytes = sum(_utf8_length(key) for key in payload)
    if text_bytes > MAX_PAYLOAD_BYTES:
        raise CanonicalJsonError("Payload exceeds the byte limit")
    active_containers: set[int] = set()
    node_count = 0
    leaf_count = 0
    while pending:
        value, depth, exiting = pending.pop()
        if exiting:
            active_containers.remove(id(value))
            continue
        node_count += 1
        if node_count > MAX_PAYLOAD_BYTES:
            raise CanonicalJsonError("Payload exceeds the byte limit")
        if isinstance(value, dict):
            if depth >= MAX_NESTING_DEPTH:
                raise CanonicalJsonError("Payload nesting depth exceeds the limit")
            identity = id(value)
            if identity in active_containers:
                raise CanonicalJsonError("Cyclic values are not JSON serializable")
            active_containers.add(identity)
            pending.append((value, depth, True))
            if len(value) > MAX_PAYLOAD_BYTES:
                raise CanonicalJsonError("Payload exceeds the byte limit")
            for key, child in value.items():
                if not isinstance(key, str):
                    raise CanonicalJsonError("JSON object keys must be strings")
                text_bytes += _utf8_length(key)
                if text_bytes > MAX_PAYLOAD_BYTES:
                    raise CanonicalJsonError("Payload exceeds the byte limit")
                pending.append((child, depth + 1, False))
        elif isinstance(value, list):
            if depth >= MAX_NESTING_DEPTH:
                raise CanonicalJsonError("Payload nesting depth exceeds the limit")
            identity = id(value)
            if identity in active_containers:
                raise CanonicalJsonError("Cyclic values are not JSON serializable")
            active_containers.add(identity)
            pending.append((value, depth, True))
            if len(value) > MAX_PAYLOAD_BYTES:
                raise CanonicalJsonError("Payload exceeds the byte limit")
            pending.extend((child, depth + 1, False) for child in value)
        else:
            if isinstance(value, str):
                text_bytes += _utf8_length(value)
                if text_bytes > MAX_PAYLOAD_BYTES:
                    raise CanonicalJsonError("Payload exceeds the byte limit")
            leaf_count += 1
            if leaf_count > MAX_SCALAR_LEAVES:
                raise CanonicalJsonError("Payload exceeds the scalar leaf limit")
    return leaf_count


def _validate_payload_size(payload: dict[str, JsonValue]) -> int:
    leaf_count = _validate_payload(payload)
    if len(canonicalize(payload)) > MAX_PAYLOAD_BYTES:
        raise CanonicalJsonError("Payload exceeds the byte limit")
    return leaf_count


def _validate_commitment_tree(commitments: dict[str, JsonValue]) -> None:
    if len(commitments) > MAX_PAYLOAD_BYTES:
        raise CanonicalJsonError("Payload exceeds the byte limit")
    pending: list[tuple[object, int, bool]] = [
        (value, 1, False) for value in commitments.values()
    ]
    for key in commitments:
        if not isinstance(key, str):
            raise CanonicalJsonError("JSON object keys must be strings")
    text_bytes = sum(_utf8_length(key) for key in commitments)
    if text_bytes > MAX_PAYLOAD_BYTES:
        raise CanonicalJsonError("Payload exceeds the byte limit")
    active_containers: set[int] = set()
    leaf_count = 0
    node_count = 0
    while pending:
        value, depth, exiting = pending.pop()
        if exiting:
            active_containers.remove(id(value))
            continue
        node_count += 1
        if node_count > MAX_PAYLOAD_BYTES:
            raise CanonicalJsonError("Payload exceeds the byte limit")
        if isinstance(value, dict):
            if depth >= MAX_NESTING_DEPTH:
                raise CanonicalJsonError("Payload nesting depth exceeds the limit")
            if len(value) > MAX_PAYLOAD_BYTES:
                raise CanonicalJsonError("Payload exceeds the byte limit")
            identity = id(value)
            if identity in active_containers:
                raise CanonicalJsonError("Cyclic values are not JSON serializable")
            active_containers.add(identity)
            pending.append((value, depth, True))
            for key, child in value.items():
                if not isinstance(key, str):
                    raise CanonicalJsonError("JSON object keys must be strings")
                text_bytes += _utf8_length(key)
                if text_bytes > MAX_PAYLOAD_BYTES:
                    raise CanonicalJsonError("Payload exceeds the byte limit")
                pending.append((child, depth + 1, False))
        elif isinstance(value, list):
            if depth >= MAX_NESTING_DEPTH:
                raise CanonicalJsonError("Payload nesting depth exceeds the limit")
            if len(value) > MAX_PAYLOAD_BYTES:
                raise CanonicalJsonError("Payload exceeds the byte limit")
            identity = id(value)
            if identity in active_containers:
                raise CanonicalJsonError("Cyclic values are not JSON serializable")
            active_containers.add(identity)
            pending.append((value, depth, True))
            pending.extend((child, depth + 1, False) for child in value)
        elif isinstance(value, str) and _HASH_RE.fullmatch(value):
            leaf_count += 1
            if leaf_count > MAX_SCALAR_LEAVES:
                raise CanonicalJsonError("Payload exceeds the scalar leaf limit")
        else:
            raise ValueError("Malformed payload commitment tree")
    if len(canonicalize(commitments)) > MAX_PAYLOAD_BYTES:
        raise CanonicalJsonError("Payload exceeds the byte limit")


def _parse_pointer(pointer: str) -> tuple[str, ...]:
    if not isinstance(pointer, str):
        raise PayloadPointerError("JSON Pointer must be text")
    try:
        pointer_bytes = _utf8_length(pointer)
    except CanonicalJsonError as exc:
        raise PayloadPointerError("JSON Pointer must contain valid Unicode") from exc
    if pointer_bytes > MAX_PAYLOAD_BYTES:
        raise PayloadPointerError("JSON Pointer exceeds the byte limit")
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise PayloadPointerError("JSON Pointer must be empty or start with '/'")
    result: list[str] = []
    for raw_token in pointer[1:].split("/"):
        token: list[str] = []
        index = 0
        while index < len(raw_token):
            character = raw_token[index]
            if character != "~":
                token.append(character)
                index += 1
            elif index + 1 < len(raw_token) and raw_token[index + 1] in "01":
                token.append("~" if raw_token[index + 1] == "0" else "/")
                index += 2
            else:
                raise PayloadPointerError("JSON Pointer contains an invalid escape")
        result.append("".join(token))
    return tuple(result)


def _resolve_child(value: JsonValue, token: str) -> JsonValue:
    if isinstance(value, dict):
        try:
            return value[token]
        except KeyError as exc:
            raise PayloadPointerError("JSON Pointer path does not exist") from exc
    if isinstance(value, list):
        if not _ARRAY_INDEX_RE.fullmatch(token):
            raise PayloadPointerError("JSON Pointer array index is not canonical")
        if len(token) > len(str(len(value))):
            raise PayloadPointerError("JSON Pointer path does not exist")
        index = int(token)
        if index >= len(value):
            raise PayloadPointerError("JSON Pointer path does not exist")
        return value[index]
    raise PayloadPointerError("JSON Pointer path does not exist")


def _child_pointer(parent: str, token: str) -> str:
    return f"{parent}/{token.replace('~', '~0').replace('/', '~1')}"


def _assign(
    parent: _Parent,
    token: str | int,
    value: JsonValue,
) -> None:
    if isinstance(parent, dict):
        if not isinstance(token, str):
            raise RuntimeError("Object payload pointer has a non-string key")
        parent[token] = value
    else:
        if not isinstance(token, int):
            raise RuntimeError("Array payload pointer has a non-integer index")
        parent[token] = value


def _utf8_length(value: str) -> int:
    length = 0
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise CanonicalJsonError("JSON strings must contain valid Unicode")
        if codepoint <= 0x7F:
            length += 1
        elif codepoint <= 0x7FF:
            length += 2
        elif codepoint <= 0xFFFF:
            length += 3
        else:
            length += 4
    return length
