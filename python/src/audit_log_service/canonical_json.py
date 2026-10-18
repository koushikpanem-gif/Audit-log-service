from __future__ import annotations

import json
import math
from typing import TypeAlias, cast

import rfc8785

MAX_INPUT_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 10
MAX_DOCUMENT_DEPTH = 32
MAX_SAFE_INTEGER = 9_007_199_254_740_991

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


class CanonicalJsonError(ValueError):
    """Raised for invalid or unsupported JCS JSON input."""


def parse_json(
    data: bytes | str,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_depth: int = MAX_NESTING_DEPTH,
) -> JsonValue:
    if max_bytes <= 0 or max_depth <= 0:
        raise CanonicalJsonError("JSON limits must be positive")
    if isinstance(data, bytes):
        raw = data
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalJsonError("JSON input must be valid UTF-8") from exc
    elif isinstance(data, str):
        _validate_string(data)
        text = data
        raw = text.encode("utf-8")
    else:
        raise CanonicalJsonError("JSON input must be UTF-8 bytes or text")

    if len(raw) > max_bytes:
        raise CanonicalJsonError("JSON input exceeds the byte limit")
    _check_depth(raw, max_depth)

    try:
        value: object = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_parse_integer,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, CanonicalJsonError):
            raise
        raise CanonicalJsonError("Invalid JSON input") from exc
    _validate_value(value, max_depth=max_depth)
    return cast(JsonValue, value)


def canonicalize(value: JsonValue, *, max_depth: int = MAX_NESTING_DEPTH) -> bytes:
    _validate_value(value, max_depth=max_depth)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, RecursionError) as exc:
        raise CanonicalJsonError("Unable to canonicalize JSON value") from exc


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError("Duplicate JSON object key")
        result[key] = value
    return result


def _parse_integer(token: str) -> int:
    value = int(token)
    if abs(value) > MAX_SAFE_INTEGER:
        raise CanonicalJsonError("JSON integer token exceeds the safe range")
    return value


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise CanonicalJsonError("JSON number must be finite")
    return value


def _reject_constant(token: str) -> None:
    raise CanonicalJsonError(f"Non-JSON numeric constant is not permitted: {token}")


def _check_depth(raw: bytes, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in (0x7B, 0x5B):
            depth += 1
            if depth > max_depth:
                raise CanonicalJsonError("JSON nesting depth exceeds the limit")
        elif byte in (0x7D, 0x5D):
            depth -= 1


def _validate_string(value: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJsonError("JSON strings must contain valid Unicode") from exc


def _validate_value(value: object, *, max_depth: int) -> None:
    pending: list[tuple[object, int, bool]] = [(value, 0, False)]
    active_containers: set[int] = set()
    while pending:
        current, depth, exiting = pending.pop()
        if exiting:
            active_containers.remove(id(current))
        elif isinstance(current, str):
            _validate_string(current)
        elif current is None or isinstance(current, bool):
            continue
        elif isinstance(current, int):
            if abs(current) > MAX_SAFE_INTEGER:
                raise CanonicalJsonError("Integer exceeds the safe range")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise CanonicalJsonError("JSON number must be finite")
        elif isinstance(current, dict):
            if depth >= max_depth:
                raise CanonicalJsonError("JSON nesting depth exceeds the limit")
            identity = id(current)
            if identity in active_containers:
                raise CanonicalJsonError("Cyclic values are not JSON serializable")
            active_containers.add(identity)
            pending.append((current, depth, True))
            for key, child in current.items():
                if not isinstance(key, str):
                    raise CanonicalJsonError("JSON object keys must be strings")
                _validate_string(key)
                pending.append((child, depth + 1, False))
        elif isinstance(current, list):
            if depth >= max_depth:
                raise CanonicalJsonError("JSON nesting depth exceeds the limit")
            identity = id(current)
            if identity in active_containers:
                raise CanonicalJsonError("Cyclic values are not JSON serializable")
            active_containers.add(identity)
            pending.append((current, depth, True))
            pending.extend((child, depth + 1, False) for child in current)
        else:
            raise CanonicalJsonError("Value is not in the supported JSON data model")
