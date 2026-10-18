"""Strict JSON parsing and RFC 8785 (JCS) canonicalization for the offline verifier.

Self-contained on purpose: nothing here imports the Starlette service or its own
canonicalization module, so a defect there cannot change what the verifier accepts.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_DOCUMENT_DEPTH = 32


class JsonError(ValueError):
    """Input is not strict, canonicalizable JSON, or exceeds a resource limit."""


class DepthError(JsonError):
    """Nesting depth exceeds the configured limit."""


def _scan_depth(text: str, max_depth: int) -> None:
    """Iterative nesting check so no recursive code runs on hostile input."""
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise DepthError("JSON nesting depth exceeds the limit")
        elif char in "]}":
            depth -= 1


def _check_string(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise JsonError("String contains a lone surrogate") from error


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _check_string(key)
        if key in result:
            raise JsonError("Duplicate object key")
        result[key] = value
    return result


def _integer(token: str) -> int:
    try:
        value = int(token)
    except ValueError as error:
        raise JsonError("Integer token is not representable") from error
    if abs(value) > MAX_SAFE_INTEGER:
        raise JsonError("Integer token is outside the safe range")
    return value


def _float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise JsonError("Number is not finite")
    return value


def _constant(token: str) -> Any:
    raise JsonError("NaN and infinity are not valid JSON")


def _check_strings(value: Any) -> None:
    """Lone surrogates may only appear in string values; keys are checked earlier."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            _check_string(item)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.values())


def parse_strict(raw: bytes, *, max_depth: int = MAX_DOCUMENT_DEPTH) -> Any:
    """Parse UTF-8 JSON, rejecting everything the v1 protocol forbids."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise JsonError("Input is not valid UTF-8") from error
    if text.startswith("\ufeff"):
        raise JsonError("A byte order mark is not allowed")
    _scan_depth(text, max_depth)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_float=_float,
            parse_constant=_constant,
        )
    except JsonError:
        raise
    except (ValueError, RecursionError) as error:
        raise JsonError("Input is not valid JSON") from error
    _check_strings(value)
    return value


def _quote(value: str) -> str:
    _check_string(value)
    out = ['"']
    for char in value:
        code = ord(char)
        if char == '"':
            out.append('\\"')
        elif char == "\\":
            out.append("\\\\")
        elif char == "\b":
            out.append("\\b")
        elif char == "\f":
            out.append("\\f")
        elif char == "\n":
            out.append("\\n")
        elif char == "\r":
            out.append("\\r")
        elif char == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def format_double(value: float) -> str:
    """ECMAScript Number::toString for a finite binary64 (RFC 8785 3.2.2.3)."""
    if not math.isfinite(value):
        raise JsonError("Number is not finite")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    assert isinstance(exponent, int)
    digits = "".join(str(d) for d in digit_tuple).lstrip("0")
    while digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    k = len(digits)
    n = k + exponent
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mantissa}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _serialize(value: Any, out: list[str], depth: int, max_depth: int) -> None:
    if depth > max_depth:
        raise DepthError("JSON nesting depth exceeds the limit")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise JsonError("Integer is outside the safe range")
        out.append(str(value))
    elif isinstance(value, float):
        out.append(format_double(value))
    elif isinstance(value, str):
        out.append(_quote(value))
    elif isinstance(value, list):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _serialize(item, out, depth + 1, max_depth)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for index, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if index:
                out.append(",")
            out.append(_quote(key))
            out.append(":")
            _serialize(value[key], out, depth + 1, max_depth)
        out.append("}")
    else:
        raise JsonError("Value is not a JSON type")


def canonicalize(value: Any, *, max_depth: int = MAX_DOCUMENT_DEPTH) -> bytes:
    """Return the JCS UTF-8 bytes of value."""
    out: list[str] = []
    try:
        _serialize(value, out, 1, max_depth)
    except RecursionError as error:
        raise DepthError("JSON nesting depth exceeds the limit") from error
    return "".join(out).encode("utf-8")
