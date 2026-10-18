from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone

_ISO = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?"
    r"(?:(Z)|([+-])(\d{2}):(\d{2}))\Z"
)
_STORED = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")


def format_micros(value: datetime) -> str:
    utc = value.astimezone(UTC)
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}T"
        f"{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}.{utc.microsecond:06d}Z"
    )


def parse_offset_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp that carries an explicit offset (UTC result)."""
    match = _ISO.fullmatch(value)
    if match is None:
        raise ValueError("timestamp must be ISO-8601 with an offset")
    year, month, day, hour, minute, second, fraction, zulu, sign, oh, om = (
        match.groups()
    )
    micros = int((fraction or "").ljust(6, "0")[:6] or 0)
    if zulu:
        zone = UTC
    else:
        delta = timedelta(hours=int(oh), minutes=int(om))
        if int(oh) > 18 or int(om) > 59:
            raise ValueError("timestamp offset is out of range")
        zone = timezone(delta if sign == "+" else -delta)
    try:
        parsed = datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second or 0),
            micros,
            tzinfo=zone,
        )
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValueError("timestamp is out of range") from exc


def parse_stored_timestamp(value: str) -> datetime:
    if _STORED.fullmatch(value) is None:
        raise ValueError("stored timestamp is malformed")
    return parse_offset_timestamp(value)
