from __future__ import annotations

from collections.abc import Mapping

from audit_log_service.canonical_json import JsonValue
from audit_log_service.errors import invalid

EVENT_TYPE = "ACCOUNT_DATA_ACCESS"
RESOURCE_TYPE = "CLIENT_ACCOUNT"

_ENUMS: dict[str, frozenset[str]] = {
    "dataCategory": frozenset(
        {
            "PROFILE",
            "IDENTIFIERS",
            "BALANCES",
            "POSITIONS",
            "TRANSACTIONS",
            "STATEMENTS",
            "TAX_DOCUMENTS",
            "BANKING_DETAILS",
        }
    ),
    "accessType": frozenset({"VIEW", "SEARCH", "EXPORT", "PRINT", "MODIFY"}),
    "accessPurpose": frozenset(
        {
            "CLIENT_REQUEST",
            "TRADE_SUPPORT",
            "SERVICING",
            "COMPLIANCE_REVIEW",
            "FRAUD_INVESTIGATION",
            "LEGAL_HOLD",
            "OTHER",
        }
    ),
    "channel": frozenset(
        {"INTERNAL_APP", "SUPPORT_TOOL", "CLIENT_PORTAL", "API", "BATCH"}
    ),
    "outcome": frozenset({"GRANTED", "DENIED"}),
}


def validate(
    event_type: str, resource_type: str, payload: Mapping[str, JsonValue]
) -> None:
    """Validate the ACCOUNT_DATA_ACCESS contract; messages never echo values."""
    if event_type != EVENT_TYPE:
        return
    if resource_type != RESOURCE_TYPE:
        raise invalid("ACCOUNT_DATA_ACCESS requires resourceType CLIENT_ACCOUNT")
    chosen = {name: _enum(payload, name) for name in _ENUMS}
    if chosen["accessPurpose"] == "OTHER":
        _required_text(payload, "justification", 1000)
    else:
        _optional_text(payload, "justification", 1000)
    if chosen["outcome"] == "DENIED":
        _required_text(payload, "denialReason", 500)
    else:
        _optional_text(payload, "denialReason", 500)
    _optional_text(payload, "sessionId", 128)
    _optional_text(payload, "sourceIp", 64)


def _enum(payload: Mapping[str, JsonValue], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or value not in _ENUMS[name]:
        raise invalid(f"ACCOUNT_DATA_ACCESS payload.{name} is missing or not allowed")
    return value


def _required_text(payload: Mapping[str, JsonValue], name: str, limit: int) -> None:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise invalid(
            f"ACCOUNT_DATA_ACCESS payload.{name} must be non-blank text of at "
            f"most {limit} characters"
        )


def _optional_text(payload: Mapping[str, JsonValue], name: str, limit: int) -> None:
    if name not in payload:
        return
    value = payload[name]
    if not isinstance(value, str) or len(value) > limit:
        raise invalid(
            f"ACCOUNT_DATA_ACCESS payload.{name} must be text of at most "
            f"{limit} characters"
        )
