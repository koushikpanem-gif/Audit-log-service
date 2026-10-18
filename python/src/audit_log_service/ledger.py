from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from audit_log_service import account_access
from audit_log_service.canonical_json import (
    MAX_INPUT_BYTES,
    MAX_SAFE_INTEGER,
    CanonicalJsonError,
    JsonValue,
    canonicalize,
    parse_json,
)
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError, invalid
from audit_log_service.payload_commitments import (
    PayloadLeaf,
    PayloadPointerError,
    commit_payload,
    reveal_payload,
)
from audit_log_service.signing import CheckpointSigner
from audit_log_service.store import SqliteStore
from audit_log_service.timeutil import (
    format_micros,
    parse_offset_timestamp,
    parse_stored_timestamp,
)
from audit_log_service.v1_hashes import (
    HASH_VERSION,
    chain_hash,
    content_hash,
    content_object,
    genesis_hash,
)

RESERVED_EVENT_TYPES = frozenset(
    {
        "RECORD_REDACTED",
        "RECORDS_ARCHIVED",
        "BUNDLE_EXPORTED",
        "COMPLIANCE_REPORT_GENERATED",
    }
)
MAX_FUTURE_SKEW = timedelta(seconds=300)
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
_ENVELOPE_FIELDS = frozenset(
    {"eventType", "actorId", "resourceType", "resourceId", "payload", "occurredAt"}
)
_FILTER_NAMES = ("actorId", "resourceType", "resourceId", "eventType", "from", "to")
_B64URL = re.compile(r"[A-Za-z0-9_-]*\Z")
_EVENT_COLUMNS = (
    "seq, event_id, event_type, actor_id, resource_type, resource_id, "
    "occurred_at, recorded_at, source, payload_commitments, hash_version, "
    "content_hash, prev_hash, chain_hash"
)

Clock = Callable[[], datetime]


def system_clock() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class AppendRequest:
    event_type: str
    actor_id: str
    resource_type: str
    resource_id: str
    payload: dict[str, JsonValue]
    occurred_at: str | None


def parse_append_request(
    body: JsonValue, configuration: AuditConfiguration
) -> AppendRequest:
    """Validate the event envelope; unknown fields and caller metadata are rejected."""
    if not isinstance(body, dict):
        raise invalid("Request body must be a JSON object")
    unknown = set(body) - _ENVELOPE_FIELDS
    if unknown:
        raise invalid("Request contains fields that callers may not submit")
    texts: dict[str, str] = {}
    for name in ("eventType", "actorId", "resourceType", "resourceId"):
        texts[name] = _require_text(body.get(name), name)
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise invalid("payload must be a JSON object")
    occurred = body.get("occurredAt")
    if occurred is not None and not isinstance(occurred, str):
        raise invalid("occurredAt must be an ISO-8601 timestamp with an offset")
    if texts["eventType"] in RESERVED_EVENT_TYPES:
        raise invalid("Reserved system event types cannot be submitted")
    normalized = _normalize_payload(payload, configuration)
    account_access.validate(texts["eventType"], texts["resourceType"], normalized)
    return AppendRequest(
        texts["eventType"],
        texts["actorId"],
        texts["resourceType"],
        texts["resourceId"],
        normalized,
        _normalize_occurred_at(occurred),
    )


def _require_text(value: JsonValue, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > MAX_INPUT_BYTES
    ):
        raise invalid(f"{name} must be non-empty text within the request limit")
    return value


def _normalize_occurred_at(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return format_micros(parse_offset_timestamp(value))
    except ValueError as exc:
        raise invalid("occurredAt must be a valid ISO-8601 timestamp") from exc


def _normalize_payload(
    payload: dict[str, JsonValue], configuration: AuditConfiguration
) -> dict[str, JsonValue]:
    try:
        canonical = canonicalize(payload)
        if len(canonical) > configuration.payload_limit_bytes:
            raise invalid("Payload exceeds the configured byte limit")
        reparsed = parse_json(canonical, max_depth=configuration.max_depth + 2)
    except CanonicalJsonError as exc:
        raise invalid("Payload is not valid canonical JSON") from exc
    assert isinstance(reparsed, dict)
    leaves = 0
    pending: list[tuple[JsonValue, int]] = [(v, 1) for v in reparsed.values()]
    while pending:
        value, depth = pending.pop()
        if isinstance(value, dict | list):
            if depth >= configuration.max_depth:
                raise invalid("Payload nesting depth exceeds the configured limit")
            children = value.values() if isinstance(value, dict) else value
            pending.extend((child, depth + 1) for child in children)
        else:
            leaves += 1
            if leaves > configuration.max_leaves:
                raise invalid("Payload exceeds the configured scalar leaf limit")
    return reparsed


class AppendService:
    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        signer: CheckpointSigner,
        clock: Clock = system_clock,
        event_id_source: Callable[[], str] | None = None,
    ) -> None:
        self._store = store
        self._configuration = configuration
        self._signer = signer
        self._clock = clock
        self._event_id = event_id_source or (lambda: str(uuid.uuid4()))

    def append(self, request: AppendRequest, source: str) -> dict[str, Any]:
        if not source.strip() or source == "system":
            raise invalid("System source is reserved for internal events")
        with self._store.write_transaction() as connection:
            return self._append_locked(connection, request, source)

    def _append_locked(
        self, connection: sqlite3.Connection, request: AppendRequest, source: str
    ) -> dict[str, Any]:
        head = connection.execute(
            "SELECT seq, chain_hash, recorded_at FROM audit_events "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = 1 if head is None else int(head["seq"]) + 1
        if seq > MAX_SAFE_INTEGER:
            raise ApiError(500, "INTERNAL_ERROR", "Ledger sequence limit reached")
        now = self._clock().astimezone(UTC)
        if request.occurred_at is not None and (
            parse_offset_timestamp(request.occurred_at) > now + MAX_FUTURE_SKEW
        ):
            raise invalid("occurredAt exceeds the 300-second future-skew limit")
        recorded = now
        if head is not None:
            recorded = max(now, parse_stored_timestamp(head["recorded_at"]))
        timestamp = format_micros(recorded)
        previous = (
            genesis_hash(self._configuration.ledger_id)
            if head is None
            else str(head["chain_hash"])
        )
        event_id = self._event_id()
        committed = commit_payload(request.payload)
        content = content_object(
            seq=seq,
            event_id=event_id,
            event_type=request.event_type,
            actor_id=request.actor_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            occurred_at=request.occurred_at,
            timestamp=timestamp,
            source=source,
            payload=committed.commitments,
        )
        content_digest = content_hash(cast(Any, content))
        chain_digest = chain_hash(previous, content_digest)
        connection.execute(
            "INSERT INTO audit_events(seq, event_id, event_type, actor_id, "
            "resource_type, resource_id, occurred_at, recorded_at, source, "
            "payload_commitments, hash_version, content_hash, prev_hash, chain_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                seq,
                event_id,
                request.event_type,
                request.actor_id,
                request.resource_type,
                request.resource_id,
                request.occurred_at,
                timestamp,
                source,
                canonicalize(committed.commitments).decode("utf-8"),
                HASH_VERSION,
                content_digest,
                previous,
                chain_digest,
            ),
        )
        connection.executemany(
            "INSERT INTO payload_leaves(seq, pointer, salt, value) VALUES (?, ?, ?, ?)",
            [
                (
                    seq,
                    pointer,
                    leaf.salt.hex(),
                    canonicalize(leaf.value).decode("utf-8"),
                )
                for pointer, leaf in committed.leaves.items()
            ],
        )
        if seq % self._configuration.checkpoint_interval == 0:
            _insert_checkpoint(
                connection,
                self._signer,
                self._configuration.ledger_id,
                seq,
                chain_digest,
                timestamp,
            )
        return {
            "eventType": request.event_type,
            "actorId": request.actor_id,
            "resourceType": request.resource_type,
            "resourceId": request.resource_id,
            "payload": request.payload,
            "occurredAt": request.occurred_at,
            "eventId": event_id,
            "seq": seq,
            "timestamp": timestamp,
            "source": source,
            "hashVersion": HASH_VERSION,
            "payloadCommitments": committed.commitments,
            "redactedPaths": [],
            "contentHash": content_digest,
            "prevHash": previous,
            "chainHash": chain_digest,
        }

    def append_system_event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        payload: dict[str, JsonValue],
    ) -> dict[str, Any]:
        """Append a service-generated event inside a caller-owned write transaction."""
        request = AppendRequest(
            event_type, actor_id, resource_type, resource_id, payload, None
        )
        return self._append_locked(connection, request, "system")

    def store_checkpoint(
        self,
        connection: sqlite3.Connection,
        seq: int,
        chain_digest: str,
        created_at: str,
    ) -> dict[str, Any]:
        return _insert_checkpoint(
            connection,
            self._signer,
            self._configuration.ledger_id,
            seq,
            chain_digest,
            created_at,
        )

    def create_checkpoint(self) -> dict[str, Any]:
        """Sign the current head on demand; an empty ledger has nothing to sign."""
        with self._store.write_transaction() as connection:
            head = connection.execute(
                "SELECT seq, chain_hash, recorded_at FROM audit_events "
                "ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if head is None:
                raise ApiError(
                    409, "CONFLICT", "An empty ledger cannot be checkpointed"
                )
            created = max(
                self._clock().astimezone(UTC),
                parse_stored_timestamp(head["recorded_at"]),
            )
            return _insert_checkpoint(
                connection,
                self._signer,
                self._configuration.ledger_id,
                int(head["seq"]),
                str(head["chain_hash"]),
                format_micros(created),
            )


def _insert_checkpoint(
    connection: sqlite3.Connection,
    signer: CheckpointSigner,
    ledger_id: str,
    seq: int,
    chain_digest: str,
    created_at: str,
) -> dict[str, Any]:
    checkpoint = signer.sign_checkpoint(
        ledger_id=ledger_id, seq=seq, chain_hash=chain_digest, created_at=created_at
    )
    connection.execute(
        "INSERT INTO checkpoints(seq, chain_hash, created_at, key_id, signature) "
        "VALUES (?, ?, ?, ?, ?)",
        (seq, chain_digest, created_at, checkpoint.key_id, checkpoint.signature),
    )
    return {
        "seq": seq,
        "chainHash": chain_digest,
        "createdAt": created_at,
        "keyId": checkpoint.key_id,
        "signature": checkpoint.signature,
    }


class QueryService:
    def __init__(self, store: SqliteStore, cursor_key: bytes) -> None:
        self._store = store
        self._cursor_key = cursor_key

    def list_events(
        self,
        *,
        filters: dict[str, str | None],
        limit: int | None,
        order: str | None,
        cursor: str | None,
    ) -> dict[str, Any]:
        normalized = _normalize_filters(filters)
        page_size = DEFAULT_PAGE_SIZE if limit is None else limit
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise invalid("limit must be between 1 and 500")
        direction = "asc" if order is None else order.lower()
        if direction not in {"asc", "desc"}:
            raise invalid("order must be asc or desc")
        state = None if cursor is None else self._decode(cursor, normalized, direction)
        with self._store.read_snapshot() as connection:
            if state is None:
                as_of = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(seq), 0) FROM audit_events"
                    ).fetchone()[0]
                )
                last_seq = None
            else:
                as_of, last_seq = state
            sql = (
                f"SELECT {_EVENT_COLUMNS} FROM audit_events "
                "WHERE archived = 0 AND seq <= ?"
            )
            params: list[object] = [as_of]
            for column, name in (
                ("actor_id", "actorId"),
                ("resource_type", "resourceType"),
                ("resource_id", "resourceId"),
                ("event_type", "eventType"),
            ):
                if normalized[name] is not None:
                    sql += f" AND {column} = ?"
                    params.append(normalized[name])
            if normalized["from"] is not None:
                sql += " AND recorded_at >= ?"
                params.append(normalized["from"])
            if normalized["to"] is not None:
                sql += " AND recorded_at <= ?"
                params.append(normalized["to"])
            if last_seq is not None:
                sql += " AND seq > ?" if direction == "asc" else " AND seq < ?"
                params.append(last_seq)
            sql += f" ORDER BY seq {direction.upper()} LIMIT ?"
            params.append(page_size + 1)
            rows = connection.execute(sql, params).fetchall()
            more = len(rows) > page_size
            rows = rows[:page_size]
            items = [_event_view(connection, row) for row in rows]
        next_cursor = None
        if more and rows:
            next_cursor = self._encode(
                normalized, direction, as_of, int(rows[-1]["seq"])
            )
        return {"items": items, "nextCursor": next_cursor}

    def get_event(self, event_id: str) -> dict[str, Any]:
        if not event_id.strip() or len(event_id) > 256:
            raise invalid("eventId must be non-empty and within 256 characters")
        with self._store.read_snapshot() as connection:
            row = connection.execute(
                f"SELECT {_EVENT_COLUMNS} FROM audit_events "
                "WHERE event_id = ? AND archived = 0",
                (event_id,),
            ).fetchone()
            if row is None:
                raise ApiError(404, "NOT_FOUND", "Audit event was not found")
            return _event_view(connection, row)

    def list_checkpoints(self, limit: int | None) -> list[dict[str, Any]]:
        page_size = DEFAULT_PAGE_SIZE if limit is None else limit
        if not 1 <= page_size <= MAX_PAGE_SIZE:
            raise invalid("limit must be between 1 and 500")
        with self._store.read_snapshot() as connection:
            rows = connection.execute(
                "SELECT seq, chain_hash, created_at, key_id, signature "
                "FROM checkpoints ORDER BY seq DESC, id DESC LIMIT ?",
                (page_size,),
            ).fetchall()
        return [
            {
                "seq": int(row["seq"]),
                "chainHash": row["chain_hash"],
                "createdAt": row["created_at"],
                "keyId": row["key_id"],
                "signature": row["signature"],
            }
            for row in rows
        ]

    def _mac(self, data: bytes) -> bytes:
        return hmac.new(self._cursor_key, data, hashlib.sha256).digest()

    def _encode(
        self, filters: dict[str, str | None], order: str, as_of: int, last: int
    ) -> str:
        body = canonicalize(
            {
                "v": 1,
                "filters": cast(JsonValue, dict(filters)),
                "order": order,
                "asOfSeq": as_of,
                "lastSeq": last,
            }
        )
        return f"{_b64(body)}.{_b64(self._mac(body))}"

    def _decode(
        self, token: str, filters: dict[str, str | None], order: str
    ) -> tuple[int, int]:
        if len(token) > 4096:
            raise invalid("cursor exceeds the supported length")
        parts = token.split(".")
        if len(parts) != 2 or not all(_B64URL.fullmatch(part) for part in parts):
            raise invalid("cursor is malformed")
        try:
            body = _unb64(parts[0])
            signature = _unb64(parts[1])
        except (binascii.Error, ValueError) as exc:
            raise invalid("cursor is malformed") from exc
        if not hmac.compare_digest(signature, self._mac(body)):
            raise invalid("cursor signature is invalid")
        try:
            payload = parse_json(body, max_bytes=4096)
        except CanonicalJsonError as exc:
            raise invalid("cursor is malformed") from exc
        if (
            not isinstance(payload, dict)
            or set(payload) != {"v", "filters", "order", "asOfSeq", "lastSeq"}
            or payload["v"] != 1
            or payload["order"] != order
            or payload["filters"] != dict(filters)
        ):
            raise invalid("cursor does not match these filters and order")
        as_of, last = payload["asOfSeq"], payload["lastSeq"]
        if (
            type(as_of) is not int
            or type(last) is not int
            or not 0 < last <= as_of <= MAX_SAFE_INTEGER
        ):
            raise invalid("cursor sequence is outside its snapshot")
        return as_of, last


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _normalize_filters(filters: dict[str, str | None]) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name in _FILTER_NAMES:
        value = filters.get(name)
        if value is None:
            result[name] = None
        elif name in {"from", "to"}:
            try:
                result[name] = format_micros(parse_offset_timestamp(value))
            except ValueError as exc:
                raise invalid(
                    f"{name} must be an ISO-8601 timestamp with an offset"
                ) from exc
        elif not value.strip() or len(value) > 256:
            raise invalid(f"{name} filter must be non-empty and at most 256 characters")
        else:
            result[name] = value
    start, end = result["from"], result["to"]
    if start is not None and end is not None and start > end:
        raise invalid("from must not be later than to")
    return result


def _event_view(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    try:
        commitments = parse_json(row["payload_commitments"])
        if not isinstance(commitments, dict):
            raise ValueError("commitments are not an object")
        leaves: dict[str, PayloadLeaf] = {}
        for leaf in connection.execute(
            "SELECT pointer, salt, value FROM payload_leaves "
            "WHERE seq = ? ORDER BY pointer",
            (row["seq"],),
        ):
            value = parse_json(leaf["value"])
            if isinstance(value, dict | list):
                raise ValueError("leaf is not scalar")
            leaves[leaf["pointer"]] = PayloadLeaf(bytes.fromhex(leaf["salt"]), value)
        revealed = reveal_payload(commitments, leaves)
    except (ValueError, CanonicalJsonError, PayloadPointerError, TypeError) as exc:
        raise ApiError(
            500, "INTERNAL_ERROR", "Stored audit record failed integrity checks"
        ) from exc
    return {
        "eventType": row["event_type"],
        "actorId": row["actor_id"],
        "resourceType": row["resource_type"],
        "resourceId": row["resource_id"],
        "payload": revealed.payload,
        "occurredAt": row["occurred_at"],
        "eventId": row["event_id"],
        "seq": int(row["seq"]),
        "timestamp": row["recorded_at"],
        "source": row["source"],
        "hashVersion": int(row["hash_version"]),
        "payloadCommitments": commitments,
        "redactedPaths": revealed.redacted_paths,
        "contentHash": row["content_hash"],
        "prevHash": row["prev_hash"],
        "chainHash": row["chain_hash"],
    }
