"""Selection, record rendering and the small signed export bundle (v1)."""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, cast

from audit_log_service.canonical_json import (
    MAX_DOCUMENT_DEPTH,
    MAX_INPUT_BYTES,
    JsonValue,
    canonicalize,
    parse_json,
)
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError, invalid
from audit_log_service.ledger import AppendService
from audit_log_service.signing import CheckpointSigner
from audit_log_service.store import SqliteStore
from audit_log_service.timeutil import format_micros, parse_offset_timestamp
from audit_log_service.v1_hashes import HASH_VERSION, genesis_hash

BUNDLE_FORMAT = "audit-export-bundle/v1"
MAX_FILTER_BYTES = 1024
FETCH_BATCH = 500
_FILTERS = ("actorId", "resourceType", "resourceId", "eventType")
_COLUMNS = {
    "actorId": "actor_id",
    "resourceType": "resource_type",
    "resourceId": "resource_id",
    "eventType": "event_type",
}


class ExportDataError(ApiError):
    def __init__(self, message: str) -> None:
        super().__init__(500, "EXPORT_DATA_INVALID", message)


@dataclass(frozen=True)
class Selection:
    values: dict[str, str | None]

    def document(self) -> dict[str, JsonValue]:
        """The signed selection: exactly eight keys, null when absent."""
        document: dict[str, JsonValue] = {
            name: self.values.get(name) for name in _FILTERS
        }
        document["from"] = self.values.get("from")
        document["to"] = self.values.get("to")
        document["seqFrom"] = None
        document["seqTo"] = None
        return document

    def digest(self) -> str:
        return hashlib.sha256(canonicalize(self.document())).hexdigest()

    def where(self, through_seq: int) -> tuple[str, list[Any]]:
        clauses = ["archived = 0", "seq <= ?"]
        params: list[Any] = [through_seq]
        for name in _FILTERS:
            value = self.values.get(name)
            if value is not None:
                clauses.append(f"{_COLUMNS[name]} = ?")
                params.append(value)
        if self.values.get("from") is not None:
            clauses.append("recorded_at >= ?")
            params.append(self.values["from"])
        if self.values.get("to") is not None:
            clauses.append("recorded_at <= ?")
            params.append(self.values["to"])
        return " AND ".join(clauses), params


def parse_selection(
    params: dict[str, str | None], *, require_actor_or_resource: bool
) -> Selection:
    values: dict[str, str | None] = {}
    for name in _FILTERS:
        raw = params.get(name)
        if raw is not None:
            if (
                not raw.strip()
                or len(raw.encode("utf-8", "replace")) > MAX_FILTER_BYTES
            ):
                raise invalid(f"{name} must be non-empty and at most 1024 bytes")
            if any(0xD800 <= ord(char) <= 0xDFFF for char in raw):
                raise invalid(f"{name} must be valid Unicode")
        values[name] = raw
    for name in ("from", "to"):
        raw = params.get(name)
        if raw is None:
            values[name] = None
            continue
        try:
            values[name] = format_micros(parse_offset_timestamp(raw))
        except ValueError as exc:
            raise invalid(f"{name} must be an ISO-8601 timestamp with a zone") from exc
    lower, upper = values["from"], values["to"]
    if lower is not None and upper is not None and lower > upper:
        raise invalid("from must not be after to")
    if require_actor_or_resource and not (values["actorId"] or values["resourceId"]):
        raise invalid("export requires actorId or resourceId")
    return Selection(values)


def render_record(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Render one stored live row as a bundle record; malformed data fails closed."""
    try:
        commitments = parse_json(
            str(row["payload_commitments"]).encode("utf-8"),
            max_bytes=MAX_INPUT_BYTES,
            max_depth=MAX_DOCUMENT_DEPTH,
        )
        if not isinstance(commitments, dict):
            raise ValueError("commitments are not an object")
        leaves: dict[str, JsonValue] = {}
        for leaf in connection.execute(
            "SELECT pointer, salt, value FROM payload_leaves WHERE seq = ? "
            "ORDER BY pointer",
            (row["seq"],),
        ):
            value = parse_json(
                str(leaf["value"]).encode("utf-8"),
                max_bytes=MAX_INPUT_BYTES,
                max_depth=2,
            )
            leaves[str(leaf["pointer"])] = {"salt": str(leaf["salt"]), "value": value}
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ExportDataError(
            "A stored record is malformed and cannot be exported"
        ) from exc
    if row["hash_version"] != HASH_VERSION:
        raise ExportDataError("A stored record has an unsupported hash version")
    return {
        "seq": row["seq"],
        "eventId": row["event_id"],
        "eventType": row["event_type"],
        "actorId": row["actor_id"],
        "resourceType": row["resource_type"],
        "resourceId": row["resource_id"],
        "occurredAt": row["occurred_at"],
        "timestamp": row["recorded_at"],
        "source": row["source"],
        "hashVersion": row["hash_version"],
        "payloadCommitments": commitments,
        "disclosedLeaves": leaves,
        "contentHash": row["content_hash"],
        "prevHash": row["prev_hash"],
        "chainHash": row["chain_hash"],
    }


def iter_records(
    connection: sqlite3.Connection, selection: Selection, through_seq: int
) -> Iterator[dict[str, Any]]:
    clause, params = selection.where(through_seq)
    after = 0
    while True:
        # nosec B608 (2026-10-18): where-clause built from fixed fragments; values bound.
        rows = connection.execute(
            f"SELECT * FROM audit_events WHERE {clause} AND seq > ? "  # nosec B608
            "ORDER BY seq LIMIT ?",
            (*params, after, FETCH_BATCH),
        ).fetchall()
        for row in rows:
            after = int(row["seq"])
            yield render_record(connection, row)
        if len(rows) < FETCH_BATCH:
            return


def completeness(through_seq: int) -> dict[str, JsonValue]:
    return {
        "scope": "MATCHING_RETAINED_LIVE_RECORDS",
        "throughSeq": through_seq,
        "archivedRecordsExcluded": True,
        "upstreamCoverage": "NOT_PROVEN",
        "assurance": "SIGNED_ASSERTION",
    }


def current_head(connection: sqlite3.Connection, ledger_id: str) -> tuple[int, str]:
    row = connection.execute(
        "SELECT seq, chain_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return 0, genesis_hash(ledger_id)
    return int(row["seq"]), str(row["chain_hash"])


class ExportBundleService:
    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        signer: CheckpointSigner,
        appender: AppendService,
    ) -> None:
        self._store = store
        self._configuration = configuration
        self._signer = signer
        self._appender = appender

    def export(self, selection: Selection, exported_by: str) -> bytes:
        limits = self._configuration
        records: list[dict[str, Any]] = []
        total_bytes = 0
        with self._store.write_transaction() as connection:
            through_seq, _ = current_head(connection, limits.ledger_id)
            for record in iter_records(connection, selection, through_seq):
                total_bytes += (
                    len(canonicalize(record, max_depth=MAX_DOCUMENT_DEPTH)) + 1
                )
                if (
                    len(records) + 1 > limits.export_max_records
                    or total_bytes > limits.export_max_bytes
                ):
                    raise self._too_large()
                records.append(record)
            records_digest = hashlib.sha256(
                canonicalize(cast(Any, records), max_depth=MAX_DOCUMENT_DEPTH)
            ).hexdigest()
            bundle_id = str(uuid.uuid4())
            event = self._appender.append_system_event(
                connection,
                "BUNDLE_EXPORTED",
                exported_by,
                "AUDIT_EXPORT",
                bundle_id,
                {
                    "bundleId": bundle_id,
                    "purpose": "EXPORT",
                    "throughSeq": through_seq,
                    "recordCount": len(records),
                    "recordsDigest": records_digest,
                    "selectionDigest": selection.digest(),
                    "requestedBy": exported_by,
                },
            )
            checkpoint = self._appender.store_checkpoint(
                connection, event["seq"], event["chainHash"], event["timestamp"]
            )
        body = self.signed_bundle(
            "EXPORT",
            bundle_id,
            selection,
            through_seq,
            records,
            records_digest,
            event["timestamp"],
            checkpoint,
            exported_by,
        )
        return canonicalize(body, max_depth=MAX_DOCUMENT_DEPTH)

    def signed_bundle(
        self,
        purpose: str,
        bundle_id: str,
        selection: Selection,
        through_seq: int,
        records: list[dict[str, Any]],
        records_digest: str,
        exported_at: str,
        checkpoint: dict[str, Any],
        exported_by: str,
    ) -> dict[str, JsonValue]:
        limits = self._configuration
        body: dict[str, JsonValue] = {
            "format": BUNDLE_FORMAT,
            "bundleId": bundle_id,
            "purpose": purpose,
            "ledgerId": limits.ledger_id,
            "hashAlgorithm": "SHA-256",
            "hashVersion": HASH_VERSION,
            "genesisHash": genesis_hash(limits.ledger_id),
            "signatureAlgorithm": "Ed25519",
            "exportedAt": exported_at,
            "exportedBy": exported_by,
            "selection": selection.document(),
            "completeness": completeness(through_seq),
            "recordCount": len(records),
            "recordsDigest": records_digest,
            "records": cast(Any, records),
            "headCheckpoint": cast(Any, checkpoint),
            "signer": {
                "keyId": self._signer.key_id,
                "publicKey": self._signer.public_key_base64,
            },
        }
        body["signature"] = self._signer.sign_message(body, MAX_DOCUMENT_DEPTH)
        return body

    def _too_large(self) -> ApiError:
        limits = self._configuration
        return ApiError(
            422,
            "EXPORT_LIMIT_EXCEEDED",
            "The selection exceeds the synchronous export limits; narrow the "
            "selection or create an export set with POST /audit/export-sets",
            [
                {
                    "limit": "AUDIT_EXPORT_MAX_RECORDS",
                    "value": limits.export_max_records,
                },
                {"limit": "AUDIT_EXPORT_MAX_BYTES", "value": limits.export_max_bytes},
            ],
        )
