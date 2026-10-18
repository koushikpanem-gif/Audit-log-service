"""Atomic redaction and the durable cleanup queue for redacted plaintext."""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from audit_log_service.canonical_json import (
    MAX_DOCUMENT_DEPTH,
    MAX_INPUT_BYTES,
    CanonicalJsonError,
    JsonValue,
    parse_json,
)
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError, invalid
from audit_log_service.ledger import RESERVED_EVENT_TYPES, AppendService, Clock
from audit_log_service.payload_commitments import (
    MAX_SCALAR_LEAVES,
    expand_subtree_pointer,
)
from audit_log_service.store import SqliteStore, StorageError
from audit_log_service.timeutil import format_micros

EVENT_TYPE = "RECORD_REDACTED"
RESOURCE_TYPE = "AUDIT_EVENT"
PENDING = "PENDING"
COMPLETE = "COMPLETE"
LIMITATIONS = (
    "COMPLETE means the live SQLite WAL was checkpointed and truncated after the "
    "deletion. It is not a guarantee of physical erasure and does not cover earlier "
    "exports, archive files, backups, filesystem snapshots or storage-device "
    "remnants."
)

_POINTER = re.compile(r"(/([^~/]|~[01])*)*\Z")
_MAX_REQUEST_PATHS = 500
_MAX_REASON = 1000
_MAX_TICKET = 128
_MAX_EVENT_ID = 128
_MIN_GUARDED_VALUE = 4
_MAX_STATUS_JOBS = 100
_BACKOFF_SECONDS = 0.05
# targetSeq, targetEventId, reason, ticketId, requestedBy are authorization leaves.
_METADATA_LEAVES = 5


@dataclass(frozen=True)
class CleanupSummary:
    status: str
    pending_jobs: int
    attempts: int
    last_outcome: str | None


class RedactionCleanupService:
    """Drives WAL truncation after a redaction commits.

    A job is COMPLETE only when SQLite reports busy=0 and a fully checkpointed
    log. Everything is persisted, so a crash or a held reader leaves the job
    PENDING and run_pending()/recover() finishes it later.
    """

    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        clock: Clock,
        *,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._store = store
        self._max_attempts = configuration.cleanup_max_attempts
        self._busy_timeout_ms = configuration.cleanup_busy_timeout_ms
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()

    def enqueue(
        self,
        connection: sqlite3.Connection,
        redaction_seq: int,
        target_seq: int,
        leaf_count: int,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO redaction_cleanup(redaction_seq, target_seq, leaf_count, "
            "status, created_at) VALUES (?, ?, ?, 'PENDING', ?)",
            (redaction_seq, target_seq, leaf_count, self._now()),
        )
        if cursor.lastrowid is None:
            raise StorageError("Cleanup job id was not generated")
        return int(cursor.lastrowid)

    def run_pending(self) -> CleanupSummary:
        """Make finite checkpoint attempts for every job committed before this call.

        Never raises for a busy database or a storage error: the jobs stay
        PENDING with the outcome recorded.
        """
        with self._lock:
            return self._run_pending()

    def _run_pending(self) -> CleanupSummary:
        try:
            with self._store.read_snapshot() as connection:
                up_to = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(id), 0) FROM redaction_cleanup "
                        "WHERE status = 'PENDING'"
                    ).fetchone()[0]
                )
        except StorageError:
            return CleanupSummary(PENDING, -1, 0, "ERROR")
        if up_to == 0:
            return CleanupSummary(COMPLETE, 0, 0, None)

        attempts = 0
        outcome = "ERROR"
        done = False
        while attempts < self._max_attempts and not done:
            attempts += 1
            try:
                checkpoint = self._store.checkpoint_wal_truncate(self._busy_timeout_ms)
                if checkpoint.complete:
                    outcome, done = "OK", True
                else:
                    outcome = "BUSY" if checkpoint.busy != 0 else "INCOMPLETE"
            except StorageError:
                outcome = "ERROR"
            if not done and attempts < self._max_attempts:
                self._sleep(_BACKOFF_SECONDS * attempts)

        try:
            with self._store.write_transaction() as connection:
                self._record(connection, up_to, attempts, outcome, done)
        except StorageError:
            # An unrecorded success is simply repeated by the next run.
            return CleanupSummary(PENDING, -1, attempts, outcome)
        try:
            remaining = self._count(PENDING)
        except StorageError:
            remaining = -1
        return CleanupSummary(
            COMPLETE if remaining == 0 else PENDING, remaining, attempts, outcome
        )

    def recover(self) -> CleanupSummary:
        """Called at start-up: finishes cleanup interrupted by a crash or reader."""
        return self.run_pending()

    def status(self, limit: int = _MAX_STATUS_JOBS) -> dict[str, Any]:
        bounded = max(1, min(limit, _MAX_STATUS_JOBS))
        with self._store.read_snapshot() as connection:
            jobs = [
                {
                    "id": row["id"],
                    "redactionSeq": row["redaction_seq"],
                    "targetSeq": row["target_seq"],
                    "leafCount": row["leaf_count"],
                    "status": row["status"],
                    "attempts": row["attempts"],
                    "createdAt": row["created_at"],
                    "lastAttemptAt": row["last_attempt_at"],
                    "completedAt": row["completed_at"],
                    "lastOutcome": row["last_outcome"],
                }
                for row in connection.execute(
                    "SELECT id, redaction_seq, target_seq, leaf_count, status, "
                    "attempts, created_at, last_attempt_at, completed_at, "
                    "last_outcome FROM redaction_cleanup ORDER BY id DESC LIMIT ?",
                    (bounded,),
                )
            ]
            pending = self._count_in(connection, PENDING)
            complete = self._count_in(connection, COMPLETE)
        return {
            "pendingJobs": pending,
            "completeJobs": complete,
            "jobs": jobs,
            "limitations": LIMITATIONS,
        }

    def _record(
        self,
        connection: sqlite3.Connection,
        up_to: int,
        attempts: int,
        outcome: str,
        complete: bool,
    ) -> None:
        now = self._now()
        if complete:
            connection.execute(
                "UPDATE redaction_cleanup SET status = 'COMPLETE', "
                "attempts = attempts + ?, last_attempt_at = ?, completed_at = ?, "
                "last_outcome = ? WHERE status = 'PENDING' AND id <= ?",
                (attempts, now, now, outcome, up_to),
            )
        else:
            connection.execute(
                "UPDATE redaction_cleanup SET attempts = attempts + ?, "
                "last_attempt_at = ?, last_outcome = ? "
                "WHERE status = 'PENDING' AND id <= ?",
                (attempts, now, outcome, up_to),
            )

    def _count(self, status: str) -> int:
        with self._store.read_snapshot() as connection:
            return self._count_in(connection, status)

    @staticmethod
    def _count_in(connection: sqlite3.Connection, status: str) -> int:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM redaction_cleanup WHERE status = ?", (status,)
            ).fetchone()[0]
        )

    def _now(self) -> str:
        return format_micros(self._clock())


class RedactionService:
    """Atomic redaction: authorization event, leaf deletion and queue in one commit."""

    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        appender: AppendService,
        cleanup: RedactionCleanupService,
    ) -> None:
        self._store = store
        self._appender = appender
        self._cleanup = cleanup
        self._max_leaves = (
            min(configuration.max_leaves, MAX_SCALAR_LEAVES) - _METADATA_LEAVES
        )

    def redact(
        self,
        event_id: str,
        paths: list[str],
        reason: str,
        ticket_id: str,
        requested_by: str,
    ) -> dict[str, Any]:
        _validate_request(event_id, paths, reason, ticket_id, requested_by)
        with self._store.write_transaction() as connection:
            committed = self._redact_locked(
                connection, event_id, paths, reason, ticket_id, requested_by
            )
        # The deletion is committed from here on; cleanup can never undo it.
        summary = self._cleanup.run_pending()
        event = committed.event
        status = (
            COMPLETE if committed.job_id > 0 and summary.pending_jobs == 0 else PENDING
        )
        return {
            "redactionEventId": event["eventId"],
            "redactionSeq": event["seq"],
            "timestamp": event["timestamp"],
            "contentHash": event["contentHash"],
            "chainHash": event["chainHash"],
            "targetSeq": committed.target_seq,
            "targetEventId": event_id,
            "redactedPaths": committed.leaves,
            "cleanupStatus": status,
            "cleanupAttempts": summary.attempts,
            "note": LIMITATIONS,
        }

    def _redact_locked(
        self,
        connection: sqlite3.Connection,
        event_id: str,
        paths: list[str],
        reason: str,
        ticket_id: str,
        requested_by: str,
    ) -> _Committed:
        row = connection.execute(
            "SELECT seq, event_type, source, archived, payload_commitments "
            "FROM audit_events WHERE event_id = ?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise ApiError(404, "NOT_FOUND", "Audit event was not found")
        target_seq = int(row["seq"])
        if row["archived"] != 0:
            raise ApiError(409, "CONFLICT", "Archived events cannot be redacted")
        if row["source"] == "system" or row["event_type"] in RESERVED_EVENT_TYPES:
            raise ApiError(409, "CONFLICT", "System events cannot be redacted")
        commitments = _parse_commitments(row["payload_commitments"])

        expanded: set[str] = set()
        for path in paths:
            try:
                expanded.update(expand_subtree_pointer(commitments, path))
            except (ValueError, CanonicalJsonError) as exc:
                raise invalid(
                    "paths must be valid RFC 6901 pointers to existing payload values"
                ) from exc
        present = {
            str(leaf["pointer"]): str(leaf["value"])
            for leaf in connection.execute(
                "SELECT pointer, value FROM payload_leaves WHERE seq = ?",
                (target_seq,),
            )
        }
        leaves = sorted(
            (pointer for pointer in expanded if pointer in present),
            key=lambda pointer: pointer.encode("utf-16-be"),
        )
        if not leaves:
            raise ApiError(
                409,
                "CONFLICT",
                "Nothing to redact: the selected values are already redacted",
            )
        if len(leaves) > self._max_leaves:
            raise invalid(
                f"A single redaction may remove at most {self._max_leaves} values; "
                "redact smaller subtrees separately"
            )
        _reject_echoed_values(reason, ticket_id, leaves, present)

        payload: dict[str, JsonValue] = {
            "targetSeq": target_seq,
            "targetEventId": event_id,
            "paths": list(leaves),
            "reason": reason,
            "ticketId": ticket_id,
            "requestedBy": requested_by,
        }
        try:
            event = self._appender.append_system_event(
                connection, EVENT_TYPE, requested_by, RESOURCE_TYPE, event_id, payload
            )
        except (ValueError, CanonicalJsonError) as exc:
            raise invalid(
                "The redaction authorization exceeds payload limits; "
                "redact smaller subtrees separately"
            ) from exc
        for pointer in leaves:
            deleted = connection.execute(
                "DELETE FROM payload_leaves WHERE seq = ? AND pointer = ?",
                (target_seq, pointer),
            )
            if deleted.rowcount != 1:
                raise StorageError("Redaction expected to delete exactly one leaf")
        job_id = self._cleanup.enqueue(
            connection, int(event["seq"]), target_seq, len(leaves)
        )
        return _Committed(event, target_seq, leaves, job_id)


@dataclass(frozen=True)
class _Committed:
    event: dict[str, Any]
    target_seq: int
    leaves: list[str]
    job_id: int


def _validate_request(
    event_id: object,
    paths: object,
    reason: object,
    ticket_id: object,
    requested_by: object,
) -> None:
    _require_text(event_id, "eventId", _MAX_EVENT_ID)
    _require_text(reason, "reason", _MAX_REASON)
    _require_text(ticket_id, "ticketId", _MAX_TICKET)
    _require_text(requested_by, "requestedBy", 256)
    if not isinstance(paths, list) or not paths:
        raise invalid("paths must contain at least one JSON Pointer")
    if len(paths) > _MAX_REQUEST_PATHS:
        raise invalid(f"paths exceeds the maximum of {_MAX_REQUEST_PATHS}")
    for path in paths:
        if not isinstance(path, str) or len(path) > 4096 or not _POINTER.match(path):
            raise invalid("paths must contain valid RFC 6901 JSON Pointers")
        if any(0xD800 <= ord(char) <= 0xDFFF for char in path):
            raise invalid("paths must contain valid Unicode")


def _require_text(value: object, name: str, limit: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise invalid(f"{name} is required")
    if len(value) > limit:
        raise invalid(f"{name} exceeds {limit} characters")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise invalid(f"{name} must be valid Unicode")


def _reject_echoed_values(
    reason: str, ticket_id: str, leaves: list[str], present: dict[str, str]
) -> None:
    """Best effort: free text in the permanent event must not repeat redacted values."""
    for pointer in leaves:
        text = _scalar_text(present[pointer])
        if len(text) >= _MIN_GUARDED_VALUE and (text in reason or text in ticket_id):
            raise invalid(
                "reason and ticketId must not repeat the values being redacted"
            )


def _scalar_text(stored: str) -> str:
    try:
        value = parse_json(stored.encode("utf-8"), max_bytes=MAX_INPUT_BYTES)
    except (ValueError, UnicodeError):
        return ""
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _parse_commitments(stored: object) -> dict[str, JsonValue]:
    try:
        parsed = parse_json(
            str(stored).encode("utf-8"),
            max_bytes=MAX_INPUT_BYTES,
            max_depth=MAX_DOCUMENT_DEPTH,
        )
    except (ValueError, UnicodeError) as exc:
        raise StorageError("Stored payload commitments are malformed") from exc
    if not isinstance(parsed, dict):
        raise StorageError("Stored payload commitments are not a JSON object")
    return parsed


__all__ = [
    "COMPLETE",
    "EVENT_TYPE",
    "LIMITATIONS",
    "PENDING",
    "CleanupSummary",
    "RedactionCleanupService",
    "RedactionService",
]
