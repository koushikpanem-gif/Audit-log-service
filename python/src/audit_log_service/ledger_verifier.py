"""Full-chain verifier for the live ledger.

One read snapshot is scanned in ordered batches. Memory is bounded by the batch size,
at most MAX_DIAGNOSTICS retained diagnostics and a private scratch database that
indexes validated authorization events. Everything read from storage is untrusted:
malformed values produce MALFORMED_RECORD diagnostics and never an exception.
"""

from __future__ import annotations

import bisect
import re
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NamedTuple

from audit_log_service.canonical_json import (
    MAX_INPUT_BYTES,
    MAX_SAFE_INTEGER,
    JsonValue,
    parse_json,
)
from audit_log_service.payload_commitments import (
    MAX_SCALAR_LEAVES,
    PayloadLeaf,
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
    leaf_hash,
)

BATCH_SIZE = 1000
MAX_DIAGNOSTICS = 100
HASH_ALGORITHM = "SHA-256"

VIOLATION_TYPES = (
    "SEQUENCE_GAP",
    "GENESIS_MISMATCH",
    "CHAIN_LINK_BROKEN",
    "CONTENT_HASH_MISMATCH",
    "CHAIN_HASH_MISMATCH",
    "MALFORMED_RECORD",
    "PAYLOAD_VALUE_MISMATCH",
    "UNAUTHORIZED_REDACTION",
    "UNAUTHORIZED_ARCHIVE",
    "RETENTION_POLICY_VIOLATION",
    "CHECKPOINT_SIGNATURE_INVALID",
    "CHECKPOINT_MISMATCH",
    "TRUNCATION_DETECTED",
)
_TYPE_ORDER = {name: index for index, name in enumerate(VIOLATION_TYPES)}

REDACTED_TYPE = "RECORD_REDACTED"
ARCHIVED_TYPE = "RECORDS_ARCHIVED"
_RESERVED_TYPES = frozenset(
    {REDACTED_TYPE, ARCHIVED_TYPE, "BUNDLE_EXPORTED", "COMPLIANCE_REPORT_GENERATED"}
)
_SYSTEM_SOURCE = "system"
_REDACTION_KEYS = frozenset(
    {"targetSeq", "targetEventId", "paths", "reason", "ticketId", "requestedBy"}
)
_ARCHIVE_KEYS = frozenset(
    {
        "archivedThroughSeq",
        "fromSeq",
        "toSeq",
        "count",
        "cutoff",
        "retentionDays",
        "lastArchivedChainHash",
        "archiveFile",
        "archiveSha256",
        "archiveBundleId",
        "requestedBy",
    }
)
_MAX_RETENTION_DAYS = 500_000
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"[0-9a-f]{16}\Z")
_POINTER = re.compile(r"(?:/(?:[^~/]|~[01])*)*\Z")
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z")
_MAX_COMMITMENT_DEPTH = 12
_EVENT_COLUMNS = (
    "seq, event_id, event_type, actor_id, resource_type, resource_id, occurred_at, "
    "recorded_at, source, payload_commitments, hash_version, content_hash, "
    "prev_hash, chain_hash, archived, archived_at"
)


class _Raw(NamedTuple):
    seq: Any
    event_id: Any
    event_type: Any
    actor_id: Any
    resource_type: Any
    resource_id: Any
    occurred_at: Any
    recorded_at: Any
    source: Any
    commitments: Any
    hash_version: Any
    content_hash: Any
    prev_hash: Any
    chain_hash: Any
    archived: Any
    archived_at: Any


@dataclass(frozen=True)
class _RedactionGrant:
    target_seq: int
    paths: list[str]


@dataclass(frozen=True)
class _ArchiveGrant:
    through_seq: int


_Authorization = _RedactionGrant | _ArchiveGrant


@dataclass(frozen=True)
class _Inspection:
    archived: bool
    authorization: _Authorization | None


class _InvalidAuthorizationError(Exception):
    pass


class _Diagnostics:
    """Keeps the earliest MAX_DIAGNOSTICS diagnostics in a deterministic order."""

    def __init__(self) -> None:
        self.total = 0
        self._order = 0
        self._kept: list[tuple[tuple[int, int, str, str, int], dict[str, Any]]] = []

    def add(
        self, violation_type: str, seq: int | None, pointer: str | None, message: str
    ) -> None:
        self.total += 1
        key = (
            MAX_SAFE_INTEGER * 4 if seq is None else seq,
            _TYPE_ORDER[violation_type],
            pointer or "",
            message,
            self._order,
        )
        self._order += 1
        entry = {
            "type": violation_type,
            "seq": seq,
            "pointer": pointer,
            "message": message,
        }
        bisect.insort(self._kept, (key, entry), key=lambda item: item[0])
        if len(self._kept) > MAX_DIAGNOSTICS:
            self._kept.pop()

    def retained(self) -> list[dict[str, Any]]:
        return [entry for _, entry in self._kept]


def _as_int(value: Any) -> int | None:
    return value if type(value) is int else None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _hash(value: Any) -> str | None:
    return value if isinstance(value, str) and _HASH.fullmatch(value) else None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return parse_stored_timestamp(value)
    except ValueError:
        return None


def _instant(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _INSTANT.fullmatch(value):
        return None
    try:
        return parse_offset_timestamp(value)
    except ValueError:
        return None


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _commitment_leaves(commitments: dict[str, JsonValue]) -> dict[str, str]:
    leaves: dict[str, str] = {}
    pending: list[tuple[JsonValue, str]] = [
        (value, "/" + _escape(key)) for key, value in commitments.items()
    ]
    while pending:
        value, pointer = pending.pop()
        if isinstance(value, dict):
            pending.extend(
                (child, f"{pointer}/{_escape(key)}") for key, child in value.items()
            )
        elif isinstance(value, list):
            pending.extend(
                (child, f"{pointer}/{index}") for index, child in enumerate(value)
            )
        elif isinstance(value, str):
            leaves[pointer] = value
            if len(leaves) > MAX_SCALAR_LEAVES:
                raise ValueError("too many commitment leaves")
        else:
            raise ValueError("commitment leaves must be strings")
    return leaves


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise _InvalidAuthorizationError(f"{field} must be a bounded non-blank string")
    return value


def _positive(value: Any, field: str) -> int:
    if type(value) is not int:
        raise _InvalidAuthorizationError(f"{field} must be an integer")
    if not 0 < value <= MAX_SAFE_INTEGER:
        raise _InvalidAuthorizationError(f"{field} must be a positive safe integer")
    return value


def _require_keys(payload: dict[str, Any], keys: frozenset[str]) -> None:
    if set(payload) != keys:
        raise _InvalidAuthorizationError("payload fields do not match the schema")


class LedgerVerifier:
    def __init__(
        self,
        store: SqliteStore,
        ledger_id: str,
        public_key_base64: str,
        clock: Callable[[], datetime] | None = None,
        batch_size: int = BATCH_SIZE,
    ) -> None:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        self._store = store
        self._ledger_id = ledger_id
        self._public_key = public_key_base64
        self._clock = clock or (lambda: datetime.now(UTC))
        self._batch_size = batch_size

    def verify(self) -> dict[str, Any]:
        with self._store.read_snapshot() as connection:
            return self.verify_connection(connection)

    def verify_connection(self, connection: sqlite3.Connection) -> dict[str, Any]:
        """Verify on a caller-owned connection and transaction (snapshot or write)."""
        started = time.monotonic()
        verified_at = self._clock()
        original_factory = connection.text_factory
        connection.text_factory = lambda raw: raw.decode("utf-8", "surrogateescape")
        scratch = sqlite3.connect("", isolation_level=None)
        try:
            return _Scan(self, connection, scratch).run(started, verified_at)
        finally:
            scratch.close()
            connection.text_factory = original_factory


class _Scan:
    def __init__(
        self,
        owner: LedgerVerifier,
        db: sqlite3.Connection,
        scratch: sqlite3.Connection,
    ) -> None:
        self._ledger_id = owner._ledger_id
        self._public_key = owner._public_key
        self._batch = owner._batch_size
        self._clock = owner._clock
        self._db = db
        self._scratch = scratch
        self._diag = _Diagnostics()
        self._genesis = genesis_hash(self._ledger_id)
        self.checked = 0
        self.archived = 0
        self.redacted_fields = 0
        self.head_seq = 0
        self.head_hash: str | None = self._genesis
        self.checkpoints_verified = 0
        scratch.execute(
            "CREATE TABLE redactions(target_seq INTEGER NOT NULL,"
            " pointer TEXT NOT NULL,"
            " PRIMARY KEY(target_seq, pointer)) WITHOUT ROWID"
        )
        scratch.execute(
            "CREATE TABLE archives(event_seq INTEGER PRIMARY KEY,"
            " through_seq INTEGER NOT NULL)"
        )

    def violate(
        self,
        report: bool,
        violation_type: str,
        seq: int | None,
        pointer: str | None,
        message: str,
    ) -> None:
        if report:
            self._diag.add(violation_type, seq, pointer, message)

    def run(self, started: float, verified_at: datetime) -> dict[str, Any]:
        self._check_metadata()
        self._build_authorization_index()
        self._scan_events()
        self._verify_checkpoints()
        self._detect_orphan_leaves()
        kept = self._diag.retained()
        return {
            "intact": self._diag.total == 0,
            "ledgerId": self._ledger_id,
            "hashAlgorithm": HASH_ALGORITHM,
            "checkedRecords": self.checked,
            "archivedRecords": self.archived,
            "redactedFields": self.redacted_fields,
            "headSeq": self.head_seq,
            "headHash": self.head_hash,
            "checkpointsVerified": self.checkpoints_verified,
            "firstViolation": kept[0] if kept else None,
            "violations": kept,
            "totalViolationCount": self._diag.total,
            "violationsTruncated": self._diag.total > len(kept),
            "verifiedAt": format_micros(verified_at),
            "durationMs": int((time.monotonic() - started) * 1000),
        }

    def _check_metadata(self) -> None:
        rows = self._db.execute(
            "SELECT ledger_id, schema_version FROM ledger_meta"
        ).fetchall()
        matches = (
            len(rows) == 1
            and rows[0][0] == self._ledger_id
            and _as_int(rows[0][1]) == 3
        )
        if not matches:
            self.violate(
                True,
                "MALFORMED_RECORD",
                None,
                None,
                "ledger metadata is missing, duplicated or bound to a different ledger",
            )

    def _read_batch(self, where: str, params: tuple[Any, ...]) -> list[_Raw]:
        rows = self._db.execute(
            f"SELECT {_EVENT_COLUMNS} FROM audit_events {where} ORDER BY seq LIMIT ?",
            (*params, self._batch),
        ).fetchall()
        return [_Raw(*row) for row in rows]

    def _build_authorization_index(self) -> None:
        for event_type in (REDACTED_TYPE, ARCHIVED_TYPE):
            after = -(2**63)
            while True:
                batch = self._read_batch(
                    "WHERE event_type = ? AND archived = 0 AND seq > ?",
                    (event_type, after),
                )
                for event in batch:
                    after = event.seq
                    inspection = self._safe_inspect(event, False)
                    self._grant(event.seq, inspection.authorization)
                if len(batch) < self._batch:
                    break

    def _grant(self, event_seq: int, authorization: _Authorization | None) -> None:
        if isinstance(authorization, _RedactionGrant):
            self._scratch.executemany(
                "INSERT OR IGNORE INTO redactions(target_seq, pointer) VALUES (?, ?)",
                [(authorization.target_seq, path) for path in authorization.paths],
            )
        elif isinstance(authorization, _ArchiveGrant):
            self._scratch.execute(
                "INSERT OR REPLACE INTO archives(event_seq, through_seq) VALUES (?, ?)",
                (event_seq, authorization.through_seq),
            )

    def _scan_events(self) -> None:
        previous_seq = 0
        have_record = False
        previous_chain: str | None = None
        previous_recorded: datetime | None = None
        after = -(2**63)
        while True:
            batch = self._read_batch("WHERE seq > ?", (after,))
            for event in batch:
                seq = event.seq
                after = seq
                self.checked += 1
                inspection = self._safe_inspect(event, True)
                if inspection.archived:
                    self.archived += 1
                    if not self._archive_granted(seq):
                        self.violate(
                            True,
                            "UNAUTHORIZED_ARCHIVE",
                            seq,
                            None,
                            "archived record has no validated archive authorization",
                        )
                expected = previous_seq + 1
                if seq != expected:
                    self.violate(
                        True,
                        "SEQUENCE_GAP",
                        seq,
                        None,
                        f"expected sequence {expected} but found {seq}",
                    )
                prev = _hash(event.prev_hash)
                chain = _hash(event.chain_hash)
                if prev is not None:
                    if not have_record and seq == 1:
                        if prev != self._genesis:
                            self.violate(
                                True,
                                "GENESIS_MISMATCH",
                                seq,
                                None,
                                "first record does not link to the ledger genesis hash",
                            )
                    elif (
                        have_record and previous_chain is not None
                    ) and prev != previous_chain:
                        self.violate(
                            True,
                            "CHAIN_LINK_BROKEN",
                            seq,
                            None,
                            "previous hash does not match the stored hash of "
                            f"sequence {previous_seq}",
                        )
                recorded = _timestamp(event.recorded_at)
                if (
                    recorded is not None
                    and previous_recorded is not None
                    and recorded < previous_recorded
                ):
                    self.violate(
                        True,
                        "MALFORMED_RECORD",
                        seq,
                        None,
                        "recordedAt moves backwards",
                    )
                if recorded is not None:
                    previous_recorded = recorded
                previous_seq = seq
                previous_chain = chain
                have_record = True
                self.head_seq = seq
                self.head_hash = chain
            if len(batch) < self._batch:
                break

    def _safe_inspect(self, event: _Raw, report: bool) -> _Inspection:
        try:
            return self._inspect(event, report)
        except Exception:  # noqa: BLE001 - untrusted data must never escape as an error
            self.violate(
                report,
                "MALFORMED_RECORD",
                event.seq,
                None,
                "record could not be validated",
            )
            return _Inspection(_as_int(event.archived) == 1, None)

    def _inspect(self, e: _Raw, report: bool) -> _Inspection:
        seq = e.seq
        sound = True
        flag = _as_int(e.archived)
        archived = flag == 1
        if flag not in (0, 1):
            self.violate(
                report, "MALFORMED_RECORD", seq, None, "archived flag must be 0 or 1"
            )
            sound = False
        content_digest = _hash(e.content_hash)
        prev_hash = _hash(e.prev_hash)
        chain_digest = _hash(e.chain_hash)
        hashes_valid = None not in (content_digest, prev_hash, chain_digest)
        if not hashes_valid:
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "stored hashes must be lowercase 64-character hexadecimal",
            )
            sound = False
        supported = _as_int(e.hash_version) == HASH_VERSION
        if not supported:
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "unsupported or invalid hash version",
            )
            sound = False
        recorded = _timestamp(e.recorded_at)
        if recorded is None:
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "recordedAt is not a valid UTC microsecond timestamp",
            )
            sound = False
        if (
            hashes_valid
            and supported
            and content_digest is not None
            and prev_hash is not None
            and chain_hash(prev_hash, content_digest) != chain_digest
        ):
            self.violate(
                report,
                "CHAIN_HASH_MISMATCH",
                seq,
                None,
                "stored chain hash does not match its previous and content hashes",
            )
            sound = False

        if archived:
            self._inspect_skeleton(e, report)
            return _Inspection(True, None)
        if flag is not None and e.archived_at is not None:
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "live record carries an archive timestamp",
            )
            sound = False

        fields = [
            _text(e.event_id),
            _text(e.event_type),
            _text(e.actor_id),
            _text(e.resource_type),
            _text(e.resource_id),
            _text(e.source),
        ]
        if None in fields or not isinstance(e.commitments, str):
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "live record is missing required text fields",
            )
            return _Inspection(False, None)
        event_id, event_type, actor_id, resource_type, resource_id, source = (
            str(item) for item in fields
        )
        system_source = source == _SYSTEM_SOURCE
        if system_source != (event_type in _RESERVED_TYPES):
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "system source and reserved event types must be used together",
            )
            sound = False
        occurred_at: str | None = None
        if e.occurred_at is not None:
            if _timestamp(e.occurred_at) is None:
                self.violate(
                    report,
                    "MALFORMED_RECORD",
                    seq,
                    None,
                    "occurredAt is not a valid UTC microsecond timestamp",
                )
                sound = False
            else:
                occurred_at = str(e.occurred_at)

        try:
            tree = parse_json(
                e.commitments.encode("utf-8"),
                max_bytes=MAX_INPUT_BYTES,
                max_depth=_MAX_COMMITMENT_DEPTH,
            )
            if not isinstance(tree, dict):
                raise ValueError("not an object")
        except (ValueError, UnicodeError):
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "payload commitment tree is not a valid JSON object",
            )
            return _Inspection(False, None)
        commitments: dict[str, JsonValue] = tree
        if not supported:
            return _Inspection(False, None)

        try:
            computed = content_hash(
                content_object(
                    seq=seq,
                    event_id=event_id,
                    event_type=event_type,
                    actor_id=actor_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    occurred_at=occurred_at,
                    timestamp=str(e.recorded_at),
                    source=source,
                    payload=commitments,
                )  # type: ignore[arg-type]
            )
            if content_digest is not None and computed != content_digest:
                self.violate(
                    report,
                    "CONTENT_HASH_MISMATCH",
                    seq,
                    None,
                    "recomputed content hash does not match the stored content hash",
                )
                sound = False
            expected = _commitment_leaves(commitments)
        except (ValueError, TypeError):
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "record cannot be canonicalized as a hash version 1 record",
            )
            return _Inspection(False, None)

        leaves: dict[str, PayloadLeaf] = {}
        stored_pointers: set[str] = set()
        sound &= self._load_leaves(seq, report, leaves, stored_pointers)
        missing: list[str] = []
        for pointer, commitment in expected.items():
            leaf = leaves.get(pointer)
            if leaf is None:
                if pointer not in stored_pointers:
                    missing.append(pointer)
            elif not _leaf_matches(leaf, pointer, commitment):
                self.violate(
                    report,
                    "PAYLOAD_VALUE_MISMATCH",
                    seq,
                    pointer,
                    "stored leaf does not match its commitment",
                )
                sound = False
        for pointer in sorted(stored_pointers):
            if pointer not in expected:
                self.violate(
                    report,
                    "MALFORMED_RECORD",
                    seq,
                    pointer,
                    "stored leaf is not part of the commitment tree",
                )
                sound = False
        for pointer in missing:
            if not system_source and self._redaction_granted(seq, pointer):
                if report:
                    self.redacted_fields += 1
            else:
                self.violate(
                    report,
                    "UNAUTHORIZED_REDACTION",
                    seq,
                    pointer,
                    "leaf is absent without a validated redaction authorization",
                )
                sound = False

        authorization: _Authorization | None = None
        if (
            sound
            and system_source
            and not missing
            and event_type in (REDACTED_TYPE, ARCHIVED_TYPE)
        ):
            authorization = self._parse_authorization(
                e, event_type, commitments, leaves, recorded, report
            )
        return _Inspection(False, authorization)

    def _inspect_skeleton(self, e: _Raw, report: bool) -> None:
        seq = e.seq
        business = (
            e.event_type,
            e.actor_id,
            e.resource_type,
            e.resource_id,
            e.occurred_at,
            e.source,
            e.commitments,
        )
        if any(value is not None for value in business):
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "archived record retains business columns",
            )
        if _instant(e.archived_at) is None:
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "archived record has no valid archive timestamp",
            )
        row = self._db.execute(
            "SELECT 1 FROM payload_leaves WHERE seq = ? LIMIT 1", (seq,)
        ).fetchone()
        if row is not None:
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                "archived record retains payload leaves",
            )

    def _load_leaves(
        self,
        seq: int,
        report: bool,
        leaves: dict[str, PayloadLeaf],
        stored_pointers: set[str],
    ) -> bool:
        sound = True
        cursor = self._db.execute(
            "SELECT pointer, salt, value FROM payload_leaves WHERE seq = ? "
            "ORDER BY pointer LIMIT ?",
            (seq, MAX_SCALAR_LEAVES + 1),
        )
        count = 0
        for pointer_value, salt_value, value in cursor:
            count += 1
            if count > MAX_SCALAR_LEAVES:
                self.violate(
                    report,
                    "MALFORMED_RECORD",
                    seq,
                    None,
                    "record stores more payload leaves than the protocol allows",
                )
                return False
            pointer = pointer_value if isinstance(pointer_value, str) else None
            leaf = _read_leaf(pointer, salt_value, value)
            if pointer is None or leaf is None:
                self.violate(
                    report,
                    "MALFORMED_RECORD",
                    seq,
                    pointer,
                    "stored payload leaf is malformed",
                )
                sound = False
                if pointer is not None:
                    stored_pointers.add(pointer)
                continue
            stored_pointers.add(pointer)
            leaves[pointer] = leaf
        return sound

    def _parse_authorization(
        self,
        e: _Raw,
        event_type: str,
        commitments: dict[str, JsonValue],
        leaves: dict[str, PayloadLeaf],
        recorded: datetime | None,
        report: bool,
    ) -> _Authorization | None:
        seq = e.seq
        try:
            payload = reveal_payload(commitments, leaves).payload
            if event_type == REDACTED_TYPE:
                return self._parse_redaction(payload, seq)
            return self._parse_archive(payload, seq, recorded, report)
        except (_InvalidAuthorizationError, ValueError, OverflowError) as exc:
            detail = f": {exc}" if isinstance(exc, _InvalidAuthorizationError) else ""
            self.violate(
                report,
                "MALFORMED_RECORD",
                seq,
                None,
                f"authorization event payload is invalid{detail}",
            )
            return None

    def _parse_redaction(self, payload: dict[str, Any], seq: int) -> _RedactionGrant:
        _require_keys(payload, _REDACTION_KEYS)
        target_seq = _positive(payload["targetSeq"], "targetSeq")
        target_event_id = _require_text(payload["targetEventId"], "targetEventId")
        _require_text(payload["reason"], "reason")
        _require_text(payload["ticketId"], "ticketId")
        _require_text(payload["requestedBy"], "requestedBy")
        if target_seq >= seq:
            raise _InvalidAuthorizationError("target must precede the authorization")
        paths = payload["paths"]
        if not isinstance(paths, list) or not paths or len(paths) > MAX_SCALAR_LEAVES:
            raise _InvalidAuthorizationError("paths must be a bounded non-empty array")
        exact: list[str] = []
        for path in paths:
            if not isinstance(path, str) or not _POINTER.fullmatch(path):
                raise _InvalidAuthorizationError("paths must be RFC 6901 pointers")
            exact.append(path)
        target = self._skeleton(target_seq)
        if target is None or target[0] != target_event_id:
            raise _InvalidAuthorizationError("target does not match the ledger")
        return _RedactionGrant(target_seq, exact)

    def _parse_archive(
        self,
        payload: dict[str, Any],
        seq: int,
        recorded: datetime | None,
        report: bool,
    ) -> _ArchiveGrant:
        _require_keys(payload, _ARCHIVE_KEYS)
        through = _positive(payload["archivedThroughSeq"], "archivedThroughSeq")
        first = _positive(payload["fromSeq"], "fromSeq")
        last_seq = _positive(payload["toSeq"], "toSeq")
        count = _positive(payload["count"], "count")
        retention_days = _positive(payload["retentionDays"], "retentionDays")
        cutoff = _instant(payload["cutoff"])
        last_hash = _require_text(
            payload["lastArchivedChainHash"], "lastArchivedChainHash"
        )
        file_digest = _require_text(payload["archiveSha256"], "archiveSha256")
        _require_text(payload["archiveFile"], "archiveFile")
        _require_text(payload["archiveBundleId"], "archiveBundleId")
        _require_text(payload["requestedBy"], "requestedBy")
        if (
            cutoff is None
            or retention_days > _MAX_RETENTION_DAYS
            or not _HASH.fullmatch(last_hash)
            or not _HASH.fullmatch(file_digest)
        ):
            raise _InvalidAuthorizationError("archive metadata has invalid values")
        if (
            first > last_seq
            or last_seq >= seq
            or through != last_seq
            or count != last_seq - first + 1
        ):
            raise _InvalidAuthorizationError("archive range is inconsistent")
        last = self._skeleton(last_seq)
        if last is None or last_hash != last[1]:
            raise _InvalidAuthorizationError(
                "archive end hash does not match the ledger"
            )
        last_recorded = _timestamp(last[2])
        violation = (
            recorded is None
            or last_recorded is None
            or cutoff > recorded - timedelta(days=retention_days)
            or last_recorded >= cutoff
        )
        if violation:
            self.violate(
                report,
                "RETENTION_POLICY_VIOLATION",
                seq,
                None,
                "archive cutoff violates the retention policy declared by the event",
            )
        return _ArchiveGrant(through)

    def _skeleton(self, seq: int) -> tuple[Any, Any, Any] | None:
        row = self._db.execute(
            "SELECT event_id, chain_hash, recorded_at FROM audit_events WHERE seq = ?",
            (seq,),
        ).fetchone()
        return None if row is None else (row[0], row[1], row[2])

    def _redaction_granted(self, seq: int, pointer: str) -> bool:
        return (
            self._scratch.execute(
                "SELECT 1 FROM redactions WHERE target_seq = ? AND pointer = ?",
                (seq, pointer),
            ).fetchone()
            is not None
        )

    def _archive_granted(self, seq: int) -> bool:
        return (
            self._scratch.execute(
                "SELECT 1 FROM archives WHERE event_seq > ? AND through_seq >= ? "
                "LIMIT 1",
                (seq, seq),
            ).fetchone()
            is not None
        )

    def _verify_checkpoints(self) -> None:
        after = -(2**63)
        while True:
            rows = self._db.execute(
                "SELECT id, seq, chain_hash, created_at, key_id, signature "
                "FROM checkpoints WHERE id > ? ORDER BY id LIMIT ?",
                (after, self._batch),
            ).fetchall()
            for row in rows:
                after = row[0]
                self._check_checkpoint(row[1], row[2], row[3], row[4], row[5])
            if len(rows) < self._batch:
                break

    def _check_checkpoint(
        self, seq_value: Any, chain_value: Any, created: Any, key: Any, signature: Any
    ) -> None:
        seq = _as_int(seq_value)
        chain = _hash(chain_value)
        if (
            seq is None
            or not 0 < seq <= MAX_SAFE_INTEGER
            or chain is None
            or _timestamp(created) is None
            or not (isinstance(key, str) and _KEY_ID.fullmatch(key))
            or not isinstance(signature, str)
        ):
            self.violate(
                True,
                "MALFORMED_RECORD",
                seq if seq is not None and seq > 0 else None,
                None,
                "checkpoint record is malformed",
            )
            return
        message: dict[str, object] = {
            "type": "audit-checkpoint/v1",
            "ledgerId": self._ledger_id,
            "seq": seq,
            "chainHash": chain,
            "createdAt": created,
            "keyId": key,
            "signature": signature,
        }
        try:
            valid = CheckpointSigner.verify_checkpoint(message, self._public_key)
        except ValueError:
            valid = False
        if not valid:
            self.violate(
                True,
                "CHECKPOINT_SIGNATURE_INVALID",
                seq,
                None,
                "checkpoint signature is invalid for the pinned key and ledger",
            )
            return
        if seq > self.head_seq:
            self.violate(
                True,
                "TRUNCATION_DETECTED",
                seq,
                None,
                "a signed checkpoint covers sequences beyond the ledger head",
            )
            return
        stored = self._skeleton(seq)
        if stored is None:
            self.violate(
                True,
                "CHECKPOINT_MISMATCH",
                seq,
                None,
                "checkpointed sequence is missing from the ledger",
            )
        elif chain != stored[1]:
            self.violate(
                True,
                "CHECKPOINT_MISMATCH",
                seq,
                None,
                "checkpoint chain hash differs from the stored chain hash",
            )
        else:
            self.checkpoints_verified += 1

    def _detect_orphan_leaves(self) -> None:
        cursor = self._db.execute(
            "SELECT DISTINCT l.seq FROM payload_leaves l "
            "LEFT JOIN audit_events e ON e.seq = l.seq "
            "WHERE e.seq IS NULL ORDER BY l.seq"
        )
        for (value,) in cursor:
            self.violate(
                True,
                "MALFORMED_RECORD",
                _as_int(value),
                None,
                "payload leaves exist for a missing record",
            )


def _read_leaf(pointer: str | None, salt: Any, value: Any) -> PayloadLeaf | None:
    if pointer is None or not _POINTER.fullmatch(pointer):
        return None
    if not isinstance(salt, str) or not _HASH.fullmatch(salt):
        return None
    if not isinstance(value, str):
        return None
    try:
        parsed = parse_json(
            value.encode("utf-8"), max_bytes=MAX_INPUT_BYTES, max_depth=2
        )
    except (ValueError, UnicodeError):
        return None
    if isinstance(parsed, dict | list):
        return None
    return PayloadLeaf(bytes.fromhex(salt), parsed)


def _leaf_matches(leaf: PayloadLeaf, pointer: str, commitment: str) -> bool:
    try:
        return leaf_hash(leaf.salt, pointer, leaf.value) == commitment
    except (ValueError, TypeError):
        return False
