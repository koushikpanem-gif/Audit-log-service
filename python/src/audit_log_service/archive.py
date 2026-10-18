"""Bounded, durable retention archive with a crash-safe state machine."""

from __future__ import annotations

import contextlib
import hashlib
import math
import os
import re
import sqlite3
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, timedelta
from pathlib import Path
from typing import Any, cast

from audit_log_service.canonical_json import MAX_DOCUMENT_DEPTH, JsonValue, canonicalize
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError
from audit_log_service.export_bundle import (
    BUNDLE_FORMAT,
    completeness,
    render_record,
)
from audit_log_service.ledger import AppendService, Clock
from audit_log_service.signing import CheckpointSigner
from audit_log_service.store import SqliteStore, StorageError
from audit_log_service.timeutil import format_micros, parse_stored_timestamp
from audit_log_service.v1_hashes import HASH_VERSION, genesis_hash

EVENT_TYPE = "RECORDS_ARCHIVED"
RESOURCE_TYPE = "AUDIT_ARCHIVE"
FINAL_PATTERN = re.compile(
    r"archive-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json\Z"
)
TEMP_PATTERN = re.compile(
    r"\.archive-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp\Z"
)
ENVELOPE_HEADROOM_BYTES = 8192
MAX_STATUS_ITEMS = 100

AFTER_JOB_RECORDED = "AFTER_JOB_RECORDED"
AFTER_TEMP_FORCED = "AFTER_TEMP_FORCED"
AFTER_PUBLISH = "AFTER_PUBLISH"
BEFORE_COMMIT = "BEFORE_COMMIT"
AFTER_COMMIT = "AFTER_COMMIT"

NOTE = (
    "Archived records leave normal query, export and report results. Their business "
    "fields are recoverable only from the signed archive file. The directory sync "
    "flag is false where the platform cannot fsync a directory (for example "
    "Windows); the rename is still atomic but its durability then depends on the "
    "filesystem."
)


def final_name(bundle_id: str) -> str:
    return f"archive-{bundle_id}.json"


def temp_name(bundle_id: str) -> str:
    return f".archive-{bundle_id}.tmp"


@dataclass(frozen=True)
class _Plan:
    from_seq: int
    to_seq: int
    count: int
    last_chain_hash: str
    last_recorded_at: str
    records: list[dict[str, Any]]
    more: bool


class ArchiveService:
    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        signer: CheckpointSigner,
        appender: AppendService,
        clock: Clock,
    ) -> None:
        self._store = store
        self._configuration = configuration
        self._signer = signer
        self._appender = appender
        self._clock = clock
        self._lock = threading.Lock()
        self._dir = configuration.archive_dir
        # Test seam: called with a stage name; an ordinary exception exercises the
        # failure path, SimulatedCrashError models a dying process.
        self.stage_hook: Callable[[str], None] | None = None

    @property
    def archive_dir(self) -> Path:
        return self._dir

    def _stage(self, name: str) -> None:
        if self.stage_hook is not None:
            self.stage_hook(name)

    def _cutoff(self) -> tuple[str, int]:
        days = max(1, math.ceil(self._configuration.retention_days))
        moment = self._clock().astimezone(UTC) - timedelta(days=days)
        return format_micros(moment), days

    def archive(self, dry_run: bool, requested_by: str) -> dict[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise ApiError(409, "ARCHIVE_IN_PROGRESS", "An archive run is in progress")
        try:
            cutoff, days = self._cutoff()
            if dry_run:
                return self._dry_run(cutoff, days)
            return self._run(cutoff, days, requested_by)
        finally:
            self._lock.release()

    def _dry_run(self, cutoff: str, days: int) -> dict[str, Any]:
        with self._store.read_snapshot() as connection:
            plan = self._plan(connection, cutoff)
        if plan is None:
            return _summary("NOTHING_TO_ARCHIVE", True, cutoff, days)
        result = _summary("DRY_RUN", True, cutoff, days)
        result.update(_range(plan))
        return result

    def _run(self, cutoff: str, days: int, requested_by: str) -> dict[str, Any]:
        with self._store.read_snapshot() as connection:
            interrupted = connection.execute(
                "SELECT COUNT(*) FROM archive_jobs WHERE status = 'PREPARING'"
            ).fetchone()[0]
            plan = self._plan(connection, cutoff)
        if interrupted:
            raise ApiError(
                409,
                "ARCHIVE_JOB_INTERRUPTED",
                "A previous archive job was interrupted; reconcile it first",
            )
        if plan is None:
            return _summary("NOTHING_TO_ARCHIVE", False, cutoff, days)
        bundle_id = str(uuid.uuid4())
        with self._store.write_transaction() as connection:
            connection.execute(
                "INSERT INTO archive_jobs(bundle_id, status, temp_name, final_name, "
                "requested_by, created_at, updated_at) "
                "VALUES (?, 'PREPARING', ?, ?, ?, ?, ?)",
                (
                    bundle_id,
                    temp_name(bundle_id),
                    final_name(bundle_id),
                    requested_by,
                    self._now(),
                    self._now(),
                ),
            )
        try:
            self._stage(AFTER_JOB_RECORDED)
            return self._commit(bundle_id, cutoff, days, requested_by)
        except Exception as exc:
            committed = self._fail(bundle_id, exc)
            if committed is not None:
                return committed
            if isinstance(exc, ApiError | StorageError):
                raise
            raise ApiError(
                500,
                "ARCHIVE_PUBLICATION_FAILED",
                "Archive publication failed; live plaintext was retained and the "
                "job was marked FAILED",
            ) from exc

    def _plan(self, connection: sqlite3.Connection, cutoff: str) -> _Plan | None:
        first = connection.execute(
            "SELECT MIN(seq) FROM audit_events WHERE archived = 0"
        ).fetchone()[0]
        if first is None:
            return None
        limit = self._configuration.archive_max_bytes - ENVELOPE_HEADROOM_BYTES
        records: list[dict[str, Any]] = []
        total = 0
        expected = int(first)
        more = False
        last_hash = ""
        last_recorded = ""
        rows = connection.execute(
            "SELECT * FROM audit_events WHERE archived = 0 AND seq >= ? "
            "ORDER BY seq LIMIT ?",
            (expected, self._configuration.archive_max_records + 1),
        )
        for row in rows:
            if int(row["seq"]) != expected or row["recorded_at"] >= cutoff:
                break
            if len(records) >= self._configuration.archive_max_records:
                more = True
                break
            record = render_record(connection, row)
            size = len(canonicalize(record, max_depth=MAX_DOCUMENT_DEPTH)) + 1
            if size > limit:
                raise ApiError(
                    422,
                    "ARCHIVE_RECORD_TOO_LARGE",
                    "A single record exceeds the archive size limit",
                )
            if total + size > limit:
                more = True
                break
            total += size
            records.append(record)
            last_hash = str(row["chain_hash"])
            last_recorded = str(row["recorded_at"])
            expected += 1
        if not records:
            return None
        return _Plan(
            int(first),
            expected - 1,
            len(records),
            last_hash,
            last_recorded,
            records,
            more,
        )

    def _commit(
        self, bundle_id: str, cutoff: str, days: int, requested_by: str
    ) -> dict[str, Any]:
        with self._store.write_transaction() as connection:
            plan = self._plan(connection, cutoff)
            if plan is None:
                raise ApiError(409, "CONFLICT", "Nothing is eligible for archiving")
            created = format_micros(
                max(
                    self._clock().astimezone(UTC),
                    parse_stored_timestamp(plan.last_recorded_at),
                )
            )
            checkpoint = self._appender.store_checkpoint(
                connection, plan.to_seq, plan.last_chain_hash, created
            )
            data = self._bundle(bundle_id, plan, created, requested_by, checkpoint)
            if len(data) > self._configuration.archive_max_bytes:
                raise ApiError(
                    422,
                    "ARCHIVE_TOO_LARGE",
                    "The archive bundle exceeds its size limit",
                )
            digest = hashlib.sha256(data).hexdigest()
            synced = self._publish(bundle_id, data)
            self._stage(AFTER_PUBLISH)
            # Only now, with the file durably published, is live plaintext removed.
            updated = connection.execute(
                "UPDATE audit_events SET archived = 1, archived_at = ?, "
                "event_type = NULL, actor_id = NULL, resource_type = NULL, "
                "resource_id = NULL, occurred_at = NULL, source = NULL, "
                "payload_commitments = NULL "
                "WHERE seq BETWEEN ? AND ? AND archived = 0",
                (created, plan.from_seq, plan.to_seq),
            )
            if updated.rowcount != plan.count:
                raise StorageError("Archive expected to clear the planned rows")
            connection.execute(
                "DELETE FROM payload_leaves WHERE seq BETWEEN ? AND ?",
                (plan.from_seq, plan.to_seq),
            )
            payload: dict[str, JsonValue] = {
                "archivedThroughSeq": plan.to_seq,
                "fromSeq": plan.from_seq,
                "toSeq": plan.to_seq,
                "count": plan.count,
                "cutoff": cutoff,
                "retentionDays": days,
                "lastArchivedChainHash": plan.last_chain_hash,
                "archiveFile": final_name(bundle_id),
                "archiveSha256": digest,
                "archiveBundleId": bundle_id,
                "requestedBy": requested_by,
            }
            event = self._appender.append_system_event(
                connection, EVENT_TYPE, requested_by, RESOURCE_TYPE, bundle_id, payload
            )
            connection.execute(
                "UPDATE archive_jobs SET status = 'COMMITTED', updated_at = ?, "
                "from_seq = ?, to_seq = ?, record_count = ?, cutoff = ?, "
                "retention_days = ?, archive_sha256 = ?, archive_bytes = ?, "
                "directory_synced = ?, archive_event_seq = ? WHERE bundle_id = ?",
                (
                    self._now(),
                    plan.from_seq,
                    plan.to_seq,
                    plan.count,
                    cutoff,
                    days,
                    digest,
                    len(data),
                    1 if synced else 0,
                    event["seq"],
                    bundle_id,
                ),
            )
            self._stage(BEFORE_COMMIT)
        self._stage(AFTER_COMMIT)
        wal = self._store.checkpoint_wal_truncate(
            self._configuration.cleanup_busy_timeout_ms
        )
        result = _summary("ARCHIVED", False, cutoff, days)
        result.update(_range(plan))
        result.update(
            {
                "bundleId": bundle_id,
                "archiveFile": final_name(bundle_id),
                "archiveSha256": digest,
                "archiveBytes": len(data),
                "archiveEventSeq": event["seq"],
                "directorySynced": synced,
                "walCheckpoint": "COMPLETE" if wal.complete else "BUSY",
            }
        )
        return result

    def _bundle(
        self,
        bundle_id: str,
        plan: _Plan,
        created: str,
        requested_by: str,
        checkpoint: dict[str, Any],
    ) -> bytes:
        ledger_id = self._configuration.ledger_id
        records_digest = hashlib.sha256(
            canonicalize(cast(Any, plan.records), max_depth=MAX_DOCUMENT_DEPTH)
        ).hexdigest()
        selection: dict[str, JsonValue] = {
            "actorId": None,
            "resourceType": None,
            "resourceId": None,
            "eventType": None,
            "from": None,
            "to": None,
            "seqFrom": plan.from_seq,
            "seqTo": plan.to_seq,
        }
        body: dict[str, JsonValue] = {
            "format": BUNDLE_FORMAT,
            "bundleId": bundle_id,
            "purpose": "RETENTION_ARCHIVE",
            "ledgerId": ledger_id,
            "hashAlgorithm": "SHA-256",
            "hashVersion": HASH_VERSION,
            "genesisHash": genesis_hash(ledger_id),
            "signatureAlgorithm": "Ed25519",
            "exportedAt": created,
            "exportedBy": requested_by,
            "selection": selection,
            "completeness": completeness(plan.to_seq),
            "recordCount": plan.count,
            "recordsDigest": records_digest,
            "records": cast(Any, plan.records),
            "headCheckpoint": cast(Any, checkpoint),
            "signer": {
                "keyId": self._signer.key_id,
                "publicKey": self._signer.public_key_base64,
            },
        }
        body["signature"] = self._signer.sign_message(body, MAX_DOCUMENT_DEPTH)
        return canonicalize(body, max_depth=MAX_DOCUMENT_DEPTH)

    def _publish(self, bundle_id: str, data: bytes) -> bool:
        self._dir.mkdir(parents=True, exist_ok=True)
        temp = self._dir / temp_name(bundle_id)
        final = self._dir / final_name(bundle_id)
        if temp.exists() or final.exists():
            raise StorageError("Archive file name already exists")
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        self._stage(AFTER_TEMP_FORCED)
        os.replace(temp, final)
        if final.stat().st_size != len(data):
            raise StorageError("Published archive has an unexpected size")
        return _sync_directory(self._dir)

    def _fail(self, bundle_id: str, exc: BaseException) -> dict[str, Any] | None:
        """Mark the job FAILED and clean up; returns a result if it had committed."""
        code = exc.code if isinstance(exc, ApiError) else "PUBLICATION_FAILED"
        try:
            with self._store.write_transaction() as connection:
                row = connection.execute(
                    "SELECT status FROM archive_jobs WHERE bundle_id = ?",
                    (bundle_id,),
                ).fetchone()
                if row is not None and row["status"] == "COMMITTED":
                    return self._from_job(connection, bundle_id)
                connection.execute(
                    "UPDATE archive_jobs SET status = 'FAILED', failure_code = ?, "
                    "cleanup_state = 'PENDING', updated_at = ? "
                    "WHERE bundle_id = ? AND status = 'PREPARING'",
                    (code, self._now(), bundle_id),
                )
        except StorageError:
            return None
        self.cleanup_job(bundle_id)
        return None

    def _from_job(
        self, connection: sqlite3.Connection, bundle_id: str
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM archive_jobs WHERE bundle_id = ?", (bundle_id,)
        ).fetchone()
        result = _summary("ARCHIVED", False, row["cutoff"], row["retention_days"])
        result.update(
            {
                "fromSeq": row["from_seq"],
                "toSeq": row["to_seq"],
                "count": row["record_count"],
                "bundleId": bundle_id,
                "archiveFile": row["final_name"],
                "archiveSha256": row["archive_sha256"],
                "archiveBytes": row["archive_bytes"],
                "archiveEventSeq": row["archive_event_seq"],
                "directorySynced": bool(row["directory_synced"]),
            }
        )
        return result

    def cleanup_job(self, bundle_id: str) -> str:
        """Delete a FAILED job's files only when they are proven unreferenced."""
        with self._store.read_snapshot() as connection:
            job = connection.execute(
                "SELECT * FROM archive_jobs WHERE bundle_id = ?", (bundle_id,)
            ).fetchone()
            if job is None or job["status"] != "FAILED":
                return "NONE"
            referenced = self._referenced(connection, job["final_name"])
        names = [job["temp_name"], job["final_name"]]
        proven = (
            not referenced
            and job["temp_name"] == temp_name(bundle_id)
            and job["final_name"] == final_name(bundle_id)
            and TEMP_PATTERN.match(job["temp_name"]) is not None
            and FINAL_PATTERN.match(job["final_name"]) is not None
        )
        state = "BLOCKED"
        detail: str | None = "files are referenced or have unexpected names"
        if proven:
            state, detail = "DONE", None
            for name in names:
                path = self._dir / name
                try:
                    if path.is_symlink() or path.is_file():
                        path.unlink()
                except OSError:
                    state, detail = "PENDING", "file deletion failed; retry later"
        with contextlib.suppress(StorageError), self._store.write_transaction() as c:
            c.execute(
                "UPDATE archive_jobs SET cleanup_state = ?, cleanup_detail = ?, "
                "updated_at = ? WHERE bundle_id = ? AND status = 'FAILED'",
                (state, detail, self._now(), bundle_id),
            )
        return state

    @staticmethod
    def _referenced(connection: sqlite3.Connection, name: str) -> bool:
        committed = connection.execute(
            "SELECT 1 FROM archive_jobs WHERE final_name = ? AND status = 'COMMITTED'",
            (name,),
        ).fetchone()
        live = connection.execute(
            "SELECT 1 FROM payload_leaves WHERE pointer = '/archiveFile' AND value = ?",
            (canonicalize(name).decode("utf-8"),),
        ).fetchone()
        return committed is not None or live is not None

    def reconcile(self) -> dict[str, Any]:
        """Fail interrupted jobs and retry cleanup; safe at start-up and on demand."""
        if not self._lock.acquire(blocking=False):
            raise ApiError(409, "ARCHIVE_IN_PROGRESS", "An archive run is in progress")
        try:
            with self._store.write_transaction() as connection:
                connection.execute(
                    "UPDATE archive_jobs SET status = 'FAILED', "
                    "failure_code = 'INTERRUPTED', cleanup_state = 'PENDING', "
                    "updated_at = ? WHERE status = 'PREPARING'",
                    (self._now(),),
                )
                pending = [
                    str(row["bundle_id"])
                    for row in connection.execute(
                        "SELECT bundle_id FROM archive_jobs WHERE status = 'FAILED' "
                        "AND cleanup_state = 'PENDING' ORDER BY id"
                    )
                ]
            for bundle_id in pending:
                self.cleanup_job(bundle_id)
        finally:
            self._lock.release()
        return self.status()

    def status(self) -> dict[str, Any]:
        with self._store.read_snapshot() as connection:
            jobs = [
                {
                    "bundleId": row["bundle_id"],
                    "status": row["status"],
                    "requestedBy": row["requested_by"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                    "fromSeq": row["from_seq"],
                    "toSeq": row["to_seq"],
                    "recordCount": row["record_count"],
                    "archiveFile": row["final_name"],
                    "archiveSha256": row["archive_sha256"],
                    "archiveEventSeq": row["archive_event_seq"],
                    "failureCode": row["failure_code"],
                    "cleanupState": row["cleanup_state"],
                    "cleanupDetail": row["cleanup_detail"],
                }
                for row in connection.execute(
                    "SELECT * FROM archive_jobs ORDER BY id DESC LIMIT ?",
                    (MAX_STATUS_ITEMS,),
                )
            ]
            open_jobs = connection.execute(
                "SELECT COUNT(*) FROM archive_jobs WHERE status = 'PREPARING' "
                "OR (status = 'FAILED' AND cleanup_state IN ('PENDING', 'BLOCKED'))"
            ).fetchone()[0]
            known = {
                name
                for row in connection.execute(
                    "SELECT temp_name, final_name FROM archive_jobs"
                )
                for name in (row["temp_name"], row["final_name"])
            }
        orphans: list[str] = []
        unrecognized = 0
        if self._dir.is_dir():
            for entry in sorted(self._dir.iterdir(), key=lambda p: p.name):
                if entry.name in known:
                    continue
                if FINAL_PATTERN.match(entry.name) or TEMP_PATTERN.match(entry.name):
                    if len(orphans) < MAX_STATUS_ITEMS:
                        orphans.append(entry.name)
                else:
                    unrecognized += 1
        return {
            "openJobs": int(open_jobs),
            "jobs": jobs,
            "orphanFiles": orphans,
            "unrecognizedFileCount": unrecognized,
            "note": (
                "Files without a job row are reported but never deleted "
                "automatically; an operator must prove they are unreferenced."
            ),
        }

    def _now(self) -> str:
        return format_micros(self._clock())


def _sync_directory(path: Path) -> bool:
    if os.name == "nt":
        return False
    try:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        return False
    return True


def _summary(status: str, dry_run: bool, cutoff: str, days: int) -> dict[str, Any]:
    return {
        "status": status,
        "dryRun": dry_run,
        "cutoff": cutoff,
        "retentionDays": days,
        "note": NOTE,
    }


def _range(plan: _Plan) -> dict[str, Any]:
    return {
        "fromSeq": plan.from_seq,
        "toSeq": plan.to_seq,
        "count": plan.count,
        "moreAvailable": plan.more,
    }


__all__ = [
    "AFTER_COMMIT",
    "AFTER_JOB_RECORDED",
    "AFTER_PUBLISH",
    "AFTER_TEMP_FORCED",
    "BEFORE_COMMIT",
    "EVENT_TYPE",
    "ArchiveService",
    "final_name",
    "temp_name",
]
