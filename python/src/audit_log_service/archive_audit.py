"""Explicit audit of published archive files against the ledger skeleton."""

from __future__ import annotations

import hashlib
import sqlite3
import stat
from datetime import UTC
from pathlib import Path
from typing import Any

from audit_log_service.archive import EVENT_TYPE, FINAL_PATTERN
from audit_log_service.canonical_json import MAX_INPUT_BYTES, parse_json
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.ledger import Clock
from audit_log_service.store import SqliteStore
from audit_log_service.timeutil import format_micros
from audit_log_service.verifier.bundle import VERIFIED, Options, verify_bundle

_MAX_CODES = 5
_FIELDS = {
    "/archiveBundleId": "bundleId",
    "/archiveFile": "file",
    "/archiveSha256": "sha256",
    "/fromSeq": "fromSeq",
    "/toSeq": "toSeq",
    "/count": "count",
}

SCOPE = (
    "Checks each referenced archive file's name, digest, signed bundle and "
    "skeleton hashes. It does not verify the ledger chain; use GET /audit/verify "
    "for that. A missing archive is reported as ARCHIVE_FILE_MISSING, distinct "
    "from a chain break."
)


class ArchiveAuditService:
    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        public_key: str,
        key_id: str,
        clock: Clock,
    ) -> None:
        self._store = store
        self._configuration = configuration
        self._public_key = public_key
        self._key_id = key_id
        self._clock = clock
        self._dir: Path = configuration.archive_dir

    def audit(self) -> dict[str, Any]:
        with self._store.read_snapshot() as connection:
            entries = self._entries(connection)
            archives = [self._check(connection, entry) for entry in entries]
            coverage = self._coverage(connection, entries)
        missing = sum(1 for a in archives if a["status"] == "ARCHIVE_FILE_MISSING")
        unavailable = sum(
            1 for a in archives if a["status"] == "ARCHIVE_FILE_UNREADABLE"
        )
        failed = sum(1 for a in archives if a["status"] != "OK")
        return {
            "auditedAt": format_micros(self._clock().astimezone(UTC)),
            "archiveCount": len(archives),
            "intact": failed == 0 and coverage["complete"],
            "failedArchiveCount": failed,
            "missingArchiveCount": missing,
            "unavailableArchiveCount": unavailable,
            "keyId": self._key_id,
            "coverage": coverage,
            "archives": archives,
            "scope": SCOPE,
        }

    def _entries(self, connection: sqlite3.Connection) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for row in connection.execute(
            "SELECT * FROM archive_jobs WHERE status = 'COMMITTED' ORDER BY id"
        ):
            merged[row["bundle_id"]] = {
                "bundleId": row["bundle_id"],
                "file": row["final_name"],
                "sha256": row["archive_sha256"],
                "fromSeq": row["from_seq"],
                "toSeq": row["to_seq"],
                "count": row["record_count"],
                "eventSeq": row["archive_event_seq"],
                "metadataConflict": False,
            }
        for row in connection.execute(
            "SELECT seq FROM audit_events WHERE archived = 0 AND source = 'system' "
            "AND event_type = ? ORDER BY seq",
            (EVENT_TYPE,),
        ):
            event = self._event_metadata(connection, int(row["seq"]))
            if event is None:
                continue
            existing = merged.get(event["bundleId"])
            if existing is None:
                merged[event["bundleId"]] = event
            else:
                conflict = (
                    any(existing[key] != event[key] for key in _FIELDS.values())
                    or existing["eventSeq"] != event["eventSeq"]
                )
                merged[event["bundleId"]] = {**event, "metadataConflict": conflict}
        return sorted(merged.values(), key=lambda e: (e["fromSeq"] or 0, e["bundleId"]))

    @staticmethod
    def _event_metadata(
        connection: sqlite3.Connection, seq: int
    ) -> dict[str, Any] | None:
        values: dict[str, Any] = {}
        for leaf in connection.execute(
            "SELECT pointer, value FROM payload_leaves WHERE seq = ?", (seq,)
        ):
            name = _FIELDS.get(str(leaf["pointer"]))
            if name is None:
                continue
            try:
                values[name] = parse_json(
                    str(leaf["value"]).encode("utf-8"), max_bytes=MAX_INPUT_BYTES
                )
            except (ValueError, UnicodeError):
                return None
        if set(values) != set(_FIELDS.values()):
            return None
        for key in ("bundleId", "file", "sha256"):
            if not isinstance(values[key], str):
                return None
        for key in ("fromSeq", "toSeq", "count"):
            if (
                isinstance(values[key], bool)
                or not isinstance(values[key], int)
                or values[key] < 1
            ):
                return None
        values["eventSeq"] = seq
        values["metadataConflict"] = False
        return values

    def _check(
        self, connection: sqlite3.Connection, entry: dict[str, Any]
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "bundleId": entry["bundleId"],
            "archiveFile": entry["file"],
            "fromSeq": entry["fromSeq"],
            "toSeq": entry["toSeq"],
            "count": entry["count"],
            "archiveEventSeq": entry["eventSeq"],
            "status": "OK",
            "diagnostics": [],
        }
        status, diagnostics = self._status(connection, entry)
        result["status"] = status
        result["diagnostics"] = diagnostics
        return result

    def _status(
        self, connection: sqlite3.Connection, entry: dict[str, Any]
    ) -> tuple[str, list[str]]:
        if entry["metadataConflict"]:
            return "METADATA_MISMATCH", ["job and ledger event disagree"]
        name = str(entry["file"])
        if not FINAL_PATTERN.match(name) or name != f"archive-{entry['bundleId']}.json":
            return "FILE_NAME_UNSAFE", ["archive file name is not service-generated"]
        path = self._dir / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            return "ARCHIVE_FILE_MISSING", ["archive file does not exist"]
        except OSError:
            return "ARCHIVE_FILE_UNREADABLE", ["archive file cannot be inspected"]
        if not stat.S_ISREG(info.st_mode):
            return "FILE_NAME_UNSAFE", ["archive path is not a regular file"]
        limit = self._configuration.archive_max_bytes
        if info.st_size > limit:
            return "DIGEST_MISMATCH", ["archive file exceeds the size limit"]
        try:
            data = path.read_bytes()
        except OSError:
            return "ARCHIVE_FILE_UNREADABLE", ["archive file cannot be read"]
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            return "DIGEST_MISMATCH", ["file digest differs from the authorization"]
        outcome = verify_bundle(
            data,
            Options(
                pinned_key=self._public_key,
                max_bytes=limit,
                max_records=self._configuration.archive_max_records,
            ),
        )
        if outcome.status != VERIFIED:
            codes = sorted({str(d["code"]) for d in outcome.diagnostics})
            return "BUNDLE_INVALID", codes[:_MAX_CODES] or [outcome.status]
        problem = self._shape_problem(connection, data, entry)
        if problem is not None:
            return "BUNDLE_INVALID", [problem]
        if not self._skeleton_matches(connection, data, limit):
            return "SKELETON_MISMATCH", ["archive hashes differ from the ledger"]
        return "OK", []

    def _shape_problem(
        self, connection: sqlite3.Connection, data: bytes, entry: dict[str, Any]
    ) -> str | None:
        body = parse_json(data, max_bytes=self._configuration.archive_max_bytes)
        if not isinstance(body, dict):
            return "BUNDLE_NOT_OBJECT"
        head = body.get("headCheckpoint")
        signer = body.get("signer")
        checks = (
            body.get("purpose") == "RETENTION_ARCHIVE",
            body.get("bundleId") == entry["bundleId"],
            body.get("recordCount") == entry["count"],
            body.get("ledgerId") == self._configuration.ledger_id,
            isinstance(signer, dict) and signer.get("keyId") == self._key_id,
            isinstance(head, dict) and head.get("seq") == entry["toSeq"],
            entry["eventSeq"] is not None and entry["eventSeq"] > entry["toSeq"],
            entry["toSeq"] - entry["fromSeq"] + 1 == entry["count"],
        )
        if not all(checks):
            return "BUNDLE_METADATA_MISMATCH"
        exists = (
            connection.execute(
                "SELECT 1 FROM audit_events WHERE seq = ?", (entry["eventSeq"],)
            ).fetchone()
            is not None
        )
        return None if exists else "AUTHORIZING_EVENT_MISSING"

    @staticmethod
    def _skeleton_matches(
        connection: sqlite3.Connection, data: bytes, limit: int
    ) -> bool:
        body = parse_json(data, max_bytes=limit)
        records = body["records"] if isinstance(body, dict) else []
        if not isinstance(records, list):
            return False
        for record in records:
            if not isinstance(record, dict):
                return False
            row = connection.execute(
                "SELECT event_id, recorded_at, hash_version, content_hash, prev_hash, "
                "chain_hash FROM audit_events WHERE seq = ? AND archived = 1",
                (record.get("seq"),),
            ).fetchone()
            if row is None:
                return False
            expected = (
                record.get("eventId"),
                record.get("timestamp"),
                record.get("hashVersion"),
                record.get("contentHash"),
                record.get("prevHash"),
                record.get("chainHash"),
            )
            if tuple(row) != expected:
                return False
        return True

    @staticmethod
    def _coverage(
        connection: sqlite3.Connection, entries: list[dict[str, Any]]
    ) -> dict[str, Any]:
        archived = int(
            connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE archived = 1"
            ).fetchone()[0]
        )
        covered = 0
        next_seq = 1
        contiguous = True
        for entry in entries:
            if entry["fromSeq"] != next_seq:
                contiguous = False
            covered += int(entry["count"])
            next_seq = int(entry["toSeq"]) + 1
        return {
            "archivedRecords": archived,
            "recordsCoveredByArchives": covered,
            "complete": archived == covered and contiguous,
        }
