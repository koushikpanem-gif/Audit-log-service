"""Export sets: signed manifests plus immutable chunks for selections too large for a
single v1 bundle.

A job streams the selection from one frozen read snapshot into bounded chunk files in
a staging directory, then appends the BUNDLE_EXPORTED event and signs the manifest in
one write transaction. The staging directory is renamed into place and only then is
the durable job file marked READY. Recovery is repeatable and re-derives state from
the job files, the staged manifests and the ledger.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from audit_log_service.canonical_json import (
    MAX_DOCUMENT_DEPTH,
    JsonValue,
    canonicalize,
)
from audit_log_service.configuration import AuditConfiguration
from audit_log_service.errors import ApiError
from audit_log_service.export_bundle import (
    Selection,
    completeness,
    current_head,
    iter_records,
)
from audit_log_service.ledger import AppendService, Clock
from audit_log_service.signing import CheckpointSigner
from audit_log_service.store import SqliteStore
from audit_log_service.timeutil import format_micros, parse_stored_timestamp
from audit_log_service.v1_hashes import HASH_VERSION, genesis_hash

MANIFEST_FORMAT = "audit-export-set-manifest/v1"
CHUNK_FORMAT = "audit-export-chunk/v1"
DESCRIPTOR_FORMAT = "audit-export-set-descriptor/v1"
CHUNK_NAME_PATTERN = r"chunk-[0-9]{6}\.json"
MAX_ACTIVE_JOBS = 16
MAX_CHUNKS = 100_000
CHUNK_OVERHEAD = 512
MAX_JOB_FILE_BYTES = 64 * 1024
_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_CHUNK = re.compile(CHUNK_NAME_PATTERN + r"\Z")
_MANIFEST = "manifest.json"


class SimulatedCrashError(BaseException):
    """Raised by test hooks to model a process dying; never caught by the service."""


def _not_found() -> ApiError:
    return ApiError(404, "NOT_FOUND", "The export set was not found")


def _fsync_directory(path: Path) -> None:
    # Directory fsync is unsupported on Windows; the rename is still atomic there.
    with contextlib.suppress(OSError):
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_durable(path: Path, data: bytes) -> None:
    """Write through a unique temp file, fsync it, then atomically rename."""
    temp = path.with_name(f".{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            temp.unlink()
        raise
    _fsync_directory(path.parent)


class ExportSetService:
    def __init__(
        self,
        store: SqliteStore,
        configuration: AuditConfiguration,
        signer: CheckpointSigner,
        appender: AppendService,
        clock: Clock,
        *,
        synchronous: bool = False,
        after_commit_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._store = store
        self._config = configuration
        self._signer = signer
        self._appender = appender
        self._clock = clock
        self._synchronous = synchronous
        self._hook = after_commit_hook
        root = configuration.export_dir
        self._jobs = root / "jobs"
        self._staging = root / "staging"
        self._ready = root / "ready"
        for directory in (self._jobs, self._staging, self._ready):
            directory.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._active: set[str] = set()
        self._futures: dict[str, Future[None]] = {}
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="export")
        self.recover()

    def close(self) -> None:
        self._executor.shutdown(wait=True)

    def wait(self, export_set_id: str, timeout: float = 60.0) -> None:
        future = self._futures.get(export_set_id)
        if future is not None:
            future.result(timeout)

    def _now(self) -> datetime:
        return self._clock().astimezone(UTC)

    # -- job file persistence ------------------------------------------------

    def _job_path(self, export_set_id: str) -> Path:
        return self._jobs / f"{export_set_id}.json"

    def _save(self, job: dict[str, Any]) -> None:
        data = json.dumps(job, sort_keys=True).encode("utf-8")
        if len(data) > MAX_JOB_FILE_BYTES:
            raise ApiError(500, "EXPORT_IO_FAILURE", "Export job metadata is too large")
        write_durable(self._job_path(str(job["exportSetId"])), data)

    def _load(self, export_set_id: str) -> dict[str, Any] | None:
        if not _ID.fullmatch(export_set_id):
            return None
        path = self._job_path(export_set_id)
        try:
            if path.stat().st_size > MAX_JOB_FILE_BYTES or path.is_symlink():
                return None
            job = json.loads(path.read_bytes())
        except (OSError, ValueError):
            return None
        if not isinstance(job, dict) or job.get("exportSetId") != export_set_id:
            return None
        return job

    # -- public API ----------------------------------------------------------

    def create(self, selection: Selection, requested_by: str) -> dict[str, Any]:
        export_set_id = str(uuid.uuid4())
        with self._lock:
            if len(self._active) >= MAX_ACTIVE_JOBS:
                raise ApiError(
                    429, "EXPORT_SET_BUSY", "Too many export sets are being produced"
                )
            self._active.add(export_set_id)
        job: dict[str, Any] = {
            "exportSetId": export_set_id,
            "status": "RUNNING",
            "requestedBy": requested_by,
            "selection": selection.values,
            "createdAt": format_micros(self._now()),
        }
        try:
            self._save(job)
        except BaseException:
            with self._lock:
                self._active.discard(export_set_id)
            raise
        if self._synchronous:
            self._run(export_set_id, selection, requested_by)
        else:
            self._futures[export_set_id] = self._executor.submit(
                self._run, export_set_id, selection, requested_by
            )
        return self.describe(export_set_id)

    def describe(self, export_set_id: str) -> dict[str, Any]:
        job = self._current(export_set_id)
        descriptor: dict[str, Any] = {
            "format": DESCRIPTOR_FORMAT,
            "exportSetId": export_set_id,
            "status": job["status"],
            "purpose": "EXPORT",
            "requestedBy": job["requestedBy"],
            "selection": Selection(job["selection"]).document(),
            "createdAt": job["createdAt"],
        }
        if job["status"] == "READY":
            base = f"/audit/export-sets/{export_set_id}"
            descriptor.update(
                {
                    "expiresAt": job["expiresAt"],
                    "totalRecords": job["totalRecords"],
                    "chunkCount": job["chunkCount"],
                    "selectionHeadSeq": job["selectionHeadSeq"],
                    "postEventHeadSeq": job["postEventHeadSeq"],
                    "manifestSha256": job["manifestSha256"],
                    "manifestUrl": f"{base}/manifest",
                    "chunkUrlTemplate": f"{base}/chunks/{{name}}",
                    "chunkNamePattern": CHUNK_NAME_PATTERN,
                }
            )
        elif job["status"] == "FAILED":
            descriptor["errorCode"] = job.get("errorCode", "EXPORT_FAILED")
            descriptor["message"] = job.get("message", "The export set failed")
        return descriptor

    def manifest_path(self, export_set_id: str) -> Path:
        self._require_ready(export_set_id)
        return self._safe_file(export_set_id, _MANIFEST)

    def chunk_path(self, export_set_id: str, name: str) -> Path:
        job = self._require_ready(export_set_id)
        match = _CHUNK.fullmatch(name)
        if match is None or int(name[6:12]) >= int(job["chunkCount"]):
            raise ApiError(404, "NOT_FOUND", "The export chunk was not found")
        return self._safe_file(export_set_id, name)

    # -- internals -----------------------------------------------------------

    def _current(self, export_set_id: str) -> dict[str, Any]:
        job = self._load(export_set_id)
        if job is None:
            raise _not_found()
        if job["status"] == "READY" and job["expiresAt"] <= format_micros(self._now()):
            self._expire(job)
            job = self._load(export_set_id) or job
        return job

    def _expire(self, job: dict[str, Any]) -> None:
        shutil.rmtree(self._ready / str(job["exportSetId"]), ignore_errors=True)
        job["status"] = "EXPIRED"
        self._save(job)

    def _require_ready(self, export_set_id: str) -> dict[str, Any]:
        job = self._current(export_set_id)
        status = job["status"]
        if status == "READY":
            return job
        if status == "EXPIRED":
            raise ApiError(410, "EXPORT_SET_EXPIRED", "The export set has expired")
        if status == "FAILED":
            raise ApiError(409, "EXPORT_SET_FAILED", "The export set failed")
        raise ApiError(409, "EXPORT_SET_NOT_READY", "The export set is not ready")

    def _safe_file(self, export_set_id: str, name: str) -> Path:
        directory = (self._ready / export_set_id).resolve()
        path = directory / name
        try:
            real = path.resolve(strict=True)
        except OSError as exc:
            raise ApiError(404, "NOT_FOUND", "The export file was not found") from exc
        if (
            real.parent != directory
            or path.is_symlink()
            or not real.is_file()
            or not str(real).startswith(str(directory))
        ):
            raise ApiError(404, "NOT_FOUND", "The export file was not found")
        return real

    def _run(self, export_set_id: str, selection: Selection, requested_by: str) -> None:
        try:
            self._produce(export_set_id, selection, requested_by)
        except ApiError as exc:
            self._fail(export_set_id, exc.code, exc.message)
        except OSError:
            self._fail(
                export_set_id, "EXPORT_IO_FAILURE", "Export files could not be written"
            )
        except Exception:  # noqa: BLE001 - recorded as a generic failure
            self._fail(export_set_id, "EXPORT_FAILED", "The export set failed")
        finally:
            with self._lock:
                self._active.discard(export_set_id)

    def _fail(self, export_set_id: str, code: str, message: str) -> None:
        shutil.rmtree(self._staging / export_set_id, ignore_errors=True)
        job = self._load(export_set_id)
        if job is None or job["status"] != "RUNNING":
            return
        job.update({"status": "FAILED", "errorCode": code, "message": message})
        with contextlib.suppress(OSError, ApiError):
            self._save(job)

    def _produce(
        self, export_set_id: str, selection: Selection, requested_by: str
    ) -> None:
        stage = self._staging / export_set_id
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        config = self._config
        chunks: list[dict[str, Any]] = []
        pending: list[dict[str, Any]] = []
        pending_bytes = CHUNK_OVERHEAD
        total = 0

        def flush() -> None:
            nonlocal pending, pending_bytes
            if not pending:
                return
            if len(chunks) >= MAX_CHUNKS:
                raise ApiError(422, "EXPORT_TOO_MANY_CHUNKS", "Too many chunks")
            index = len(chunks)
            name = f"chunk-{index:06d}.json"
            data = canonicalize(
                cast(
                    Any,
                    {
                        "format": CHUNK_FORMAT,
                        "exportSetId": export_set_id,
                        "index": index,
                        "records": pending,
                    },
                ),
                max_depth=MAX_DOCUMENT_DEPTH,
            )
            write_durable(stage / name, data)
            chunks.append(
                {
                    "index": index,
                    "name": name,
                    "recordCount": len(pending),
                    "firstSeq": pending[0]["seq"],
                    "lastSeq": pending[-1]["seq"],
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            pending = []
            pending_bytes = CHUNK_OVERHEAD

        with self._store.read_snapshot() as snapshot:
            through_seq, head_chain = current_head(snapshot, config.ledger_id)
            for record in iter_records(snapshot, selection, through_seq):
                size = len(canonicalize(record, max_depth=MAX_DOCUMENT_DEPTH)) + 1
                if size + CHUNK_OVERHEAD > config.export_chunk_max_bytes:
                    raise ApiError(
                        422,
                        "EXPORT_RECORD_TOO_LARGE",
                        "A record exceeds the chunk limit",
                    )
                if total + 1 > config.export_set_max_records:
                    raise ApiError(
                        422,
                        "EXPORT_SET_TOO_LARGE",
                        "The selection exceeds the set limit",
                    )
                if pending and (
                    len(pending) >= config.export_chunk_max_records
                    or pending_bytes + size > config.export_chunk_max_bytes
                ):
                    flush()
                pending.append(record)
                pending_bytes += size
                total += 1
            flush()

        chunks_digest = hashlib.sha256(
            canonicalize(cast(Any, chunks), max_depth=MAX_DOCUMENT_DEPTH)
        ).hexdigest()
        with self._store.write_transaction() as connection:
            event = self._appender.append_system_event(
                connection,
                "BUNDLE_EXPORTED",
                requested_by,
                "AUDIT_EXPORT",
                export_set_id,
                {
                    "exportSetId": export_set_id,
                    "purpose": "EXPORT",
                    "throughSeq": through_seq,
                    "totalRecords": total,
                    "chunkCount": len(chunks),
                    "chunksDigest": chunks_digest,
                    "selectionDigest": selection.digest(),
                    "requestedBy": requested_by,
                },
            )
            checkpoint = self._appender.store_checkpoint(
                connection, event["seq"], event["chainHash"], event["timestamp"]
            )
            created = parse_stored_timestamp(event["timestamp"])
            manifest: dict[str, JsonValue] = {
                "format": MANIFEST_FORMAT,
                "exportSetId": export_set_id,
                "purpose": "EXPORT",
                "ledgerId": config.ledger_id,
                "hashAlgorithm": "SHA-256",
                "hashVersion": HASH_VERSION,
                "genesisHash": genesis_hash(config.ledger_id),
                "signatureAlgorithm": "Ed25519",
                "createdAt": event["timestamp"],
                "expiresAt": format_micros(
                    created + timedelta(seconds=config.export_set_ttl_seconds)
                ),
                "exportedBy": requested_by,
                "selection": selection.document(),
                "completeness": completeness(through_seq),
                "selectionHead": {"seq": through_seq, "chainHash": head_chain},
                "headCheckpoint": checkpoint,
                "totalRecords": total,
                "chunkCount": len(chunks),
                "chunkLimits": {
                    "maxRecords": config.export_chunk_max_records,
                    "maxBytes": config.export_chunk_max_bytes,
                },
                "chunks": cast(Any, chunks),
                "chunksDigest": chunks_digest,
                "exclusions": {
                    "archivedRecords": "EXCLUDED",
                    "nonMatchingRecords": "EXCLUDED",
                    "recordsAfterSelectionHead": "EXCLUDED",
                    "upstreamCoverage": "NOT_PROVEN",
                },
                "signer": {
                    "keyId": self._signer.key_id,
                    "publicKey": self._signer.public_key_base64,
                },
            }
            manifest["signature"] = self._signer.sign_message(
                manifest, MAX_DOCUMENT_DEPTH
            )
            write_durable(
                stage / _MANIFEST, canonicalize(manifest, max_depth=MAX_DOCUMENT_DEPTH)
            )
        if self._hook is not None:
            self._hook(export_set_id)
        self._publish(export_set_id)

    def _publish(self, export_set_id: str) -> None:
        stage = self._staging / export_set_id
        _fsync_directory(stage)
        target = self._ready / export_set_id
        os.replace(stage, target)
        _fsync_directory(self._ready)
        self._mark_ready(export_set_id)

    def _mark_ready(self, export_set_id: str) -> None:
        manifest_bytes = (self._ready / export_set_id / _MANIFEST).read_bytes()
        manifest = json.loads(manifest_bytes)
        job = self._load(export_set_id)
        if job is None:
            return
        job.update(
            {
                "status": "READY",
                "expiresAt": manifest["expiresAt"],
                "totalRecords": manifest["totalRecords"],
                "chunkCount": manifest["chunkCount"],
                "selectionHeadSeq": manifest["selectionHead"]["seq"],
                "postEventHeadSeq": manifest["headCheckpoint"]["seq"],
                "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
            }
        )
        self._save(job)

    # -- recovery ------------------------------------------------------------

    def recover(self) -> None:
        """Repeatable restart recovery; never deletes a tree a live job references."""
        for temp in self._jobs.glob(".*.tmp"):
            with contextlib.suppress(OSError):
                temp.unlink()
        live: set[str] = set()
        for path in sorted(self._jobs.glob("*.json")):
            export_set_id = path.stem
            job = self._load(export_set_id)
            if job is None:
                continue
            live.add(export_set_id)
            if job["status"] == "RUNNING":
                self._recover_running(export_set_id)
            elif job["status"] == "READY":
                self._current(export_set_id)
        for root in (self._staging, self._ready):
            for child in root.iterdir():
                job = self._load(child.name)
                keep = job is not None and (
                    (root == self._ready and job["status"] == "READY")
                    or (root == self._staging and job["status"] == "RUNNING")
                )
                if not keep:
                    shutil.rmtree(child, ignore_errors=True)

    def _recover_running(self, export_set_id: str) -> None:
        if (self._ready / export_set_id / _MANIFEST).is_file():
            self._mark_ready(export_set_id)
            return
        if self._staged_export_is_proven(export_set_id):
            self._publish(export_set_id)
            return
        self._fail(export_set_id, "EXPORT_INTERRUPTED", "The export was interrupted")

    def _staged_export_is_proven(self, export_set_id: str) -> bool:
        stage = self._staging / export_set_id
        try:
            manifest = json.loads((stage / _MANIFEST).read_bytes())
            if manifest["exportSetId"] != export_set_id:
                return False
            for chunk in manifest["chunks"]:
                name = str(chunk["name"])
                if not _CHUNK.fullmatch(name):
                    return False
                data = (stage / name).read_bytes()
                if (
                    len(data) != chunk["bytes"]
                    or hashlib.sha256(data).hexdigest() != chunk["sha256"]
                ):
                    return False
            checkpoint = manifest["headCheckpoint"]
            with self._store.read_snapshot() as connection:
                row = connection.execute(
                    "SELECT 1 FROM checkpoints c JOIN audit_events e ON e.seq = c.seq "
                    "WHERE c.seq = ? AND c.chain_hash = ? AND e.chain_hash = ? "
                    "AND e.event_type = 'BUNDLE_EXPORTED' AND e.resource_id = ?",
                    (
                        checkpoint["seq"],
                        checkpoint["chainHash"],
                        checkpoint["chainHash"],
                        export_set_id,
                    ),
                ).fetchone()
            return row is not None
        except (OSError, ValueError, KeyError, TypeError):
            return False
