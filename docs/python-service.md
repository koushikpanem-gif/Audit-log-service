# Python service: append, query, checkpoints, exports, redaction and archive (Actions 17-19)

Implemented in `python/src/audit_log_service/` independently of Java. Hashing uses the Python JCS/hash/signing modules from earlier actions. No Java is invoked.

## Run

```
cd python
.venv\Scripts\python -m audit_log_service      # Windows
.venv/bin/python -m audit_log_service          # Unix
```

`create_app(configuration=None, *, clock=...)` is a factory, so importing the module creates no files. Environment variables are the same as in `configuration-and-signing.md`, plus `AUDIT_DB_PATH` (default `audit-data/audit.db`).

## Built routes

| Route | Roles |
|---|---|
| `GET /health`, `GET /audit/public-key`, `/openapi.json`, `/docs` | public |
| `POST /audit/events` | writer, admin |
| `GET /audit/events`, `GET /audit/events/{eventId}` | reader, auditor, admin |
| `GET /audit/checkpoints` | auditor, admin |
| `POST /audit/admin/checkpoints` | admin (409 on empty ledger) |
| `GET /audit/verify` | auditor, admin |
| `GET /audit/export?actorId=&resourceId=&...` | auditor, admin |
| `POST /audit/export-sets` (202 + Location) | auditor, admin |
| `GET /audit/export-sets/{id}`, `.../manifest`, `.../chunks/{name}` | auditor, admin |

Not built (Action 20 onward). It authenticates and checks the role, then returns **501 NOT_IMPLEMENTED** and never fabricates success:
`GET /compliance/account-access-report`.

## Redaction, retention and recovery (Action 19)

| Route | Roles |
|---|---|
| `POST /audit/admin/redactions` (201 + Location) | admin |
| `GET /audit/admin/redaction-cleanups`, `POST .../retry` | admin |
| `POST /audit/admin/archive` (`{"dryRun": bool}`), `GET /audit/admin/archive-jobs`, `POST .../archive-jobs/reconcile` | admin |
| `GET /audit/archive-audit` | auditor, admin |

- **Redaction** appends `RECORD_REDACTED`, deletes the leaf values and salts, and enqueues a durable cleanup job in ONE write transaction. After commit it runs `PRAGMA wal_checkpoint(TRUNCATE)` and inspects the result tuple (busy is returned, not raised). The response carries `cleanupStatus` COMPLETE or PENDING. PENDING never means the deletion rolled back. Cleanup makes at most `AUDIT_CLEANUP_MAX_ATTEMPTS` (3) attempts of `AUDIT_CLEANUP_BUSY_TIMEOUT_MS` (1000) each. Status, retry and start-up recovery finish pending jobs. 409 for no-op, archived or system targets; 422 for bad or unknown pointers or free text that repeats a redacted value.
- **Archive** takes the oldest live contiguous prefix with `recordedAt < now - ceil(retentionDays)`, bounded by `AUDIT_ARCHIVE_MAX_RECORDS` (1000) and `AUDIT_ARCHIVE_MAX_BYTES` (8 MiB). `dryRun` mutates nothing and writes no file. A real run records a PREPARING job, then in one write transaction: signs a `RETENTION_ARCHIVE` bundle, writes and fsyncs a temp file, atomically renames it, and only then clears live columns and leaves and appends `RECORDS_ARCHIVED`. If publication fails the transaction rolls back, plaintext stays live, the job is FAILED (500 `ARCHIVE_PUBLICATION_FAILED`) and its files are removed. A crash leaves a PREPARING job that blocks new archives (409 `ARCHIVE_JOB_INTERRUPTED`) until start-up or `reconcile` marks it FAILED and removes its files.
- Files are deleted only when their name matches the service pattern and equals the job's name, no COMMITTED job and no live `RECORDS_ARCHIVED` event references them. Files with no job row are only reported (`orphanFiles`), never deleted.
- **Archive audit** checks every committed archive: name, regular file, digest, pinned-key bundle verification, metadata, and skeleton hashes. A missing file is `ARCHIVE_FILE_MISSING`, distinct from a chain break. It does not verify the chain.
- Env vars: `AUDIT_ARCHIVE_DIR` (default `<db dir>/archives`), `AUDIT_ARCHIVE_MAX_RECORDS`, `AUDIT_ARCHIVE_MAX_BYTES`, `AUDIT_CLEANUP_MAX_ATTEMPTS`, `AUDIT_CLEANUP_BUSY_TIMEOUT_MS`.
- **Platform limits.** Directory fsync is unsupported on Windows, so `directorySynced` is false there; the rename is atomic but its durability depends on the filesystem. Redaction and archiving give no physical-erasure guarantee for storage devices, backups, earlier exports or archive copies. Archived records leave normal query, export and report results.

## Verification and exports (Action 18)

- `GET /audit/verify` is a port of the Java verifier: ordered batches of 1000 in one snapshot, all 13 violation types, at most 100 diagnostics with exact `totalViolationCount`, fail-closed on malformed rows. Authorization events are indexed in a scratch SQLite database, not in memory. Redaction/archive authorization is evaluated, and the write APIs are built in Action 19.
- `GET /audit/export` returns one signed `audit-export-bundle/v1`. It needs `actorId` or `resourceId`, and appends a `BUNDLE_EXPORTED` event plus checkpoint in the same write transaction. Over `AUDIT_EXPORT_MAX_RECORDS` / `AUDIT_EXPORT_MAX_BYTES` it returns 422 `EXPORT_LIMIT_EXCEEDED` and never truncates. A malformed stored row returns 500 `EXPORT_DATA_INVALID` and rolls back.
- `POST /audit/export-sets` (same selection rules) freezes one snapshot head and writes immutable `chunk-NNNNNN.json` files plus a signed manifest under `AUDIT_EXPORT_DIR`. The job is READY only after atomic publication. Restart recovery re-derives job state from job files, staged manifests and the ledger. At most 16 active jobs (429 `EXPORT_SET_BUSY`). Downloads use fixed chunk names only, so there is no path traversal. Expired sets are removed lazily.
- The manifest `selectionHead` is the head used for selection. `headCheckpoint` is the later post-`BUNDLE_EXPORTED` checkpoint.
- Extra env vars: `AUDIT_EXPORT_MAX_RECORDS` (1000), `AUDIT_EXPORT_MAX_BYTES` (8 MiB), `AUDIT_EXPORT_CHUNK_MAX_RECORDS`, `AUDIT_EXPORT_CHUNK_MAX_BYTES`, `AUDIT_EXPORT_SET_MAX_RECORDS` (1,000,000), `AUDIT_EXPORT_SET_TTL_SECONDS` (60..2,592,000), `AUDIT_EXPORT_DIR`.
- Archived records are excluded from exports, as are records appended after the snapshot.

## Storage

`store.py` applies the same `schema-v1.sql` and the v1→v2→v3 migrations as Java. The SQL files are copied verbatim into `sql/`. PRAGMAs: WAL, `synchronous=FULL`, `foreign_keys=ON`, `secure_delete=ON`, `busy_timeout=30000`. Mutations use `BEGIN IMMEDIATE` with rollback on error. Reads use a snapshot transaction with `query_only`. Busy and locked errors map to 503. Constraint and trigger failures map to 409.

## Limits and disclosures

- The query cursor is bound to the filters, the order and the snapshot head. Archive or redaction can change visibility across pages.
- `/docs` is a plain HTML route table, not Swagger UI.
- The Java controller has no `POST /audit/admin/checkpoints` even though the requirements list it. Python implements it. This is a Java gap to fix in a later action.
- Not yet run for Python: bandit and pip-audit.
