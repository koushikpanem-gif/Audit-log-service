# Durable retention archives (Action 13)

## Flow
`POST /audit/admin/archive {"dryRun":bool}` (admin) archives the oldest live contiguous prefix whose
`recordedAt` is strictly before `cutoff = now - ceil(retentionDays)` days (minimum 1 day; ceil because the
`RECORDS_ARCHIVED` event stores an integer). The batch is bounded by `AUDIT_ARCHIVE_MAX_RECORDS`
(default 1000) and `AUDIT_ARCHIVE_MAX_BYTES` (default 8 MiB, min 65536).

`dryRun=true` writes nothing (no file, no job). A real run:
1. Inserts an `archive_jobs` row (`PREPARING`) in its own transaction.
2. In one write transaction: store a checkpoint at `toSeq`; build and sign a `RETENTION_ARCHIVE`
   `audit-export-bundle/v1`; write it to `.archive-<uuid>.tmp` (CREATE_NEW), `force(true)`;
   atomically move to `archive-<uuid>.json`; best-effort directory fsync; **only then** set
   `archived=1`, NULL business columns/commitments, delete leaves, append `RECORDS_ARCHIVED`, mark the job
   `COMMITTED`, commit.
3. After commit, a best-effort `wal_checkpoint(TRUNCATE)` is reported (COMPLETE/BUSY/ERROR).

Hashes, seq, eventId, recordedAt and hashVersion of archived rows are unchanged.

## Job states and recovery
| Crash/failure point | Result | Recovery |
|---|---|---|
| after job row | live data intact, job PREPARING | `reconcile` -> FAILED/INTERRUPTED, files cleaned |
| after temp forced / after publish / before commit | live plaintext intact (transaction rolled back), file may exist | same; file deleted only if name matches strict pattern, equals the job's own name, and nothing references it |
| orderly exception (`RuntimeException`/`SQLException`) | job FAILED, cleanup attempted (PENDING/DONE/BLOCKED) | retry via reconcile |
| after commit | job COMMITTED, archive event live | none needed |

A PREPARING job blocks new archives (409 `ARCHIVE_JOB_INTERRUPTED`) until reconciled; reconcile runs at
startup and via `POST /audit/admin/archive-jobs/reconcile`. Pattern-matching files without a job row are
reported as orphans and never deleted. `GET /audit/admin/archive-jobs` shows status.

## Audit
`GET /audit/archive-audit` (auditor) and the offline CLI check every committed archive (job table plus live
archive events, cumulative, including archive events that were themselves archived): safe name (a symlink or
directory in place of the file is `FILE_NAME_UNSAFE`), bounded read (at most `archiveMaxBytes`), size,
SHA-256, signed bundle with the **pinned** key, bundle ledger id / signer key id / head checkpoint seq,
metadata, the authorizing `RECORDS_ARCHIVED` event (must follow the range and exist; live ones must validate),
and each record against the skeleton (eventId, timestamp, hashVersion, three hashes, `archived=1`).
A global coverage check requires the archive ranges to be contiguous from seq 1 and to cover exactly the
rows marked archived, so an archived row with no evidence fails the audit. A missing or unreadable file is
reported as `ARCHIVE_FILE_MISSING` / `ARCHIVE_FILE_UNREADABLE` (counted in `unavailableArchiveCount`),
distinct from chain violations; `/audit/verify` does not read archive files.

### CLI
```
java -cp target\classes;<deps> com.auditlog.service.ArchiveAuditCli --db ledger.db --ledger-id ID
     --archive-dir DIR (--pinned-key-file key.b64 | --pinned-key BASE64) [--max-bytes N] [--max-records N]
```
Prints the JSON report. Exit 0 intact, 1 archive evidence failed, 2 input/usage error. A pinned key is
mandatory (no self-asserted mode). The CLI opens the DB through the normal repository, which checks the ledger
binding and schema version and migrates an older schema; use a copy if that is unwanted. The CLI never deletes
or writes archive files.

## Limits and assumptions
- Archive files are plaintext copies: redaction does not reach them, and normal query/export exclude
  archived records.
- Directory fsync is unavailable on Windows (recorded as `directory_synced=0`); atomic rename and
  durability depend on the filesystem (network/FAT/some containers weaker).
- Single-process assumption: an in-process lock serialises archive runs; multi-process is untested.
- Cleanup of the WAL after archive is best effort, not a durable job.
- Schema v3 adds `archive_jobs` (migrated from v1/v2).
