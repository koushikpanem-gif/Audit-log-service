# Python service: append, query and checkpoints (Action 17)

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

Not built (Action 19 onward). They authenticate and check roles, then return **501 NOT_IMPLEMENTED**. They never fabricate success:
`POST /audit/admin/redactions`, `POST /audit/admin/archive`, `GET /compliance/account-access-report`.

## Verification and exports (Action 18)

- `GET /audit/verify` is a port of the Java verifier: ordered batches of 1000 in one snapshot, all 13 violation types, at most 100 diagnostics with exact `totalViolationCount`, fail-closed on malformed rows. Authorization events are indexed in a scratch SQLite database, not in memory. Redaction/archive authorization is evaluated, but those write APIs are not built yet.
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
