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

Not built (Action 18 onward). They authenticate and check roles, then return **501 NOT_IMPLEMENTED**. They never fabricate success:
`GET /audit/verify`, `GET /audit/export`, `POST /audit/admin/redactions`, `POST /audit/admin/archive`, `GET /compliance/account-access-report`.

## Storage

`store.py` applies the same `schema-v1.sql` and the v1→v2→v3 migrations as Java. The SQL files are copied verbatim into `sql/`. PRAGMAs: WAL, `synchronous=FULL`, `foreign_keys=ON`, `secure_delete=ON`, `busy_timeout=30000`. Mutations use `BEGIN IMMEDIATE` with rollback on error. Reads use a snapshot transaction with `query_only`. Busy and locked errors map to 503. Constraint and trigger failures map to 409.

## Limits and disclosures

- The query cursor is bound to the filters, the order and the snapshot head. Archive or redaction can change visibility across pages.
- `/docs` is a plain HTML route table, not Swagger UI.
- The Java controller has no `POST /audit/admin/checkpoints` even though the requirements list it. Python implements it. This is a Java gap to fix in a later action.
- Not yet run for Python: bandit and pip-audit.
