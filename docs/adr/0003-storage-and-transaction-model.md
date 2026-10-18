# ADR-0003: SQLite storage and transaction model

- **Status:** Accepted as a supplied design constraint; validation is pending.
- **Context:** The chain head and event insertion must be serialized, and
  ordinary application writes should not accidentally mutate immutable rows.
- **Decision:** One ledger per SQLite database. Bind its ID and schema version
  in `ledger_meta`; use explicit migrations and the prescribed event,
  commitment-leaf, checkpoint, cleanup-job and archive-job records/indexes.
  Configure WAL, `synchronous=FULL`, foreign keys, `secure_delete`, and
  `busy_timeout=30000` on every connection. Mutations use `BEGIN IMMEDIATE`
  before reading the head and roll back on failure; multi-read verification and
  export use a consistent snapshot. Guard accidental updates/deletes with the
  specified triggers.
- **Initial schema:** Version 1 is the DDL in
  [`schema-v1.sql`](../../java/src/main/resources/db/schema-v1.sql). The JDBC
  adapter applies it atomically on a new database, records both SQLite
  `user_version` and `ledger_meta.schema_version`, and refuses unversioned,
  unknown-version, or differently bound databases. Later versions must add
  explicit migrations; existing rows are never reset to install a schema.
- **Transaction port:** `AuditRepository.writeTransaction` starts
  `BEGIN IMMEDIATE`; `readSnapshot` starts a read transaction on a connection
  configured `query_only=ON`. Both commit only after the callback succeeds and
  explicitly roll back on callback or commit failure. Each operation owns and
  closes its connection. WAL is enabled at initialization and checked for each
  subsequent connection; connection-local durability, foreign-key, secure
  delete, and busy-timeout pragmas are applied on every open.
- **Schema v1:** Tables cover `ledger_meta`, `audit_events`, `payload_leaves`
  and `checkpoints`, with the specified query indexes and immutable-row
  triggers. Audit-event updates permit only an `archived=0` to `archived=1`
  transition preserving sequence, event ID, recorded time, hash version and
  hashes; table checks require archived business fields to be cleared. Cleanup
  and archive-job tables are deferred until those actions define their use.
- **Consequences:** Triggers do not protect against a database administrator.
  Row-level trigger tests must insert matching rows first. Busy conditions map
  to explicit 503 responses. Schema changes require versioned migrations.
