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
- **Consequences:** Triggers do not protect against a database administrator.
  Row-level trigger tests must insert matching rows first. Busy conditions map
  to explicit 503 responses. Schema changes require versioned migrations.
