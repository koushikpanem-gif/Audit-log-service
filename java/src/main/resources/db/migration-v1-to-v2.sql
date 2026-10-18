-- Explicit migration from schema version 1 to 2 (Action 12: durable redaction cleanup jobs).
-- Applied inside one BEGIN IMMEDIATE transaction by JdbcAuditRepository. Existing ledger data
-- is not touched; ledger_meta is rebuilt only because its CHECK pins the schema version.

CREATE TABLE redaction_cleanup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    redaction_seq INTEGER NOT NULL UNIQUE REFERENCES audit_events(seq) ON DELETE RESTRICT,
    target_seq INTEGER NOT NULL REFERENCES audit_events(seq) ON DELETE RESTRICT,
    leaf_count INTEGER NOT NULL CHECK (leaf_count > 0),
    status TEXT NOT NULL CHECK (status IN ('PENDING', 'COMPLETE')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at TEXT NOT NULL,
    last_attempt_at TEXT,
    completed_at TEXT,
    last_outcome TEXT CHECK (last_outcome IN ('BUSY', 'INCOMPLETE', 'ERROR', 'OK')),
    CHECK ((status = 'COMPLETE') = (completed_at IS NOT NULL))
);

CREATE INDEX idx_redaction_cleanup_status ON redaction_cleanup(status, id);

CREATE TRIGGER redaction_cleanup_block_delete
BEFORE DELETE ON redaction_cleanup
BEGIN
    SELECT RAISE(ABORT, 'redaction_cleanup rows cannot be deleted');
END;

CREATE TRIGGER redaction_cleanup_guard_update
BEFORE UPDATE ON redaction_cleanup
WHEN NOT (
    OLD.status = 'PENDING'
    AND NEW.status IN ('PENDING', 'COMPLETE')
    AND NEW.id IS OLD.id
    AND NEW.redaction_seq IS OLD.redaction_seq
    AND NEW.target_seq IS OLD.target_seq
    AND NEW.leaf_count IS OLD.leaf_count
    AND NEW.created_at IS OLD.created_at
)
BEGIN
    SELECT RAISE(ABORT, 'redaction_cleanup identity is immutable and COMPLETE is final');
END;

CREATE TABLE ledger_meta_v2 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ledger_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 2)
);

INSERT INTO ledger_meta_v2(singleton, ledger_id, schema_version)
SELECT singleton, ledger_id, 2 FROM ledger_meta;

DROP TABLE ledger_meta;

ALTER TABLE ledger_meta_v2 RENAME TO ledger_meta;
