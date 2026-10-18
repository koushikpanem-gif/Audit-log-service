-- Explicit migration from schema version 2 to 3 (Action 13: durable retention archive jobs).
-- Applied inside one BEGIN IMMEDIATE transaction by JdbcAuditRepository. Existing ledger data
-- is not touched; ledger_meta is rebuilt only because its CHECK pins the schema version.
--
-- archive_jobs is operational metadata. The authoritative authorization is the validated
-- RECORDS_ARCHIVED ledger event; this table lets recovery prove which files belong to the service.

CREATE TABLE archive_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('PREPARING', 'COMMITTED', 'FAILED')),
    temp_name TEXT NOT NULL,
    final_name TEXT NOT NULL UNIQUE,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    from_seq INTEGER,
    to_seq INTEGER,
    record_count INTEGER,
    cutoff TEXT,
    retention_days INTEGER,
    archive_sha256 TEXT,
    archive_bytes INTEGER,
    directory_synced INTEGER CHECK (directory_synced IN (0, 1)),
    archive_event_seq INTEGER REFERENCES audit_events(seq) ON DELETE RESTRICT,
    failure_code TEXT,
    cleanup_state TEXT NOT NULL DEFAULT 'NONE'
        CHECK (cleanup_state IN ('NONE', 'PENDING', 'DONE', 'BLOCKED')),
    cleanup_detail TEXT,
    CHECK ((status = 'COMMITTED') = (archive_event_seq IS NOT NULL)),
    CHECK ((status = 'FAILED') = (failure_code IS NOT NULL)),
    CHECK (status <> 'COMMITTED' OR (
        from_seq IS NOT NULL AND to_seq IS NOT NULL AND record_count IS NOT NULL
        AND cutoff IS NOT NULL AND retention_days IS NOT NULL
        AND archive_sha256 IS NOT NULL AND archive_bytes IS NOT NULL
        AND directory_synced IS NOT NULL))
);

CREATE INDEX idx_archive_jobs_status ON archive_jobs(status, id);

CREATE TRIGGER archive_jobs_block_delete
BEFORE DELETE ON archive_jobs
BEGIN
    SELECT RAISE(ABORT, 'archive_jobs rows cannot be deleted');
END;

CREATE TRIGGER archive_jobs_guard_update
BEFORE UPDATE ON archive_jobs
WHEN NOT (
    NEW.id IS OLD.id
    AND NEW.bundle_id IS OLD.bundle_id
    AND NEW.temp_name IS OLD.temp_name
    AND NEW.final_name IS OLD.final_name
    AND NEW.requested_by IS OLD.requested_by
    AND NEW.created_at IS OLD.created_at
    AND (
        OLD.status = 'PREPARING'
        OR (OLD.status = 'FAILED'
            AND NEW.status = 'FAILED'
            AND NEW.failure_code IS OLD.failure_code
            AND OLD.cleanup_state IN ('PENDING', 'BLOCKED')
            AND NEW.cleanup_state IN ('PENDING', 'DONE', 'BLOCKED'))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'archive_jobs identity is immutable and COMMITTED is final');
END;

CREATE TABLE ledger_meta_v3 (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ledger_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 3)
);

INSERT INTO ledger_meta_v3(singleton, ledger_id, schema_version)
SELECT singleton, ledger_id, 3 FROM ledger_meta;

DROP TABLE ledger_meta;

ALTER TABLE ledger_meta_v3 RENAME TO ledger_meta;
