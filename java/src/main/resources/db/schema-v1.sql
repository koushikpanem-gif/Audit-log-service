CREATE TABLE ledger_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ledger_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1)
);

CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY CHECK (seq > 0),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT,
    actor_id TEXT,
    resource_type TEXT,
    resource_id TEXT,
    occurred_at TEXT,
    recorded_at TEXT NOT NULL,
    source TEXT,
    payload_commitments TEXT,
    hash_version INTEGER NOT NULL CHECK (hash_version > 0),
    content_hash TEXT NOT NULL CHECK (
        length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    prev_hash TEXT NOT NULL CHECK (
        length(prev_hash) = 64 AND prev_hash NOT GLOB '*[^0-9a-f]*'
    ),
    chain_hash TEXT NOT NULL CHECK (
        length(chain_hash) = 64 AND chain_hash NOT GLOB '*[^0-9a-f]*'
    ),
    archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1)),
    archived_at TEXT,
    CHECK (
        (archived = 0 AND archived_at IS NULL
            AND event_type IS NOT NULL AND actor_id IS NOT NULL
            AND resource_type IS NOT NULL AND resource_id IS NOT NULL
            AND source IS NOT NULL AND payload_commitments IS NOT NULL
            AND json_valid(payload_commitments)
            AND json_type(payload_commitments) = 'object')
        OR
        (archived = 1 AND archived_at IS NOT NULL
            AND event_type IS NULL AND actor_id IS NULL
            AND resource_type IS NULL AND resource_id IS NULL
            AND occurred_at IS NULL AND source IS NULL
            AND payload_commitments IS NULL)
    )
);

CREATE TABLE payload_leaves (
    seq INTEGER NOT NULL REFERENCES audit_events(seq) ON DELETE RESTRICT,
    pointer TEXT NOT NULL,
    salt TEXT NOT NULL CHECK (
        length(salt) = 64 AND salt NOT GLOB '*[^0-9a-f]*'
    ),
    value TEXT NOT NULL CHECK (
        json_valid(value)
        AND json_type(value) IN ('null', 'true', 'false', 'integer', 'real', 'text')
    ),
    PRIMARY KEY (seq, pointer)
);

CREATE TABLE checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seq INTEGER NOT NULL REFERENCES audit_events(seq) ON DELETE RESTRICT,
    chain_hash TEXT NOT NULL CHECK (
        length(chain_hash) = 64 AND chain_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL,
    key_id TEXT NOT NULL CHECK (
        length(key_id) = 16 AND key_id NOT GLOB '*[^0-9a-f]*'
    ),
    signature TEXT NOT NULL
);

CREATE INDEX idx_audit_events_actor_seq ON audit_events(actor_id, seq);
CREATE INDEX idx_audit_events_resource_seq ON audit_events(resource_type, resource_id, seq);
CREATE INDEX idx_audit_events_type_seq ON audit_events(event_type, seq);
CREATE INDEX idx_audit_events_recorded_seq ON audit_events(recorded_at, seq);

CREATE TRIGGER audit_events_block_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events cannot be deleted');
END;

CREATE TRIGGER audit_events_archive_only_update
BEFORE UPDATE ON audit_events
WHEN NOT (
    OLD.archived = 0
    AND NEW.archived = 1
    AND NEW.seq IS OLD.seq
    AND NEW.event_id IS OLD.event_id
    AND NEW.recorded_at IS OLD.recorded_at
    AND NEW.hash_version IS OLD.hash_version
    AND NEW.content_hash IS OLD.content_hash
    AND NEW.prev_hash IS OLD.prev_hash
    AND NEW.chain_hash IS OLD.chain_hash
)
BEGIN
    SELECT RAISE(ABORT, 'audit_events are immutable except for archive transition');
END;

CREATE TRIGGER payload_leaves_block_update
BEFORE UPDATE ON payload_leaves
BEGIN
    SELECT RAISE(ABORT, 'payload_leaves cannot be updated');
END;

CREATE TRIGGER checkpoints_block_update
BEFORE UPDATE ON checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoints cannot be updated');
END;

CREATE TRIGGER checkpoints_block_delete
BEFORE DELETE ON checkpoints
BEGIN
    SELECT RAISE(ABORT, 'checkpoints cannot be deleted');
END;
