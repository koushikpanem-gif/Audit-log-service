package com.auditlog.verify;

/** Typed verification diagnostics; declaration order is the deterministic tie-break order. */
public enum ViolationType {
    SEQUENCE_GAP,
    GENESIS_MISMATCH,
    CHAIN_LINK_BROKEN,
    CONTENT_HASH_MISMATCH,
    CHAIN_HASH_MISMATCH,
    MALFORMED_RECORD,
    PAYLOAD_VALUE_MISMATCH,
    UNAUTHORIZED_REDACTION,
    UNAUTHORIZED_ARCHIVE,
    RETENTION_POLICY_VIOLATION,
    CHECKPOINT_SIGNATURE_INVALID,
    CHECKPOINT_MISMATCH,
    TRUNCATION_DETECTED
}
