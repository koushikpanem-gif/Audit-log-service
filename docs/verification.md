# Full-chain verification (Java)

`GET /audit/verify` (auditor or admin role) scans the whole ledger inside one
read snapshot and returns a typed report. Implementation:
`com.auditlog.verify.LedgerVerifier`.

## Report

`intact, ledgerId, hashAlgorithm ("SHA-256"), checkedRecords, archivedRecords,
redactedFields, headSeq, headHash, checkpointsVerified, firstViolation,
violations, totalViolationCount, violationsTruncated, verifiedAt, durationMs`.
An empty valid ledger is intact at `headSeq` 0 with the genesis hash as
`headHash`. A violation is `{type, seq, pointer, message}`; messages never
contain stored business values. At most 100 earliest diagnostics are retained,
ordered by `(seq, type in the order below, pointer, message, discovery)`;
`totalViolationCount` is exact and the scan continues after truncation.

## Diagnostics

| Type | Raised when |
| --- | --- |
| `SEQUENCE_GAP` | a row's `seq` is not the predecessor + 1 (one per gap) |
| `GENESIS_MISMATCH` | seq 1 does not link to `genesis(ledgerId)` |
| `CHAIN_LINK_BROKEN` | a stored `prev_hash` differs from the predecessor's stored `chain_hash`; reported on the row after an edit, which localizes the edited record |
| `CONTENT_HASH_MISMATCH` | recomputed content hash differs from stored |
| `CHAIN_HASH_MISMATCH` | `chain(prev_hash, content_hash)` differs from stored `chain_hash` |
| `MALFORMED_RECORD` | any malformed stored value: archived flag, hash format, unknown `hash_version`, timestamps, text fields, commitment tree, leaf salt/value/pointer, extra or orphan leaves, source/type misuse, bad ledger metadata, malformed checkpoint rows, or an invalid authorization event |
| `PAYLOAD_VALUE_MISMATCH` | a stored leaf does not hash to its commitment |
| `UNAUTHORIZED_REDACTION` | a leaf is missing without a validated redaction authorization |
| `UNAUTHORIZED_ARCHIVE` | an archived skeleton has no validated archive authorization |
| `RETENTION_POLICY_VIOLATION` | a validated archive event's cutoff is later than its recording time minus its declared retention, or does not exceed the last archived record's time |
| `CHECKPOINT_SIGNATURE_INVALID` | signature/key ID does not verify under the pinned public key and ledger |
| `CHECKPOINT_MISMATCH` | a validly signed checkpoint's hash differs from the stored chain hash, or its seq is absent below the head |
| `TRUNCATION_DETECTED` | a validly signed checkpoint covers a seq beyond the ledger head |

Unknown versions, malformed values and unexpected per-record exceptions all
become `MALFORMED_RECORD`; the endpoint never returns 500 for bad stored data.
Records with an unusable hash version skip recomputation rather than guess.

## Fail-closed authorization

Missing leaves and archived skeletons are authorized only by *validated*
service events (`source = "system"`, reserved type):

- The authorization event itself must pass content, leaf, schema and source
  checks and have no missing leaves.
- `RECORD_REDACTED` payload keys are exactly `targetSeq, targetEventId, paths,
  reason, ticketId, requestedBy`; `targetSeq` must precede the event, match the
  stored `event_id`, and each path must be an RFC 6901 pointer. It grants those
  exact `(seq, pointer)` leaves only. System records can never be redacted.
- `RECORDS_ARCHIVED` payload keys are exactly the build-requirement names;
  `archivedThroughSeq == toSeq`, `count == to - from + 1`, `toSeq` precedes the
  event, `lastArchivedChainHash` equals the stored chain hash at `toSeq`, and
  `retentionDays` is a bounded integer. Coverage is cumulative: a skeleton at
  `S` is authorized by any validated event after `S` with `archivedThroughSeq >= S`.
- A malformed authorization grants nothing and yields `MALFORMED_RECORD`.

Assumptions (written when the verifier was built, before the redaction and archive
writers; the writers later used the same payload names): retention is judged against the
retention declared in the event, not live configuration; archive-file
availability and bundle integrity are **not** audited here.

## Bounded resources

Events are read by `seq > ? ORDER BY seq LIMIT 1000`. Authorization events are
found through the `(event_type, seq)` index in pages of 1000 and indexed in a
private, anonymous SQLite scratch database, so memory is bounded by the batch
size, 100 diagnostics and one record's leaves (capped at 500). Checkpoints are
paged by `id`. A single pathologically large tampered row can still be loaded.

## Attack coverage (`LedgerVerifierTests`, real SQLite, raw-JDBC tampering)

Edit field, edit with recomputed hashes, delete, reorder, leaf value edit,
leaf deletion, forged/malformed/wrong-target/caller-sourced authorizations,
archive hash/policy cases, raw malformed values, extra/orphan leaves, genesis
change, checkpoint tamper / other key / mismatch / malformed row, signed-checkpoint
truncation, >100 diagnostics with exact totals, small batch sizes, and a
ledger bound to another id.

## Documented limits (demonstrated by tests)

A hash chain cannot detect, without a surviving trusted checkpoint:

- rewriting the uncheckpointed tail with recomputed hashes;
- deleting records after the last checkpoint;
- deleting the tail together with its local checkpoints;
- a full rewrite once no checkpoint survives.

Key compromise, a DB administrator who rewrites and re-signs, and absence of
an external witness/KMS/WORM are out of scope.

## Tamper testing

Tamper cases are exercised by LedgerVerifierTests against synthetic ledgers (guard triggers dropped as a DBA could). To try it by hand, edit a copy of a throwaway dev database with SQLite, then call GET /audit/verify; never tamper with real data.
