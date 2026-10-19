# Atomic redaction and cleanup recovery (Java, schema v2)

## Endpoints (admin role only)

| Method and path | Purpose |
|---|---|
| `POST /audit/admin/redactions` | Body `{eventId, paths, reason, ticketId}`; unknown fields rejected. Returns `201`. |
| `GET /audit/admin/redaction-cleanups` | Pending/complete counts and the newest 100 jobs. |
| `POST /audit/admin/redaction-cleanups/retry` | Runs the bounded cleanup attempts again and returns status. |

The `requestedBy` value is the authenticated principal, never the body. The `201` body contains
`redactionEventId`, `redactionSeq`, `timestamp`, `contentHash`, `chainHash`, `targetSeq`,
`targetEventId`, `redactedPaths` (the exact expanded leaf pointers), `cleanupStatus`
(`COMPLETE` or `PENDING`), `cleanupAttempts` and a limitations note. It never contains a value.

## Transaction

One `BEGIN IMMEDIATE` write transaction:

1. Look up the target by `eventId`: missing is `404`; archived, `source=system` or a reserved
   type is `409`.
2. Validate each path as RFC 6901 syntax (the empty root pointer is allowed) and expand it against
   the stored commitment tree. A non-existent path, non-canonical array index or bad escape is
   `422`. Expanded leaves are de-duplicated and sorted.
3. Keep only leaves that still exist in `payload_leaves`. Nothing left (already redacted, or an
   empty container) is a `409` no-op.
4. Append a `RECORD_REDACTED` system event with payload `{targetSeq, targetEventId, paths,
   reason, ticketId, requestedBy}` (`paths` are the exact leaves).
5. Delete the leaf rows, which removes both the value and the salt.
6. Insert a `redaction_cleanup` row with status `PENDING`.

Any failure rolls back all of it. The target's commitment tree and hashes are never modified, so
the chain and checkpoints still verify; `LedgerVerifier` grants each missing leaf only through a
valid `RECORD_REDACTED` event that passes content, leaf and schema checks.

Limits: at most 500 request paths and at most `min(AUDIT_MAX_LEAVES, 500) - 5` (495 by default)
expanded leaves per redaction, because the authorization event is itself an ordinary payload. A
larger subtree gets `422`; redact smaller subtrees separately. `reason` is at most 1000
characters and `ticketId` at most 128. The service rejects a `reason` or `ticketId` that repeats
a redacted value of four or more characters; this is best effort only and does not detect
paraphrases. Callers must not put sensitive values in free text, because the authorization event
is permanent.

## Cleanup

Deleted rows can survive in older WAL frames and in unreclaimed pages. After commit the service
runs `PRAGMA wal_checkpoint(TRUNCATE)` on a fresh connection and inspects the returned
`(busy, log, checkpointed)` tuple. A busy result is returned by SQLite, not always thrown, so the
tuple is the source of truth. Cleanup counts as done only when `busy = 0` and `log = checkpointed`.

- Attempts are finite (`AUDIT_CLEANUP_MAX_ATTEMPTS`, default 3, max 10) with a short back-off.
- Each attempt waits at most `AUDIT_CLEANUP_BUSY_TIMEOUT_MS` (default 1000, max 30000). This is
  a deliberate deviation from the 30000 ms default used by normal connections, so a held reader
  cannot stall the request thread for minutes.
- States: `PENDING` -> `COMPLETE`. `last_outcome` is `BUSY`, `INCOMPLETE`, `ERROR` or `OK`. A
  committed redaction is never rolled back by a failed cleanup; the response reports `PENDING`.
- A job set is completed only by a successful run that started after it was committed.
- Restart recovery: the cleanup service runs once at start-up and leaves jobs `PENDING` if that
  fails. The retry endpoint can be called at any time.
- Triggers block deleting cleanup rows, changing identity fields and any status transition other
  than `PENDING` -> `COMPLETE`.

## Schema migration

Schema version 2 adds `redaction_cleanup` and rebuilds `ledger_meta` with `schema_version = 2`.
Version 1 databases migrate on open in one transaction; an unknown version is rejected.

## Limits

COMPLETE means the live SQLite database and WAL were checkpointed and truncated. It is not a
guarantee of physical erasure. It does not cover storage-device remnants, filesystem snapshots,
backups, copies of the database file, earlier exports and bundles, or archive files. Payload
shape, event IDs, hashes and the fact and time of redaction remain visible. Redaction of
archived events is refused; the archive file is a separate copy and must be handled by its own
procedure.
