# Architecture

Two independent implementations of one contract, plus an independent offline verifier.
Neither service calls the other. They share only the documented protocol, SQL schema files,
JSON schemas and the cross-language test vectors in [`test-vectors/`](./test-vectors).

```
 client ──HTTP, X-API-Key──► Java service  (Spring Boot, port 8080) ── SQLite file A
 client ──HTTP, X-API-Key──► Python service (Starlette,   port 8000) ── SQLite file B
 signed bundle / export set ─► offline verifier (Java CLI or python -m audit_log_service.verifier)
                               needs only a pinned public key, no DB and no service
```

One ledger per database. `ledger_meta` binds the ledger ID and schema version; a mismatch is refused.
Either service can open a database written by the other (asserted by the cross-process tamper matrix in
[e2e-validation.md](./e2e-validation.md)).

## Layers

| Layer | Java (`java/src/main/java/com/auditlog/`) | Python (`python/src/audit_log_service/`) |
|---|---|---|
| Canonical JSON, v1 hashes, commitments, signing | `core` | `canonical_json.py`, `v1_hashes.py`, `payload_commitments.py`, `signing.py` |
| Domain contracts | `domain` | `account_access.py` and request validation in `app.py` |
| Storage (plain JDBC / sqlite3, no ORM) | `store` (`AuditRepository`, `JdbcAuditRepository`) | `store.py` |
| Services | `service` | `ledger.py`, `redaction.py`, `archive.py`, `archive_audit.py`, `export_bundle.py`, `export_sets.py`, `account_report.py` |
| Ledger verification | `verify` | `ledger_verifier.py` |
| Offline evidence verification | `verifier` | `verifier/` (imports nothing from the service) |
| HTTP, auth, config | `web`, `config` (only place Spring is used) | `app.py`, `auth.py`, `configuration.py`, `errors.py` |

`core`, `domain`, `store`, `service`, `verify` and `verifier` in Java do not depend on Spring.

## Write path

Every mutation runs in `BEGIN IMMEDIATE`, reads the head inside the transaction, computes
`recordedAt = max(now, previous)`, appends, and rolls back on any error. Multi-read operations
(query pages, verify, export, report) use one snapshot transaction. Checkpoints are signed every
`AUDIT_CHECKPOINT_INTERVAL` appends, on demand, and on export, archive and report. Triggers block
`audit_events` DELETE, payload-leaf UPDATE and checkpoint UPDATE/DELETE, and allow only the archive
0→1 update. They guard against accidents, not against a database administrator.

## Data flows

- **Append / query (A):** `POST /audit/events` → validate → salted commitments per scalar leaf → content,
  chain hash → insert event and leaves. Queries use seq keyset pages with an HMAC-bound cursor.
- **Verify (A):** ordered batches of 1000 in one snapshot; recompute content, leaves and chain; at most 100
  diagnostics with exact totals; redaction/archive authorizations are indexed in a scratch SQLite database,
  not memory. See [verification.md](./verification.md).
- **Redaction (B):** one transaction appends `RECORD_REDACTED`, deletes leaf values and salts, enqueues a
  durable cleanup job; then `wal_checkpoint(TRUNCATE)` runs and its result is inspected. See [redaction.md](./redaction.md).
- **Archive (B):** PREPARING job → signed `RETENTION_ARCHIVE` bundle written, fsynced, atomically renamed →
  only then live columns are cleared and `RECORDS_ARCHIVED` appended. See [retention-archive.md](./retention-archive.md).
- **Export (B):** small selections return one signed `audit-export-bundle/v1`. Larger ones create an export
  set (immutable chunks plus a signed manifest) from one frozen snapshot. See [export-bundles.md](./export-bundles.md)
  and [export-sets.md](./export-sets.md).
- **Account-access report (C):** one write transaction verifies the ledger, selects matching retained-live events
  at or before the verified head, appends `COMPLIANCE_REPORT_GENERATED` and a checkpoint, and signs evidence.
  See [account-access-report.md](./account-access-report.md).

## Trust boundaries

| Boundary | What is trusted | What is not |
|---|---|---|
| Caller → service | API key hash and roles; source is derived from the principal | Everything in the request body |
| Service → SQLite file | Nothing beyond the verifier's checks; the verifier fails closed on malformed rows | Anyone with write access to the file or its directory |
| Evidence → verifier | An out-of-band pinned public key | The key embedded in the bundle (accepted only in explicit self-asserted mode, labelled untrusted) |
| Signing key | Local PKCS#8 file with restrictive permissions | Key compromise is out of scope; no KMS/HSM |

## Limits

Hash consistency alone cannot detect a full rewrite or tail loss; that needs surviving trusted
checkpoints, and removal of data plus the local checkpoints evades detection. There is no external
witness, KMS or WORM storage. See [threat-model.md](./threat-model.md) and [../ENGINEERING_SUMMARY.md](../ENGINEERING_SUMMARY.md).

Decisions are recorded in [adr/](./adr).
