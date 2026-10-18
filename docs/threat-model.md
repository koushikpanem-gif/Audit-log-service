# Threat model

## Scope and security objective

The intended service records accepted events in a tamper-evident chain and
provides evidence that can be independently checked. This model captures
requirements for later implementation; it is not a security assessment of the
existing Spring starter. Detailed residual limitations are part of the
specification and must remain visible in product documentation.

## Assets

- Event metadata, committed payload structure, disclosed leaf values and salts.
- SQLite ledger, schema metadata, checkpoints, archive bundles and export sets.
- Ed25519 private signing key; public key and key ID; API key material and
  principal-role mapping.
- Redaction/cleanup state, archive job state, report evidence and audit history.
- Integrity and availability of verification results, generated evidence and
  operational configuration.

## Trust boundaries and actors

- HTTP clients cross an untrusted network boundary and authenticate with
  `X-API-Key`; roles separate writers, readers, auditors and administrators.
- The service process owns database transactions and derives event source from
  the authenticated principal. Caller-controlled values cannot impersonate
  reserved system events.
- Local filesystem/database administrators are outside the protection of
  SQLite triggers and application-only controls.
- Archive/export files, backups, upstream event producers, and offline verifier
  operators are separate trust domains. A verifier's pinned public key must be
  provisioned out of band for trusted-origin claims.
- The engineer is responsible for production key custody, deployment, human
  review and sign-off; this prototype specification does not imply those
  controls already exist.

## Threats and required mitigations

| Threat | Required controls | Residual limitation |
|---|---|---|
| Unauthorized read/write or privilege escalation | API-key authentication; constant-time comparison of key hashes; least-role authorization; no persisted plaintext keys; reject caller system source/types; generic non-sensitive errors. | Prototype key distribution and rotation remain operational responsibilities. |
| Event alteration, insertion, deletion, reordering or malformed stored values | Domain-separated hashes, monotonic sequence, genesis link, immutable-row triggers, full bounded verifier, strict schema/version validation, checkpoint signatures and pinned-key bundle verification. | Triggers are accidental-write guardrails, not defense against DB administrator; a complete rewrite or uncheckpointed tail loss can evade detection absent surviving trusted checkpoint. |
| Forged or replayed checkpoints/bundles | Ed25519 over exact JCS messages, key ID derived from raw public key, strict algorithms/version checks, out-of-band pinned keys by default. | Key compromise and self-asserted trust are outside the prototype protection; self-asserted mode must be labeled untrusted. |
| Plaintext payload exposure | Salted per-leaf commitments, access control, redaction removing both value and salt, `secure_delete`, WAL cleanup tracking, bounded exports, no secret/sensitive values in errors or authorization metadata. | Redaction does not guarantee physical erasure from storage devices, backups, prior exports or archive copies; payload shape and IDs remain visible. |
| Data loss or inconsistent redaction/archive on crash | Immediate write transactions, rollback, durable cleanup/archive jobs, flush/force and atomic archive publication before clearing live content, restart reconciliation. | Filesystem durability/atomic rename and directory-sync guarantees vary, especially on Windows; document actual platform behavior. |
| Incomplete or misleading query/export/report | Snapshot/head binding, versioned keyset cursor, exact counts and caps, no silent truncation, explicit archive/upstream exclusions, report integrity state and separate verified/post-report heads. | Visibility may change due to redaction/archive during query pagination; filtered exports do not prove global inclusion; missing upstream events cannot be detected. |
| Resource exhaustion or parser abuse | Request/payload/leaf/depth/report limits; pre-recursion validation; bounded verification batches/diagnostics; bounded export chunk record+byte sizes; safe paths; finite retries and validated finite retention. | Limits require operational tuning against actual workloads; benchmarks are required, no target is presumed. |
| SQLite concurrency/busy handling | WAL, FULL sync, foreign keys, secure delete, per-connection busy timeout, `BEGIN IMMEDIATE` for mutations, snapshot reads, bounded conflict handling and explicit 503 on busy. | Local database and filesystem reliability remain deployment dependencies. |
| Sensitive artifacts or credentials committed to source | Ignore environment secrets, private keys, API-key files, database/WAL files, generated archives/exports and local output; provide only clearly marked examples/test keys. | Ignore rules do not remove already tracked secrets; review history and repository status before any publication. No publication is authorized by this task. |

## Explicit non-claims

The design does not claim external witnessing, KMS/HSM custody, WORM storage,
legal compliance, complete upstream event capture, physical erasure, or
protection from a compromised signing key or database administrator. An
archive skeleton alone cannot recompute archived content; archive integrity
and availability are separately audited. The unanchored-tail limits are
demonstrated by tests and listed in [verification](verification.md).
