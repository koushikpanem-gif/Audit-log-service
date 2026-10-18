# AI usage log

Actual AI changes and validation only; not engineer approval.

## Action 01 — requirements and ownership

- **Changed:** Added requirements/acceptance mapping, provisional Scenario C
  questions, threat model, ADRs, unsigned attestation template, README, and
  secret-safe ignore rules. No implementation or stakeholder decisions.
- **Validation:** Exact specification copy matched; 16 required documents and
  42 acceptance IDs checked; ignore rules and staged whitespace passed.
  Java/Python tests not applicable.
- **Git:** At the time, local Git initialization succeeded but author identity
  was missing, so no commit was attempted. Existing starter files were left
  untouched.

## Action 02 — Java and Python scaffolds

- **Changed:** Added Java 21/Spring Boot 3 and Python/Starlette skeletons,
  health endpoints, OpenAPI paths, smoke tests, exact dependency pins, CI, and
  setup/run instructions. No ledger functionality. Preserved the pre-existing
  root starter.
- **Version note:** Used Spring Boot 3.5.16 to match the assignment; its OSS
  support ended 2026-06-30. Pins and sources are in
  [`docs/dependency-versions.md`](./docs/dependency-versions.md).
- **Validation:** `mvn -B -f java\pom.xml verify` passed (3 tests) on Java
  21.0.12.1/Maven 3.10.0. In Python venv (Python 3.15.0; 3.11 unavailable),
  `ruff check .`, `ruff format --check .`, `mypy src`, `python -m pytest`
  (1 test), and `python -m pip check` passed. Corrected one Ruff import issue
  and replaced deprecated HTTPX test transport with pinned HTTPX2. Remote CI
  not run.
- **Commit:** `673753e8240d00a920e40ddbc877b86ae8e4201f`
  (`build: scaffold Java and Python services`); local `main` is ahead by one.
  No push performed.

## Action 03 — canonical JSON and v1 hashes

- **Changed:** Added bounded strict JSON/JCS and exact v1 hash/content helpers
  in both services, plus shared byte/hash vectors and pinned JCS dependencies.
  Both validate payload commitment trees and exact content shape. Java applies
  strict Jackson checks before JCS; Python validates before its pinned RFC
  8785 serializer. No database or event service added.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (13 tests). From
  `python\` using `.venv\Scripts\python.exe`, Ruff check/format, `mypy src`,
  pytest (31 passed), and `pip check` passed; Pylance syntax check passed.
  Focused binary64 output matched RFC 8785. The initial global-Python Ruff
  command failed because Ruff is only installed in the project venv; Pylance's
  default global interpreter also lacks `rfc8785`, while the project venv has
  pinned `rfc8785==0.1.4`. Python 3.11 was unavailable; CI not run.
- **Git:** Authorized local commit message: `feat: implement canonical JSON
  and v1 hashes`. No push or engineer review claimed.

## Action 04 — salted payload commitments

- **Changed:** Added bounded iterative commitment/reveal and RFC 6901 subtree
  expansion in both languages. Empty containers persist, null is committed,
  salts/values remain outside the tree, and missing disclosures return sorted
  `[REDACTED]` paths. Production uses secure random 32-byte salts; injectable
  fixed salts are package-private/internal for tests. Shared vectors use
  independently calculated SHA-256 values.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (20 tests). From
  `python\`, venv Ruff check/format, `mypy src`, pytest (44 passed), and
  `pip check` passed. Tests cover byte/depth/leaf boundaries, root and escaped
  pointers, invalid indices/escapes, redaction, and repeated random writes.
- **Git:** Authorized local commit message: `feat: implement salted payload
  commitments`. No push or engineer review claimed.

## Action 05 — Ed25519 signing and configuration

- **Changed:** Added matching Java/Python Ed25519 checkpoint signers using JCS,
  raw 32-byte public keys, key IDs, strict PKCS#8/key-pair validation, and
  exclusive dev-only key creation with POSIX owner permissions or Windows
  current-user ACLs. Added environment validation, finite retention bounded to
  500,000 days, positive size/count limits, production API-key-file validation,
  and a shared, explicitly test-only signature vector. Updated signing/
  configuration ADRs, README, key-artifact ignore rules, and setup docs. The
  health-only app scaffolds do not yet load these helpers; ledger lifecycle
  integration remains for a later action.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (26 tests). In the
  Python venv (Python 3.15.0; Python 3.11 unavailable), `ruff check .`,
  `ruff format --check .`, `mypy src`, pytest (76 passed), and `pip check`
  passed. Shared fixed-key signing bytes matched in Java and Python; dev
  creation/reuse and production refusal were exercised on Windows. Remote CI
  and production integration were not run.
- **Git:** Authorized commit message: `feat: implement Ed25519 signing and
  configuration`. No push or engineer sign-off claimed.

## Action 06 — SQLite schema and transactions

- **Changed:** Added version-1 SQLite DDL, ledger binding and explicit
  unsupported/unversioned schema refusal; JDBC `AuditRepository` and adapter
  open a fresh configured connection per operation, serialize writes with
  `BEGIN IMMEDIATE`, and provide read-only snapshots with rollback on failure.
  Added required indexes, foreign keys, JSON/hash constraints, and event,
  payload-leaf, and checkpoint guard triggers. Cleanup/archive job tables
  remain deferred to their owning actions.
- **Validation:** Focused `mvn -B -f java\pom.xml
  '-Dtest=JdbcAuditRepositoryTests' test` passed (6 tests); full
  `mvn -B -f java\pom.xml verify` passed (32 tests). Tests cover schema
  initialization/reopen/version and ledger mismatch, PRAGMAs, rollback,
  serialized concurrent writers, stable read snapshots, real matching rows
  for every trigger, valid archive transition, and foreign-key/JSON constraints.
  Python regression checks (`ruff check .`, `ruff format --check .`,
  `mypy src`, `python -m pytest` with 76 passed, `pip check`) also passed;
  Python sources were unchanged. Remote CI and cross-process stress were not
  run.
- **Git:** Authorized commit message: `feat: implement SQLite schema and
  transactions`. No push or engineer sign-off claimed.

## Action 07 — serialized event append

- **Changed:** Added a strict append input model and Java append service. The
  service validates configured request/payload/depth/leaf limits, rejects
  caller-supplied source/timestamp fields and reserved event types, normalizes
  `occurredAt` and enforces 300-second future skew. Under the existing
  `BEGIN IMMEDIATE` transaction it reads the current head, assigns a UUID and
  nondecreasing UTC-microsecond server time, creates salted payload
  commitments, computes v1 content/chain hashes, and inserts the event, leaves
  and interval checkpoints atomically. Added injectable clock/ID/salt sources,
  with secure random defaults, and documented the append transaction in
  ADR-0003.
- **Validation:** The first focused test run exposed an envelope-string
  validation bug; corrected it and reran successfully. Final
  `mvn -B -f java\pom.xml verify` passed (44 tests), including 20 concurrent
  Java writers, clock rollback/ties, future-skew rejection, empty payload and
  null leaves, restart continuity, strict unknown/source/timestamp rejection,
  configured limits, valid signed interval checkpoints, and rollback on leaf
  and checkpoint insertion failures. Python source was unchanged; its
  regression checks passed in the project venv: Ruff check/format, mypy, pytest
  (76 passed), and `pip check`. Cross-process stress, remote CI and live API
  integration were not run.
- **Git:** No commit or engineer sign-off claimed yet.

## Action 08 — secured append and query APIs

- **Changed:** Connected Java runtime configuration to the SQLite repository,
  configured signer, append service, and query service, including
  `AUDIT_DB_PATH`. Added hash-only API-key file loading and constant-time
  SHA-256 comparisons with writer/reader/auditor/admin role gates. Added fixed,
  documented dev-only sample credentials; production still requires a valid
  API-key file and signing key pair. Added strict byte-limited JSON parsing
  (duplicate keys, malformed Unicode, unsafe numbers, depth), exact append
  envelope rejection, and uniform error responses including safe 503 handling.
  Exposed append, filtered query, single-event retrieval, checkpoint listing,
  public key, health, OpenAPI, and docs routes. Queries use inclusive normalized
  UTC time bounds, sequence keyset pagination, and one read snapshot for event
  rows and payload leaves. Versioned HMAC cursors bind filters, ordering, and
  the first-page head; the cursor signing key is derived from configured key
  hashes, so key-set changes invalidate outstanding cursors. The API docs call
  out that archive/redaction visibility can change across pages. Extended the
  Java strict parser/hash serialization depth by the bounded API-envelope
  overhead so configured payload depth remains usable; existing v1 hash
  vectors remain unchanged.
- **Validation:** Focused HTTP/config/JSON/hash and append regressions passed.
  Final `mvn -B -f java\pom.xml verify` passed (50 tests), including HTTP
  HTTP status/role enforcement (401/403/404/405/409/413/422), safe 503
  exception-handler mapping, unknown and
  duplicate JSON fields, payload depth/size, timestamp ties and inclusive
  ranges, all filters, ascending/descending order, cursor misuse/tampering,
  keyset snapshot behavior, checkpoint access, and concurrent HTTP appends.
  Python source was unchanged; from `python\` the venv commands
  `python -m ruff check .`, `python -m ruff format --check .`,
  `python -m mypy src`, `python -m pytest` (76 passed), and
  `python -m pip check` passed. Cross-process stress and remote CI were not run.
- **Git:** No commit or engineer sign-off claimed yet.

## Action 09 — full-chain verification

- **Changed:** Added the Java `LedgerVerifier` (`com.auditlog.verify`) and
  `GET /audit/verify` (auditor/admin). One read snapshot, 1000-row ordered
  batches, all 13 diagnostic types, earliest-100 diagnostics with exact total,
  `firstViolation` and `violationsTruncated`. Stored data is treated as
  untrusted raw values; malformed data becomes `MALFORMED_RECORD`, not an
  error. Missing leaves and archive skeletons fail closed unless a validated
  system authorization event exists; authorizations are indexed in a private
  scratch SQLite database so memory stays bounded. Added `docs/verification.md`
  and `scripts/synthetic_tamper.py` (refuses non-`synthetic-` ledgers, needs an
  explicit flag).
- **AI decisions:** Accepted: one-snapshot batched design and scratch-DB
  authorization index. Modified: first draft read SQLite integers as `Long`
  only, which flagged every row malformed (found by tests; fixed to accept
  integer types). Assumptions that need engineer review: exact-key payload
  schemas for `RECORD_REDACTED`/`RECORDS_ARCHIVED` (the writers do not exist
  yet), retention judged by the event's declared `retentionDays`, and
  cumulative archive coverage by `archivedThroughSeq`.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (80 tests, including 30
  `LedgerVerifierTests` and the `/audit/verify` HTTP role checks). From
  `python\`: `ruff check .`, `ruff format --check .`, `mypy src`, `pytest`
  (80 passed, including 4 tamper-tool tests) and `pip check` passed.
- **Not done:** no concurrent-append-during-verify test, no cross-process
  stress, no remote CI run, no archive-file audit (later action), no benchmark.
  Python has no verify endpoint yet.
- **Git:** No commit or engineer sign-off claimed yet.

## Action 10 fix pass — align signed bundles with the small v1 contract

- **Why:** The first Action 10 commit (`d2a1b92`) used invented `selection` and
  `completeness` shapes, invented diagnostic codes, exit 2 for a missing key and a 409
  for an empty ledger. The engineer re-issued Action 10 with a normative contract.
- **Changed:** JSON Schemas in `docs/schemas/`; `BundleSelection/Completeness/Purpose/
  Diagnostic*` domain types; `ExportBundleService` rewritten (selection captures
  `throughSeq` before the meta-event; checkpoint at post-event head; limits
  `AUDIT_EXPORT_MAX_RECORDS`/`AUDIT_EXPORT_MAX_BYTES` with a final-canonical-size check;
  422 `EXPORT_LIMIT_EXCEEDED` with rollback; empty selection allowed); `BundleVerifier` and
  CLI rewritten (trust statuses, 20 diagnostic codes, exit 0/1/2); tests rewritten;
  Python generator, frozen golden fixtures, fixture and schema pytests; `docs/export-bundles.md`
  rewritten.
- **AI decisions:** Accepted: separate fix commit rather than amending. Assumed (listed in
  `docs/export-bundles.md`): code mappings for hashVersion, selection and head violations;
  non-canonical input accepted; malformed pinned key is exit 2. Modified: my recalled
  RFC 8032 public key was wrong in the first generator run; the generator's assertion caught
  it and I corrected it against the RFC text (the signature value matched). Also removed
  the old test expectation that actorId plus resourceId is rejected, since the contract
  allows combined filters. Rejected: adding networknt json-schema-validator; schemas are
  validated by Python `jsonschema` 4.26.0 (new pinned dev dependency) instead.
- **Validation:** `mvn -B -f java\pom.xml verify`: 101 tests, 0 failures, BUILD SUCCESS.
  From `python\`: `ruff check .`, `ruff format` (no changes), `mypy src`, `pytest` (96 passed).
  `pip check`, `bandit`, `pip-audit` not re-run in this pass.
- **Not done:** no Python production verifier (Action 16), no export sets (Action 11), no
  benchmark (Action 23); no independent Java-vs-Python verifier cross-check beyond the frozen
  fixtures; the byte-limit boundary test asserts rejection at size-1 but the exact-size
  acceptance is not asserted. No engineer sign-off.
- **Git:** committed locally as `fix: align signed bundles with small v1 contract`; hash in
  the final report.

## Action 10 — signed bundles and Java verifier (original entry; superseded by the fix pass above)

- **Changed:** Added `ExportBundleService` and `GET /audit/export` (auditor/admin,
  exactly one of `actorId`/`resourceId`) that builds the exact v1 bundle: selection,
  checkpoint signing at the selection head and a system `BUNDLE_EXPORTED` event in
  one write transaction. Added the framework-independent offline verifier
  (`com.auditlog.verifier.BundleVerifier`) and CLI (`BundleVerifierCli`, exit 0/1/2)
  that requires a pinned key unless `--allow-self-asserted` is given (labelled
  untrusted). Added `CheckpointSigner.signMessage/verifyRaw/keyIdFor`,
  `CanonicalJson` overloads with a caller-set byte bound, and
  `AppendEventService.appendSystemEvent/storeCheckpoint`. Documented in
  `docs/export-bundles.md`.
- **AI decisions:** Accepted: one transaction for selection + checkpoint + export
  event; `BUNDLE_EXPORTED` payload carries bundleId, digest and heads but not the
  selection value. Assumptions needing engineer review: the shape of `selection`
  and `completeness` (the brief fixes only the field names), the 1000-record /
  8 MiB small-export limits, 409 for export from an empty ledger (no checkpoint can
  exist), and the `RECORD_AFTER_HEAD`-style verifier violation codes (the brief
  lists none for bundles). Modified: an edit briefly dropped an import in
  `AuditController`; the compiler caught it and I restored it.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (105 tests, including 24
  `BundleExportVerifierTests` and an HTTP export-then-verify test). From
  `python\`: `pytest` (80 passed), `ruff check` and `mypy src` passed; Python is
  unchanged in this action.
- **Not done:** oversized selections are rejected (422 `EXPORT_TOO_LARGE`), no
  export-set/chunks (next action); no Python verifier or Python export, so no
  cross-language bundle vectors; verifier tests use bundles from the Java
  builder and re-signing with the same test key, so they are not independent of
  Java; no benchmark; `ruff format --check`, `pip check` not re-run.
- **Git:** No commit or engineer sign-off claimed yet.

## Action 11: bounded complete bulk exports

- **Scope:** signed export-set manifest and chunk protocol, job service with staging, durable
  READY and restart recovery, auditor-only create/status/manifest/chunk endpoints, Java set
  verifier (`ExportSetVerifier`, CLI `--manifest`), 8 new diagnostic codes. Documented in
  `docs/export-sets.md` and `docs/schemas/export-set-manifest.schema.json`. Small v1 bundles
  are unchanged.
- **AI decisions:** Accepted: selection snapshot first, then one write transaction for the
  `BUNDLE_EXPORTED` event, checkpoint and manifest signature, so selection head and post-event head
  are separate fields; jobs fail on any limit breach instead of truncating; after the ledger commit
  recovery finishes publication from the ledger instead of deleting staged files. Assumptions for
  engineer review: POST always returns a descriptor, an empty filter set exports the whole retained
  ledger, TTL/limit defaults, lazy expiry, 16 active jobs per process, 202 with polling.
  Modified: a job `createdAt` used nanosecond clock precision and was rejected by the microsecond
  check; the HTTP test caught it and I truncated to micros. An HTTP test assumed a synchronous job
  and was changed to poll.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (129 tests; 27 in `ExportSetServiceTests`,
  covering 10,100 records, 60 KB values, concurrent appends, missing/altered/reordered/duplicated/
  unlisted chunks, path traversal, restart recovery, expiry; plus `ExportSetHttpTests`). From
  `python\`: `ruff check`, `ruff format --check`, `mypy src` passed; `pytest` 96 passed (Python
  unchanged).
- **Not done / blocked:** no Python verifier or independent cross-language set vectors (Java round
  trips only share one implementation); no memory measurement beyond design and chunk-size limits;
  no benchmarks; `bandit`, `pip-audit`, `pip check` not re-run.
- **Git:** committed locally as one commit; no engineer sign-off claimed.

## Action 12: atomic redaction and cleanup recovery

- **Scope:** Java redaction service, durable cleanup jobs with status/retry endpoints (admin role),
  schema v2 migration (`redaction_cleanup`), cleanup config, admin role rule for `/audit/admin/**`.
  Documented in `docs/redaction.md`.
- **AI decisions:** Accepted: one write transaction appends `RECORD_REDACTED`, deletes leaves and
  salts and inserts the PENDING job; WAL cleanup runs after commit and never undoes it; COMPLETE only
  when the returned tuple has busy=0 and log=checkpointed. Assumptions for engineer review: a
  shorter cleanup busy timeout than the 30000 ms standard, a cap of 495 expanded leaves per
  redaction, a best-effort check that reason/ticketId does not repeat a redacted value, and a
  start-up recovery attempt. Modified: `LedgerVerifier` required `schema_version = 1`, so every
  v2 ledger looked malformed; the first test run caught it and I changed it to 2. A test expected
  the plaintext in the WAL while a reader was held, but it was in the main database file; the
  assertion now accepts either file.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (147 tests; 14 `RedactionServiceTests`
  covering root/nested/subtree/overlap paths, no-op, archived/system/missing targets, rollback
  by a forced trigger failure, forged and malformed authorizations, held-reader busy then
  release/retry with plaintext absence in both files, restart recovery; plus `RedactionHttpTests`,
  `SchemaMigrationTests` and config tests). From `python\`: `ruff check`, `ruff format --check`,
  `mypy src` passed; `pytest` 96 passed (Python unchanged).
- **Not done / blocked:** no Python redaction or cross-language vectors; no multi-process
  redaction test; no physical-erasure claim; `bandit`, `pip-audit`, `pip check` not re-run;
  JaCoCo thresholds ran as configured, none changed.
- **Git:** committed locally as one commit; no engineer sign-off claimed.

## Action 13: durable retention archives

- **Scope:** Java only. Schema v3 (`archive_jobs`), `ArchiveService` (dryRun, bounded oldest-prefix batch,
  job state machine, forced signed file publication before clearing live data, skeleton, `RECORDS_ARCHIVED`,
  reconcile/cleanup), `ArchiveAuditService`, admin/auditor endpoints, archive config. Documented in
  `docs/retention-archive.md`.
- **AI decisions:** Accepted: file is forced and atomically moved inside the DB write transaction before live
  fields are cleared, so a crash or failure leaves plaintext intact. Assumptions for engineer review: retention
  rounded up (ceil) to an integer for the event field; in-process lock (single-process); orphans reported, never
  deleted; best-effort WAL checkpoint and directory fsync (not on Windows). Modified: a test showed the
  `AFTER_JOB_RECORDED` hook ran outside the failure handler, leaving the job PREPARING on an orderly failure; I
  moved it inside. Rewrote a convoluted cutoff assertion and a test that pointed at the wrong seq.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (175 tests: `ArchiveServiceTests` 25, `ArchiveHttpTests`
  3, migration/repository tests updated). Python checks run again (code unchanged); see result in the commit
  report.
- **Not done / blocked:** no Python archive implementation or cross-language checks; no multi-process tests; no
  v2->v3 dedicated migration test or archive config unit tests; `bandit`/`pip-audit` not re-run; a missing
  archive file is reported only by the archive audit; no human sign-off.
- **Git:** one local commit, not pushed.

## Action 14: archived evidence audit

- **Scope:** Java only. Extended `ArchiveAuditService` (standalone constructor with out-of-band pinned key;
  bundle ledger/signer/head-seq checks; authorizing-event checks; bounded, no-symlink file reads; global range
  contiguity/coverage check; `unavailableArchiveCount`) and added `ArchiveAuditCli` (exit 0/1/2). Documented in
  `docs/retention-archive.md`.
- **AI decisions:** Accepted: reuse the Action 13 audit rather than a second implementation. Assumptions for
  engineer review: the CLI opens the DB through the normal repository (which may migrate an older schema); a
  pinned key is mandatory (no self-asserted mode); the coverage check treats any archived row not inside a
  committed archive range as a failure. Modified: two of my first-draft tests were wrong (a ledger-id mismatch
  correctly yields METADATA_MISMATCH, and a raw tamper had to satisfy the archived-row CHECK constraint); I fixed
  the tests, not the product code. Not tested: symlinks (needs Windows privileges), so only a directory in place
  of the file is covered.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (188 tests; 13 new in `ArchiveAuditTests` covering
  missing/substituted/corrupt/oversized files, wrong key, wrong ledger, changed eventId/timestamp/hashVersion,
  repeat archives with an archived authorization event, coverage break, CLI exit codes). Python code unchanged,
  checks not re-run for this action.
- **Not done / blocked:** no Python archive audit or cross-language checks; no multi-process tests;
  `bandit`/`pip-audit` not re-run; no human sign-off.
- **Git:** one local commit, not pushed.
