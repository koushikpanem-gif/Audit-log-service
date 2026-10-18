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
