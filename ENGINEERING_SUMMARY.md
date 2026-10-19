# Engineering summary

Prepared by the AI assistant for engineer review. **This is not a sign-off.** The root [ATTESTATION.md](./ATTESTATION.md) carries
the engineer's attestation text and details required by the assignment; the engineer must still own and stand behind it. The
engineering review record, [docs/attestation-template.md](./docs/attestation-template.md), is deliberately unfilled: only the
engineer can record what they actually reviewed and approved.
Nothing has been published or submitted by the assistant. Detailed per-action decisions are in [AI_USAGE_LOG.md](./AI_USAGE_LOG.md).

## Choices that are mine, not assignment requirements

The assignment PDF asks for Scenarios A, B and C plus deliverables; it does not mandate Java, Spring Boot, Python, RFC 8785 JCS
or Ed25519. Those, the second implementation and the independent verifier are my design choices
([adr/0001](./docs/adr/0001-platform-and-layout.md)), made so a recipient can verify without our code and so the protocol is
shown to be specified rather than incidental. The cost is double the surface to maintain and defend.

## Scope boundaries to state in the defense

- **"Export all records" means all matching retained live records.** Archived records are excluded and the bundle says so
  ([export-bundles.md](./docs/export-bundles.md)). A historical export spanning archives is not implemented; this is a
  retention-policy choice.
- **Detection is conditional.** Modification or deletion is detected only while a trusted signed checkpoint at or beyond the
  affected record survives and the key is uncompromised. Uncheckpointed tail changes and deletion together with the covering
  checkpoints are not detected (`LedgerVerifierTests`). See [live-defense.md](./docs/live-defense.md).
- **Timestamp:** server-assigned `timestamp`; optional caller `occurredAt` ([api.md](./docs/api.md)).

## What was delivered

Two independently implemented services of one contract (same API, schema, protocol), each run against its own SQLite file:

- **Java 21 / Spring Boot 3.5 / Maven** in `java/` (plain JDBC, no JPA; Spring only in `web` and `config`).
- **Python 3.11+ / Starlette / Pydantic 2** in `python/`, plus an independent offline verifier (`python -m audit_log_service.verifier`)
  that does not import the service. The Java side has its own bundle and export-set verifier CLI.

Architecture: [docs/architecture.md](./docs/architecture.md). API: [docs/api.md](./docs/api.md). Decisions: [docs/adr/](./docs/adr).
Setup: [docs/setup.md](./docs/setup.md). Defense notes: [docs/live-defense.md](./docs/live-defense.md).

## Scenario traceability

Requirement IDs refer to [docs/requirements-mapping.md](./docs/requirements-mapping.md) (SH-01..08, A-01..10, B-01..12, C-01..07, Q-01..05).

| Scenario | Delivered behaviour | Design doc | Main evidence (tests) |
|---|---|---|---|
| Shared (SH) | v1 JCS and hashes, salted commitments, Ed25519 checkpoints, SQLite WAL schema and triggers, config, auth | [adr/0002](./docs/adr/0002-canonicalization-and-hash-protocol.md), [adr/0003](./docs/adr/0003-storage-and-transaction-model.md), [adr/0005](./docs/adr/0005-signatures-verification-and-trust.md) | Java `CanonicalJsonTests`, `V1HashesTests`, `PayloadCommitmentsTests`, `CheckpointSignerTests`, `JdbcAuditRepositoryTests`, `SchemaMigrationTests`; Python `test_canonical_json`, `test_v1_hashes`, `test_signing`, `test_service_store`; shared `docs/test-vectors/`; `PythonInteropTests`, `test_cross_service_parity` |
| A: append, query, verify | Serialized append, secured query with keyset cursors, full-chain verifier with 13 violation types | [adr/0004](./docs/adr/0004-api-authentication-and-validation.md), [verification.md](./docs/verification.md) | Java `AppendEventServiceTests`, `AuditApiHttpTests`, `LedgerVerifierTests`; Python `test_service_api`, `test_ledger_verifier`, `test_synthetic_tamper`; `test_e2e_http` (processes, concurrency, restart, tamper matrix) |
| B: redaction, retention, export | Atomic redaction with cleanup recovery; archive with signed bundles and crash recovery; archive audit; small bundles and chunked export sets; offline verifiers | [redaction.md](./docs/redaction.md), [retention-archive.md](./docs/retention-archive.md), [export-bundles.md](./docs/export-bundles.md), [export-sets.md](./docs/export-sets.md), [adr/0006](./docs/adr/0006-redaction-and-retention.md), [adr/0007](./docs/adr/0007-export-and-offline-verification.md) | Java `RedactionServiceTests`, `ArchiveServiceTests`, `ArchiveAuditTests`, `ExportSetServiceTests`, `BundleExportVerifierTests`, HTTP suites; Python `test_redaction`, `test_archive`, `test_exports`, `test_verifier`, `test_bundle_fixtures` |
| C: account-access report | Internal auditor on-demand report on labelled assumptions; signed evidence; one-transaction snapshot | [scenario-c.md](./docs/scenario-c.md), [account-access-report.md](./docs/account-access-report.md), [adr/0008](./docs/adr/0008-account-access-report.md) | Java `AccountAccessContractTests`, `AccountAccessReportServiceTests`, `AccountAccessReportHttpTests`; Python `test_account_report` |
| Quality (Q) | Gates, security review, packaging, benchmarks | [quality-gates.md](./docs/quality-gates.md), [performance.md](./docs/performance.md), [adr/0009](./docs/adr/0009-testing-and-operational-evidence.md) | see results below |

## Test and gate results (most recent full runs, Action 23)

These were not re-run in Action 24, which changed only documentation (plus a code change that was reverted; see the rehearsal below).

| Gate | Result |
|---|---|
| `mvn -B -f java\pom.xml verify` | 216 tests, 1 skipped, all configured gates green |
| Python `pytest --cov` | 422 passed, 1 skipped; coverage 87.17% |
| Python `ruff check`, `ruff format --check`, `mypy src` | clean |
| `python scripts\check_hygiene.py` | clean (re-run in Action 24, see AI log) |
| `pip-audit --local` | no known vulnerabilities (editable project skipped) |

Cross-process and cross-language checks (`test_e2e_http`, interop, tamper matrix) are part of the Python run; Java-parameterised cases
need the packaged jar and are skipped, not faked, without it.

## Not run or not verified

- GitHub Actions CI (`.github/workflows/ci.yml`) never ran; not validated by a runner.
- Docker images and `compose.yaml` never built (no Docker locally).
- `bandit` could not be installed locally (CPython 3.15 / PyYAML); `ruff --select S` was a partial proxy.
- OWASP dependency-check not run (needs an NVD key).
- `scripts/demo.sh` never executed; `scripts/demo.ps1` was run on Windows.
- Linux memory probe not run; no Python 3.11 or 3.13 run locally (local interpreter is 3.15).
- Benchmarks are from one Windows machine (see [docs/performance.md](./docs/performance.md)); no targets are claimed.

## Trust and privacy limits

- Tamper-evident, not tamper-proof. A full rewrite, tail loss, or removal of data plus local checkpoints is undetectable without surviving trusted checkpoints.
- No external witness, KMS/HSM or WORM. Key compromise is out of scope.
- Redaction and archiving give no physical-erasure guarantee for storage devices, backups, earlier exports or archive copies.
  Payload shape, IDs and the fact and time of redaction remain visible.
- Archived records are excluded from normal query, export and reports. Archive file availability is a separate audit.
- Query cursors can show visibility drift after redaction or archive.
- Scenario C has no stakeholder answers; all choices are labelled assumptions. The service cannot detect events upstream systems never sent.
- Disk-full surfaces as a generic 500 (documented, not changed); an engineer decision is open.
- Spring Boot 3.5 open-source support ended 2026-06-30 ([docs/dependency-versions.md](./docs/dependency-versions.md)).
- `scripts/check_hygiene.py` scans tracked files for secrets; dev sample API keys are public and development-only.

## AI use (summary)

Every action's accepted, modified and rejected choices are in `AI_USAGE_LOG.md`. Examples: a Java small-bundle verifier was corrected
against the RFC text in the Action 10 fix pass; adding a JSON-schema validator library was rejected in favour of verifier-enforced rules;
Action 21's HTTP validation exposed a missing Java `POST /audit/admin/checkpoints` route (answered 500), which was then implemented.
The log records what was actually run; blocked checks are listed above rather than hidden.

## Event-contract extension rehearsal

Adding a `channel` value was rehearsed and reverted; results are in [docs/live-defense.md](./docs/live-defense.md).

## Engineer actions remaining

1. Review the design and the open Scenario C questions with the business owner.
2. Decide on disk-full handling, Spring Boot support and the pre-existing root starter (`pom.xml`, `src/`, untracked and unused).
3. Run CI, build the images, and run bandit and OWASP dependency-check where they work.
4. Confirm the personal details in `ATTESTATION.md`, fill in `docs/attestation-template.md` with what you actually reviewed, and
   keep the submission date accurate.
