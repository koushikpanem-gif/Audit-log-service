# Engineering summary

Prepared with AI assistance under engineer oversight. On 2026-10-19, Koushik Panem confirmed that he thoroughly reviewed
every commit, repeatedly prompted for the desired result, and intervened throughout development. The dated
[engineering review record](./docs/engineering-review.md) records that confirmation and its scope; it is not an independently
witnessed review or production sign-off. The root [ATTESTATION.md](./ATTESTATION.md) records the engineer's personal attestation.
The optional [review template](./docs/attestation-template.md) remains available for more detailed review notes; its unfilled
status is not evidence that human review did not occur.
Nothing has been published or submitted by the assistant. Detailed per-action decisions are in [AI_USAGE_LOG.md](./AI_USAGE_LOG.md).

## Choices that are mine, not assignment requirements

The assignment PDF asks for Scenarios A, B and C plus deliverables; it does not mandate Java, Spring Boot, RFC 8785 JCS
or Ed25519. Those and the offline verifier are my design choices
([adr/0001](./docs/adr/0001-platform-and-layout.md)), made so a recipient can verify without our code.

**Python service removed.** I first built a second Python/Starlette implementation of the same contract plus an independent
Python verifier. It duplicated the Java service, so I removed it to keep one service to maintain and defend. The trade-off:
independent cross-implementation evidence now rests only on frozen golden fixtures (`java/src/test/resources/golden/`, produced
once by the removed implementation) and the Java offline verifier. Earlier results and history that mention Python are historical.

## Scope boundaries to state in the defense

- **"Export all records" means all matching retained live records.** Archived records are excluded and the bundle says so
  ([export-bundles.md](./docs/export-bundles.md)). A historical export spanning archives is not implemented; this is a
  retention-policy choice.
- **Detection is conditional.** Modification or deletion is detected only while a trusted signed checkpoint at or beyond the
  affected record survives and the key is uncompromised. Uncheckpointed tail changes and deletion together with the covering
  checkpoints are not detected (`LedgerVerifierTests`). See [live-defense.md](./docs/live-defense.md).
- **Timestamp:** server-assigned `timestamp`; optional caller `occurredAt` ([api.md](./docs/api.md)).

## What was delivered

One service, with its own SQLite file:

- **Java 21 / Spring Boot 3.5 / Maven** in `java/` (plain JDBC, no JPA; Spring only in `web` and `config`), including a
  bundle and export-set verifier CLI (`BundleVerifierCli`) that needs only a pinned public key.

Architecture: [docs/architecture.md](./docs/architecture.md). API: [docs/api.md](./docs/api.md). Decisions: [docs/adr/](./docs/adr).
Setup: [docs/setup.md](./docs/setup.md). Defense notes: [docs/live-defense.md](./docs/live-defense.md).

## Scenario traceability

Requirement IDs refer to [docs/requirements-mapping.md](./docs/requirements-mapping.md) (SH-01..08, A-01..10, B-01..12, C-01..07, Q-01..05).

| Scenario | Delivered behaviour | Design doc | Main evidence (tests) |
|---|---|---|---|
| Shared (SH) | v1 JCS and hashes, salted commitments, Ed25519 checkpoints, SQLite WAL schema and triggers, config, auth | [adr/0002](./docs/adr/0002-canonicalization-and-hash-protocol.md), [adr/0003](./docs/adr/0003-storage-and-transaction-model.md), [adr/0005](./docs/adr/0005-signatures-verification-and-trust.md) | Java `CanonicalJsonTests`, `V1HashesTests`, `PayloadCommitmentsTests`, `CheckpointSignerTests`, `JdbcAuditRepositoryTests`, `SchemaMigrationTests`; shared `docs/test-vectors/`; `GoldenSignedFixtureTests` |
| A: append, query, verify | Serialized append, secured query with keyset cursors, full-chain verifier with 13 violation types | [adr/0004](./docs/adr/0004-api-authentication-and-validation.md), [verification.md](./docs/verification.md) | Java `AppendEventServiceTests`, `AuditApiHttpTests`, `LedgerVerifierTests`, `FailureModeTests`, `AppendEventServiceTests` (concurrency) |
| B: redaction, retention, export | Atomic redaction with cleanup recovery; archive with signed bundles and crash recovery; archive audit; small bundles and chunked export sets; offline verifiers | [redaction.md](./docs/redaction.md), [retention-archive.md](./docs/retention-archive.md), [export-bundles.md](./docs/export-bundles.md), [export-sets.md](./docs/export-sets.md), [adr/0006](./docs/adr/0006-redaction-and-retention.md), [adr/0007](./docs/adr/0007-export-and-offline-verification.md) | Java `RedactionServiceTests`, `ArchiveServiceTests`, `ArchiveAuditTests`, `ExportSetServiceTests`, `BundleExportVerifierTests`, HTTP suites |
| C: account-access report | Internal auditor on-demand report on labelled assumptions; signed evidence; one-transaction snapshot | [scenario-c.md](./docs/scenario-c.md), [account-access-report.md](./docs/account-access-report.md), [adr/0008](./docs/adr/0008-account-access-report.md) | Java `AccountAccessContractTests`, `AccountAccessReportServiceTests`, `AccountAccessReportHttpTests` |
| Quality (Q) | Gates, security review, packaging, benchmarks | [quality-gates.md](./docs/quality-gates.md), [performance.md](./docs/performance.md), [adr/0009](./docs/adr/0009-testing-and-operational-evidence.md) | see results below |

## Test and gate results

Run in this session after removing the Python service:

| Gate | Result |
|---|---|
| `mvn -B -f java\pom.xml verify` | 215 tests, 0 failures, BUILD SUCCESS (formatting, SpotBugs and coverage gates green) |
| `python scripts\check_hygiene.py` | clean |

Earlier Python results (pytest, ruff, mypy, pip-audit) belonged to the removed service and are no longer applicable. Cross-process
tests that started the Python service no longer exist; Java-only concurrency and failure-mode tests remain.

## Not run or not verified

- GitHub Actions CI (`.github/workflows/ci.yml`) is being fixed after its first runs; check the Actions tab.
- Docker images and `compose.yaml` never built (no Docker locally).
- OWASP dependency-check needs an NVD API key (repository secret `NVD_API_KEY`).
- Linux memory probe not run.
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

1. Seek business-owner input on the open Scenario C questions; engineer commit review is recorded in `docs/engineering-review.md`.
2. Decide on disk-full handling and Spring Boot support.
3. Check the CI run, build the images, and run OWASP dependency-check with an NVD key.
4. Keep the personal details and actual submission date in `ATTESTATION.md` accurate. Add more detailed review notes if available, and record review of subsequent changes separately.
