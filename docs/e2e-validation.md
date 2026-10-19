# Adversarial and cross-process validation

The Java service is covered by in-process and MockMvc/HTTP tests (`mvn -B -f java/pom.xml verify`). This document records what those tests
cover and the limits. An earlier revision also drove a second (Python) implementation as a real process and compared the two;
that service was removed (see [ADR 0001](./adr/0001-platform-and-layout.md)), so those cross-process and cross-language checks no longer exist.

## What is covered (Java)

- Scenarios A/B/C: append, query paging, verify, on-demand checkpoint, export, redaction, chunked export sets verified from the manifest,
  account-access report (`AuditApiHttpTests`, `ExportSetServiceTests`, `AccountAccessReportHttpTests`).
- Offline verification with the pinned key, a wrong pinned key, self-asserted mode and no key (`BundleExportVerifierTests`).
- Independently signed frozen fixtures verify and reject wrong or missing keys (`GoldenSignedFixtureTests`).
- Archive, archive audit and repeat archive (`ArchiveServiceTests`); busy-WAL redaction cleanup (`FailureModeTests`).
- Concurrent appends keep a gapless sequence (`AppendEventServiceTests`, `JdbcAuditRepositoryTests`).
- Rejected writes (reserved type, caller source, caller timestamp, missing target) leave no gap.
- Tamper detection: content, chain hash, previous hash, genesis, sequence gap, leaf value, unknown hash version, unauthorized redaction or
  archive, bad checkpoint signature, tail truncation with a surviving checkpoint, forged checkpoint, retention violation (`LedgerVerifierTests`).

## Limits (honest)

- Real multi-process, abrupt-kill and cross-language runs are no longer exercised.
- Archive crash stages are covered only by in-process simulated-crash tests.
- No benchmarks or load targets are claimed here; see [performance.md](./performance.md).