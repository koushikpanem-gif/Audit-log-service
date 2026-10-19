# ADR-0009: Validation, testing, and operational evidence

- **Status:** Accepted as a supplied completion gate.
- **Context:** Integrity properties cross language, database, process,
  filesystem and operational boundaries.
- **Decision:** Exercise real SQLite and HTTP behavior, concurrency in threads
  and processes, restart/rollback/tampering, malformed records, pinned keys,
  busy WAL, archive crash stages, redaction/archive interactions, export-all,
  and report snapshot consistency. Use independently produced test
  vectors and signed bundles using labeled test-only keys.
  Run the specified Java Maven quality/security gates, benchmark
  append/query/verify/export with workload/environment and throughput/p50/p95/
  p99, and demo A/B/C plus offline verification/tampering. Record exact
  commands, actual outcomes and tool/network blockers.
- **Consequences:** Coverage enforcement follows an honest baseline; no
  performance targets or passing results are invented. User-facing setup,
  prototype limits, AI traceability, human review, and live-defense rehearsal
  remain required completion evidence.

## Update: Action 22 gates (2026-10-18)

- Coverage thresholds were set from measured baselines (Java line/branch
  0.84/0.68 vs 86.2%/70.7%) with no coverage exclusions.
- SpotBugs findings were fixed where real; the remainder are
  suppressed only with dated justification (see `docs/quality-gates.md`).
- Tools needing network or compilers that were unavailable locally (OWASP NVD
  scan, Docker) are reported as blocked, not passed.
- Production fail-closed behavior is verified by real-process tests
  rather than configuration-unit tests alone.

## Update: Action 23 measurements (2026-10-18)

- `scripts/benchmark.py` measures append/query/verify/export of the service
  over HTTP and records environment, fsync probe, p50/p95/p99 and peak memory;
  results and analysis are in `docs/performance.md`. There are no timing gates.
- Failure simulation is bounded and deterministic: SQLite `max_page_count`
  (disk full), latency injected inside the write transaction (slow I/O), a held
  write lock with a short busy timeout, and the export-job limit (429).
  Production defaults are unchanged; the page cap and short timeout are
  test seams.
- Disk-full surfaces as a generic 500. This was documented, not
  changed; a distinct retryable status is an open engineering decision.
