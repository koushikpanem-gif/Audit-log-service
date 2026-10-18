# ADR-0009: Validation, testing, and operational evidence

- **Status:** Accepted as a supplied completion gate.
- **Context:** Integrity properties cross language, database, process,
  filesystem and operational boundaries.
- **Decision:** Exercise real SQLite and HTTP behavior, concurrency in threads
  and processes, restart/rollback/tampering, malformed records, pinned keys,
  busy WAL, archive crash stages, redaction/archive interactions, export-all,
  and report snapshot consistency. Independently generate cross-language
  vectors and signed bundles in both directions using labeled test-only keys.
  Run the specified Java Maven and Python quality/security gates, benchmark
  append/query/verify/export with workload/environment and throughput/p50/p95/
  p99, and demo A/B/C plus offline verification/tampering. Record exact
  commands, actual outcomes and tool/network blockers.
- **Consequences:** Coverage enforcement follows an honest baseline; no
  performance targets or passing results are invented. User-facing setup,
  prototype limits, AI traceability, human review, and live-defense rehearsal
  remain required completion evidence.
