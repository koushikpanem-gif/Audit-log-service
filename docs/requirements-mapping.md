# Requirements and acceptance mapping

This is a requirements baseline for later engineering work, not evidence that
the service or the acceptance checks already exist. IDs are stable traceability
anchors. The engineer reviews the requirements, resolves the questions in
[`scenario-c.md`](./scenario-c.md), and owns acceptance and sign-off.

## Shared protocol, platform, and ownership

| ID | Requirement | Acceptance evidence (to be produced during implementation) |
|---|---|---|
| SH-01 | Provide Java 21 / Spring Boot 3 / Maven and Python >=3.11 / Starlette services, independent offline Python verifier, shared API/schema/protocol, separate DB files, and the specified repository layout. | Both services build/run independently; Python verifier imports no Java service code; contract and bidirectional cross-language tests pass. |
| SH-02 | Pin compatible supported dependency versions based on official sources at bootstrap; document version rationale; preserve the specified stack. | Manifests lock exact resolved dependencies and docs record source/date/rationale; dependency and build checks pass. |
| SH-03 | Use RFC 8785 JCS and the exact v1 genesis, leaf, content, and chain formulas. Validate JSON safely before recursive processing; preserve hash-version compatibility. | Independently generated golden vectors match in both languages; malformed JSON, duplicate keys, invalid Unicode, unsafe integers, NaN/infinity, depth and size are rejected. |
| SH-04 | Commit payload scalar leaves with fresh 32-byte salts and RFC 6901 pointers; preserve container shape and explicit redaction presentation. | Cross-language leaf vectors cover null/scalars/arrays/escaped pointers; repeated writes use distinct cryptographic salts; reveal output identifies sorted redacted paths. |
| SH-05 | Sign checkpoints and bundles with Ed25519 over JCS; enforce exact key encodings, IDs, signed fields, and pinned-key verification. | Cross-language signatures verify; key ID/raw key vectors pass; altered signed content and unpinned/self-asserted trust cases are identified correctly. |
| SH-06 | Keep the Java core/domain/store/service/verify/verifier framework-independent; use plain JDBC via `AuditRepository`, not JPA; keep Spring to web/config. | Dependency/module checks and tests establish that core layers do not depend on Spring; repository behavior uses JDBC. |
| SH-07 | Engineer owns design review, stakeholder decisions, and sign-off; retain authentic history; never fabricate approval, results, identities, or past commits. | Review records and final unsigned template are completed by an identified engineer; AI logs contain only actual choices/results. |
| SH-08 | Operate both services independently; provide Windows/Unix setup, operational scripts, CI, and documented prototype limits. | A documented demo exercises A/B/C for both services; CI and setup instructions are replayed on supported environments. |

## Scenario A — append, query, verify

| ID | Requirement | Acceptance evidence (to be produced during implementation) |
|---|---|---|
| A-01 | Append valid events with server-generated IDs, sequence, UTC recorded timestamp, source derived from authenticated principal, payload commitments, content/chain hashes; first link uses ledger genesis. | HTTP and real-SQLite tests verify response schema, deterministic canonical hash vector, monotonic timestamps, seq=1 genesis and subsequent predecessor links. |
| A-02 | Authenticate with `X-API-Key`; compare hashed keys in constant time, store only key hashes/roles, enforce writer/reader/auditor/admin role capabilities, and reserve system sources/types. | HTTP tests cover missing/invalid key, insufficient role, caller-supplied source, reserved event type, and each role matrix. |
| A-03 | Reject invalid JSON/envelopes, duplicate/unknown fields, invalid times, oversized payloads, excessive depth/leaves, invalid numbers/Unicode, and future-skewed occurrence times with the specified status/error shape. | Boundary and malformed-input tests assert 413/422 and stable non-sensitive error shape; no stack traces or submitted secret values leak. |
| A-04 | Query by any combination of supported filters with inclusive UTC bounds, ordering, bounded page size, opaque versioned cursor, keyset pagination and a fixed `asOfSeq`; disclose visibility drift from redaction/archive. | Multi-page tests verify stable sequence ordering, filter/order/head-bound cursors, no OFFSET use, reversed-range rejection and documented visibility limitations. |
| A-05 | Fetch a single live event by ID; missing and archived events return 404. Do not provide event PUT/PATCH/DELETE endpoints. | HTTP contract tests verify 404 behavior and OpenAPI route inventory excludes update/delete routes. |
| A-06 | Verify ledger records in ordered bounded batches and one snapshot, recomputing commitments, content hashes, chain links, schema/version and trusted checkpoints. | Real SQLite tests cover intact and empty ledgers, raw-store tampering, gaps, malformed records, edited rows and trusted checkpoint detection. |
| A-07 | Return all specified verification counters, first violation, at most 100 earliest deterministic diagnostics, exact violation total, truncation flag, head and duration. | Large-corruption test checks exact totals/order/first violation while retained diagnostics remain <=100 and scan continues. |
| A-08 | Treat authenticated keys as role principals and return only non-sensitive errors; map SQLite busy to 503. | HTTP tests assert error behavior and ensure error output excludes stack traces, payload values, key material and SQL details. |
| A-09 | Expose public health/key endpoints, OpenAPI JSON/docs, verify and checkpoint listing with correct authorization. | HTTP tests and generated OpenAPI checks verify route shape, auth, status codes and documentation endpoint availability. |
| A-10 | Create no checkpoint for an empty ledger; checkpoint on configured append intervals and on demand. | Integration tests cover empty-ledger 409, interval boundary and admin-triggered checkpoint with signature verification. |

## Scenario B — redaction, retention, verifiable bulk export

| ID | Requirement | Acceptance evidence (to be produced during implementation) |
|---|---|---|
| B-01 | Redact scalar/container subtrees using validated RFC 6901 pointers, including root; expand/deduplicate leaf paths, reject no-op/archived/system targets, append authorization event, delete values and salts, and preserve original hashes/tree. | SQLite/API tests cover pointer escaping, root/subtree expansion, duplicates, absent paths, no-op, archived/system targets and preserved content/chain hashes. |
| B-02 | After redaction commit, perform bounded WAL checkpoint retries, persist cleanup state, expose admin status/retry and recover after restart; report COMPLETE/PENDING without misrepresenting committed redaction. | Busy-WAL and restart tests prove durable result remains committed, cleanup state is accurate and retries are bounded. |
| B-03 | Archive only expired oldest contiguous live prefix; support dry run, positive bounded retention, bounded record/byte batches, signed bundles and crash-safe publication before clearing live content. | Archive tests cover cutoff and policy, dry-run no side effects, publication failure retaining DB values, crash stages, safe names, restart reconciliation and bounded batches. |
| B-04 | Preserve verifiable archive skeleton and append archive authorization metadata only after durable publication; handle cumulative authorizations and never delete unproven referenced artifacts. | Tests validate metadata/skeleton, repeated archives including archived authorizations, orphan handling, file loss diagnostics and no premature deletion. |
| B-05 | Exclude archived records from normal reads/exports and disclose exclusion; separately audit archive bundle integrity, signature, digest, metadata and range against skeleton. | Query/export tests verify exclusion/disclosure; archive audit differentiates missing/invalid archive evidence from a chain break. |
| B-06 | Produce exact v1 signed export bundle fields, records, digest, purpose, checkpoint and signer; never silently truncate or claim unsupported completeness. | Independent Python/Java fixture verification checks exact semantic fields, canonical signature, records digest/count, and output-size behavior. |
| B-07 | For large outputs use versioned signed export-set manifest/chunks frozen to one snapshot/head, bounded by record and byte limits, atomically READY only when published, recoverable, safe to download. | Tests verify chunk ordering/counts/digests, manifest selection/head/exclusion/expiry, path safety, publication states and recovery. |
| B-08 | Verify bundles with an out-of-band pinned key by default; optional self-asserted mode must label origin untrusted. Validate all protocol, record and set invariants with bounded resources. | CLI tests cover valid/altered/untrusted/malformed input; default trust requires pinning and exits 0 verified, 1 invalid evidence, 2 usage/input. |
| B-09 | Clearly scope filtered exports: sequence gaps do not prove global inclusion; missing disclosed leaf is not proof of authorized redaction; completeness relies on signer. | Contract and verifier tests distinguish filtered evidence from full-ledger inclusion and avoid claiming redaction authorization without evidence. |
| B-10 | Reserve internal event types and `source="system"` for redaction, archive, export and report system actions. | Authorization/append tests reject external attempts to submit each reserved type/source. |
| B-11 | Protect SQLite with WAL, FULL synchronous, foreign keys, secure_delete, per-connection busy timeout, BEGIN IMMEDIATE mutations, snapshot reads, schema binding, migrations and write-guard triggers. | Real database tests inspect pragmas/schema, transaction rollback/serialization, ledger mismatch, migrations and exact trigger allowances. |
| B-12 | Retain correct UTC timestamp/sequence behavior and reject caller occurrence times >300 seconds in the future. | Clock-controlled concurrent/process tests cover monotonic `recordedAt`, tie handling, UTC format and 422 future-skew case. |

## Scenario C — account-access compliance report

| ID | Requirement | Acceptance evidence (to be produced during implementation) |
|---|---|---|
| C-01 | Before implementation, resolve or explicitly label assumptions for account scope, denied/attempt events, subject/period, regulator access, privacy, retention, upstream coverage, completeness, legal holds and minimization. | Engineer-approved answers or explicit unresolved decisions are recorded; no question is presented as stakeholder-confirmed without evidence. |
| C-02 | Validate `ACCOUNT_DATA_ACCESS`, `CLIENT_ACCOUNT`, all enumerated data categories/access types/purposes/channels/outcomes, conditional `OTHER` justification and denial reason, optional lengths, and extra fields. | Schema/API tests cover each enum, conditional required values, lengths and invalid resource type. |
| C-03 | Require exactly one account or actor selector and explicit `from`/`to`; use a consistent snapshot to verify selected data head, select live retained matching events, derive signed evidence, append report event and checkpoint. | Concurrency/snapshot integration tests show report evidence head, selection and checkpoint are consistent and clearly distinct. |
| C-04 | Group report by actor/category/purpose/outcome/type; show denied/OTHER exceptions; represent missing grouping leaves as `UNKNOWN_REDACTED`, not inferred outcomes. | Fixture tests verify grouping, exception rows, redacted counts and absence of invented granted/denied classifications. |
| C-05 | Include requester, scope, counts, chain status, earliest violation, evidence and explicit live/archive/upstream exclusions; mark integrity-failed reports untrustworthy. | Response tests validate required fields and labels for intact, corrupted, archived/excluded and incomplete-upstream scenarios. |
| C-06 | Cap synchronous reports at 10,000 records and return explicit 422 requesting a narrower period rather than partial output. | Boundary tests at cap and cap+1 verify full response versus explicit error, with no truncated success-shaped report. |
| C-07 | Disclaim regulator portal/legal opinion and make no claim that absent upstream events can be detected. | Documentation and report output consistently label internal scope and evidence limitations. |

## Quality, security, and completion

| ID | Requirement | Acceptance evidence (to be produced during implementation) |
|---|---|---|
| Q-01 | Test unit, integration, HTTP, real SQLite, concurrent threads/processes, restart, rollback, tampering, malformed data, key pinning, busy WAL, archive crash, redaction/archive interactions, exports and snapshot-consistent reports. | Test inventory maps each listed case to a passing test; failures/tool/network gaps are recorded verbatim and not suppressed. |
| Q-02 | Generate independently authored cross-language vectors and signed bundles in both directions; use only labeled non-production test keys. | Java-produced evidence independently verifies in Python and vice versa; expected values are not produced by the implementation under test. |
| Q-03 | Run Java Maven verify, meaningful coverage enforcement after baseline, formatting/static analysis/dependency scan; Python ruff check/format, mypy, pytest, bandit and pip-audit. | CI/local logs record exact commands and actual outcomes; coverage is measured and enforced only after an honest baseline. |
| Q-04 | Benchmark append/query/verify/export and report workload, environment, throughput and p50/p95/p99 without invented targets. | Reproducible benchmark report contains workload/environment and measured values or a clearly reported blocker. |
| Q-05 | Demo A/B/C in both services, pinned-key offline verification, and tampering; document prototype limits, setup, human review, AI decisions and live-defense rehearsal. | Recorded demo evidence, reproducible setup and engineer-reviewed final summary/attestation; no fabricated sign-off. |
