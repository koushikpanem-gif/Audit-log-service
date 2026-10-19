# Live defense notes and extension rehearsal

For the engineer to read and adapt before a live review. The explanations are drawn from this repository's
design and tests; the engineer owns the design and must be able to defend each point in their own words.
Nothing here is a sign-off.

## Ten-minute walkthrough

1. **Append** a `TRADE` event; show `contentHash`, `prevHash`, `chainHash` in the response and that `source` comes from the key, not the body.
2. **Verify**: `GET /audit/verify` is intact. Edit one stored value directly in SQLite (as a database administrator could, after dropping the guard triggers; use a throwaway synthetic database only).
   Verify reports the edited record (`CONTENT_HASH_MISMATCH` or `PAYLOAD_VALUE_MISMATCH`) and `firstViolation`.
3. **Redact** a leaf: value and salt are deleted, the tree and hashes stay, verification stays intact because a validated `RECORD_REDACTED` authorizes it.
4. **Export** with the pinned key and verify offline (exit 0); wrong key (exit 1); no key (exit 1 `TRUSTED_KEY_REQUIRED`).
5. **Report**: Scenario C report, then explain `verifiedDataHead` versus the post-report checkpoint.

The demo scripts were removed together with the Python service; run the steps above by hand with the dev keys.

## Questions to expect

| Question | Answer grounded in this repo |
|---|---|
| Why a hash chain and per-leaf salted commitments? | The chain orders and links records. Per-leaf salted commitments let one value be removed (redaction) or withheld (export) while every hash still verifies. The salt stops guessing low-entropy values from the commitment. |
| What does the chain not protect against? | A full rewrite, tail loss, or removal of data plus the local checkpoints. Only surviving trusted checkpoints (or an external witness, which does not exist here) can reveal those. Concretely, `LedgerVerifierTests` demonstrates that changing the uncheckpointed tail, and deleting records together with the checkpoints that covered them, are not detected. The assurance is conditional: modification or deletion is detected only while a trusted, signed checkpoint at or beyond the affected record survives and the signing key is uncompromised. Defense stance: say this first; it is the honest meaning of "tamper-evident" here. Mitigation is operational (frequent checkpoints, copying checkpoints and exports off the host), not built in. |
| Does "export all records" mean all history? | No: all matching retained live records. Archived records are excluded and the bundle says so (`completeness.archivedRecordsExcluded`). Spanning archives is not implemented; this is a retention-policy choice, see [export-bundles.md](./export-bundles.md). |
| Why Java, Spring, JCS, Ed25519? Why was the Python service removed? | They are my choices, not PDF requirements: standard JCS/Ed25519 let a recipient verify without our code. I first built a second Python implementation to prove the protocol is specified, then removed it because it duplicated the Java service. What is lost: a live second implementation and an independent verifier; what remains: frozen golden fixtures and the Java offline verifier. See [adr/0001](./adr/0001-platform-and-layout.md). |
| Why is the key pinned out of band? | A bundle carries its own public key; trusting it proves nothing. Self-asserted mode exists but labels the origin untrusted. |
| Why did redaction need a cleanup job? | The delete commits first; `wal_checkpoint(TRUNCATE)` can report busy without throwing. The job makes that retryable and restart-safe. `PENDING` never means the delete rolled back. |
| Does redaction erase data? | Not physically. Backups, earlier exports, archive copies and storage remnants are outside it. |
| What happens if the archive write fails? | The transaction rolls back and plaintext stays live; the job is FAILED. A crash leaves PREPARING, which blocks new archives until reconcile. |
| Why a separate export-set protocol? | Small v1 bundles stay unchanged. Large selections are chunked from one frozen snapshot with a signed manifest; never silently truncated. |
| How do we know the crypto bytes are right? | The frozen golden fixtures were produced once by a separate implementation using the `cryptography` package and the public RFC 8032 test key; Java verifies them, and `jcs-v1.json` holds independently derived expected values. There is no live second implementation any more. |
| Is Scenario C confirmed? | No. It rests on labelled assumptions and no stakeholder has answered. |
| What would you not claim? | WORM, KMS custody, regulator readiness, physical erasure, detection of upstream events that never arrived. |

## Known weaknesses to volunteer

- Disk-full returns a generic 500.
- Spring Boot 3.5's open-source support ended 2026-06-30.
- CI, container images, OWASP dependency-check and the Linux memory probe have not been run to completion.
- Benchmarks are one Windows machine, not a capacity statement.
- Query cursors can show visibility drift after redaction or archive.

## Small event-contract extension rehearsal

**Goal:** add a new `channel` value, `MOBILE_APP`, to the `ACCOUNT_DATA_ACCESS` contract. This is a rehearsal of the
procedure; the value was **not** adopted and the code was reverted. The build requirement fixes the enum at five values.

**Why it is small:** the payload is hashed as opaque scalar leaves, so the hash protocol, schema, verifiers and bundles are
unchanged. Only the validators enumerate values.

**Steps rehearsed (Action 24):**

1. Java: add it to the channel set in `java/src/main/java/com/auditlog/domain/AccountAccessContract.java`.
2. Add one test that appends or validates `channel = MOBILE_APP`.
3. Update `docs/account-access-report.md` and the build-requirement enum list.
4. Run targeted tests, then `mvn -f java/pom.xml verify`.

**Actual result (rehearsed in Action 24 when a Python twin also existed):** the Java change and the targeted tests were run on the working tree, then reverted with `git checkout`.
Java `AccountAccessContractTests`, `AccountAccessReportServiceTests`, `AccountAccessReportHttpTests`: all passed (8, 9 and 3 tests, 0 failures). The full gates were not run for the
rehearsal, and the docs step was not applied.

**What would be needed for a real change:** a decision on rolling upgrades. Old verifiers and old service versions reject the new
value, so existing records stay valid but a mixed fleet would disagree on new appends. A change to the hashed content shape, by contrast, needs
a new `hashVersion` and a compatibility plan, because v1 is immutable.
