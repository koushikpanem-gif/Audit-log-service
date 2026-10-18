# Cross-service parity (account-access report)

`python/tests/test_cross_service_parity.py` runs one scenario against both services and compares the results.

## How it runs

- The Java service is the built jar `java/target/audit-log-service-0.1.0-SNAPSHOT.jar`, started as a separate process (`java -Djava.io.tmpdir=<test dir> -jar ... --server.port=<free port>`) with its own DB, key, archive and export paths.
- The Python service runs in-process through Starlette's test client on its own DB file.
- Both use ledger id `parity-ledger` and the documented dev API keys.
- The test **skips** (never passes silently) if `java` or the jar is missing. The jar is not rebuilt by the test, so it reflects the last `mvn package`.

## Scenario

Six ACCOUNT_DATA_ACCESS events (granted, denied, OTHER, second actor, second account), four invalid payloads, one redaction of `/outcome`, then:

- 401, 403, both-subjects, missing-period and reversed-range error cases;
- the account report and the actor report.

## What is compared

Full JSON bodies, after replacing nondeterministic values with placeholders:

- ids: `eventId`, `reportId`, `bundleId`, `reportEventId`
- clocks: `timestamp`, `createdAt`, `verifiedAt`, `exportedAt`, `durationMs`
- hashes and signatures: `contentHash`, `prevHash`, `chainHash`, `headHash`, `recordsDigest`, `signature`, `checkpointSignature`, `publicKey`, `keyId`, `checkpointKeyId`
- `salt`
- `payloadCommitments` (salted; only the tree shape is compared)

Everything else must be identical, including counts, groups, exception rows and reasons, `UNKNOWN_REDACTED` handling, integrity block, exclusions, scope, the signed evidence structure (selection, completeness, disclosed leaves, signer fields) and `recordCap`.

Error responses are compared by status and `error.code` only. Message wording is free text and differs.

Each service's evidence is also verified offline with its own pinned key by the independent Python verifier; pinning the other service's key must fail.

## Not covered

- Salted hash values are not compared across services (they cannot be equal). Hash correctness is covered by the separate v1 vector tests.
- The 10000 cap and byte cap are tested only on Python (`tests/test_account_report.py`); Java has its own tests. The cap is not configurable on the Java process, so it is not exercised here.
- Tampered-ledger and archived-event reports are tested per service, not across services.
- Concurrency barriers are tested per service, not across services.
- Timing-dependent fields are normalized, so their values are not compared.
