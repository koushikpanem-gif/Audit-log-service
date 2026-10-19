# Export bundles (small v1) and the Java offline verifier

Status: small v1 bundles and the Java verifier (Action 10, aligned to the normative
contract in the fix pass). Selections over the configured limits are rejected explicitly
with no partial output; larger selections use the export-set protocol in
[export-sets.md](./export-sets.md).

## Scope of "export all records"

The assignment asks to export "all records" for a `resourceId` or `actorId`. This
implementation exports all **matching retained live records**. Records already
archived under the retention policy are not included (`completeness.scope =
"MATCHING_RETAINED_LIVE_RECORDS"`, `archivedRecordsExcluded: true`). This is a
deliberate retention-policy choice: archiving clears business data from the live
store, so it cannot be re-exported from there. A historical export spanning archives
is **not implemented**; archived data lives in signed archive bundles verified by the
archive audit. A recipient must not read a bundle as proof that no older archived
records exist for the selection.

## Schemas

JSON Schema (draft 2020-12) files in [`schemas/`](./schemas): `selection`, `completeness`,
`checkpoint`, `record`, `bundle`, `diagnostics`. A minimal signed example is
[`schemas/examples/minimal-valid-bundle.json`](./schemas/examples/minimal-valid-bundle.json)
(non-production RFC 8032 test key). Schemas check shape only. Cross-field rules (digest,
count, order, selection matching, hashes, signatures) are enforced by the verifier.

## Endpoint

`GET /audit/export` (auditor or admin) with `actorId`, `resourceType`, `resourceId`,
`eventType`, `from`, `to`. `actorId` or `resourceId` is required; filters are ANDed;
`from`/`to` are inclusive microsecond UTC timestamps on `recorded_at`; reversed ranges and
malformed values give 422. The HTTP body is exactly the final JCS bytes that were signed
(`application/json`).

| Status | Meaning |
|---|---|
| 200 | Signed `audit-export-bundle/v1` |
| 422 `EXPORT_LIMIT_EXCEEDED` | Selected records exceed `AUDIT_EXPORT_MAX_RECORDS` (default 1000, max 100000) or the final canonical bundle exceeds `AUDIT_EXPORT_MAX_BYTES` (default 8 MiB, max 64 MiB). `details` lists both limits; no data is returned, nothing is committed (no `BUNDLE_EXPORTED` event, no checkpoint). Narrow the selection. |

There is no empty-ledger 409: an empty selection is a valid signed bundle with
`throughSeq: 0`, because the `BUNDLE_EXPORTED` event makes the checkpoint non-empty.

## Bundle body

`format, bundleId, purpose, ledgerId, hashAlgorithm, hashVersion, genesisHash,
signatureAlgorithm, exportedAt, exportedBy, selection, completeness, recordCount,
recordsDigest, records, headCheckpoint, signer, signature`.

- `signature = Ed25519(JCS(body without signature))`, standard Base64.
- `recordsDigest = SHA256(JCS(records))`, lowercase hex, no domain prefix.
- `selection` always has exactly eight keys: `actorId, resourceType, resourceId, eventType,
  from, to, seqFrom, seqTo` (null when unused). Archive exports use seq bounds and no
  ordinary filters; HTTP exports keep seq bounds null; archived records are never included.
- `completeness` is exactly `{scope:"MATCHING_RETAINED_LIVE_RECORDS", throughSeq,
  archivedRecordsExcluded:true, upstreamCoverage:"NOT_PROVEN", assurance:"SIGNED_ASSERTION"}`.
  `throughSeq` is the head captured in the export transaction before the meta-event, so
  every record has `seq <= throughSeq <= headCheckpoint.seq`. The head checkpoint and
  `exportedAt` are the post-event head (`BUNDLE_EXPORTED`, which is not in the records).
- Records: `seq, eventId, eventType, actorId, resourceType, resourceId, occurredAt, timestamp,
  source, hashVersion, payloadCommitments, disclosedLeaves, contentHash, prevHash,
  chainHash`. A leaf that was redacted is simply absent from `disclosedLeaves`.
- `BUNDLE_EXPORTED` payload: `bundleId, purpose, throughSeq, recordCount, recordsDigest,
  selectionDigest` (SHA-256 of JCS(selection), so no selection values), `requestedBy`.

## Offline verifier

`com.auditlog.verifier.BundleVerifierCli` depends only on `core.crypto` and `domain`.

```
BundleVerifierCli --bundle bundle.json (--pinned-key-file key.b64 | --pinned-key BASE64
                  | --allow-self-asserted) [--max-bytes N] [--max-records N]
```

| Exit | Meaning |
|---|---|
| 0 | Valid. `VERIFIED` (pinned key matched) or `INTEGRITY_VALID_ORIGIN_UNTRUSTED` (self-asserted, with a prominent warning; never printed as plain VERIFIED) |
| 1 | Evidence invalid: schema, resource limit, signature, hashes, or no trusted key (`TRUSTED_KEY_REQUIRED`) |
| 2 | Input/usage: unreadable file, bad arguments, malformed pinned key, conflicting trust options |

Defaults: 64 MiB input, 100000 records, depth 32. Input is not required to be canonical.

Diagnostic codes (at most 100 kept, exact total reported): `BUNDLE_SCHEMA_INVALID,
UNSUPPORTED_FORMAT, UNSUPPORTED_ALGORITHM, RESOURCE_LIMIT_EXCEEDED, TRUSTED_KEY_REQUIRED,
SIGNER_KEY_MISMATCH, KEY_ID_MISMATCH, BUNDLE_SIGNATURE_INVALID, CHECKPOINT_SIGNATURE_INVALID,
CHECKPOINT_MISMATCH, GENESIS_MISMATCH, RECORD_COUNT_MISMATCH, RECORDS_DIGEST_MISMATCH,
RECORD_ORDER_INVALID, RECORD_OUT_OF_RANGE, SELECTION_MISMATCH, LEAF_COMMITMENT_MISMATCH,
CONTENT_HASH_MISMATCH, CHAIN_HASH_MISMATCH, CHAIN_LINK_BROKEN`.

Mapping decisions (assumptions for engineer review): `hashVersion != 1` ->
`UNSUPPORTED_ALGORITHM`; filter or seq-bound violation -> `SELECTION_MISMATCH`;
`seq > throughSeq` or beyond the head -> `RECORD_OUT_OF_RANGE`; head hash mismatch or
`head.seq < throughSeq` -> `CHECKPOINT_MISMATCH`; non-canonical timestamp ->
`BUNDLE_SCHEMA_INVALID`; a malformed `--pinned-key` is a usage error (exit 2).

## Compatibility decision

The first Action 10 commit (`d2a1b92`) used invented `selection`/`completeness` shapes,
invented diagnostic codes, exit 2 for a missing key and a 409 for an empty ledger. Nothing
was released or pushed, so the fix pass supersedes those shapes without a compatibility
layer. The fix is a separate commit so the history stays honest.

## What the tests prove

- Java builder -> Java verifier round trips and re-signing with the same key prove internal
  consistency only. They are not independent crypto evidence.
- Frozen golden fixtures (`java/src/test/resources/golden/bundle_vectors`) were produced once by a
  separate implementation (a since-removed Python generator using the `cryptography` package)
  with the public RFC 8032 section 7.1 TEST 1 key (non-production). Java verifies them
  but never regenerates them.
- Independently signed edge-case fixtures (`java/src/test/resources/golden/independent_signed`)
  are verified by `GoldenSignedFixtureTests`, including rejection under a wrong or missing key.
- There is no longer a second implementation or a second verifier, so there is no live
  cross-implementation check; independence rests on these frozen fixtures only.
- Not proven: benchmarks beyond the single-machine run in performance.md; multi-process behaviour of the verifier; the
  Windows-skipped symlink test.

## Limits

- A missing disclosed leaf is undisclosed/redacted; it is not proof that a redaction was
  authorized (that needs authorization events).
- Filtered selections have no global inclusion proof; completeness is a signer assertion
  (`SIGNED_ASSERTION`) and upstream coverage is `NOT_PROVEN`.
- A pinned-key pass shows the pinned signer produced the bundle, not that its claims are
  complete. Key compromise is out of scope.
