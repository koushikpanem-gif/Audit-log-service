# Export bundles (v1) and the Java offline verifier

Status: implemented in Action 10 for small selections. Export sets for large selections
are a later action; until then oversized selections are rejected explicitly.

## Endpoint

`GET /audit/export?actorId=...` or `GET /audit/export?resourceId=...` (auditor or admin).
Exactly one selector is required (422 otherwise). Responses:

| Status | Meaning |
|---|---|
| 200 | Signed `audit-export-bundle/v1` JSON |
| 409 `EMPTY_LEDGER` | No checkpoint can exist for an empty ledger |
| 422 `EXPORT_TOO_LARGE` | More than 1000 records or 8 MiB canonical bytes (assumption, configurable in code); narrow the selection. No partial result is returned and no export event is written |

Selection, the signed head checkpoint and the `BUNDLE_EXPORTED` system event happen in one
`BEGIN IMMEDIATE` transaction. Archived records are excluded; the bundle says so.

## Bundle body

Fields exactly as specified: `format`, `bundleId`, `purpose`, `ledgerId`, `hashAlgorithm`,
`hashVersion`, `genesisHash`, `signatureAlgorithm`, `exportedAt`, `exportedBy`, `selection`,
`completeness`, `recordCount`, `recordsDigest`, `records`, `headCheckpoint`, `signer`, plus
`signature = Ed25519(JCS(body without signature))`. `recordsDigest = SHA256(JCS(records))`
with no domain prefix. Records carry `disclosedLeaves` for leaves still stored; redacted
leaves are simply absent.

Assumed shapes (the brief fixes names only; engineer review needed):

- `selection`: `{criteria:{actorId|resourceId}, order:"seq-asc", archivedRecords:"EXCLUDED"}`.
- `completeness`: `{statement, selectionHeadSeq, selectionHeadChainHash, postEventSeq,
  postEventChainHash, exportEventId}`. The selection head is the signed `headCheckpoint`;
  the post-event head includes the `BUNDLE_EXPORTED` event, which is not in the bundle.
- `BUNDLE_EXPORTED` payload: `bundleId, purpose, selectionType, selectionHeadSeq,
  selectionHeadChainHash, recordCount, recordsDigest, requestedBy` (no selection value).

## Offline verifier

`com.auditlog.verifier.BundleVerifierCli` depends only on `core.crypto`.

```
java -cp java\target\classes;<jackson jars> com.auditlog.verifier.BundleVerifierCli ^
  --bundle bundle.json (--pinned-key-file key.b64 | --pinned-key BASE64 | --allow-self-asserted)
  [--max-bytes N] [--max-records N]
```

Exit codes: 0 verified, 1 evidence invalid, 2 input/usage error (unreadable, over-limit,
non-strict JSON, missing key choice). A pinned key is required by default; `--allow-self-asserted`
uses the bundle's own key, prints `UNTRUSTED_SELF_ASSERTED_KEY` and proves only internal
consistency. Defaults: 64 MiB input, 100000 records, depth 32.

Checks: exact field sets; format/algorithms/hashVersion/purpose; signer key and keyId;
pinned-key equality; bundle signature; genesis; record count and digest; per record the
leaf commitments, content hash, chain hash, strictly increasing seq, adjacent `prevHash`
links, seq 1 genesis; head checkpoint signature, keyId, no record newer than the head, and
head chain-hash equality. Violation codes: `SCHEMA_INVALID`, `SIGNER_INVALID`, `KEY_NOT_PINNED`,
`SIGNATURE_INVALID`, `GENESIS_MISMATCH`, `RECORD_COUNT_MISMATCH`, `RECORDS_DIGEST_MISMATCH`,
`MALFORMED_RECORD`, `ORDER_INVALID`, `LEAF_POINTER_UNKNOWN`, `LEAF_COMMITMENT_MISMATCH`,
`CONTENT_HASH_MISMATCH`, `CHAIN_HASH_MISMATCH`, `CHAIN_LINK_BROKEN`, `HEAD_CHECKPOINT_INVALID`,
`RECORD_AFTER_HEAD`, `HEAD_MISMATCH` (at most 100 are listed; the exact total is reported).

## Limits

- A missing disclosed leaf is reported as undisclosed/redacted. The bundle does not prove it
  was authorized; that needs the ledger's authorization events.
- Filtered selections have no global inclusion proof; completeness is asserted by the signer.
- A verified bundle with a pinned key proves the signer produced it, not that the signer's
  claims are complete. Key compromise is out of scope.
- No Python verifier, no cross-language bundle vectors and no export-set chunks yet.
