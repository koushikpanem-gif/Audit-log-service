# Export sets (bounded complete bulk exports)

Small selections use the signed `audit-export-bundle/v1` bundle (`GET /audit/export`, see
[export-bundles.md](export-bundles.md)). When a selection exceeds the small limits that endpoint
returns `422 EXPORT_LIMIT_EXCEEDED` and never truncates. Larger selections use an export set: an
immutable set of chunk files plus a signed manifest, all frozen to one snapshot/head.

## API (auditor or admin role)

| Call | Result |
| --- | --- |
| `POST /audit/export-sets?actorId&resourceType&resourceId&eventType&from&to` | `202` + `Location`, descriptor. All filters optional; no filters selects every retained live record (assumption). No body. |
| `GET /audit/export-sets/{id}` | descriptor: `status` RUNNING / READY / FAILED / EXPIRED, counts, heads, URLs, `errorCode` when FAILED |
| `GET /audit/export-sets/{id}/manifest` | signed manifest (READY only) |
| `GET /audit/export-sets/{id}/chunks/{name}` | one chunk; `name` must match `chunk-[0-9]{6}.json` and be listed in the manifest |

Errors: unknown/malformed id or name `404`; not READY `409`; expired `410`; too many active jobs
`429`. A failed job reports its code in the descriptor (`EXPORT_SET_TOO_LARGE`,
`EXPORT_RECORD_TOO_LARGE`, `EXPORT_TOO_MANY_CHUNKS`, `EXPORT_IO_FAILURE`, `EXPORT_INTERRUPTED`).
Nothing is ever silently dropped: a limit breach fails the job.

## Configuration

`AUDIT_EXPORT_DIR` (default `<db dir>/exports`), `AUDIT_EXPORT_CHUNK_MAX_RECORDS` (1000, max 100000),
`AUDIT_EXPORT_CHUNK_MAX_BYTES` (8 MiB, max 64 MiB), `AUDIT_EXPORT_SET_MAX_RECORDS` (1,000,000, max
10,000,000), `AUDIT_EXPORT_SET_TTL_SECONDS` (86400, 60..2,592,000).

## Protocol

1. Snapshot transaction fixes `selectionHead` (`throughSeq`); records stream in `seq` order into
   chunk files written to `staging/<id>/` (temp file, fsync, atomic rename). Memory is bounded by one
   record plus one chunk buffer. A chunk holds at most the record and byte limits.
2. One write transaction appends `BUNDLE_EXPORTED` (payload: exportSetId, throughSeq, totals,
   digests, requester; never the selection values), stores a signed checkpoint, signs the manifest.
   Selection happens before this event, so `selectionHead` (`completeness.throughSeq`) differs from
   `headCheckpoint` (post-event head); the manifest carries both.
3. The staging directory is atomically renamed to `ready/<id>/`, then the job file is set READY.
   READY is therefore durable only after publication.
4. Restart recovery: temp job files and orphan directories are removed; RUNNING jobs whose ledger
   event is committed and whose staged chunks match the manifest digests are published, others
   FAIL as `EXPORT_INTERRUPTED`. Expired sets are deleted lazily and on restart.

Manifest (`audit-export-set-manifest/v1`, schema `schemas/export-set-manifest.schema.json`): signed
over JCS of the body without `signature`. Fields: format, exportSetId, purpose, ledgerId, hash and
signature algorithms, genesisHash, createdAt, expiresAt, exportedBy, selection, completeness,
selectionHead, headCheckpoint, totalRecords, chunkCount, chunkLimits, chunks
(`index,name,recordCount,firstSeq,lastSeq,bytes,sha256`), `chunksDigest` = SHA-256(JCS(chunks)),
exclusions (archived records, non-matching records, records after the selection head: EXCLUDED;
upstream coverage: NOT_PROVEN), signer, signature. Chunk file: JCS of
`{format:"audit-export-chunk/v1",exportSetId,index,records}` with records in the v1 bundle record shape.

## Verification

`ExportSetVerifier` / `BundleVerifierCli --manifest <manifest.json> --pinned-key <b64>` (exit 0/1/2)
checks the signature and pinned key, genesis, counts and digests, ordered unique chunk names, safe
names (no path separators, symlinks refused), bounded reads, per-record hashes, links across chunk
boundaries, and flags unlisted chunk files. Codes: `CHUNK_MISSING`, `CHUNK_DIGEST_MISMATCH`,
`CHUNK_ORDER_INVALID`, `CHUNK_COUNT_MISMATCH`, `CHUNK_NAME_UNSAFE`, `CHUNK_UNEXPECTED`,
`TOTAL_COUNT_MISMATCH`, `CHUNKS_DIGEST_MISMATCH` plus the bundle codes.

## Limits

The offline verifier (`BundleVerifierCli`, see [export-bundles.md](./export-bundles.md)) verifies sets. Active
job count is per process (16). Directory fsync is best effort on Windows. A signer can sign an
incomplete set; completeness relies on the signer. Archived records and upstream gaps are excluded
and not provable.
