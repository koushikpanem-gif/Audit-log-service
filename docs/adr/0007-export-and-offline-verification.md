# ADR-0007: Signed export bundles and chunked export sets

- **Status:** Accepted as a supplied format requirement.
- **Context:** Small exports need a stable v1 format; large exports must not be
  silently truncated or require unbounded memory.
- **Decision:** Preserve the exact semantic v1 bundle fields and per-record
  fields, sign JCS(body without signature), and digest JCS(records) with no
  domain prefix. Small outputs remain JSON bundles. Large results use a
  versioned signed manifest and immutable bounded chunks frozen to one
  snapshot/head, with record and byte limits, selection/exclusion scope,
  ordered names/digests/counts, expiry, and atomic READY publication.
  Downloads require auditor authorization and safe path handling. Export
  selection precedes its BUNDLE_EXPORTED event; distinguish selection head
  from post-event head.
- **Consequences:** Verify algorithms, versions, signatures, key IDs, genesis,
  counts, records digest, leaf/content/chain integrity, ordering, links, head,
  chunks and safe paths using bounded resources. Filtered gaps are not global
  inclusion proofs; signed completeness relies on the signer. Missing
  disclosed values do not independently prove authorized redaction.
