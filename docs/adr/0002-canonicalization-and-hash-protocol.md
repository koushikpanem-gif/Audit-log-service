# ADR-0002: Canonical JSON and v1 commitment protocol

- **Status:** Implemented for strict parsing, canonicalization, and v1 hashes;
  acceptance vectors are in `docs/test-vectors/`.
- **Context:** Independent verifiability requires identical byte-level
  encoding and immutable event semantics.
- **Decision:** Use UTF-8, RFC 8785 JCS, SHA-256, lowercase 64-hex hashes,
  domain-separated genesis/leaf/content/chain formulas, exact v1 content keys,
  RFC 6901 pointers, and fresh 32-byte random salts per scalar leaf. Preserve
  payload object/array shape and replace scalar leaves with lowercase 64-hex
  commitment hashes.
  Explicitly reject duplicate keys, non-finite numbers, lone surrogates,
  unsafe integer tokens, and over-limit inputs before recursive processing.
  Monetary precision is represented as strings. `occurredAt` is explicit null
  when absent; API timestamp maps to hashed `recordedAt`.
- **Payload handling:** Commitment tree construction and reveal use iterative
  traversal after 64-KiB byte, depth-10, and 500-scalar-leaf checks. Empty
  containers remain empty; null is committed as a scalar. Stored leaf values
  and salts are separate from the tree. Missing stored leaves reveal as
  `[REDACTED]` and UTF-16-sorted redacted pointers. RFC 6901 escapes are strict;
  array indices use canonical decimal notation. Fixed salt sources are test-only.
- **Compatibility:** Hash version 1 is immutable. Any changed encoding or
  semantics requires a new version and compatibility plan. Golden vectors
  must be independently produced.
- **Consequences:** JCS behavior, UTF-16 property ordering, ECMAScript number
  formatting, and pointer escaping are protocol obligations, not serializer
  defaults that may vary by language. Strict Jackson
  parsing is applied before the RFC 8785 canonicalizer. `jcs-v1.json` contains
  independent expected canonical bytes and SHA-256 values consumed by the
  test suite.
