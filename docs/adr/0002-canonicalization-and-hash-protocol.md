# ADR-0002: Canonical JSON and v1 commitment protocol

- **Status:** Accepted as a protocol requirement; no implementation exists yet.
- **Context:** Cross-language verifiability requires identical byte-level
  encoding and immutable event semantics.
- **Decision:** Use UTF-8, RFC 8785 JCS, SHA-256, lowercase 64-hex hashes,
  domain-separated genesis/leaf/content/chain formulas, exact v1 content keys,
  RFC 6901 pointers, and fresh 32-byte random salts per scalar leaf. Preserve
  payload object/array shape and replace scalar leaves with commitments.
  Explicitly reject duplicate keys, non-finite numbers, lone surrogates,
  unsafe integer tokens, and over-limit inputs before recursive processing.
  Monetary precision is represented as strings. `occurredAt` is explicit null
  when absent; API timestamp maps to hashed `recordedAt`.
- **Compatibility:** Hash version 1 is immutable. Any changed encoding or
  semantics requires a new version and compatibility plan. Both services must
  use independently produced golden vectors.
- **Consequences:** JCS behavior, UTF-16 property ordering, ECMAScript number
  formatting, and pointer escaping are protocol obligations, not serializer
  defaults that may vary by language.
