# ADR-0006: Redaction and archive retention

- **Status:** Accepted as a supplied design constraint.
- **Context:** Payload privacy and retention must coexist with immutable
  evidence and recoverability across process/filesystem failures.
- **Decision:** Redaction operates on validated JSON pointers, expands selected
  scalar/container subtrees to exact deduplicated leaves, rejects invalid,
  no-op, archived and system targets, appends a system authorization event,
  removes both stored values and salts, and preserves the original commitment
  tree/hashes. Durable WAL cleanup is tracked, retried finitely and exposed as
  COMPLETE/PENDING without changing the committed HTTP outcome.
  Archive only the expired oldest contiguous live prefix. Prepare and
  durably publish a signed archive artifact with bounded record/byte sizes
  before clearing live business data; retain a verifiable skeleton and append
  authorization metadata after publication. Reconcile crash states on
  restart, preserve referenced files, and disclose platform durability limits.
- **Consequences:** Redaction cannot promise physical erasure from media,
  backups, previous exports or archive copies. Archive integrity and missing
  artifacts are audited separately from the hash chain. Normal queries/exports
  exclude archived records and disclose this exclusion.
