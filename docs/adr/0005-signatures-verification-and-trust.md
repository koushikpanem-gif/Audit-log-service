# ADR-0005: Signatures, verification, and trust limits

- **Status:** Accepted as a supplied protocol and trust model.
- **Context:** Hash chains provide local consistency evidence but do not alone
  establish trusted origin or detect every form of truncation.
- **Decision:** Use Ed25519 over JCS messages. Private keys are PKCS#8 PEM;
  public keys are raw 32-byte Ed25519 values encoded in Base64; key IDs are the
  first 16 hex characters of SHA-256(raw public key). Checkpoints sign exactly
  the specified checkpoint message, never exist for an empty ledger, and are
  created at configured intervals and on demand. Scan ordered bounded batches
  in one snapshot, validate schemas/versions/leaves/hashes/links/checkpoints,
  and retain at most 100 earliest deterministic diagnostics while counting all
  violations. Verifiers require an out-of-band pinned key by default;
  self-asserted mode is explicitly untrusted.
- **Key-pair validation:** Both implementations load the private key as PKCS#8
  PEM, accept only Ed25519, decode the public key as strict standard Base64 of
  exactly 32 raw bytes, and prove the pair matches before signing. Java wraps
  raw public bytes in the Ed25519 SubjectPublicKeyInfo prefix only when passing
  them to the JDK provider; that DER encoding is never exposed as the protocol
  public key.
- **Key-file lifecycle:** Development may create `signing-private.pem` and
  `signing-public.b64` exclusively when neither exists. POSIX files are created
  with owner-only read/write permissions; Windows applies a current-account
  `icacls` ACL before writing key bytes. A partial pair is an error, never an
  invitation to replace a key. Production accepts only an existing valid pair
  and a valid API-key file. See [configuration and signing](../configuration-and-signing.md)
  for environment names and file format.
- **Fixture:** The shared `ed25519-checkpoint-v1.json` test vector contains a
  fixed private key explicitly marked TEST ONLY. It exists solely to prove
  Java/Python signature-byte compatibility and must never be used operationally.
- **Consequences:** Report all specified violation types and counters.
  See [verification](../verification.md) for the implemented Java verifier,
  its authorization schemas and demonstrated limits.
  Authorization events must themselves validate before they authorize
  redaction/archive. No claim is made against full rewrite, uncheckpointed
  tail loss, removal of local checkpoints, administrator access, or key
  compromise. The Python offline verifier must not import Java service code.
