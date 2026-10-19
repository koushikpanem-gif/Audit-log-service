# Configuration and checkpoint signing

This document records the configuration validation and the
framework-independent Ed25519 signer. Startup loads this configuration
for the secured append/query API and the later ledger workflows.

## Environment

| Variable | Default | Validation |
| --- | --- | --- |
| `AUDIT_ENV` | `dev` | Exactly `dev` or `prod`. |
| `AUDIT_LEDGER_ID` | `development-ledger` | Non-empty; at most 256 UTF-8 bytes. |
| `AUDIT_DB_PATH` | `audit-data/audit.db` | SQLite database path for this ledger. |
| `AUDIT_RETENTION_DAYS` | `2555` | Finite, positive, at most 500,000 days (bounded for safe date/duration arithmetic). Production requires at least 1 day. |
| `AUDIT_CHECKPOINT_INTERVAL` | `100` | Positive integer, maximum 1,000,000. |
| `AUDIT_REQUEST_LIMIT_BYTES` | `262144` | Positive integer, maximum 1 MiB. |
| `AUDIT_PAYLOAD_LIMIT_BYTES` | `65536` | Positive integer, no larger than request limit. |
| `AUDIT_MAX_DEPTH` | `10` | Positive integer, maximum 10. |
| `AUDIT_MAX_LEAVES` | `500` | Positive integer, maximum 500. |
| `AUDIT_SIGNING_PRIVATE_KEY` | `audit-data/signing-private.pem` | PKCS#8 PEM containing an unencrypted Ed25519 private key. |
| `AUDIT_SIGNING_PUBLIC_KEY` | `audit-data/signing-public.b64` | Standard Base64 of exactly 32 raw Ed25519 public-key bytes. |
| `AUDIT_API_KEYS_FILE` | unset | Required in production; when provided, it must be a valid API-key document. |

Any empty or malformed explicit value is invalid; it is not silently replaced
by the default. The key loader will generate a pair only in `dev` and only
when neither key file exists. It never replaces either member of an existing
or partial pair. On POSIX, new key files are owner read/write only. On Windows,
the implementation applies an ACL granting full control only to the current
account before writing key bytes; inability to establish that ACL fails key
creation. The development key directory must be protected by its parent
directory ACL. Do not use development key creation as a production key
provisioning process.

Production signer initialization requires the existing valid pair and an
existing API-key file. The documented API-key format contains key hashes,
never credentials:

```json
{
  "service-writer": {
    "keyHash": "64-lowercase-hex-characters",
    "roles": ["writer"]
  },
  "compliance-auditor": {
    "keyHash": "64-lowercase-hex-characters",
    "roles": ["auditor"]
  }
}
```

Principal names are 1–128 characters. The file must be strict JSON, no more
than 64 KiB, with 1–10,000 principals. Each entry has exactly `keyHash` and
`roles`; each hash is a 64-character lowercase SHA-256 hex digest, and roles
are distinct members of `writer`, `reader`, `auditor`, and `admin`. The hashes
are the SHA-256 digests of API-key bytes encoded as UTF-8. In `dev` only,
when `AUDIT_API_KEYS_FILE` is unset, the API accepts these fixed sample
credentials: `dev-writer-only`, `dev-reader-only`, `dev-auditor-only`, and
`dev-admin-only`. They are public, unsuitable for shared or production
environments, and must be replaced by an API-key file before deployment. The
admin sample has writer, reader, auditor, and admin roles. The Java
authenticator stores only the associated hashes and roles in memory.

## Checkpoint message

The signer constructs exactly
`{type,ledgerId,seq,chainHash,createdAt}` where `type` is
`audit-checkpoint/v1`, then signs that object’s RFC 8785 JCS UTF-8 bytes with
Ed25519. The signature is standard Base64. `keyId` is the first 16 lowercase
hex characters of SHA-256 over the raw public key; neither `keyId` nor
`signature` is inside the signed message. Sequence must be a positive safe
integer. A ledger service must reject checkpoint creation for an empty ledger.

The shared [Ed25519 vector](./test-vectors/ed25519-checkpoint-v1.json) is
explicitly test-only. Its private key is public by design and must never be
trusted or reused.
