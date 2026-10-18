# API and schema reference

Identical in both services (Java port 8080, Python port 8000). Authentication is the `X-API-Key` header.
Machine-readable contracts: `GET /openapi.json` (each service) and the JSON Schemas in [`schemas/`](./schemas).
Python's `/docs` is a plain HTML route table; Java's `/docs` is the springdoc UI.

## Roles and routes

Roles: `writer`, `reader`, `auditor`, `admin` (the admin sample key holds all roles).
Dev sample keys (public, development only): `dev-writer-only`, `dev-reader-only`, `dev-auditor-only`, `dev-admin-only`.

| Route | Roles | Notes |
|---|---|---|
| `GET /health`, `GET /audit/public-key`, `GET /openapi.json`, `GET /docs` | public | |
| `POST /audit/events` | writer, admin | 201; body `{eventType,actorId,resourceType,resourceId,payload,occurredAt?}`, unknown fields rejected |
| `GET /audit/events` | reader, auditor, admin | filters `actorId,resourceType,resourceId,eventType,from,to`; `limit` (50, max 500); `order` asc/desc; opaque `cursor` |
| `GET /audit/events/{eventId}` | reader, auditor, admin | 404 if missing or archived |
| `GET /audit/checkpoints` | auditor, admin | |
| `POST /audit/admin/checkpoints` | admin | 201; 409 on an empty ledger |
| `GET /audit/verify` | auditor, admin | full-chain report (see [verification.md](./verification.md)) |
| `GET /audit/export` | auditor, admin | one signed bundle; needs `actorId` or `resourceId`; 422 `EXPORT_LIMIT_EXCEEDED` above limits |
| `POST /audit/export-sets` | auditor, admin | 202 + `Location`; for selections too large for one bundle |
| `GET /audit/export-sets/{id}`, `/manifest`, `/chunks/{name}` | auditor, admin | 404 unknown, 409 not READY, 410 expired, 429 `EXPORT_SET_BUSY` (16 active jobs) |
| `POST /audit/admin/redactions` | admin | `{eventId,paths,reason,ticketId}`; 201 with `cleanupStatus` COMPLETE or PENDING |
| `GET /audit/admin/redaction-cleanups`, `POST .../retry` | admin | |
| `POST /audit/admin/archive` | admin | `{dryRun:boolean}` |
| `GET /audit/admin/archive-jobs`, `POST .../archive-jobs/reconcile` | admin | |
| `GET /audit/archive-audit` | auditor, admin | archive files, digests, signatures against the skeleton |
| `GET /compliance/account-access-report` | auditor, admin | exactly one of `accountId`/`actorId`, plus `from` and `to` |

There is no event PUT, PATCH or DELETE. Verified in both services' route tables (`AuditController.java`, `app.py`) and role tables
(`ApiSecurityInterceptor.java`, `auth.py`).

## Error shape and statuses

`{"error":{"code":"...","message":"...","details":[]}}`. No stack traces or payload values.
401 missing/invalid key, 403 role, 404 missing, 409 conflict, 413 size, 422 invalid input, 503 database busy
(generic message). A disk-full condition currently surfaces as a generic 500 in both services (see
[performance.md](./performance.md)); that is an open engineer decision.

## Limits (defaults)

Request 256 KiB, payload 64 KiB, depth 10, scalar leaves 500; query page 50 (max 500); small export 1000 records / 8 MiB;
export set 1,000,000 records; report cap 10,000 records; `occurredAt` at most 300 s in the future. Caller-supplied
timestamps are rejected with 422. Reserved types `RECORD_REDACTED`, `RECORDS_ARCHIVED`, `BUNDLE_EXPORTED`,
`COMPLIANCE_REPORT_GENERATED` and source `system` cannot be submitted. Environment variables are listed in
[configuration-and-signing.md](./configuration-and-signing.md) and [python-service.md](./python-service.md).

## Pagination caveat

Cursors are bound to the filters, order and first-page head (`asOfSeq`) and use seq keyset paging, never OFFSET.
A redaction or archive between pages can change what later pages show. This is a disclosed limitation.

## Schemas

| File | Describes |
|---|---|
| [`schemas/bundle.json`](./schemas/bundle.json) | `audit-export-bundle/v1` |
| [`schemas/record.json`](./schemas/record.json) | one exported record |
| [`schemas/checkpoint.json`](./schemas/checkpoint.json) | `headCheckpoint` |
| [`schemas/selection.json`](./schemas/selection.json), [`completeness.json`](./schemas/completeness.json) | selection and completeness blocks |
| [`schemas/export-set-manifest.json`](./schemas/export-set-manifest.json) | signed export-set manifest |
| [`schemas/diagnostics.json`](./schemas/diagnostics.json) | verifier diagnostics |

Schemas check shape only. Digests, counts, ordering, hashes and signatures are enforced by the verifiers. Test vectors:
[`test-vectors/`](./test-vectors). Protocol details: [adr/0002](./adr/0002-canonicalization-and-hash-protocol.md),
[adr/0005](./adr/0005-signatures-verification-and-trust.md), [adr/0007](./adr/0007-export-and-offline-verification.md).
