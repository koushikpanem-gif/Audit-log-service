# Account-access report (Scenario C, Java implementation)

Status: implemented in Java (Action 15). The Python service does not implement it yet. All Scenario C
answers in [scenario-c.md](./scenario-c.md) remain **assumptions** with no stakeholder confirmation;
the engineer owns the design and sign-off.

## ACCOUNT_DATA_ACCESS contract

Enforced on `POST /audit/events` when `eventType` is `ACCOUNT_DATA_ACCESS` (422 otherwise):

- `resourceType` must be `CLIENT_ACCOUNT`; `resourceId` is the account.
- Payload enums: `dataCategory` (PROFILE, IDENTIFIERS, BALANCES, POSITIONS, TRANSACTIONS, STATEMENTS,
  TAX_DOCUMENTS, BANKING_DETAILS), `accessType` (VIEW, SEARCH, EXPORT, PRINT, MODIFY), `accessPurpose`
  (CLIENT_REQUEST, TRADE_SUPPORT, SERVICING, COMPLIANCE_REVIEW, FRAUD_INVESTIGATION, LEGAL_HOLD, OTHER),
  `channel` (INTERNAL_APP, SUPPORT_TOOL, CLIENT_PORTAL, API, BATCH), `outcome` (GRANTED, DENIED).
- `accessPurpose=OTHER` requires non-blank `justification` (max 1000); `outcome=DENIED` requires non-blank
  `denialReason` (max 500). Optional `sessionId` (max 128) and `sourceIp` (max 64). Extra fields allowed.
- Error messages name fields only and never echo values.

## GET /compliance/account-access-report

Auditor or admin. Parameters: exactly one of `accountId` or `actorId`, plus explicit `from` and `to`
(inclusive UTC, compared with the server `recordedAt`). Anything else is 422.

In ONE write transaction: verify the whole ledger -> select retained-live matching events up to the
verified head -> build signed evidence -> append `COMPLIANCE_REPORT_GENERATED` -> sign a checkpoint.
Concurrent append, redaction and archive wait for the lock, so the verified head, selected records and
evidence describe the same state. Trade-off: full verification runs under the write lock.

Response: `verifiedDataHead` (the state that was verified and reported on) and `postReportHead` (the report
event and its checkpoint) are separate. `integrity` carries chain status, counts and up to 100 earliest
violations; `trustworthy`/`trustLabel` say `NOT TRUSTWORTHY` when verification failed (the evidence
signature does not repair an invalid ledger; the meta-event and checkpoint are still written and labeled).
`counts` and `groups` aggregate by actor/category/purpose/outcome/type. A grouping leaf that was redacted
is counted as `UNKNOWN_REDACTED` (never assumed granted or denied); an out-of-enum value is
`UNKNOWN_INVALID`. `exceptions` lists DENIED, `OTHER` and unknown-field rows by structured fields only.
`evidence` is a signed `audit-export-bundle/v1` with purpose `COMPLIANCE_REPORT`, verifiable with the
existing bundle verifier and a pinned key. The meta-event stores a digest of the selection, not the subject.

Cap: more than 10000 matching events (or evidence over the export byte limit) gives 422
`REPORT_LIMIT_EXCEEDED`, asks for a narrower period, writes nothing and returns no partial result.
Bulk export-all is separate.

Exclusions stated in every report: archived events, upstream events never received (not detectable),
no regulator portal, no legal opinion.
