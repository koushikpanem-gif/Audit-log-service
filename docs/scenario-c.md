# Scenario C — account-access report clarification

## Current status

No stakeholder answers have been provided. The statements below are questions
for the engineer/business owner, followed by provisional assumptions that must
not be represented as confirmed requirements. The working clarified statement
is explicitly provisional.

## Questions requiring owner input

1. **Account data scope:** Which account identifiers and account types are in
   scope? How are joint, delegated, closed, test, or merged accounts treated?
2. **Access attempts and denials:** Must attempted-but-blocked, failed, and
   denied accesses be recorded as well as successful access? Which upstream
   events are authoritative?
3. **Report subjects and period:** Who may request a report, and may the
   requester select either an account or an actor? What time zone and maximum
   period should be permitted?
4. **Regulator access:** Is the report solely for an internal auditor, or is
   direct regulator access required? What identity, workflow, and delivery
   controls would be required before any external access is considered?
5. **Privacy and minimization:** Which actor, IP, session, account, or event
   fields may be shown, masked, or withheld? Who may access report artifacts?
6. **Retention and legal holds:** How long are access events and reports
   retained? How do legal holds affect redaction, archive, expiry, and report
   availability?
7. **Upstream instrumentation:** Which systems emit access events, how are
   their events authenticated and delivered, and what coverage/latency gaps
   exist?
8. **Completeness:** What evidence can establish source coverage? Are missing
   events detectable, or can the service only attest to events it received?
9. **Data minimization:** Should reports contain event details, grouped counts,
   exceptions, or links to separately authorized evidence? What fields are
   necessary for an audit purpose?
10. **Operational limits:** Is the specified synchronous 10,000-record cap
    acceptable, and what user-facing workflow should handle larger periods?

## Provisional assumptions (not stakeholder answers)

- The requested product is an **internal auditor** report, not a regulator
  portal or legal opinion.
- A report is on-demand and must identify exactly one account or actor and an
  explicit inclusive time range.
- Only retained live `ACCOUNT_DATA_ACCESS` events are included; archived,
  expired, uncollected upstream events are explicit exclusions.
- Event completeness is limited to events actually received and accepted by
  this service; the service cannot infer missing upstream events.
- The report must preserve evidence integrity, display a verified data head
  separately from the report event/checkpoint head, and label integrity-failed
  output as untrustworthy.
- Missing grouping fields caused by redaction are counted as
  `UNKNOWN_REDACTED`; outcomes are never inferred.
- No externally mandated legal retention period, privacy policy, regulator
  workflow, or production data source is assumed here.

These assumptions require engineer/business-owner approval or replacement
before implementation. The build specification's enum and size constraints are
captured in `BUILD_REQUIREMENTS.txt` and the acceptance IDs in
`requirements-mapping.md`.

## Provisional clarified statement

> As an authorized internal auditor, I can request a bounded account-access
> report for exactly one account or actor over an explicit time range. The
> report summarizes retained live access events, identifies denied and
> `OTHER`-purpose exceptions, reports redacted grouping values as
> `UNKNOWN_REDACTED`, and provides signed evidence tied to a verified data
> snapshot. It clearly discloses integrity failures and the limits imposed by
> archived, expired, and upstream events not received by the service. It does
> not provide a regulator portal or legal opinion.

This wording is a proposed baseline, not a recorded business decision.
