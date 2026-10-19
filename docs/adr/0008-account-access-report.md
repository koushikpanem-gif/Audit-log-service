# ADR-0008: Internal account-access compliance report

- **Status:** Implemented in Java (Action 15) on unconfirmed assumptions; see
  [account-access-report.md](../account-access-report.md). Stakeholder/engineer clarification is still pending.
- **Context:** The assignment requests an account-access report but explicitly
  requires unresolved business/legal questions to remain visible.
- **Decision:** The provisional scope is an on-demand report for an internal
  auditor, exactly one account or actor and explicit time range. Use the
  specified `ACCOUNT_DATA_ACCESS` schema and enums; in a consistent snapshot
  verify the selected data head, select retained live events, derive evidence,
  append a report event and checkpoint. Keep verified data head distinct from
  post-report checkpoint. Group by actor/category/purpose/outcome/type, show
  denied/OTHER exceptions, and classify redacted grouping leaves only as
  `UNKNOWN_REDACTED`. Cap synchronous reports at 10,000 with explicit 422, not
  partial success.
- **Consequences:** Label integrity-failed reports untrustworthy and disclose
  retained-live, archive and upstream coverage limits. This does not provide a
  regulator portal or legal opinion and cannot detect events never received.
  Questions and assumptions in `scenario-c.md` still require owner review; the
  implementation may change when answers arrive.
