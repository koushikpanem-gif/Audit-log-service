# Audit Log Service

This workspace is at Action 01: requirements and ownership definition. No audit
ledger, API, verifier, or compliance report has been implemented by this action.
The full supplied build specification is preserved in
[`docs/BUILD_REQUIREMENTS.txt`](./docs/BUILD_REQUIREMENTS.txt).

## Scope and ownership

The intended deliverables are:

- Scenario A: append, query, and verify audit events.
- Scenario B: redact, retain/archive, and export verifiable evidence.
- Scenario C: an internally used, on-demand account-access report, subject to
  the questions and provisional assumptions in
  [`docs/scenario-c.md`](./docs/scenario-c.md).

The engineer owns design decisions, stakeholder clarification, implementation
review, and sign-off. The attestation in
[`docs/attestation-template.md`](./docs/attestation-template.md) is an unsigned
template only. No stakeholder answer, test result, or human approval is
asserted here.

## Intended layout and technology

The assignment specifies Java 21 / Spring Boot 3 / Maven and a separate Python
3.11+ / Starlette service, with shared protocol contracts under `docs/`,
operational scripts under `scripts/`, and CI under `.github/workflows/`.
Implementation belongs in `java/` and `python/`.

The workspace currently contains a pre-existing Spring Boot starter at the
repository root (`pom.xml`, `src/`, and Maven wrapper). Action 01 leaves it
untouched. Reconcile this starter layout and its dependency versions against
the assignment before implementation; do not treat it as delivered audit-log
functionality.

## Current action validation

This action changes documentation and secret-ignore rules only. The focused
checks and their actual results are recorded in [`AI_USAGE_LOG.md`](./AI_USAGE_LOG.md).
Java/Python behavioral gates are deferred until affected implementation
modules exist; no feature is claimed to pass them.

## Next action

Stop for engineer review of requirements, ownership, and the unresolved
Scenario C questions before beginning implementation.
