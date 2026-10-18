# ADR-0001: Platform and repository layout

- **Status:** Accepted as the supplied assignment baseline; both services
  are implemented under `java/` and `python/`; the pre-existing root starter is untouched and unused, and its
  disposition is pending engineer review.
- **Context:** The assignment requires two interoperable services and an
  independent offline verifier. The workspace already has a root-level Spring
  starter, which is not the specified Java location.
- **Decision:** Target Java 21, Spring Boot 3, Maven, Jackson, SQLite JDBC,
  springdoc OpenAPI, JUnit 5 and JaCoCo; use plain JDBC through
  `AuditRepository`, no JPA. Keep core/domain/store/service/verify/verifier
  framework-independent and Spring limited to web/config. Target Python >=3.11,
  Starlette, Pydantic 2, cryptography, pytest, ruff and mypy; keep its offline
  verifier independent of the Java service. Use `java/`, `python/`, `docs/`,
  `docs/adr/`, `scripts/` and `.github/workflows/`; use separate DB files when
  running the services independently.
- **Version policy:** Resolve compatible supported patch versions from
  official sources at bootstrap, pin exact resolved dependencies, and record
  rationale. Do not guess latest versions or preserve obsolete pins.
- **Consequences:** Existing root `pom.xml`/`src/` are preserved in Action 01.
  Before implementation, an engineer must decide how to reconcile the starter
  layout and its current dependency version without silently changing the
  specified stack.
