# ADR-0001: Platform and repository layout

- **Status:** Accepted as the supplied assignment baseline; the service is
  implemented under `java/`. A second Python service was built and later removed (see the
  decision note below). The unused root starter skeleton was deleted.
- **Context:** The assignment PDF asks for a tamper-evident audit log service
  (Scenarios A, B, C) and does not mandate a language, framework, canonicalization
  scheme or signature algorithm. The stack and the offline verifier are the engineer's
  design choices (the engineer's build brief), made for these reasons: a typed,
  mainstream JVM stack; RFC 8785 JCS and Ed25519 because they are standardized, so a
  recipient can verify without our code.
- **Decision:** Target Java 21, Spring Boot 3, Maven, Jackson, SQLite JDBC,
  springdoc OpenAPI, JUnit 5 and JaCoCo; use plain JDBC through
  `AuditRepository`, no JPA. Keep core/domain/store/service/verify/verifier
  framework-independent and Spring limited to web/config. Use `java/`, `docs/`,
  `docs/adr/`, `scripts/` and `.github/workflows/`.
- **Decision: Python service removed.** The Python/Starlette service and its offline
  verifier implemented the same API, schema and protocol as the Java service, so it was a
  functional duplicate. The engineer chose to keep one Java service to reduce the
  maintenance and defense surface. Trade-off: the second independent implementation and
  the independent Python verifier are gone, so independent cross-implementation evidence
  is limited to the frozen golden fixtures in `java/src/test/resources/golden/`, which
  were produced once by the removed implementation.
- **Version policy:** Resolve compatible supported patch versions from
  official sources at bootstrap, pin exact resolved dependencies, and record
  rationale. Do not guess latest versions or preserve obsolete pins.
- **Consequences:** Reconciling the root starter was resolved by deleting it; the
  specified stack lives under `java/`.
