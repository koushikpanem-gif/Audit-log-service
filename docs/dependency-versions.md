# Dependency versions (bootstrap pins)

Resolved on **2026-10-18** from official Maven Central and upstream
project release documentation. These are scaffold pins, not a claim that the
chosen Spring Boot line still receives community security updates.

## Java

| Component | Exact version | Source / compatibility basis |
|---|---:|---|
| Java runtime/toolchain | 21 | Engineer's choice (Java 21 LTS; the assignment PDF does not mandate a stack); local validation runtime is Eclipse Temurin 21.0.12.1. |
| Spring Boot parent | 3.5.16 | Latest stable `3.5.x` in Maven Central metadata on resolution date; Java 21 is within the line's supported runtime range. |
| springdoc OpenAPI WebMVC UI | 2.8.17 | Latest stable `2.8.x` in Maven Central metadata; springdoc v2 is for Spring Boot 3.x. |
| SQLite JDBC | 3.53.4.0 | Latest stable release in Maven Central metadata on resolution date. |
| java-json-canonicalization | 1.1 | Apache-2.0 JCS implementation; used after strict Jackson validation. |
| JaCoCo Maven plugin | 0.8.15 | Latest stable release in Maven Central metadata on resolution date. |
| JUnit / Spring test libraries | Spring Boot managed | Resolved through the exact Spring Boot parent BOM to keep a compatible set. |

Spring Boot 3.5.16 was the final 3.5.x open-source release and that support
ended on 2026-06-30. Commercial support may differ; no support contract is
assumed. The assignment PDF does not mandate Spring Boot, Java, Python, JCS or
Ed25519; the Spring Boot 3 line is the engineer's stack choice (rationale in
[ADR-0001](./adr/0001-platform-and-layout.md)). This scaffold uses the final 3.5
patch and records the support risk rather than silently changing the chosen
major version. Confirm the support arrangement or
authorize a framework upgrade before production use.

## Official references

- [Spring Boot 3.5.16 release](https://github.com/spring-projects/spring-boot/releases/tag/v3.5.16)
- [Spring Boot system requirements](https://docs.spring.io/spring-boot/3.5/system-requirements.html)
- [Spring Boot support policy](https://spring.io/projects/spring-boot#support)
- [Maven Central Spring Boot parent metadata](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/maven-metadata.xml)
- [springdoc compatibility FAQ](https://springdoc.org/faq.html#compatibility-matrix-of-springdoc-openapi-with-spring-boot)
- [Maven Central springdoc metadata](https://repo.maven.apache.org/maven2/org/springdoc/springdoc-openapi-starter-webmvc-ui/maven-metadata.xml)
- [Maven Central SQLite JDBC metadata](https://repo.maven.apache.org/maven2/org/xerial/sqlite-jdbc/maven-metadata.xml)
- [Maven Central JaCoCo plugin metadata](https://repo.maven.apache.org/maven2/org/jacoco/jacoco-maven-plugin/maven-metadata.xml)

## Action 22 additions (2026-10-18)

Versions below were read from Maven Central `maven-metadata.xml` and the
GitHub tags API / Docker Hub registry API on 2026-10-18; they are build/CI
tooling, not runtime dependencies.

| Tool | Exact version | Role |
|---|---:|---|
| maven-enforcer-plugin | 3.6.3 | Java/Maven version and duplicate-dependency rules |
| spotless-maven-plugin | 3.10.4 | Java format check |
| spotbugs-maven-plugin / SpotBugs | 4.10.5.0 / 4.10.5 | Java static analysis |
| dependency-check-maven | 13.0.0 | Java dependency CVE scan (profile `security-scan`) |
| eclipse-temurin:21-jre-jammy | digest-pinned in Dockerfiles | Container base images |

