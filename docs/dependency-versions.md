# Scaffold dependency versions

Resolved on **2026-10-18** from official Maven Central, PyPI, and upstream
project release documentation. These are scaffold pins, not a claim that the
chosen Spring Boot line still receives community security updates.

## Java

| Component | Exact version | Source / compatibility basis |
|---|---:|---|
| Java runtime/toolchain | 21 | Assignment requires Java 21; local validation runtime is Eclipse Temurin 21.0.12.1. |
| Spring Boot parent | 3.5.16 | Latest stable `3.5.x` in Maven Central metadata on resolution date; Java 21 is within the line's supported runtime range. |
| springdoc OpenAPI WebMVC UI | 2.8.17 | Latest stable `2.8.x` in Maven Central metadata; springdoc v2 is for Spring Boot 3.x. |
| SQLite JDBC | 3.53.4.0 | Latest stable release in Maven Central metadata on resolution date. |
| JaCoCo Maven plugin | 0.8.15 | Latest stable release in Maven Central metadata on resolution date. |
| JUnit / Spring test libraries | Spring Boot managed | Resolved through the exact Spring Boot parent BOM to keep a compatible set. |

Spring Boot 3.5.16 was the final 3.5.x open-source release and that support
ended on 2026-06-30. Commercial support may differ; no support contract is
assumed. The assignment explicitly requires Spring Boot 3, so this scaffold
uses the final 3.5 patch and records the support risk rather than silently
changing the requested major version. Confirm the support arrangement or
authorize a framework upgrade before production use.

## Python

`python/pyproject.toml` pins the direct runtime and development dependencies
with exact `==` versions. The project declares Python `>=3.11`; the CI baseline
is 3.11.

| Package | Exact version | Purpose / source |
|---|---:|---|
| [Starlette](https://pypi.org/project/starlette/) | 1.8.0 | ASGI application; upstream release requires Python >=3.11. |
| [Pydantic](https://pypi.org/project/pydantic/) | 2.14.1 | Data/schema validation stack. |
| [cryptography](https://pypi.org/project/cryptography/) | 50.0.2 | Cryptographic implementation dependency for later actions. |
| [Uvicorn](https://pypi.org/project/uvicorn/) | 0.54.0 | ASGI development/runtime server. |
| [pytest](https://pypi.org/project/pytest/) | 9.1.1 | Tests. |
| [HTTPX2](https://pypi.org/project/httpx2/) | 2.13.1 | Starlette 1.8 test client transport; replaces deprecated HTTPX integration. |
| [Ruff](https://pypi.org/project/ruff/) | 0.17.1 | Lint and formatting checks. |
| [mypy](https://pypi.org/project/mypy/) | 2.4.0 | Static type checking. |
| [setuptools](https://pypi.org/project/setuptools/) | 84.0.0 | Pinned PEP 517 build backend. |

The versions and declared Python requirements were read from each package's
official PyPI JSON metadata endpoint on 2026-10-18. Re-resolve and update these
pins through the dependency-upgrade process when the project intentionally
updates its supported environment.

## Official references

- [Spring Boot 3.5.16 release](https://github.com/spring-projects/spring-boot/releases/tag/v3.5.16)
- [Spring Boot system requirements](https://docs.spring.io/spring-boot/3.5/system-requirements.html)
- [Spring Boot support policy](https://spring.io/projects/spring-boot#support)
- [Maven Central Spring Boot parent metadata](https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-starter-parent/maven-metadata.xml)
- [springdoc compatibility FAQ](https://springdoc.org/faq.html#compatibility-matrix-of-springdoc-openapi-with-spring-boot)
- [Maven Central springdoc metadata](https://repo.maven.apache.org/maven2/org/springdoc/springdoc-openapi-starter-webmvc-ui/maven-metadata.xml)
- [Maven Central SQLite JDBC metadata](https://repo.maven.apache.org/maven2/org/xerial/sqlite-jdbc/maven-metadata.xml)
- [Maven Central JaCoCo plugin metadata](https://repo.maven.apache.org/maven2/org/jacoco/jacoco-maven-plugin/maven-metadata.xml)
- [Python 3.11.17 release](https://www.python.org/downloads/release/python-31117/)
- [Starlette 1.8.0 release](https://github.com/Kludex/starlette/releases/tag/1.8.0)
