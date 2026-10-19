# Quality, security and packaging gates

Recorded 2026-10-18 (Action 22). The Python service and its gates were removed later; see ADR 0001. Thresholds were set just below a measured
baseline; coverage exclusions were not added to raise them.

## Gates

| Area | Gate | Where |
| --- | --- | --- |
| Java build env | maven-enforcer 3.6.3: Java >= 21, Maven >= 3.9, no duplicate POM dependency versions | `java/pom.xml` |
| Java format | spotless 3.10.4 `check` (unused imports, trailing whitespace, final newline); deliberately not a full reformat | `java/pom.xml` |
| Java static analysis | SpotBugs 4.10.5 (plugin 4.10.5.0), effort Max, threshold Medium, fails build | `java/pom.xml`, `java/spotbugs-exclude.xml` |
| Java tests/coverage | JaCoCo 0.8.15 `check`: LINE >= 0.84, BRANCH >= 0.68 (baseline 86.2% / 70.7%, instructions 88.6%) | `java/pom.xml` |
| Java dependency scan | OWASP dependency-check 13.0.0, profile `security-scan`, fail on CVSS >= 7 | `java/pom.xml`, CI job `java-dependency-scan` |
| Hygiene | `scripts/check_hygiene.py` scans tracked files for keys, tokens, DB/log/artifact files | CI `hygiene` job |
| Packaging | executable Spring Boot jar, non-root image, compose \| CI `images` \|

## Dated suppressions and exclusions (none hidden)

- SpotBugs `EI_EXPOSE_REP`/`EI_EXPOSE_REP2` (2026-10-18): constructor-injected
  collaborators/value records stored by reference; defensive copies of shared
  services are not appropriate. Re-review if records gain mutable collections.
- SpotBugs `UWF_UNWRITTEN_FIELD` on `ExportSetService.afterCommitHook`
  (2026-10-18): package-private fault-injection seam written only by tests.
- OWASP suppressions file `java/dependency-check-suppressions.xml`: empty.
- Pins: GitHub Actions by commit SHA (checkout v4.4.0, setup-java v4.9.1,
  upload-artifact v4.6.2, download-artifact v4.3.0),
  Maven plugins by version property, Docker
  base images by tag+digest.

## Source fixes made while enabling the gates

SpotBugs found real issues, fixed rather than suppressed: a leaked
`PreparedStatement` on a parameter-binding failure, unchecked `Path.getParent()`/
`getFileName()` null returns (4 sites), `System.getenv("USERNAME")` instead of
the `user.name` property, catching `NullPointerException` for a null column,
Long reboxing in a comparator, and `String.formatted` over a multi-line SQL
text block.

## Blocked / not verified in the authoring environment

- OWASP dependency-check (NVD download) was not run locally; CI needs the
  `NVD_API_KEY` secret. Without the secret the CI job skips the scan with a visible warning (an empty key is rejected by the plugin); add the secret to enforce the gate.
- Docker was unavailable: images/compose are unbuilt; Dockerfile HEALTHCHECK for
  the Java image uses bash `/dev/tcp` and is untested.
- `ci.yml` was not executed or schema-validated by a runner.

## Artifact hygiene

`.gitignore` covers keys, `.env*`, API-key files, databases, archives, exports,
coverage output and `deploy/`. The only tracked private key is the labelled
non-production golden test key `docs/test-vectors/ed25519-checkpoint-v1.json`
(allow-listed in the hygiene script). `.dockerignore` is an allow-list.
