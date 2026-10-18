# AI usage log

Actual AI changes and validation only; not engineer approval.

## Action 01 — requirements and ownership

- **Changed:** Added requirements/acceptance mapping, provisional Scenario C
  questions, threat model, ADRs, unsigned attestation template, README, and
  secret-safe ignore rules. No implementation or stakeholder decisions.
- **Validation:** Exact specification copy matched; 16 required documents and
  42 acceptance IDs checked; ignore rules and staged whitespace passed.
  Java/Python tests not applicable.
- **Git:** At the time, local Git initialization succeeded but author identity
  was missing, so no commit was attempted. Existing starter files were left
  untouched.

## Action 02 — Java and Python scaffolds

- **Changed:** Added Java 21/Spring Boot 3 and Python/Starlette skeletons,
  health endpoints, OpenAPI paths, smoke tests, exact dependency pins, CI, and
  setup/run instructions. No ledger functionality. Preserved the pre-existing
  root starter.
- **Version note:** Used Spring Boot 3.5.16 to match the assignment; its OSS
  support ended 2026-06-30. Pins and sources are in
  [`docs/dependency-versions.md`](./docs/dependency-versions.md).
- **Validation:** `mvn -B -f java\pom.xml verify` passed (3 tests) on Java
  21.0.12.1/Maven 3.10.0. In Python venv (Python 3.15.0; 3.11 unavailable),
  `ruff check .`, `ruff format --check .`, `mypy src`, `python -m pytest`
  (1 test), and `python -m pip check` passed. Corrected one Ruff import issue
  and replaced deprecated HTTPX test transport with pinned HTTPX2. Remote CI
  not run.
- **Commit:** `673753e8240d00a920e40ddbc877b86ae8e4201f`
  (`build: scaffold Java and Python services`); local `main` is ahead by one.
  No push performed.

## Action 03 — canonical JSON and v1 hashes

- **Changed:** Added bounded strict JSON/JCS and exact v1 hash/content helpers
  in both services, plus shared byte/hash vectors and pinned JCS dependencies.
  Both validate payload commitment trees and exact content shape. Java applies
  strict Jackson checks before JCS; Python validates before its pinned RFC
  8785 serializer. No database or event service added.
- **Validation:** `mvn -B -f java\pom.xml verify` passed (13 tests). From
  `python\` using `.venv\Scripts\python.exe`, Ruff check/format, `mypy src`,
  pytest (31 passed), and `pip check` passed; Pylance syntax check passed.
  Focused binary64 output matched RFC 8785. The initial global-Python Ruff
  command failed because Ruff is only installed in the project venv; Pylance's
  default global interpreter also lacks `rfc8785`, while the project venv has
  pinned `rfc8785==0.1.4`. Python 3.11 was unavailable; CI not run.
- **Git:** Authorized local commit message: `feat: implement canonical JSON
  and v1 hashes`. No push or engineer review claimed.
